//! C FFI wrappers for encryption operations.
//!
//! Provides C-compatible functions for AES-256-GCM encryption with:
//! - Panic safety via catch_unwind
//! - Comprehensive null pointer checks
//! - Counter exhaustion detection
//! - Clear error reporting via CachekitError enum
//!
//! All functions are feature-gated with #[cfg(feature = "encryption")]

// AES-256-GCM ciphertext format constants
// Output format: [nonce(12)][ciphertext][auth_tag(16)]
#[cfg(feature = "encryption")]
const NONCE_SIZE: usize = 12;
#[cfg(feature = "encryption")]
const TAG_SIZE: usize = 16;
/// Total overhead added to plaintext: 12-byte nonce + 16-byte authentication tag
#[cfg(feature = "encryption")]
const CIPHERTEXT_OVERHEAD: usize = NONCE_SIZE + TAG_SIZE; // 28 bytes

#[cfg(feature = "encryption")]
use crate::encryption::{ZeroKnowledgeEncryptor, derive_domain_key};
#[cfg(feature = "encryption")]
use crate::ffi::error::CachekitError;
#[cfg(feature = "encryption")]
use crate::ffi::handles::CachekitEncryptor;
#[cfg(feature = "encryption")]
use std::panic::catch_unwind;
#[cfg(feature = "encryption")]
use std::slice;

/// Create a new ZeroKnowledgeEncryptor instance.
///
/// # Returns
/// Opaque pointer to ZeroKnowledgeEncryptor instance, or null on failure.
/// Must be freed with `cachekit_encryptor_free`.
///
/// # Parameters
/// - `error_out`: Optional pointer to receive error code on failure (may be null)
///
/// # Error Codes
/// - `CachekitError::Ok` (0) on success
/// - `CachekitError::RngFailure` (13) if random number generation failed
///
/// # Safety
/// - Returned pointer must be freed with `cachekit_encryptor_free`
/// - Do not use pointer after calling `cachekit_encryptor_free`
/// - Function is panic-safe and will never unwind across FFI boundary
///
/// # ⚠️ CRITICAL: NONCE REUSE WARNING ⚠️
///
/// **SEVERITY: CATASTROPHIC** - Nonce reuse in AES-GCM enables complete key recovery
/// from as few as 2 ciphertexts encrypted with the same nonce.
///
/// **ARCHITECTURE**: Each `CachekitEncryptor` handle has an INDEPENDENT nonce counter
/// starting at 0. This means:
///
/// ## ✅ CORRECT USAGE (Singleton Pattern)
/// ```c
/// // ONE handle per key for the application lifetime
/// CachekitEncryptor* encryptor = cachekit_encryptor_new(NULL);
/// // Use this single handle for all encryptions with this key
/// cachekit_encrypt(encryptor, key, ...);  // nonce=0
/// cachekit_encrypt(encryptor, key, ...);  // nonce=1
/// cachekit_encrypt(encryptor, key, ...);  // nonce=2
/// ```
///
/// ## ❌ INCORRECT USAGE (Immediate Nonce Reuse!)
/// ```c
/// // DANGER: Creating multiple handles with the same key
/// CachekitEncryptor* enc1 = cachekit_encryptor_new(NULL);
/// CachekitEncryptor* enc2 = cachekit_encryptor_new(NULL);
/// cachekit_encrypt(enc1, key, ...);  // nonce=0
/// cachekit_encrypt(enc2, key, ...);  // nonce=0 AGAIN! KEY COMPROMISED!
/// ```
///
/// **RECOMMENDATION**: Store the encryptor handle in a global/singleton and reuse it.
/// Each handle supports 2^32 (~4 billion) encryptions before requiring a new key.
#[cfg(feature = "encryption")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cachekit_encryptor_new(
    error_out: *mut CachekitError,
) -> *mut CachekitEncryptor {
    let result = catch_unwind(|| match ZeroKnowledgeEncryptor::new() {
        Ok(encryptor) => {
            if !error_out.is_null() {
                unsafe { *error_out = CachekitError::Ok };
            }
            CachekitEncryptor::into_opaque_ptr(encryptor)
        }
        Err(e) => {
            if !error_out.is_null() {
                unsafe { *error_out = CachekitError::from(e) };
            }
            std::ptr::null_mut()
        }
    });

    result.unwrap_or_else(|_| {
        if !error_out.is_null() {
            unsafe { *error_out = CachekitError::InvalidInput };
        }
        std::ptr::null_mut()
    })
}

/// Free a ZeroKnowledgeEncryptor instance.
///
/// # Parameters
/// - `handle`: Pointer returned from `cachekit_encryptor_new`
///
/// # Safety
/// - `handle` must have been created by `cachekit_encryptor_new`
/// - `handle` must not be null
/// - `handle` must not be used after this call
/// - Function is panic-safe and will never unwind across FFI boundary
#[cfg(feature = "encryption")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cachekit_encryptor_free(handle: *mut CachekitEncryptor) {
    let _ = catch_unwind(|| {
        // from_opaque_ptr handles null check and validity tracking
        // Returns None for null, already-freed, or never-created handles
        // SAFETY: If Some is returned, we own the encryptor and it will be dropped
        unsafe {
            let _encryptor = CachekitEncryptor::from_opaque_ptr(handle);
            // If Some: _encryptor dropped here, memory reclaimed
            // If None: handle was invalid (null, double-free, or never created)
        }
    });
}

/// Get current nonce counter value from encryptor.
///
/// Used for monitoring counter exhaustion. Returns 0 if handle is null.
///
/// # Parameters
/// - `handle`: Pointer to encryptor instance (must not be null)
///
/// # Returns
/// Current nonce counter value (0 to 2^32-1), or 0 if handle is null.
///
/// # Safety
/// - `handle` must have been created by `cachekit_encryptor_new`
/// - `handle` must remain valid for duration of call
/// - Function is panic-safe and will never unwind across FFI boundary
#[cfg(feature = "encryption")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cachekit_encryptor_get_counter(handle: *const CachekitEncryptor) -> u64 {
    let result = catch_unwind(|| {
        // as_ref handles null check and validity tracking
        // SAFETY: We don't consume the handle, just borrow it
        let encryptor = match unsafe { CachekitEncryptor::as_ref(handle) } {
            Some(enc) => enc,
            None => return 0, // Invalid handle
        };
        encryptor.get_nonce_counter()
    });

    result.unwrap_or(0)
}

/// Encrypt data using AES-256-GCM with authenticated additional data.
///
/// # Parameters
/// - `handle`: Pointer to encryptor instance (must not be null)
/// - `key`: Pointer to 256-bit (32-byte) encryption key (must not be null)
/// - `key_len`: Length of key in bytes (must be 32)
/// - `aad`: Pointer to additional authenticated data (must not be null, can point to empty data)
/// - `aad_len`: Length of AAD in bytes (can be 0)
/// - `plaintext`: Pointer to plaintext data (must not be null)
/// - `plaintext_len`: Length of plaintext in bytes
/// - `output`: Pointer to output buffer (must not be null)
/// - `output_len`: Pointer to output buffer size (must not be null)
///   On input: size of output buffer (must be at least `plaintext_len + CIPHERTEXT_OVERHEAD` (28 bytes))
///   On output: actual size of encrypted data
///
/// # Output Format
/// `[nonce(12)][ciphertext][auth_tag(16)]`
///
/// # Returns
/// - `CachekitError::Ok` (0) on success
/// - `CachekitError::NullPointer` (9) if any pointer is null
/// - `CachekitError::InvalidKeyLength` (7) if key is not 32 bytes
/// - `CachekitError::RotationNeeded` (5) if counter >= 2^31 (recommended rotation threshold)
/// - `CachekitError::CounterExhausted` (6) if counter >= 2^32 (critical, requires new encryptor)
/// - `CachekitError::BufferTooSmall` (8) if output buffer is too small
/// - `CachekitError::InvalidInput` (1) for other encryption failures
///
/// # Safety
/// Caller must ensure:
/// - All pointers point to valid memory regions of specified lengths
/// - `output` buffer has at least `plaintext_len + CIPHERTEXT_OVERHEAD` (28) bytes available
/// - Pointers remain valid for duration of call
/// - Key material is never logged or exposed
///
/// Function is panic-safe and will never unwind across FFI boundary.
#[cfg(feature = "encryption")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cachekit_encrypt(
    handle: *mut CachekitEncryptor,
    key: *const u8,
    key_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    output: *mut u8,
    output_len: *mut usize,
) -> CachekitError {
    let result = catch_unwind(|| {
        // Null pointer checks for non-handle parameters
        if key.is_null() {
            return CachekitError::NullPointer;
        }
        if aad.is_null() {
            return CachekitError::NullPointer;
        }
        if plaintext.is_null() {
            return CachekitError::NullPointer;
        }
        if output.is_null() {
            return CachekitError::NullPointer;
        }
        if output_len.is_null() {
            return CachekitError::NullPointer;
        }

        // Validate handle (checks null, registered, and not freed)
        // SAFETY: We don't consume the handle, just borrow it
        let encryptor = match unsafe { CachekitEncryptor::as_ref(handle) } {
            Some(enc) => enc,
            None => return CachekitError::InvalidHandle,
        };

        // SAFETY: We've verified output_len is not null
        let available_size = unsafe { *output_len };

        // Check counter before operation (2^31 threshold for rotation recommendation)
        let counter = encryptor.get_nonce_counter();

        // At 2^31, warn that rotation is needed (before reaching 2^32 hard limit)
        if counter >= (1u64 << 31) {
            return CachekitError::RotationNeeded;
        }

        // Validate key length
        if key_len != 32 {
            return CachekitError::InvalidKeyLength;
        }

        // SAFETY: We've verified pointers are not null and lengths define valid ranges
        let key_slice = unsafe { slice::from_raw_parts(key, key_len) };
        let aad_slice = unsafe { slice::from_raw_parts(aad, aad_len) };
        let plaintext_slice = unsafe { slice::from_raw_parts(plaintext, plaintext_len) };

        // Perform encryption
        let ciphertext = match encryptor.encrypt_aes_gcm(plaintext_slice, key_slice, aad_slice) {
            Ok(data) => data,
            Err(e) => {
                // Convert encryption errors to FFI error codes
                return CachekitError::from(e);
            }
        };

        // Check if output buffer is large enough
        // Ciphertext format: [nonce(12)][encrypted_data][tag(16)] = plaintext_len + CIPHERTEXT_OVERHEAD
        if ciphertext.len() > available_size {
            // SAFETY: We've verified output_len is not null
            unsafe {
                *output_len = ciphertext.len();
            }
            return CachekitError::BufferTooSmall;
        }

        // Copy to output buffer
        // SAFETY: We've verified:
        // - output is not null
        // - available_size is the valid size of output buffer
        // - ciphertext.len() <= available_size (checked above)
        unsafe {
            std::ptr::copy_nonoverlapping(ciphertext.as_ptr(), output, ciphertext.len());
            *output_len = ciphertext.len();
        }

        CachekitError::Ok
    });

    result.unwrap_or(CachekitError::InvalidInput)
}

/// Decrypt data using AES-256-GCM with authenticated additional data.
///
/// # Parameters
/// - `handle`: Pointer to encryptor instance (must not be null). Use the same handle
///   that was used for encryption to maintain API consistency. While decryption is
///   stateless, using a handle avoids the overhead of creating a new encryptor per call.
/// - `key`: Pointer to 256-bit (32-byte) decryption key (must not be null)
/// - `key_len`: Length of key in bytes (must be 32)
/// - `aad`: Pointer to additional authenticated data (must not be null, can point to empty data)
/// - `aad_len`: Length of AAD in bytes (must match encryption AAD)
/// - `ciphertext`: Pointer to encrypted data in format `[nonce(12)][ciphertext][tag(16)]`
/// - `ciphertext_len`: Length of ciphertext in bytes (must be at least `CIPHERTEXT_OVERHEAD` (28))
/// - `output`: Pointer to output buffer (must not be null)
/// - `output_len`: Pointer to output buffer size (must not be null)
///   On input: size of output buffer
///   On output: actual size of plaintext data
///
/// # Returns
/// - `CachekitError::Ok` (0) on success
/// - `CachekitError::InvalidHandle` (10) if handle is null or invalid
/// - `CachekitError::NullPointer` (9) if any other pointer is null
/// - `CachekitError::InvalidKeyLength` (7) if key is not 32 bytes
/// - `CachekitError::InvalidInput` (1) if ciphertext is too short or malformed
/// - `CachekitError::DecryptionFailed` (4) if authentication tag verification fails
/// - `CachekitError::BufferTooSmall` (8) if output buffer is too small
///
/// # Safety
/// Caller must ensure:
/// - `handle` was created by `cachekit_encryptor_new` and not freed
/// - All pointers point to valid memory regions of specified lengths
/// - `output` buffer has enough space for decrypted data
/// - Pointers remain valid for duration of call
/// - AAD matches the AAD used during encryption
///
/// Function is panic-safe and will never unwind across FFI boundary.
#[cfg(feature = "encryption")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cachekit_decrypt(
    handle: *const CachekitEncryptor,
    key: *const u8,
    key_len: usize,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    output: *mut u8,
    output_len: *mut usize,
) -> CachekitError {
    let result = catch_unwind(|| {
        // Null pointer checks for non-handle parameters
        if key.is_null() {
            return CachekitError::NullPointer;
        }
        if aad.is_null() {
            return CachekitError::NullPointer;
        }
        if ciphertext.is_null() {
            return CachekitError::NullPointer;
        }
        if output.is_null() {
            return CachekitError::NullPointer;
        }
        if output_len.is_null() {
            return CachekitError::NullPointer;
        }

        // Validate handle (checks null, registered, and not freed)
        // SAFETY: We don't consume the handle, just borrow it
        let encryptor = match unsafe { CachekitEncryptor::as_ref(handle) } {
            Some(enc) => enc,
            None => return CachekitError::InvalidHandle,
        };

        // SAFETY: We've verified output_len is not null
        let available_size = unsafe { *output_len };

        // Validate key length
        if key_len != 32 {
            return CachekitError::InvalidKeyLength;
        }

        // Validate minimum ciphertext length (nonce + tag = CIPHERTEXT_OVERHEAD bytes minimum)
        if ciphertext_len < CIPHERTEXT_OVERHEAD {
            return CachekitError::InvalidInput;
        }

        // SAFETY: We've verified pointers are not null and lengths define valid ranges
        let key_slice = unsafe { slice::from_raw_parts(key, key_len) };
        let aad_slice = unsafe { slice::from_raw_parts(aad, aad_len) };
        let ciphertext_slice = unsafe { slice::from_raw_parts(ciphertext, ciphertext_len) };

        // Perform decryption using the provided handle (avoids creating new encryptor)
        let plaintext = match encryptor.decrypt_aes_gcm(ciphertext_slice, key_slice, aad_slice) {
            Ok(data) => data,
            Err(e) => {
                // Convert decryption errors to FFI error codes
                return CachekitError::from(e);
            }
        };

        // Check if output buffer is large enough
        if plaintext.len() > available_size {
            // SAFETY: We've verified output_len is not null
            unsafe {
                *output_len = plaintext.len();
            }
            return CachekitError::BufferTooSmall;
        }

        // Copy to output buffer
        // SAFETY: We've verified:
        // - output is not null
        // - available_size is the valid size of output buffer
        // - plaintext.len() <= available_size (checked above)
        unsafe {
            std::ptr::copy_nonoverlapping(plaintext.as_ptr(), output, plaintext.len());
            *output_len = plaintext.len();
        }

        CachekitError::Ok
    });

    result.unwrap_or(CachekitError::DecryptionFailed)
}

/// Derive a domain-specific key using HKDF-SHA256.
///
/// # Parameters
/// - `master`: Pointer to master key (must not be null, minimum 16 bytes, recommended 32 bytes)
/// - `master_len`: Length of master key in bytes (minimum 16)
/// - `salt`: Pointer to salt/tenant ID (must not be null, minimum 1 byte)
/// - `salt_len`: Length of salt in bytes (minimum 1)
/// - `domain`: Pointer to domain context string (must not be null)
/// - `domain_len`: Length of domain string in bytes
/// - `out_key`: Pointer to output buffer for derived key (must not be null, must be at least 32 bytes)
///
/// # Returns
/// - `CachekitError::Ok` (0) on success, out_key contains 32-byte derived key
/// - `CachekitError::NullPointer` (9) if any pointer is null
/// - `CachekitError::InvalidKeyLength` (7) if master key is less than 16 bytes
/// - `CachekitError::InvalidInput` (1) if salt is empty or domain is empty
///
/// # Safety
/// Caller must ensure:
/// - All pointers point to valid memory regions of specified lengths
/// - `out_key` buffer has at least 32 bytes available
/// - Pointers remain valid for duration of call
///
/// Function is panic-safe and will never unwind across FFI boundary.
#[cfg(feature = "encryption")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cachekit_derive_key(
    master: *const u8,
    master_len: usize,
    salt: *const u8,
    salt_len: usize,
    domain: *const u8,
    domain_len: usize,
    out_key: *mut u8,
) -> CachekitError {
    let result = catch_unwind(|| {
        // Null pointer checks
        if master.is_null() {
            return CachekitError::NullPointer;
        }
        if salt.is_null() {
            return CachekitError::NullPointer;
        }
        if domain.is_null() {
            return CachekitError::NullPointer;
        }
        if out_key.is_null() {
            return CachekitError::NullPointer;
        }

        // SAFETY: We've verified pointers are not null and lengths define valid ranges
        let master_slice = unsafe { slice::from_raw_parts(master, master_len) };
        let salt_slice = unsafe { slice::from_raw_parts(salt, salt_len) };
        let domain_slice = unsafe { slice::from_raw_parts(domain, domain_len) };

        // Convert domain bytes to UTF-8 string
        let domain_str = match std::str::from_utf8(domain_slice) {
            Ok(s) => s,
            Err(_) => return CachekitError::InvalidInput,
        };

        // Derive key using HKDF
        let derived_key = match derive_domain_key(master_slice, domain_str, salt_slice) {
            Ok(key) => key,
            Err(e) => {
                // Convert key derivation errors to FFI error codes
                return CachekitError::from(e);
            }
        };

        // Copy 32 bytes to output buffer
        // SAFETY: We've verified out_key is not null, and derived_key is always 32 bytes
        unsafe {
            std::ptr::copy_nonoverlapping(derived_key.as_ptr(), out_key, 32);
        }

        CachekitError::Ok
    });

    result.unwrap_or(CachekitError::InvalidInput)
}

#[cfg(all(test, feature = "encryption"))]
mod tests {
    use super::*;

    #[test]
    fn test_encryptor_lifecycle() {
        unsafe {
            let handle = cachekit_encryptor_new(std::ptr::null_mut());
            assert!(!handle.is_null());

            let counter = cachekit_encryptor_get_counter(handle);
            assert_eq!(counter, 0);

            cachekit_encryptor_free(handle);
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        unsafe {
            let handle = cachekit_encryptor_new(std::ptr::null_mut());
            assert!(!handle.is_null());

            let key = [0u8; 32];
            let aad = b"test_context";
            let plaintext = b"Hello, FFI encryption!";

            // Encrypt
            let mut ciphertext = vec![0u8; plaintext.len() + 100];
            let mut ciphertext_len = ciphertext.len();
            let result = cachekit_encrypt(
                handle,
                key.as_ptr(),
                32,
                aad.as_ptr(),
                aad.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                ciphertext.as_mut_ptr(),
                &mut ciphertext_len,
            );
            assert_eq!(result, CachekitError::Ok);
            assert_eq!(ciphertext_len, plaintext.len() + CIPHERTEXT_OVERHEAD); // nonce(12) + tag(16)

            // Decrypt (using the same handle for API consistency)
            let mut decrypted = vec![0u8; plaintext.len() + 100];
            let mut decrypted_len = decrypted.len();
            let result = cachekit_decrypt(
                handle,
                key.as_ptr(),
                32,
                aad.as_ptr(),
                aad.len(),
                ciphertext.as_ptr(),
                ciphertext_len,
                decrypted.as_mut_ptr(),
                &mut decrypted_len,
            );
            assert_eq!(result, CachekitError::Ok);
            assert_eq!(decrypted_len, plaintext.len());
            assert_eq!(&decrypted[..decrypted_len], plaintext);

            cachekit_encryptor_free(handle);
        }
    }

    #[test]
    fn test_encrypt_null_checks() {
        unsafe {
            let handle = cachekit_encryptor_new(std::ptr::null_mut());
            let key = [0u8; 32];
            let aad = b"test";
            let plaintext = b"test";
            let mut output = vec![0u8; 100];
            let mut output_len = output.len();

            // Null handle (returns InvalidHandle, not NullPointer - handles are validated separately)
            assert_eq!(
                cachekit_encrypt(
                    std::ptr::null_mut(),
                    key.as_ptr(),
                    32,
                    aad.as_ptr(),
                    aad.len(),
                    plaintext.as_ptr(),
                    plaintext.len(),
                    output.as_mut_ptr(),
                    &mut output_len,
                ),
                CachekitError::InvalidHandle
            );

            // Null key
            assert_eq!(
                cachekit_encrypt(
                    handle,
                    std::ptr::null(),
                    32,
                    aad.as_ptr(),
                    aad.len(),
                    plaintext.as_ptr(),
                    plaintext.len(),
                    output.as_mut_ptr(),
                    &mut output_len,
                ),
                CachekitError::NullPointer
            );

            cachekit_encryptor_free(handle);
        }
    }

    #[test]
    fn test_decrypt_wrong_key() {
        unsafe {
            let handle = cachekit_encryptor_new(std::ptr::null_mut());

            let key1 = [0u8; 32];
            let key2 = [1u8; 32];
            let aad = b"test";
            let plaintext = b"secret";

            // Encrypt with key1
            let mut ciphertext = vec![0u8; plaintext.len() + 100];
            let mut ciphertext_len = ciphertext.len();
            let result = cachekit_encrypt(
                handle,
                key1.as_ptr(),
                32,
                aad.as_ptr(),
                aad.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                ciphertext.as_mut_ptr(),
                &mut ciphertext_len,
            );
            assert_eq!(result, CachekitError::Ok);

            // Try to decrypt with key2 (using same handle, different key should fail auth)
            let mut decrypted = vec![0u8; plaintext.len() + 100];
            let mut decrypted_len = decrypted.len();
            let result = cachekit_decrypt(
                handle,
                key2.as_ptr(),
                32,
                aad.as_ptr(),
                aad.len(),
                ciphertext.as_ptr(),
                ciphertext_len,
                decrypted.as_mut_ptr(),
                &mut decrypted_len,
            );
            assert_eq!(result, CachekitError::DecryptionFailed);

            cachekit_encryptor_free(handle);
        }
    }

    #[test]
    fn test_derive_key_basic() {
        unsafe {
            let master = b"test_master_key_32_bytes_long!!!";
            let salt = b"tenant123";
            let domain = b"encryption";
            let mut out_key = [0u8; 32];

            let result = cachekit_derive_key(
                master.as_ptr(),
                master.len(),
                salt.as_ptr(),
                salt.len(),
                domain.as_ptr(),
                domain.len(),
                out_key.as_mut_ptr(),
            );
            assert_eq!(result, CachekitError::Ok);

            // Verify key is not all zeros
            assert_ne!(out_key, [0u8; 32]);
        }
    }

    #[test]
    fn test_derive_key_deterministic() {
        unsafe {
            let master = b"test_master_key_32_bytes_long!!!";
            let salt = b"tenant123";
            let domain = b"encryption";
            let mut key1 = [0u8; 32];
            let mut key2 = [0u8; 32];

            cachekit_derive_key(
                master.as_ptr(),
                master.len(),
                salt.as_ptr(),
                salt.len(),
                domain.as_ptr(),
                domain.len(),
                key1.as_mut_ptr(),
            );

            cachekit_derive_key(
                master.as_ptr(),
                master.len(),
                salt.as_ptr(),
                salt.len(),
                domain.as_ptr(),
                domain.len(),
                key2.as_mut_ptr(),
            );

            assert_eq!(key1, key2);
        }
    }

    #[test]
    fn test_invalid_key_length() {
        unsafe {
            let handle = cachekit_encryptor_new(std::ptr::null_mut());
            let short_key = [0u8; 16]; // Should be 32
            let aad = b"test";
            let plaintext = b"test";
            let mut output = vec![0u8; 100];
            let mut output_len = output.len();

            let result = cachekit_encrypt(
                handle,
                short_key.as_ptr(),
                16,
                aad.as_ptr(),
                aad.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                output.as_mut_ptr(),
                &mut output_len,
            );
            assert_eq!(result, CachekitError::InvalidKeyLength);

            cachekit_encryptor_free(handle);
        }
    }

    #[test]
    fn test_buffer_too_small() {
        unsafe {
            let handle = cachekit_encryptor_new(std::ptr::null_mut());
            let key = [0u8; 32];
            let aad = b"test";
            let plaintext = b"Hello, World!";
            let mut output = vec![0u8; 10]; // Way too small
            let mut output_len = output.len();

            let result = cachekit_encrypt(
                handle,
                key.as_ptr(),
                32,
                aad.as_ptr(),
                aad.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                output.as_mut_ptr(),
                &mut output_len,
            );
            assert_eq!(result, CachekitError::BufferTooSmall);
            assert_eq!(output_len, plaintext.len() + CIPHERTEXT_OVERHEAD);

            cachekit_encryptor_free(handle);
        }
    }
}
