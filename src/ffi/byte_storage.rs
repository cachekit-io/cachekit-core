//! C FFI wrappers for ByteStorage compress/decompress operations.
//!
//! Provides C-compatible functions for compression and decompression with:
//! - Panic safety via catch_unwind
//! - Comprehensive null pointer checks
//! - Buffer overflow protection
//! - Clear error reporting via CachekitError enum

use crate::byte_storage::{ByteStorage, ByteStorageError};
use crate::ffi::error::CachekitError;
use std::panic::catch_unwind;
use std::slice;

/// Compress input data using LZ4 and xxHash3-64 checksum.
///
/// # Parameters
/// - `input`: Pointer to input data buffer (must not be null)
/// - `input_len`: Length of input data in bytes
/// - `output`: Pointer to output buffer (must not be null)
/// - `output_len`: Pointer to output buffer size (must not be null)
///   On input: size of output buffer
///   On output: actual size of compressed data (or required size if BufferTooSmall)
///
/// # Returns
/// - `CachekitError::Ok` (0) on success
/// - `CachekitError::NullPointer` (9) if any pointer is null
/// - `CachekitError::InvalidInput` (1) if input data is invalid or too large
/// - `CachekitError::BufferTooSmall` (8) if output buffer is too small
///   (output_len will be set to required size)
///
/// # Safety
/// Caller must ensure:
/// - `input` points to valid memory of at least `input_len` bytes
/// - `output` points to valid writable memory of at least `*output_len` bytes
/// - `output_len` points to valid writable memory
/// - Pointers remain valid for duration of call
///
/// Function is panic-safe and will never unwind across FFI boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cachekit_compress(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: *mut usize,
) -> CachekitError {
    // Wrap entire function in catch_unwind for panic safety
    let result = catch_unwind(|| {
        // SAFETY: Null pointer checks before any dereference
        if input.is_null() {
            return CachekitError::NullPointer;
        }
        if output.is_null() {
            return CachekitError::NullPointer;
        }
        if output_len.is_null() {
            return CachekitError::NullPointer;
        }

        // SAFETY: We've verified output_len is not null
        let available_size = unsafe { *output_len };

        // SAFETY: We've verified input is not null and input_len defines the valid range
        let input_slice = unsafe { slice::from_raw_parts(input, input_len) };

        // Create ByteStorage instance and compress
        let storage = ByteStorage::new(None);
        let compressed = match storage.store(input_slice, None) {
            Ok(data) => data,
            Err(e) => {
                // Map ByteStorageError to CachekitError (using specific error codes)
                return match e {
                    ByteStorageError::InputTooLarge => CachekitError::InputTooLarge,
                    ByteStorageError::SerializationFailed(_) => CachekitError::InvalidInput,
                    _ => CachekitError::InvalidInput,
                };
            }
        };

        // Check if output buffer is large enough
        if compressed.len() > available_size {
            // SAFETY: We've verified output_len is not null
            unsafe {
                *output_len = compressed.len();
            }
            return CachekitError::BufferTooSmall;
        }

        // SAFETY: We've verified:
        // - output is not null
        // - available_size (from *output_len) is the valid size of output buffer
        // - compressed.len() <= available_size (checked above)
        unsafe {
            std::ptr::copy_nonoverlapping(compressed.as_ptr(), output, compressed.len());
            *output_len = compressed.len();
        }

        CachekitError::Ok
    });

    // If panic occurred, return error
    result.unwrap_or(CachekitError::InvalidInput)
}

/// Decompress data previously compressed with cachekit_compress.
///
/// # Parameters
/// - `input`: Pointer to compressed data buffer (must not be null)
/// - `input_len`: Length of compressed data in bytes
/// - `output`: Pointer to output buffer (must not be null)
/// - `output_len`: Pointer to output buffer size (must not be null)
///   On input: size of output buffer
///   On output: actual size of decompressed data (or required size if BufferTooSmall)
///
/// # Returns
/// - `CachekitError::Ok` (0) on success
/// - `CachekitError::NullPointer` (9) if any pointer is null
/// - `CachekitError::InvalidInput` (1) if input data is invalid or corrupted
/// - `CachekitError::ChecksumMismatch` (2) if xxHash3-64 checksum verification fails
/// - `CachekitError::DecompressionFailed` (3) if LZ4 decompression fails
/// - `CachekitError::BufferTooSmall` (8) if output buffer is too small
///   (output_len will be set to required size)
///
/// # Empty Data Handling
/// Decompressing data that was originally empty (0-byte input to `cachekit_compress`)
/// is valid and will return `CachekitError::Ok` with `*output_len = 0`. C callers
/// should NOT interpret a zero-length output as failure - check the return code.
///
/// # Safety
/// Caller must ensure:
/// - `input` points to valid memory of at least `input_len` bytes
/// - `output` points to valid writable memory of at least `*output_len` bytes
/// - `output_len` points to valid writable memory
/// - Pointers remain valid for duration of call
///
/// Function is panic-safe and will never unwind across FFI boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cachekit_decompress(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: *mut usize,
) -> CachekitError {
    // Wrap entire function in catch_unwind for panic safety
    let result = catch_unwind(|| {
        // SAFETY: Null pointer checks before any dereference
        if input.is_null() {
            return CachekitError::NullPointer;
        }
        if output.is_null() {
            return CachekitError::NullPointer;
        }
        if output_len.is_null() {
            return CachekitError::NullPointer;
        }

        // SAFETY: We've verified output_len is not null
        let available_size = unsafe { *output_len };

        // SAFETY: We've verified input is not null and input_len defines the valid range
        let input_slice = unsafe { slice::from_raw_parts(input, input_len) };

        // Create ByteStorage instance and decompress
        let storage = ByteStorage::new(None);
        let (decompressed, _format) = match storage.retrieve(input_slice) {
            Ok(data) => data,
            Err(e) => {
                // Map ByteStorageError to CachekitError (using specific error codes per design.md)
                return match e {
                    ByteStorageError::ChecksumMismatch => CachekitError::ChecksumMismatch,
                    ByteStorageError::DecompressionFailed => CachekitError::DecompressionFailed,
                    ByteStorageError::DecompressionBomb => CachekitError::DecompressionBomb,
                    ByteStorageError::InputTooLarge => CachekitError::InputTooLarge,
                    ByteStorageError::SizeValidationFailed => CachekitError::SizeValidationFailed,
                    ByteStorageError::DeserializationFailed(_) => CachekitError::InvalidInput,
                    _ => CachekitError::InvalidInput,
                };
            }
        };

        // Check if output buffer is large enough
        if decompressed.len() > available_size {
            // SAFETY: We've verified output_len is not null
            unsafe {
                *output_len = decompressed.len();
            }
            return CachekitError::BufferTooSmall;
        }

        // SAFETY: We've verified:
        // - output is not null
        // - available_size (from *output_len) is the valid size of output buffer
        // - decompressed.len() <= available_size (checked above)
        unsafe {
            std::ptr::copy_nonoverlapping(decompressed.as_ptr(), output, decompressed.len());
            *output_len = decompressed.len();
        }

        CachekitError::Ok
    });

    // If panic occurred, return error
    result.unwrap_or(CachekitError::DecompressionFailed)
}

/// Estimate maximum compressed size for input data.
///
/// Returns a conservative upper bound for the output buffer size needed
/// for cachekit_compress with the given input length. The actual compressed
/// size will typically be smaller.
///
/// # Parameters
/// - `input_len`: Length of input data in bytes
///
/// # Returns
/// Maximum possible compressed size in bytes (includes overhead for:
/// - LZ4 compression worst case (incompressible data)
/// - MessagePack envelope serialization
/// - xxHash3-64 checksum (8 bytes)
/// - Format string
///
/// # Safety
/// This is a pure computation with no memory access. Always safe to call.
#[unsafe(no_mangle)]
pub extern "C" fn cachekit_compressed_bound(input_len: usize) -> usize {
    // LZ4 worst case: input_len + (input_len / 255) + 16
    // See: https://github.com/lz4/lz4/blob/dev/lib/lz4.h#L166
    // Use saturating arithmetic to prevent overflow on 32-bit systems
    let lz4_bound = input_len.saturating_add(input_len / 255).saturating_add(16);

    // MessagePack envelope overhead:
    // - Map header: ~10 bytes
    // - "compressed_data" key: ~16 bytes
    // - Bin header for data: ~5 bytes
    // - "checksum" key + 8-byte array: ~16 bytes
    // - "original_size" key + u32: ~20 bytes
    // - "format" key + string: ~20 bytes
    let msgpack_overhead = 120;

    lz4_bound.saturating_add(msgpack_overhead)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_roundtrip() {
        let input = b"Hello, World! This is a test of the FFI compression interface.";
        let input_len = input.len();

        // Allocate output buffer for compression
        let mut compressed = vec![0u8; cachekit_compressed_bound(input_len)];
        let mut compressed_len = compressed.len();

        // Compress
        let result = unsafe {
            cachekit_compress(
                input.as_ptr(),
                input_len,
                compressed.as_mut_ptr(),
                &mut compressed_len,
            )
        };
        assert_eq!(result, CachekitError::Ok);
        assert!(compressed_len > 0);
        assert!(compressed_len < compressed.len());

        // Allocate output buffer for decompression
        let mut decompressed = vec![0u8; input_len + 1000]; // Extra space
        let mut decompressed_len = decompressed.len();

        // Decompress
        let result = unsafe {
            cachekit_decompress(
                compressed.as_ptr(),
                compressed_len,
                decompressed.as_mut_ptr(),
                &mut decompressed_len,
            )
        };
        assert_eq!(result, CachekitError::Ok);
        assert_eq!(decompressed_len, input_len);
        assert_eq!(&decompressed[..decompressed_len], input);
    }

    #[test]
    fn test_null_pointer_checks() {
        let input = b"test";
        let mut output = vec![0u8; 1024];
        let mut output_len = output.len();

        // Null input
        assert_eq!(
            unsafe { cachekit_compress(std::ptr::null(), 4, output.as_mut_ptr(), &mut output_len) },
            CachekitError::NullPointer
        );

        // Null output
        assert_eq!(
            unsafe { cachekit_compress(input.as_ptr(), 4, std::ptr::null_mut(), &mut output_len) },
            CachekitError::NullPointer
        );

        // Null output_len
        assert_eq!(
            unsafe {
                cachekit_compress(input.as_ptr(), 4, output.as_mut_ptr(), std::ptr::null_mut())
            },
            CachekitError::NullPointer
        );
    }

    #[test]
    fn test_buffer_too_small() {
        let input = b"Hello, World!";
        let input_len = input.len();

        // Try to compress with tiny buffer
        let mut compressed = vec![0u8; 10]; // Way too small
        let mut compressed_len = compressed.len();

        let result = unsafe {
            cachekit_compress(
                input.as_ptr(),
                input_len,
                compressed.as_mut_ptr(),
                &mut compressed_len,
            )
        };
        assert_eq!(result, CachekitError::BufferTooSmall);
        // compressed_len should now contain required size
        assert!(compressed_len > 10);
    }

    #[test]
    fn test_checksum_mismatch() {
        let input = b"Hello, World!";
        let input_len = input.len();

        // Compress
        let mut compressed = vec![0u8; cachekit_compressed_bound(input_len)];
        let mut compressed_len = compressed.len();
        let result = unsafe {
            cachekit_compress(
                input.as_ptr(),
                input_len,
                compressed.as_mut_ptr(),
                &mut compressed_len,
            )
        };
        assert_eq!(result, CachekitError::Ok);

        // Corrupt the compressed data (flip a byte in the middle)
        if compressed_len > 10 {
            compressed[compressed_len / 2] ^= 0xFF;
        }

        // Try to decompress corrupted data
        let mut decompressed = vec![0u8; input_len + 1000];
        let mut decompressed_len = decompressed.len();
        let result = unsafe {
            cachekit_decompress(
                compressed.as_ptr(),
                compressed_len,
                decompressed.as_mut_ptr(),
                &mut decompressed_len,
            )
        };

        // Should fail with checksum or decompression error
        assert!(result != CachekitError::Ok);
    }

    #[test]
    fn test_compressed_bound_adequate() {
        // Test that compressed_bound provides enough space
        for size in [0, 1, 10, 100, 1000, 10000] {
            let bound = cachekit_compressed_bound(size);
            assert!(bound > size); // Should be larger than input
            assert!(bound < size * 2 + 200); // But not absurdly large
        }
    }

    #[test]
    fn test_empty_data_roundtrip() {
        // Empty data is valid input and should roundtrip correctly
        // This documents the expected FFI behavior for C callers
        let input: &[u8] = b"";
        let input_len = input.len();
        assert_eq!(input_len, 0);

        // Allocate output buffer for compression
        let mut compressed = vec![0u8; cachekit_compressed_bound(input_len)];
        let mut compressed_len = compressed.len();

        // Compress empty data
        let result = unsafe {
            cachekit_compress(
                input.as_ptr(),
                input_len,
                compressed.as_mut_ptr(),
                &mut compressed_len,
            )
        };
        assert_eq!(result, CachekitError::Ok);
        assert!(compressed_len > 0); // Envelope has overhead even for empty data

        // Decompress back to empty
        let mut decompressed = vec![0u8; 100]; // Extra space
        let mut decompressed_len = decompressed.len();

        let result = unsafe {
            cachekit_decompress(
                compressed.as_ptr(),
                compressed_len,
                decompressed.as_mut_ptr(),
                &mut decompressed_len,
            )
        };
        // KEY: CachekitError::Ok with output_len=0 is VALID, not an error
        assert_eq!(result, CachekitError::Ok);
        assert_eq!(decompressed_len, 0); // Empty data decompresses to empty
    }
}
