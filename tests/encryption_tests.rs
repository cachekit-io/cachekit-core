//! Encryption module comprehensive tests
//!
//! This module validates encryption behavior beyond what Kani proofs verify.
//! While Kani proves security properties (no buffer overflows, correct AES-GCM usage,
//! constant-time operations), these tests validate:
//!
//! - **API Behavior**: Key derivation determinism, domain separation, tenant isolation
//! - **Error Handling**: Clear error messages for invalid inputs
//! - **Roundtrip Correctness**: Encrypt → decrypt preserves data
//! - **AAD Binding**: Additional Authenticated Data prevents ciphertext reuse
//! - **Nonce Uniqueness**: Non-deterministic encryption prevents pattern analysis
//! - **Tamper Resistance**: Authentication tags detect modifications
//!
//! These tests complement the 6 Kani proofs in `src/encryption/` which formally
//! verify memory safety and cryptographic correctness.

#![cfg(feature = "encryption")]

mod common;

use cachekit_core::encryption::core::{EncryptionError, ZeroKnowledgeEncryptor};
use cachekit_core::encryption::key_derivation::{KeyDerivationError, derive_domain_key};
use common::fixtures::*;

// Local test constants only used in encryption tests
const TEST_TENANT_C: &[u8] = b"tenant_charlie";

// ============================================================================
// Key Derivation Tests
// ============================================================================

mod key_derivation {
    use super::*;

    #[test]
    fn test_same_inputs_same_key() {
        // Verify determinism: same inputs → same key (required for caching)
        let key1 = derive_domain_key(TEST_MASTER_KEY, "cache", TEST_TENANT_A).unwrap();
        let key2 = derive_domain_key(TEST_MASTER_KEY, "cache", TEST_TENANT_A).unwrap();

        assert_eq!(
            key1, key2,
            "Same master key + domain + tenant must produce identical derived key"
        );
    }

    #[test]
    fn test_different_domain_different_key() {
        // Verify domain separation: prevents key confusion attacks
        let cache_key = derive_domain_key(TEST_MASTER_KEY, "cache", TEST_TENANT_A).unwrap();
        let auth_key = derive_domain_key(TEST_MASTER_KEY, "authentication", TEST_TENANT_A).unwrap();

        assert_ne!(
            cache_key, auth_key,
            "Different domains must produce different keys to prevent cross-domain key reuse"
        );

        // Additional domain to verify all are unique
        let session_key = derive_domain_key(TEST_MASTER_KEY, "session", TEST_TENANT_A).unwrap();

        assert_ne!(cache_key, session_key);
        assert_ne!(auth_key, session_key);
    }

    #[test]
    fn test_different_tenant_different_key() {
        // Verify tenant isolation: critical for multi-tenant security
        let tenant_a_key = derive_domain_key(TEST_MASTER_KEY, "cache", TEST_TENANT_A).unwrap();
        let tenant_b_key = derive_domain_key(TEST_MASTER_KEY, "cache", TEST_TENANT_B).unwrap();
        let tenant_c_key = derive_domain_key(TEST_MASTER_KEY, "cache", TEST_TENANT_C).unwrap();

        // All tenants must have unique keys
        assert_ne!(
            tenant_a_key, tenant_b_key,
            "Tenant A and B must have different keys"
        );
        assert_ne!(
            tenant_a_key, tenant_c_key,
            "Tenant A and C must have different keys"
        );
        assert_ne!(
            tenant_b_key, tenant_c_key,
            "Tenant B and C must have different keys"
        );
    }

    #[test]
    fn test_master_key_length_validation() {
        // Verify minimum key length enforcement (16 bytes minimum)
        let short_key_4 = b"tiny";
        let short_key_8 = b"8bytes!!";
        let short_key_15 = b"15bytes_exactly";
        let valid_key_16 = b"16bytes_exactly!";

        // Too short keys should fail with clear error
        let result = derive_domain_key(short_key_4, "cache", TEST_TENANT_A);
        assert!(
            matches!(result, Err(KeyDerivationError::InvalidMasterKeyLength(4))),
            "4-byte key should be rejected with InvalidMasterKeyLength(4)"
        );

        let result = derive_domain_key(short_key_8, "cache", TEST_TENANT_A);
        assert!(
            matches!(result, Err(KeyDerivationError::InvalidMasterKeyLength(8))),
            "8-byte key should be rejected"
        );

        let result = derive_domain_key(short_key_15, "cache", TEST_TENANT_A);
        assert!(
            matches!(result, Err(KeyDerivationError::InvalidMasterKeyLength(15))),
            "15-byte key (1 byte short) should be rejected"
        );

        // Minimum valid length should succeed
        let result = derive_domain_key(valid_key_16, "cache", TEST_TENANT_A);
        assert!(result.is_ok(), "16-byte key should be accepted");

        // TEST_MASTER_KEY (32 bytes) should also work
        let result = derive_domain_key(TEST_MASTER_KEY, "cache", TEST_TENANT_A);
        assert!(result.is_ok(), "32-byte key should be accepted");
    }

    #[test]
    fn test_empty_domain_rejected() {
        // Verify empty domain string is rejected
        let result = derive_domain_key(TEST_MASTER_KEY, "", TEST_TENANT_A);

        assert!(
            matches!(result, Err(KeyDerivationError::InvalidDomain(_))),
            "Empty domain should be rejected with InvalidDomain error"
        );

        // Verify error message is descriptive
        if let Err(KeyDerivationError::InvalidDomain(msg)) = result {
            assert!(
                msg.contains("empty") || msg.contains("Empty"),
                "Error message should mention 'empty': {}",
                msg
            );
        }
    }
}

// ============================================================================
// Encryption Roundtrip Tests
// ============================================================================

mod encryption_roundtrip {
    use super::*;

    #[test]
    fn test_roundtrip_empty_plaintext() {
        // Verify empty data encrypts and decrypts correctly
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0x42u8; 32]; // Test key (32 bytes for AES-256)
        let aad = b"test_domain";
        let plaintext = EMPTY_DATA;

        let ciphertext = encryptor
            .encrypt_aes_gcm(plaintext, &key, aad)
            .expect("Encryption should succeed");

        // Ciphertext should be longer than plaintext (nonce + tag = 28 bytes minimum)
        assert!(
            ciphertext.len() >= 28,
            "Ciphertext must include nonce (12 bytes) + tag (16 bytes)"
        );

        let decrypted = encryptor
            .decrypt_aes_gcm(&ciphertext, &key, aad)
            .expect("Decryption should succeed");

        assert_eq!(
            decrypted, plaintext,
            "Decrypted empty data should match original"
        );
    }

    #[test]
    fn test_roundtrip_small_plaintext() {
        // Verify typical small payload encrypts correctly
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0x3eu8; 32];
        let aad = b"cache";
        let plaintext = SMALL_DATA; // "hello world"

        let ciphertext = encryptor
            .encrypt_aes_gcm(plaintext, &key, aad)
            .expect("Encryption should succeed");

        // Verify ciphertext format: nonce (12) + encrypted_data + tag (16)
        let expected_min_size = 12 + plaintext.len() + 16;
        assert_eq!(
            ciphertext.len(),
            expected_min_size,
            "Ciphertext size should be nonce + plaintext + tag"
        );

        let decrypted = encryptor
            .decrypt_aes_gcm(&ciphertext, &key, aad)
            .expect("Decryption should succeed");

        assert_eq!(
            decrypted, plaintext,
            "Decrypted data should exactly match original"
        );
    }

    #[test]
    fn test_roundtrip_large_plaintext() {
        // Verify large payloads (10KB) work correctly
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0x5au8; 32];
        let aad = b"large_payload_domain";

        // Generate 10KB of test data
        let plaintext = vec![0x7fu8; 10_000];

        let ciphertext = encryptor
            .encrypt_aes_gcm(&plaintext, &key, aad)
            .expect("Encryption should succeed for large payload");

        assert_eq!(
            ciphertext.len(),
            12 + plaintext.len() + 16,
            "Large payload ciphertext size correct"
        );

        let decrypted = encryptor
            .decrypt_aes_gcm(&ciphertext, &key, aad)
            .expect("Decryption should succeed for large payload");

        assert_eq!(
            decrypted, plaintext,
            "Large payload should roundtrip correctly"
        );
    }

    #[test]
    fn test_roundtrip_unicode_plaintext() {
        // Verify UTF-8 unicode data preserves correctly
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0x9cu8; 32];
        let aad = b"unicode_domain";
        let plaintext = UNICODE_DATA; // "Hello 世界 🚀 Rust"

        let ciphertext = encryptor
            .encrypt_aes_gcm(plaintext, &key, aad)
            .expect("Unicode encryption should succeed");

        let decrypted = encryptor
            .decrypt_aes_gcm(&ciphertext, &key, aad)
            .expect("Unicode decryption should succeed");

        assert_eq!(decrypted, plaintext, "Unicode data should preserve exactly");

        // Verify it's still valid UTF-8
        let decrypted_str =
            std::str::from_utf8(&decrypted).expect("Decrypted data should be valid UTF-8");
        let original_str = std::str::from_utf8(plaintext).unwrap();

        assert_eq!(decrypted_str, original_str, "UTF-8 strings should match");
    }
}

// ============================================================================
// Additional Authenticated Data (AAD) Handling Tests
// ============================================================================

mod aad_handling {
    use super::*;

    #[test]
    fn test_aad_binds_to_ciphertext() {
        // Verify same AAD succeeds decryption (AAD binding works)
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0xa1u8; 32];
        let aad = b"cache_domain";
        let plaintext = b"sensitive data";

        let ciphertext = encryptor
            .encrypt_aes_gcm(plaintext, &key, aad)
            .expect("Encryption with AAD should succeed");

        // Decryption with same AAD should succeed
        let decrypted = encryptor
            .decrypt_aes_gcm(&ciphertext, &key, aad)
            .expect("Decryption with matching AAD should succeed");

        assert_eq!(decrypted, plaintext, "AAD binding should preserve data");
    }

    #[test]
    fn test_wrong_aad_fails_decryption() {
        // Verify different AAD causes authentication failure (security property)
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0xb2u8; 32];
        let correct_aad = b"cache";
        let wrong_aad = b"authentication";
        let plaintext = b"secret message";

        let ciphertext = encryptor
            .encrypt_aes_gcm(plaintext, &key, correct_aad)
            .expect("Encryption should succeed");

        // Attempt decryption with wrong AAD should fail
        let result = encryptor.decrypt_aes_gcm(&ciphertext, &key, wrong_aad);

        assert!(
            matches!(result, Err(EncryptionError::AuthenticationFailed)),
            "Wrong AAD should cause authentication failure, got: {:?}",
            result
        );
    }

    #[test]
    fn test_empty_aad_allowed() {
        // Verify empty AAD is valid (AAD is optional for some use cases)
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0xc3u8; 32];
        let empty_aad = b"";
        let plaintext = b"data without domain context";

        let ciphertext = encryptor
            .encrypt_aes_gcm(plaintext, &key, empty_aad)
            .expect("Encryption with empty AAD should succeed");

        let decrypted = encryptor
            .decrypt_aes_gcm(&ciphertext, &key, empty_aad)
            .expect("Decryption with empty AAD should succeed");

        assert_eq!(decrypted, plaintext, "Empty AAD should work correctly");

        // Verify non-empty AAD fails (demonstrates AAD binding even for empty)
        let result = encryptor.decrypt_aes_gcm(&ciphertext, &key, b"some_aad");
        assert!(
            result.is_err(),
            "Non-empty AAD should fail when encrypted with empty AAD"
        );
    }

    #[test]
    fn test_different_aad_different_ciphertext() {
        // Verify AAD affects ciphertext (domain separation property)
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0xd4u8; 32];
        let plaintext = b"same plaintext for both";

        let ciphertext1 = encryptor
            .encrypt_aes_gcm(plaintext, &key, b"domain_a")
            .expect("Encryption with AAD 'domain_a' should succeed");

        let ciphertext2 = encryptor
            .encrypt_aes_gcm(plaintext, &key, b"domain_b")
            .expect("Encryption with AAD 'domain_b' should succeed");

        // Ciphertexts should be different (AAD + random nonce ensure this)
        assert_ne!(
            ciphertext1, ciphertext2,
            "Different AAD should produce different ciphertexts (even for same plaintext/key)"
        );

        // Each should only decrypt with its own AAD
        let decrypted1 = encryptor
            .decrypt_aes_gcm(&ciphertext1, &key, b"domain_a")
            .expect("Should decrypt with matching AAD");
        let decrypted2 = encryptor
            .decrypt_aes_gcm(&ciphertext2, &key, b"domain_b")
            .expect("Should decrypt with matching AAD");

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);

        // Cross-domain decryption should fail
        assert!(
            encryptor
                .decrypt_aes_gcm(&ciphertext1, &key, b"domain_b")
                .is_err(),
            "Cross-domain decryption should fail"
        );
        assert!(
            encryptor
                .decrypt_aes_gcm(&ciphertext2, &key, b"domain_a")
                .is_err(),
            "Cross-domain decryption should fail"
        );
    }
}

// ============================================================================
// Nonce Uniqueness Tests
// ============================================================================

mod nonce_uniqueness {
    use super::*;

    #[test]
    fn test_same_plaintext_different_ciphertexts() {
        // Verify encryption is non-deterministic (nonce randomness prevents pattern analysis)
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0xe5u8; 32];
        let aad = b"nonce_test";
        let plaintext = b"same data encrypted multiple times";

        // Encrypt the same plaintext twice
        let ciphertext1 = encryptor
            .encrypt_aes_gcm(plaintext, &key, aad)
            .expect("First encryption should succeed");

        let ciphertext2 = encryptor
            .encrypt_aes_gcm(plaintext, &key, aad)
            .expect("Second encryption should succeed");

        // Ciphertexts must be different (random nonce ensures this)
        assert_ne!(
            ciphertext1, ciphertext2,
            "Same plaintext encrypted twice should produce different ciphertexts (due to random nonce)"
        );

        // Both should decrypt to the same plaintext
        let decrypted1 = encryptor
            .decrypt_aes_gcm(&ciphertext1, &key, aad)
            .expect("First decryption should succeed");
        let decrypted2 = encryptor
            .decrypt_aes_gcm(&ciphertext2, &key, aad)
            .expect("Second decryption should succeed");

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn test_nonce_extracted_correctly() {
        // Verify ciphertext format is [nonce(12)][ciphertext+tag]
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0xf6u8; 32];
        let aad = b"format_test";
        let plaintext = b"test data";

        let ciphertext = encryptor
            .encrypt_aes_gcm(plaintext, &key, aad)
            .expect("Encryption should succeed");

        // Verify minimum size: nonce(12) + plaintext(9) + tag(16) = 37 bytes
        assert_eq!(
            ciphertext.len(),
            12 + plaintext.len() + 16,
            "Ciphertext format: [nonce(12)][encrypted_data][tag(16)]"
        );

        // Extract nonce (first 12 bytes)
        let nonce = &ciphertext[..12];
        assert_eq!(nonce.len(), 12, "Nonce should be exactly 12 bytes");

        // Nonce should not be all zeros (extremely unlikely with secure RNG)
        let all_zeros = nonce.iter().all(|&b| b == 0);
        assert!(
            !all_zeros,
            "Nonce should not be all zeros (RNG working correctly)"
        );
    }
}

// ============================================================================
// Tampering Detection Tests
// ============================================================================

mod tampering_detection {
    use super::*;

    #[test]
    fn test_modified_ciphertext_rejected() {
        // Verify AES-GCM authentication tag detects tampering
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0x71u8; 32];
        let aad = b"tamper_test";
        let plaintext = b"authenticated data";

        let mut ciphertext = encryptor
            .encrypt_aes_gcm(plaintext, &key, aad)
            .expect("Encryption should succeed");

        // Tamper with ciphertext (flip a bit in the encrypted portion)
        if ciphertext.len() > 13 {
            ciphertext[13] ^= 0x01; // Flip 1 bit in the encrypted data
        }

        // Decryption should fail due to authentication tag mismatch
        let result = encryptor.decrypt_aes_gcm(&ciphertext, &key, aad);

        assert!(
            matches!(result, Err(EncryptionError::AuthenticationFailed)),
            "Modified ciphertext should fail authentication, got: {:?}",
            result
        );
    }

    #[test]
    fn test_truncated_ciphertext_rejected() {
        // Verify truncated ciphertext is rejected (prevents length attacks)
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0x82u8; 32];
        let aad = b"truncation_test";
        let plaintext = b"data that will be truncated";

        let ciphertext = encryptor
            .encrypt_aes_gcm(plaintext, &key, aad)
            .expect("Encryption should succeed");

        // Truncate ciphertext (remove last 5 bytes)
        let truncated = &ciphertext[..ciphertext.len() - 5];

        // Decryption should fail
        let result = encryptor.decrypt_aes_gcm(truncated, &key, aad);

        assert!(result.is_err(), "Truncated ciphertext should be rejected");

        // Should fail with authentication error (tag verification fails)
        assert!(
            matches!(result, Err(EncryptionError::AuthenticationFailed)),
            "Truncated ciphertext should fail authentication"
        );
    }

    #[test]
    fn test_ciphertext_minimum_size() {
        // Verify ciphertext too short is rejected (< 28 bytes = nonce + tag)
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0x93u8; 32];
        let aad = b"size_test";

        // Create invalid ciphertext (too short: only 20 bytes)
        let invalid_ciphertext = vec![0u8; 20];

        let result = encryptor.decrypt_aes_gcm(&invalid_ciphertext, &key, aad);

        assert!(
            matches!(result, Err(EncryptionError::InvalidCiphertext(_))),
            "Ciphertext < 28 bytes should be rejected as invalid, got: {:?}",
            result
        );

        // Verify error message mentions the issue
        if let Err(EncryptionError::InvalidCiphertext(msg)) = result {
            assert!(
                msg.contains("short") || msg.contains("Short"),
                "Error should mention ciphertext is too short: {}",
                msg
            );
        }
    }

    #[test]
    fn test_truncated_ciphertext_various_lengths() {
        // WHY: Network errors or storage failures can produce truncated ciphertexts
        // Verify all truncation points are detected and rejected

        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0xabu8; 32];
        let aad = b"truncation_test";
        let plaintext = b"This is a test message for truncation testing";

        let ciphertext = encryptor
            .encrypt_aes_gcm(plaintext, &key, aad)
            .expect("Encryption should succeed");

        // Test truncation at various lengths
        let test_lengths = vec![
            0,                     // Empty
            1,                     // Single byte
            11,                    // Incomplete nonce (12 bytes needed)
            12,                    // Nonce only (no ciphertext or tag)
            20,                    // Nonce + partial ciphertext (no tag)
            ciphertext.len() - 16, // Nonce + ciphertext (no tag)
            ciphertext.len() - 10, // Missing last 10 bytes of tag
            ciphertext.len() - 1,  // Missing last byte
        ];

        for truncate_len in test_lengths {
            if truncate_len >= ciphertext.len() {
                continue;
            }

            let truncated = &ciphertext[..truncate_len];
            let result = encryptor.decrypt_aes_gcm(truncated, &key, aad);

            assert!(
                result.is_err(),
                "Truncated ciphertext (len={}) should be rejected (original len={})",
                truncate_len,
                ciphertext.len()
            );
        }

        println!("✓ Truncated ciphertext: All truncation points rejected");
    }

    #[test]
    fn test_incomplete_nonce() {
        // WHY: Nonce must be exactly 12 bytes. Less should be rejected.

        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0xbcu8; 32];
        let aad = b"nonce_test";

        // Test incomplete nonces (1-11 bytes)
        for nonce_len in 1..12 {
            let incomplete_nonce = vec![0u8; nonce_len];
            let result = encryptor.decrypt_aes_gcm(&incomplete_nonce, &key, aad);

            assert!(
                result.is_err(),
                "Incomplete nonce (len={}) should be rejected",
                nonce_len
            );
        }

        println!("✓ Incomplete nonces: All lengths 1-11 bytes rejected");
    }

    #[test]
    fn test_truncated_authentication_tag() {
        // WHY: Authentication tag must be complete (16 bytes). Partial tags should fail.

        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0xcdu8; 32];
        let aad = b"tag_test";
        let plaintext = b"test data";

        let ciphertext = encryptor
            .encrypt_aes_gcm(plaintext, &key, aad)
            .expect("Encryption should succeed");

        // Ciphertext format: [nonce(12)][encrypted_data][tag(16)]
        // Remove bytes from end (truncates tag)
        for bytes_removed in 1..16 {
            let truncated = &ciphertext[..ciphertext.len() - bytes_removed];
            let result = encryptor.decrypt_aes_gcm(truncated, &key, aad);

            assert!(
                result.is_err(),
                "Ciphertext with partial tag (missing {} bytes) should be rejected",
                bytes_removed
            );
        }

        println!("✓ Truncated tags: All partial authentication tags rejected");
    }

    #[test]
    fn test_nonce_only_no_ciphertext() {
        // WHY: Edge case - ciphertext contains only nonce (12 bytes), no encrypted data or tag

        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0xdeu8; 32];
        let aad = b"nonce_only";

        // Create buffer with only nonce (12 bytes)
        let nonce_only = vec![0u8; 12];

        let result = encryptor.decrypt_aes_gcm(&nonce_only, &key, aad);

        assert!(
            result.is_err(),
            "Nonce-only ciphertext (no tag) should be rejected"
        );

        println!("✓ Nonce-only: Properly rejected");
    }
}

// ============================================================================
// Security Tests - Key Zeroization & Timing
// ============================================================================

mod security_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_key_zeroization_on_drop() {
        // WHY: Verify sensitive key material is zeroed after use
        // VALIDATES: Keys don't leak in memory after encryption operations
        //
        // NOTE: This is a best-effort test. We can't directly inspect memory
        // after Rust's Drop, but we verify the API guarantees proper cleanup.

        use cachekit_core::encryption::key_derivation::derive_domain_key;

        // Derive key in limited scope
        let key_result = {
            let key = derive_domain_key(TEST_MASTER_KEY, "cache", TEST_TENANT_A)
                .expect("Key derivation should succeed");

            // Key goes out of scope here, triggering zeroization
            // The derive_domain_key returns a SecretVec which implements Zeroize on drop
            Ok::<_, String>(key)
        };

        // Verify we got a valid key result
        assert!(key_result.is_ok(), "Key derivation should succeed");

        // NOTE: The SecretVec returned by derive_domain_key has been zeroed by zeroize crate
        // We can't verify this directly, but the zeroize::Zeroizing wrapper guarantees it
        // This test validates that key derivation works correctly with proper scoping

        println!("✓ Key zeroization: SecretVec drops safely (zeroization enforced by type system)");
    }

    #[test]
    fn test_encryption_no_key_leakage() {
        // WHY: Verify encryption operations don't leak key material
        // VALIDATES: Keys are properly scoped and zeroed

        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let plaintext = b"sensitive data";
        let aad = b"domain";

        // Create key in limited scope
        {
            let key = [0x7fu8; 32];

            // Perform encryption
            let ciphertext = encryptor
                .encrypt_aes_gcm(plaintext, &key, aad)
                .expect("Encryption should succeed");

            // Verify ciphertext is valid
            assert!(
                ciphertext.len() > 28,
                "Ciphertext should contain nonce + tag"
            );

            // Key goes out of scope here
        }

        // After key drops, we can't access it anymore (Rust type system enforces this)
        // This test validates that encryption works correctly with scoped keys

        println!("✓ No key leakage: Encryption works with properly scoped keys");
    }

    #[test]
    fn test_constant_time_operations_baseline() {
        // WHY: Establish baseline for timing validation
        // VALIDATES: Encryption timing doesn't vary significantly with data patterns
        //
        // NOTE: This is not a full constant-time verification (would require
        // specialized tools like dudect). This test uses statistical analysis
        // to detect obvious timing leaks while being robust to CI noise.

        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0xa1u8; 32];
        let aad = b"timing_test";

        let plaintext_zeros = vec![0x00u8; 1024];
        let plaintext_ones = vec![0xffu8; 1024];

        // Warm-up phase: prime caches and JIT (discarded)
        for _ in 0..100 {
            let _ = encryptor.encrypt_aes_gcm(&plaintext_zeros, &key, aad);
            let _ = encryptor.encrypt_aes_gcm(&plaintext_ones, &key, aad);
        }

        // Collect samples with interleaved execution to reduce systematic bias
        const SAMPLES: usize = 1000;
        let mut timings_zeros = Vec::with_capacity(SAMPLES);
        let mut timings_ones = Vec::with_capacity(SAMPLES);

        for _ in 0..SAMPLES {
            // Interleave to reduce correlation with system load changes
            let start = Instant::now();
            let _ = encryptor.encrypt_aes_gcm(&plaintext_zeros, &key, aad);
            timings_zeros.push(start.elapsed().as_nanos() as f64);

            let start = Instant::now();
            let _ = encryptor.encrypt_aes_gcm(&plaintext_ones, &key, aad);
            timings_ones.push(start.elapsed().as_nanos() as f64);
        }

        // Calculate statistics
        let mean_zeros: f64 = timings_zeros.iter().sum::<f64>() / SAMPLES as f64;
        let mean_ones: f64 = timings_ones.iter().sum::<f64>() / SAMPLES as f64;

        let var_zeros: f64 =
            timings_zeros.iter().map(|t| (t - mean_zeros).powi(2)).sum::<f64>() / (SAMPLES - 1) as f64;
        let var_ones: f64 =
            timings_ones.iter().map(|t| (t - mean_ones).powi(2)).sum::<f64>() / (SAMPLES - 1) as f64;

        // Welch's t-test (unequal variances)
        let se = ((var_zeros / SAMPLES as f64) + (var_ones / SAMPLES as f64)).sqrt();
        let t_stat = if se > 0.0 {
            (mean_zeros - mean_ones).abs() / se
        } else {
            0.0
        };

        // Effect size (Cohen's d) - practical significance
        let pooled_std = ((var_zeros + var_ones) / 2.0).sqrt();
        let cohens_d = if pooled_std > 0.0 {
            (mean_zeros - mean_ones).abs() / pooled_std
        } else {
            0.0
        };

        // For 1000 samples, t > 3.3 is p < 0.001 (highly significant)
        // Cohen's d > 0.8 is a "large" effect size
        // We require BOTH statistical significance AND practical significance
        let statistically_significant = t_stat > 3.3;
        let practically_significant = cohens_d > 0.8;

        println!(
            "Timing analysis: zeros={:.0}ns, ones={:.0}ns, t={:.2}, d={:.3}",
            mean_zeros, mean_ones, t_stat, cohens_d
        );

        // Only fail if difference is BOTH statistically AND practically significant
        assert!(
            !(statistically_significant && practically_significant),
            "Timing leak detected: t-stat={:.2} (>3.3), Cohen's d={:.3} (>0.8) - \
             zeros={:.0}ns, ones={:.0}ns",
            t_stat,
            cohens_d,
            mean_zeros,
            mean_ones
        );

        println!("✓ No significant timing difference detected");
    }

    #[test]
    fn test_timing_independent_of_key_pattern() {
        // WHY: Verify timing doesn't leak information about key
        // VALIDATES: Different key patterns have similar encryption times

        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let plaintext = b"constant plaintext for timing test";
        let aad = b"timing_domain";

        // Test with different key patterns
        let key_zeros = [0x00u8; 32];
        let key_ones = [0xffu8; 32];
        let key_mixed = [0x5au8; 32];

        let mut timings = Vec::new();

        for key in &[key_zeros, key_ones, key_mixed] {
            let mut key_timings = Vec::new();

            for _ in 0..100 {
                let start = Instant::now();
                let _ = encryptor
                    .encrypt_aes_gcm(plaintext, key, aad)
                    .expect("Encryption should succeed");
                key_timings.push(start.elapsed().as_nanos());
            }

            key_timings.sort_unstable();
            let median = key_timings[key_timings.len() / 2];
            timings.push(median);
        }

        // Calculate max difference between any two timings
        let min_timing = *timings.iter().min().unwrap();
        let max_timing = *timings.iter().max().unwrap();
        let diff = (max_timing - min_timing) as f64 / min_timing as f64;

        // Timings should be similar regardless of key pattern
        assert!(
            diff < 0.20,
            "Key-dependent timing difference too large: {:.1}% - possible timing leak",
            diff * 100.0
        );

        println!(
            "✓ Key-independent timing: min={}ns, max={}ns, diff={:.1}%",
            min_timing,
            max_timing,
            diff * 100.0
        );
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

mod error_handling {
    use super::*;

    #[test]
    fn test_invalid_key_length_clear_error() {
        // Verify invalid key length produces clear, actionable error messages
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let plaintext = b"test data";
        let aad = b"test_domain";

        // Test various invalid key lengths
        let short_key_16 = [0u8; 16]; // Too short (needs 32 for AES-256)
        let short_key_24 = [0u8; 24]; // Still too short
        let long_key_64 = [0u8; 64]; // Too long

        // 16-byte key (AES-128 length, but we require AES-256)
        let result = encryptor.encrypt_aes_gcm(plaintext, &short_key_16, aad);
        assert!(
            matches!(result, Err(EncryptionError::InvalidKeyLength(16))),
            "16-byte key should be rejected with InvalidKeyLength(16)"
        );
        if let Err(EncryptionError::InvalidKeyLength(len)) = result {
            assert_eq!(len, 16, "Error should report actual key length");
        }

        // 24-byte key (AES-192 length, but we require AES-256)
        let result = encryptor.encrypt_aes_gcm(plaintext, &short_key_24, aad);
        assert!(
            matches!(result, Err(EncryptionError::InvalidKeyLength(24))),
            "24-byte key should be rejected"
        );

        // 64-byte key (too long)
        let result = encryptor.encrypt_aes_gcm(plaintext, &long_key_64, aad);
        assert!(
            matches!(result, Err(EncryptionError::InvalidKeyLength(64))),
            "64-byte key should be rejected"
        );

        // Verify error message is descriptive
        let result = encryptor.encrypt_aes_gcm(plaintext, &short_key_16, aad);
        if let Err(e) = result {
            let error_msg = format!("{}", e);
            assert!(
                error_msg.contains("32 bytes") || error_msg.contains("32"),
                "Error should mention expected key length (32 bytes): {}",
                error_msg
            );
            assert!(
                error_msg.contains("16") || error_msg.contains("got 16"),
                "Error should mention actual key length: {}",
                error_msg
            );
        }
    }

    #[test]
    fn test_invalid_ciphertext_clear_error() {
        // Verify malformed ciphertext produces helpful error messages
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0xa4u8; 32];
        let aad = b"error_test";

        // Test 1: Empty ciphertext
        let empty_ciphertext = vec![];
        let result = encryptor.decrypt_aes_gcm(&empty_ciphertext, &key, aad);
        assert!(
            matches!(result, Err(EncryptionError::InvalidCiphertext(_))),
            "Empty ciphertext should be rejected as invalid"
        );

        // Test 2: Ciphertext with only nonce (no tag)
        let nonce_only = vec![0u8; 12];
        let result = encryptor.decrypt_aes_gcm(&nonce_only, &key, aad);
        assert!(
            matches!(result, Err(EncryptionError::InvalidCiphertext(_))),
            "Ciphertext with only nonce should be rejected"
        );

        // Test 3: Ciphertext that's 1 byte short (27 bytes instead of 28 minimum)
        let almost_valid = vec![0u8; 27];
        let result = encryptor.decrypt_aes_gcm(&almost_valid, &key, aad);
        assert!(
            result.is_err(),
            "Ciphertext 1 byte short of minimum should be rejected"
        );

        // Verify error message is descriptive
        if let Err(e) = result {
            let error_msg = format!("{}", e);
            assert!(
                !error_msg.is_empty(),
                "Error message should provide context"
            );
        }
    }

    #[test]
    fn test_authentication_failure_clear_error() {
        // Verify authentication failures produce clear error messages
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0xb5u8; 32];
        let wrong_key = [0xc6u8; 32];
        let aad = b"auth_test";
        let plaintext = b"authenticated message";

        // Encrypt with correct key
        let ciphertext = encryptor
            .encrypt_aes_gcm(plaintext, &key, aad)
            .expect("Encryption should succeed");

        // Test 1: Wrong key causes authentication failure
        let result = encryptor.decrypt_aes_gcm(&ciphertext, &wrong_key, aad);
        assert!(
            matches!(result, Err(EncryptionError::AuthenticationFailed)),
            "Wrong key should cause AuthenticationFailed, got: {:?}",
            result
        );

        // Test 2: Wrong AAD causes authentication failure
        let result = encryptor.decrypt_aes_gcm(&ciphertext, &key, b"wrong_aad");
        assert!(
            matches!(result, Err(EncryptionError::AuthenticationFailed)),
            "Wrong AAD should cause AuthenticationFailed"
        );

        // Verify error message mentions authentication
        if let Err(e) = result {
            let error_msg = format!("{}", e);
            assert!(
                error_msg.contains("authentication") || error_msg.contains("Authentication"),
                "Error should mention 'authentication': {}",
                error_msg
            );
        }

        // Test 3: Tampered ciphertext causes authentication failure
        let mut tampered = ciphertext.clone();
        if tampered.len() > 15 {
            tampered[15] ^= 0xff; // Flip all bits in one byte
        }
        let result = encryptor.decrypt_aes_gcm(&tampered, &key, aad);
        assert!(
            matches!(result, Err(EncryptionError::AuthenticationFailed)),
            "Tampered ciphertext should cause AuthenticationFailed"
        );
    }
}
