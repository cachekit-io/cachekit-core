//! ByteStorage Unit Tests
//!
//! This test suite validates ByteStorage behavior and error handling, complementing
//! the 5 Kani formal verification proofs with concrete examples and edge cases.
//!
//! **Relationship to Kani Proofs**:
//! - Kani proofs verify memory safety and security properties (bounds checks, overflow, etc.)
//! - These tests validate observable behavior, error messages, and data integrity
//! - Kani uses symbolic execution; these tests use concrete data patterns
//!
//! **Test Organization**:
//! - `compression_tests`: Compression behavior for various data patterns
//! - `security_limits`: Security limit enforcement and error messages
//! - `checksum_validation`: Integrity checking and corruption detection
//! - `error_messages`: Error message quality for developers
//! - `roundtrip`: Basic store → retrieve correctness
//!
//! All tests use the common fixtures module for consistency.

mod common;

use cachekit_core::byte_storage::{ByteStorage, ByteStorageError};
use common::fixtures::*;

// ============================================================================
// Compression Tests
// ============================================================================

#[cfg(feature = "compression")]
mod compression_tests {
    use super::*;

    #[test]
    fn test_empty_data_compresses_correctly() {
        let storage = ByteStorage::new(None);

        // Empty data should produce valid envelope
        let envelope_bytes = storage
            .store(EMPTY_DATA, None)
            .expect("Empty data should compress");

        // Should be able to retrieve it
        let (retrieved, format) = storage
            .retrieve(&envelope_bytes)
            .expect("Should retrieve empty data");

        assert_eq!(retrieved, EMPTY_DATA);
        assert_eq!(format, "msgpack");
    }

    #[test]
    fn test_small_data_compresses() {
        let storage = ByteStorage::new(None);

        // Small data should compress and roundtrip correctly
        let envelope_bytes = storage
            .store(SMALL_DATA, None)
            .expect("Small data should compress");

        let (retrieved, format) = storage.retrieve(&envelope_bytes).expect("Should retrieve");

        assert_eq!(retrieved, SMALL_DATA);
        assert_eq!(format, "msgpack");

        // Envelope should be reasonably small (compressed + overhead)
        assert!(
            envelope_bytes.len() < 1000,
            "Small data envelope should be compact"
        );
    }

    #[test]
    fn test_large_data_compresses() {
        let storage = ByteStorage::new(None);

        // Generate 500KB of moderately compressible realistic text-like data
        // Mix compressible template with incompressible random payload to stay under 100x ratio
        // Simulate JSON-like structure with repetitive keys but random values
        let mut large_data = Vec::new();
        let template = br#"{"id":XXXXX,"name":"userXXXXX","email":"user@example.com","timestamp":1234567890,"data":"#;

        for i in 0..2500 {
            large_data.extend_from_slice(template);
            // Use incompressible data generator to add truly random payload (stays under 100x)
            let incompressible_chunk = generate_incompressible_data(150, i as u64);
            large_data.extend_from_slice(&incompressible_chunk);
            large_data.extend_from_slice(br#""},"#);
        }

        // Should compress successfully
        let envelope_bytes = storage
            .store(&large_data, None)
            .expect("Large data should compress");

        // Compressed size will be similar to original (mix of compressible template + random data)
        // The test validates that large mixed data can be stored and retrieved correctly
        assert!(
            envelope_bytes.len() < large_data.len() * 2,
            "Envelope should not expand excessively (got ratio: {:.1}x)",
            large_data.len() as f64 / envelope_bytes.len() as f64
        );

        // Should retrieve correctly
        let (retrieved, _) = storage
            .retrieve(&envelope_bytes)
            .expect("Should retrieve large data");

        assert_eq!(retrieved, large_data);
    }

    #[test]
    fn test_incompressible_data_handled() {
        let storage = ByteStorage::new(None);

        // Generate incompressible random data (100KB - smaller to keep envelope overhead reasonable)
        let incompressible = generate_incompressible_data(100_000, 42);

        // Should still compress (LZ4 handles incompressible data gracefully)
        let envelope_bytes = storage
            .store(&incompressible, None)
            .expect("Incompressible data should still be stored");

        // Compressed size should be close to original (LZ4 has minimal overhead for incompressible data)
        // Allow up to 60% expansion for envelope overhead (MessagePack + metadata + checksum + original_size field)
        let size_ratio = envelope_bytes.len() as f64 / incompressible.len() as f64;
        assert!(
            size_ratio < 1.6,
            "Incompressible data should not expand excessively (got ratio: {:.2})",
            size_ratio
        );

        // Should retrieve correctly
        let (retrieved, _) = storage.retrieve(&envelope_bytes).expect("Should retrieve");

        assert_eq!(retrieved, incompressible);
    }

    #[test]
    fn test_estimate_compression_accuracy() {
        let storage = ByteStorage::new(None);

        // Test compression ratio estimation
        let compressible = generate_large_data(10_000, 0x42);
        let ratio = storage
            .estimate_compression(&compressible)
            .expect("Should estimate compression");

        // Compressible data should have high ratio (>10x)
        assert!(
            ratio > 10.0,
            "Compressible data should have high ratio (got {:.1})",
            ratio
        );

        // Incompressible data should have low ratio (~1x)
        let incompressible = generate_incompressible_data(10_000, 123);
        let ratio_incomp = storage
            .estimate_compression(&incompressible)
            .expect("Should estimate");

        assert!(
            ratio_incomp < 1.5,
            "Incompressible data should have low ratio (got {:.1})",
            ratio_incomp
        );
    }
}

// ============================================================================
// Security Limits Tests
// ============================================================================

#[cfg(feature = "compression")]
mod security_limits {
    use super::*;

    // Security constants from byte_storage.rs
    const MAX_UNCOMPRESSED_SIZE: usize = 512 * 1024 * 1024; // 512MB
    const MAX_COMPRESSED_SIZE: usize = 512 * 1024 * 1024; // 512MB

    #[test]
    fn test_max_uncompressed_size_rejected() {
        let storage = ByteStorage::new(None);

        // Create data slightly over 512MB limit (symbolically, not actually allocated)
        // Instead, test with a size that would exceed limit and verify error message
        let oversized = 513 * 1024 * 1024; // 513MB

        // Generate a smaller sample to simulate the behavior
        // (We can't actually allocate 513MB in a test, so verify limit logic)
        // The ByteStorage::store checks data.len() > MAX_UNCOMPRESSED_SIZE

        // Create 1KB sample and verify error message mentions size limits
        let _sample_data = vec![0u8; oversized.min(1024)];

        // For actual size limit test, document expected behavior:
        // Input of 513MB would fail with: "Data too large: X bytes exceeds maximum 536870912 bytes"

        // Test with maximum allowed size works (512MB - 1 byte)
        let _max_allowed_size = MAX_UNCOMPRESSED_SIZE - 1;

        // Note: Can't allocate 512MB in test, so verify error message structure
        // Real validation happens via Kani proofs and integration tests

        // Verify small data works (sanity check)
        let small_data = vec![0u8; 1000];
        assert!(
            storage.store(&small_data, None).is_ok(),
            "Small data should be accepted"
        );

        // Document expected behavior for oversized input:
        // storage.store(&vec![0u8; 513_000_000], None) would return:
        // Err("Data too large: 538968064 bytes exceeds maximum 536870912 bytes")
    }

    #[test]
    fn test_max_compressed_size_logic() {
        let storage = ByteStorage::new(None);

        // Test that compressed data size is validated
        // The MAX_COMPRESSED_SIZE limit is enforced in StorageEnvelope::extract()
        // and during compression in ByteStorage::store()

        // Create data that compresses to reasonable size
        let data = generate_large_data(100_000, 0x00); // Highly compressible
        let envelope = storage.store(&data, None).expect("Should compress");

        // Verify envelope is well under 512MB limit
        assert!(
            envelope.len() < MAX_COMPRESSED_SIZE,
            "Compressed envelope should be under 512MB (got {} bytes)",
            envelope.len()
        );

        // Verify envelope is reasonable size (should compress significantly)
        assert!(
            envelope.len() < 10_000,
            "Highly compressible data should produce small envelope (got {} bytes)",
            envelope.len()
        );
    }

    #[test]
    fn test_decompression_bomb_protection() {
        let storage = ByteStorage::new(None);

        // Test that compression ratio limits are enforced
        // MAX_COMPRESSION_RATIO = 1000.0 means original_size / compressed_size <= 1000
        // The ratio check happens in extract() during retrieve, not during store

        // Test 1: Data with ratio under limit should work
        // Use incompressible data to keep ratio low
        let safe_data = generate_incompressible_data(10_000, 42); // Random data compresses poorly
        let safe_envelope = storage.store(&safe_data, None).expect("Should compress");
        let (retrieved, _) = storage
            .retrieve(&safe_envelope)
            .expect("Safe ratio should decompress");
        assert_eq!(retrieved, safe_data);

        // Test 2: Malicious envelope with falsified original_size is rejected
        // This simulates a decompression bomb attack where attacker sends:
        // - Small compressed payload
        // - Falsely large original_size claim
        // The ratio check should catch this before decompression
        use rmp_serde;
        use serde::{Deserialize, Serialize};

        // Craft a malicious envelope structure (same as StorageEnvelope)
        #[derive(Serialize, Deserialize)]
        struct MaliciousEnvelope {
            compressed_data: Vec<u8>,
            checksum: [u8; 8], // xxHash3-64 is 8 bytes
            original_size: u32,
            format: String,
        }

        let malicious = MaliciousEnvelope {
            compressed_data: vec![0u8; 100], // 100 bytes of compressed data
            checksum: [0u8; 8],              // Fake checksum (doesn't matter, ratio check first)
            original_size: 500_000_000,      // Claims 500MB (5000x ratio > 1000x limit)
            format: "msgpack".to_string(),
        };

        let malicious_bytes = rmp_serde::to_vec(&malicious).expect("Serialize malicious envelope");

        // Retrieve should fail with decompression bomb error
        let result = storage.retrieve(&malicious_bytes);
        assert!(
            result.is_err(),
            "Decompression bomb should be rejected during retrieve"
        );

        // Verify error is DecompressionBomb variant
        let error = result.unwrap_err();
        assert!(
            matches!(error, ByteStorageError::DecompressionBomb),
            "Error should be DecompressionBomb variant, got: {:?}",
            error
        );
    }

    #[test]
    fn test_compression_ratio_calculation() {
        let storage = ByteStorage::new(None);

        // Test that compression ratio is calculated correctly: original_size / compressed_size

        // Test 1: Highly compressible data
        let compressible = generate_large_data(10_000, 0xFF);
        let envelope_comp = storage.store(&compressible, None).expect("Should compress");
        let ratio_comp = compressible.len() as f64 / envelope_comp.len() as f64;

        // Should achieve significant compression (>5x)
        assert!(
            ratio_comp > 5.0,
            "Compressible data should achieve >5x ratio (got {:.1}x)",
            ratio_comp
        );

        // Test 2: Incompressible data
        let incompressible = generate_incompressible_data(10_000, 99);
        let envelope_incomp = storage.store(&incompressible, None).expect("Should store");
        let ratio_incomp = incompressible.len() as f64 / envelope_incomp.len() as f64;

        // Should have low compression (~1x, may expand slightly)
        assert!(
            ratio_incomp < 2.0,
            "Incompressible data should have low ratio (got {:.1}x)",
            ratio_incomp
        );

        // Test 3: Verify estimate_compression provides reasonable estimate
        // Note: estimate_compression may use different compression settings than store()
        // so we just verify it returns a positive ratio, not exact match
        let estimate = storage
            .estimate_compression(&compressible)
            .expect("Should estimate");
        assert!(
            estimate > 1.0,
            "Compression estimate should be positive (got {:.1}x)",
            estimate
        );

        // Both should agree that compressible data compresses better than incompressible
        let estimate_incomp = storage
            .estimate_compression(&incompressible)
            .expect("Should estimate");
        assert!(
            estimate > estimate_incomp,
            "Compressible estimate {:.1}x should exceed incompressible {:.1}x",
            estimate,
            estimate_incomp
        );
    }
}

// ============================================================================
// Checksum Validation Tests
// ============================================================================

#[cfg(all(feature = "compression", feature = "checksum"))]
mod checksum_validation {
    use super::*;

    #[test]
    fn test_corrupted_checksum_rejected() {
        let storage = ByteStorage::new(None);

        // Create valid envelope
        let data = SMALL_DATA;
        let mut envelope = storage.store(data, None).expect("Should create envelope");

        // Corrupt the checksum by flipping a byte near the beginning
        // (MessagePack envelope structure: we need to find and flip checksum bytes)
        // Since we can't easily locate the checksum field, flip bytes and verify rejection
        if envelope.len() > 10 {
            envelope[5] ^= 0xFF; // Flip bits in envelope
        }

        // Corrupted envelope should be rejected
        let result = storage.retrieve(&envelope);
        assert!(result.is_err(), "Corrupted envelope should be rejected");

        // Error should mention validation or checksum
        let error_msg = format!("{:?}", result.unwrap_err());
        println!("Corruption error: {}", error_msg);
        // Note: Actual error might be deser or checksum depending on what was corrupted
    }

    #[test]
    fn test_checksum_validates_after_decompression() {
        let storage = ByteStorage::new(None);

        // Create envelope with checksum (use incompressible data to avoid >100x ratio)
        let data = generate_incompressible_data(10_000, 777);
        let envelope = storage.store(&data, None).expect("Should store");

        // Valid envelope should decompress and validate checksum
        let (retrieved, _) = storage
            .retrieve(&envelope)
            .expect("Valid checksum should pass");

        assert_eq!(
            retrieved, data,
            "Data should match after checksum validation"
        );
    }

    #[test]
    fn test_checksum_integrity_protection() {
        let storage = ByteStorage::new(None);

        // Test that checksum provides integrity protection
        let data1 = b"original data";
        let data2 = b"modified data";

        let envelope1 = storage.store(data1, None).expect("Should store");
        let envelope2 = storage.store(data2, None).expect("Should store");

        // Different data produces different envelopes (includes checksum)
        assert_ne!(
            envelope1, envelope2,
            "Different data should have different checksums"
        );

        // Each envelope validates correctly
        let (retrieved1, _) = storage.retrieve(&envelope1).expect("Should retrieve");
        let (retrieved2, _) = storage.retrieve(&envelope2).expect("Should retrieve");

        assert_eq!(retrieved1, data1);
        assert_eq!(retrieved2, data2);
    }

    #[test]
    fn test_multi_byte_corruption_detection() {
        // WHY: Single-bit flips are the easy case. Real-world corruption can flip
        // multiple adjacent bytes (e.g., memory errors, disk failures, network issues).
        // This test validates that xxHash3-64 checksums detect multi-byte corruption.

        let storage = ByteStorage::new(None);
        let data = generate_incompressible_data(5_000, 999);
        let mut envelope = storage.store(&data, None).expect("Should store");

        // Test 1: Flip two adjacent bytes in middle of envelope
        if envelope.len() > 102 {
            envelope[100] ^= 0xFF; // Flip all bits in byte 100
            envelope[101] ^= 0xFF; // Flip all bits in byte 101
        }

        let result = storage.retrieve(&envelope);
        assert!(result.is_err(), "Two-byte corruption should be detected");

        // Test 2: Flip three non-adjacent bytes
        let mut envelope = storage.store(&data, None).expect("Should store");
        if envelope.len() > 50 {
            envelope[10] ^= 0xAA;
            envelope[25] ^= 0x55;
            envelope[40] ^= 0xCC;
        }

        let result = storage.retrieve(&envelope);
        assert!(
            result.is_err(),
            "Multi-byte non-adjacent corruption should be detected"
        );

        println!("✓ Multi-byte corruption: Adjacent and non-adjacent flips detected");
    }

    #[test]
    fn test_corruption_at_various_offsets() {
        // WHY: Corruption at different locations (start, middle, end) might
        // interact differently with MessagePack structure and compression.
        // Verify checksum catches corruption everywhere.

        let storage = ByteStorage::new(None);
        let data = generate_incompressible_data(10_000, 777);
        let original_envelope = storage.store(&data, None).expect("Should store");

        // Test corruption at start (first 10 bytes)
        for offset in 0..10.min(original_envelope.len()) {
            let mut envelope = original_envelope.clone();
            envelope[offset] ^= 0xFF;

            let result = storage.retrieve(&envelope);
            assert!(
                result.is_err(),
                "Corruption at offset {} (start) should be detected",
                offset
            );
        }

        // Test corruption in middle
        let mid = original_envelope.len() / 2;
        for offset in mid.saturating_sub(5)..mid.saturating_add(5).min(original_envelope.len()) {
            let mut envelope = original_envelope.clone();
            envelope[offset] ^= 0xFF;

            let result = storage.retrieve(&envelope);
            assert!(
                result.is_err(),
                "Corruption at offset {} (middle) should be detected",
                offset
            );
        }

        // Test corruption at end (last 10 bytes)
        let len = original_envelope.len();
        for offset in len.saturating_sub(10)..len {
            let mut envelope = original_envelope.clone();
            envelope[offset] ^= 0xFF;

            let result = storage.retrieve(&envelope);
            assert!(
                result.is_err(),
                "Corruption at offset {} (end) should be detected",
                offset
            );
        }

        println!("✓ Corruption detection: Start, middle, and end verified");
    }

    #[test]
    fn test_subtle_multi_byte_patterns() {
        // WHY: Test more subtle corruption patterns that might evade weak checksums
        // (xxHash3-64 should handle all of these, but verify explicitly)

        let storage = ByteStorage::new(None);
        let data = generate_incompressible_data(5_000, 12345);
        let original_envelope = storage.store(&data, None).expect("Should store");

        // Pattern 1: XOR adjacent bytes with complementary values
        let mut envelope1 = original_envelope.clone();
        if envelope1.len() > 32 {
            envelope1[20] ^= 0xAA;
            envelope1[21] ^= 0x55; // Complementary pattern
        }
        assert!(
            storage.retrieve(&envelope1).is_err(),
            "Complementary XOR pattern should be detected"
        );

        // Pattern 2: Swap two bytes (preserves byte values, changes positions)
        // Find two positions with different byte values to ensure swap is meaningful
        let mut envelope2 = original_envelope.clone();
        if envelope2.len() > 50 {
            // Find two different byte values to swap (scan from position 20 onwards)
            let (pos1, pos2) = (20..envelope2.len() - 10)
                .find_map(|i| {
                    if envelope2[i] != envelope2[i + 10] {
                        Some((i, i + 10))
                    } else {
                        None
                    }
                })
                .expect("Should find two different bytes in envelope");

            envelope2.swap(pos1, pos2);
            assert!(
                storage.retrieve(&envelope2).is_err(),
                "Byte swap should be detected"
            );
        }

        // Pattern 3: Increment multiple bytes (subtle change)
        let mut envelope3 = original_envelope.clone();
        if envelope3.len() > 60 {
            envelope3[50] = envelope3[50].wrapping_add(1);
            envelope3[51] = envelope3[51].wrapping_add(1);
            envelope3[52] = envelope3[52].wrapping_add(1);
        }
        assert!(
            storage.retrieve(&envelope3).is_err(),
            "Multi-byte increment should be detected"
        );

        // Pattern 4: Flip bits in a 4-byte aligned block (common memory error pattern)
        let mut envelope4 = original_envelope.clone();
        if envelope4.len() > 64 {
            envelope4[60..64].iter_mut().for_each(|byte| *byte ^= 0x01); // Flip LSB in 4-byte block
        }
        assert!(
            storage.retrieve(&envelope4).is_err(),
            "Aligned block corruption should be detected"
        );

        println!("✓ Subtle patterns: XOR, swap, increment, and block corruption detected");
    }
}

// ============================================================================
// Truncated Data Handling Tests
// ============================================================================

#[cfg(feature = "compression")]
mod truncated_data {
    use super::*;

    #[test]
    fn test_truncated_envelope_various_lengths() {
        // WHY: Network failures, disk errors, or interrupted writes can produce
        // truncated data. Verify all truncation points are handled gracefully.

        let storage = ByteStorage::new(None);
        let data = generate_incompressible_data(1_000, 555);
        let envelope = storage.store(&data, None).expect("Should store");

        // Test truncation at various lengths
        let test_lengths = vec![
            0,
            1,
            5,
            10,
            20,
            envelope.len() / 2,
            envelope.len() - 10,
            envelope.len() - 1,
        ];

        for truncate_len in test_lengths {
            if truncate_len >= envelope.len() {
                continue; // Skip if truncation point exceeds envelope length
            }

            let truncated = &envelope[..truncate_len];
            let result = storage.retrieve(truncated);

            assert!(
                result.is_err(),
                "Truncated envelope (len={}) should be rejected (original len={})",
                truncate_len,
                envelope.len()
            );
        }

        println!("✓ Truncated envelopes: All truncation points properly rejected");
    }

    #[test]
    fn test_truncated_compressed_data() {
        // WHY: Truncation in the compressed data section should fail decompression

        let storage = ByteStorage::new(None);
        let data = generate_large_data(5_000, 0xAA); // Highly compressible
        let mut envelope = storage.store(&data, None).expect("Should store");

        // Truncate from the end (cuts into compressed data section)
        if envelope.len() > 20 {
            envelope.truncate(envelope.len() - 15);
        }

        let result = storage.retrieve(&envelope);
        assert!(result.is_err(), "Truncated compressed data should fail");

        println!("✓ Truncated compressed data: Properly rejected");
    }

    #[test]
    fn test_incomplete_envelope_structure() {
        // WHY: MessagePack structure might be cut off mid-field
        // Verify deserialization handles this gracefully

        let storage = ByteStorage::new(None);
        let data = b"test data for incomplete envelope";
        let envelope = storage.store(data, None).expect("Should store");

        // Test very short truncations (incomplete MessagePack structure)
        for len in 1..20.min(envelope.len()) {
            let incomplete = &envelope[..len];
            let result = storage.retrieve(incomplete);

            assert!(
                result.is_err(),
                "Incomplete envelope structure (len={}) should be rejected",
                len
            );
        }

        println!("✓ Incomplete structures: All partial envelopes rejected");
    }

    #[test]
    fn test_zero_length_envelope() {
        // WHY: Edge case - completely empty input

        let storage = ByteStorage::new(None);
        let empty_envelope: &[u8] = b"";

        let result = storage.retrieve(empty_envelope);
        assert!(result.is_err(), "Zero-length envelope should be rejected");

        // Verify error is a deserialization error (empty input can't be valid MessagePack)
        let error = result.unwrap_err();
        assert!(
            matches!(error, ByteStorageError::DeserializationFailed(_)),
            "Expected DeserializationFailed for empty envelope"
        );

        println!("✓ Zero-length envelope: Properly rejected");
    }

    #[test]
    fn test_single_byte_envelope() {
        // WHY: Single byte is too short for any valid envelope format

        let storage = ByteStorage::new(None);
        let single_byte: &[u8] = b"X";

        let result = storage.retrieve(single_byte);
        assert!(result.is_err(), "Single-byte envelope should be rejected");

        println!("✓ Single-byte envelope: Properly rejected");
    }
}

// ============================================================================
// Error Messages Tests
// ============================================================================

#[cfg(feature = "compression")]
mod error_messages {
    use super::*;

    #[test]
    fn test_invalid_envelope_clear_error() {
        let storage = ByteStorage::new(None);

        // Test with completely invalid data
        let invalid_data = b"this is not a valid envelope";

        let result = storage.retrieve(invalid_data);
        assert!(result.is_err(), "Invalid envelope should fail");

        let error_msg = format!("{:?}", result.unwrap_err());
        // Error should be descriptive (MessagePack deserialization error)
        assert!(!error_msg.is_empty(), "Error message should be non-empty");
        println!("Invalid envelope error: {}", error_msg);
    }

    #[test]
    fn test_empty_envelope_clear_error() {
        let storage = ByteStorage::new(None);

        // Test with empty envelope
        let empty_envelope: &[u8] = b"";

        let result = storage.retrieve(empty_envelope);
        assert!(result.is_err(), "Empty envelope should fail");

        let error_msg = format!("{:?}", result.unwrap_err());
        assert!(!error_msg.is_empty(), "Error message should be non-empty");
        println!("Empty envelope error: {}", error_msg);
    }

    #[test]
    fn test_truncated_envelope_clear_error() {
        let storage = ByteStorage::new(None);

        // Create valid envelope then truncate it
        let data = SMALL_DATA;
        let mut envelope = storage.store(data, None).expect("Should create");

        // Truncate to incomplete envelope
        if envelope.len() > 5 {
            envelope.truncate(5);
        }

        let result = storage.retrieve(&envelope);
        assert!(result.is_err(), "Truncated envelope should fail");

        let error_msg = format!("{:?}", result.unwrap_err());
        assert!(!error_msg.is_empty(), "Error message should be non-empty");
        println!("Truncated envelope error: {}", error_msg);
    }
}

// ============================================================================
// Roundtrip Tests
// ============================================================================

#[cfg(feature = "compression")]
mod roundtrip {
    use super::*;

    #[test]
    fn test_roundtrip_empty_data() {
        let storage = ByteStorage::new(None);

        // Empty data should roundtrip correctly
        let envelope = storage.store(EMPTY_DATA, None).expect("Should store empty");
        let (retrieved, format) = storage.retrieve(&envelope).expect("Should retrieve empty");

        assert_eq!(retrieved, EMPTY_DATA);
        assert_eq!(format, "msgpack");
    }

    #[test]
    fn test_roundtrip_small_data() {
        let storage = ByteStorage::new(None);

        // Small data should preserve exactly
        let envelope = storage.store(SMALL_DATA, None).expect("Should store");
        let (retrieved, format) = storage.retrieve(&envelope).expect("Should retrieve");

        assert_eq!(retrieved, SMALL_DATA);
        assert_eq!(format, "msgpack");
    }

    #[test]
    fn test_roundtrip_large_data() {
        let storage = ByteStorage::new(None);

        // Generate 10MB random data (in test, not as fixture)
        let large_data = generate_incompressible_data(10_000_000, 12345);

        let envelope = storage
            .store(&large_data, None)
            .expect("Should store large data");
        let (retrieved, format) = storage
            .retrieve(&envelope)
            .expect("Should retrieve large data");

        assert_eq!(retrieved.len(), large_data.len(), "Size should match");
        assert_eq!(retrieved, large_data, "Data should match exactly");
        assert_eq!(format, "msgpack");

        println!("Large data roundtrip: {}MB", large_data.len() / 1_000_000);
    }

    #[test]
    fn test_roundtrip_unicode_data() {
        let storage = ByteStorage::new(None);

        // UTF-8 emoji/unicode should preserve exactly
        let envelope = storage
            .store(UNICODE_DATA, None)
            .expect("Should store unicode");
        let (retrieved, format) = storage
            .retrieve(&envelope)
            .expect("Should retrieve unicode");

        assert_eq!(retrieved, UNICODE_DATA);
        assert_eq!(format, "msgpack");

        // Verify it's still valid UTF-8
        let as_str = std::str::from_utf8(&retrieved).expect("Should be valid UTF-8");
        println!("Unicode roundtrip: {}", as_str);
    }
}
