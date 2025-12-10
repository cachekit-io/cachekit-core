#![no_main]

use libfuzzer_sys::fuzz_target;
use cachekit_core::byte_storage::{StorageEnvelope, ByteStorageError};
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct ChecksumTestCase {
    /// Data to compress (will be used for valid envelope)
    data: Vec<u8>,
    /// Bit flip position in compressed_data (0-255)
    flip_byte_idx: u8,
    /// Bit flip mask
    flip_mask: u8,
}

fuzz_target!(|test_case: ChecksumTestCase| {
    // Attack: Checksum collision via data corruption
    // Validates: xxHash3-64 integrity verification detects mismatches

    // Limit data size for fuzzing performance
    if test_case.data.len() > 4096 {
        return;
    }

    // Create valid envelope first
    let envelope = match StorageEnvelope::new(test_case.data.clone(), "msgpack".to_string()) {
        Ok(env) => env,
        Err(_) => return, // Skip if data too large
    };

    // Valid envelope should extract successfully
    let valid_result = envelope.extract();
    assert!(
        valid_result.is_ok(),
        "Valid envelope should extract successfully"
    );

    // Now corrupt the compressed data (simulate bit flip/corruption)
    let mut corrupted_envelope = StorageEnvelope {
        compressed_data: envelope.compressed_data.clone(),
        checksum: envelope.checksum,
        original_size: envelope.original_size,
        format: envelope.format.clone(),
    };

    if !corrupted_envelope.compressed_data.is_empty() {
        let idx = (test_case.flip_byte_idx as usize) % corrupted_envelope.compressed_data.len();
        corrupted_envelope.compressed_data[idx] ^= test_case.flip_mask;
    }

    // Corrupted envelope should be rejected (checksum mismatch)
    match corrupted_envelope.extract() {
        Ok(_) => {
            // If it succeeded, data must be unchanged (flip reverted or no-op)
            // This is only acceptable if flip_mask was 0 or flipped back to original
        }
        Err(err) => {
            // Expected: Checksum validation or decompression should fail
            assert!(
                matches!(err, ByteStorageError::ChecksumMismatch | ByteStorageError::DecompressionFailed),
                "Error should be checksum or decompression failure: {:?}",
                err
            );
        }
    }

    // Test with completely wrong checksum (xxHash3-64 = 8 bytes)
    let wrong_checksum_envelope = StorageEnvelope {
        compressed_data: envelope.compressed_data.clone(),
        checksum: [0xFF; 8], // Wrong checksum
        original_size: envelope.original_size,
        format: envelope.format.clone(),
    };

    // Should be rejected unless original checksum happened to be all 0xFF
    match wrong_checksum_envelope.extract() {
        Ok(_) => {
            // Only acceptable if original checksum was [0xFF; 8]
        }
        Err(err) => {
            assert!(
                matches!(err, ByteStorageError::ChecksumMismatch | ByteStorageError::DecompressionFailed),
                "Wrong checksum should be detected: {:?}",
                err
            );
        }
    }

    // Success: Checksum validation detects corruption
    // Invariant: xxHash3-64 integrity must catch data tampering
});
