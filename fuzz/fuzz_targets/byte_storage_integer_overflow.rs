#![no_main]

use libfuzzer_sys::fuzz_target;
use cachekit_core::byte_storage::{StorageEnvelope, ByteStorageError};
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct OverflowTestCase {
    /// Original size to test (including u32::MAX, boundaries, suspicious ratios)
    original_size: u32,
    /// Compressed data size (small to create suspicious ratios)
    compressed_data_len: u8, // 0-255 bytes
    /// Checksum bytes (xxHash3-64 = 8 bytes)
    checksum: [u8; 8],
    /// Format string
    format_len: u8, // 0-255 for format string length
}

fuzz_target!(|test_case: OverflowTestCase| {
    // Attack: Integer overflow via decompression bomb (oversized original_size)
    // Validates: Size limit enforcement prevents excessive allocation

    // Generate compressed data
    let compressed_data = vec![b'x'; test_case.compressed_data_len as usize];

    // Generate format string
    let format = "f".repeat(test_case.format_len as usize);

    // Create envelope with potentially malicious original_size
    let envelope = StorageEnvelope {
        compressed_data,
        checksum: test_case.checksum,
        original_size: test_case.original_size,
        format,
    };

    // Test extract() with oversized original_size
    match envelope.extract() {
        Ok(_) => {
            // Decompression succeeded - envelope passed all validation checks
            // This should only happen for valid sizes within limits
        }
        Err(err) => {
            // Expected for oversized allocations (u32::MAX, beyond 512MB, etc.)
            // Valid error types for size/validation failures
            assert!(
                matches!(
                    err,
                    ByteStorageError::InputTooLarge
                        | ByteStorageError::DecompressionBomb
                        | ByteStorageError::DecompressionFailed
                        | ByteStorageError::ChecksumMismatch
                        | ByteStorageError::SizeValidationFailed
                ),
                "Expected size/validation error, got: {:?}",
                err
            );
        }
    }

    // Success: No panics on extreme sizes (u32::MAX, boundary cases)
    // Invariant: Size limits (512MB) must be enforced consistently
});
