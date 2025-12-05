#![no_main]

use libfuzzer_sys::fuzz_target;
use cachekit_core::byte_storage::{ByteStorage, StorageEnvelope};
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct CompressionBombTestCase {
    /// Compressed data size (tiny to create extreme ratios)
    compressed_size: u16, // 0-65535 bytes
    /// Original size claim (potentially massive for bomb attacks)
    original_size: u32,
    /// Checksum
    checksum: [u8; 32],
    /// Format string length
    format_len: u8,
    /// Actual compressed data pattern (for LZ4 valid/invalid inputs)
    data_pattern: u8,
}

fuzz_target!(|test_case: CompressionBombTestCase| {
    // Attack scenarios:
    // 1. Decompression bomb: 1KB compressed -> claims 1GB uncompressed (1000x ratio)
    // 2. Size limit bypass: Claims > 512MB output
    // 3. LZ4 malformed data: Invalid compressed stream
    // 4. Integer overflow: u32::MAX original_size

    let storage = ByteStorage::new(Some("fuzz".to_string()));

    // Generate compressed data with pattern
    let compressed_data = vec![test_case.data_pattern; test_case.compressed_size as usize];

    // Generate format string
    let format = "f".repeat(test_case.format_len as usize);

    // Create potentially malicious envelope
    let envelope = StorageEnvelope {
        compressed_data: compressed_data.clone(),
        checksum: test_case.checksum,
        original_size: test_case.original_size,
        format: format.clone(),
    };

    // **CRITICAL SECURITY PROPERTIES** (must verify ALL 4):

    // Property 1: Decompression NEVER panics (even on malformed LZ4 data)
    let extract_result = envelope.extract();

    // Property 2: Size limits enforced (512MB max output)
    match &extract_result {
        Ok(decompressed) => {
            assert!(
                decompressed.len() <= storage.max_uncompressed_size(),
                "Decompression bomb bypassed size limit: {} bytes > {} bytes",
                decompressed.len(),
                storage.max_uncompressed_size()
            );
        }
        Err(err) => {
            // Expected for malicious inputs - verify error is descriptive
            if test_case.original_size as usize > storage.max_uncompressed_size() {
                assert!(
                    err.contains("Security violation") || err.contains("too large"),
                    "Expected size limit error, got: {}",
                    err
                );
            }
        }
    }

    // Property 3: Compression ratio limits enforced (500x max expansion)
    if !compressed_data.is_empty() && test_case.original_size > 0 {
        let claimed_ratio = test_case.original_size as f64 / compressed_data.len() as f64;

        if claimed_ratio > storage.max_compression_ratio() {
            // Must reject suspicious ratios (or size limits caught it first)
            assert!(
                extract_result.is_err(),
                "Decompression bomb bypassed ratio limit: {:.1}x expansion (1KB -> {}MB)",
                claimed_ratio,
                test_case.original_size / (1024 * 1024)
            );

            if let Err(err) = &extract_result {
                // Security checks may fail in different order (size limit or ratio limit)
                assert!(
                    err.contains("Suspicious compression ratio")
                        || err.contains("decompression bomb")
                        || err.contains("too large"), // Size limit caught it first
                    "Expected security violation error, got: {}",
                    err
                );
            }
        }
    }

    // Property 4: ByteStorage.retrieve() provides additional layer of defense
    // (Envelope serialization roundtrip testing)
    if let Ok(envelope_bytes) = rmp_serde::to_vec(&envelope) {
        // Test retrieve() with fuzzer-generated envelope
        let retrieve_result = storage.retrieve(&envelope_bytes);

        match retrieve_result {
            Ok((decompressed, _)) => {
                // If retrieve succeeded, ALL security checks must have passed
                assert!(
                    decompressed.len() <= storage.max_uncompressed_size(),
                    "retrieve() bypassed size limit"
                );

                // Ratio must be within limits (for non-empty compressed data)
                if !compressed_data.is_empty() {
                    let actual_ratio = decompressed.len() as f64 / compressed_data.len() as f64;
                    assert!(
                        actual_ratio <= storage.max_compression_ratio(),
                        "retrieve() bypassed ratio limit: {:.1}x",
                        actual_ratio
                    );
                }
            }
            Err(_) => {
                // Expected for malicious/malformed envelopes
                // Error handling is working correctly
            }
        }
    }

    // Property 5: No memory exhaustion
    // Fuzzer tracks memory usage - excessive allocation will trigger OOM kill
    // Defense-in-depth: Size limits prevent 1KB -> 10GB attacks

    // SUCCESS: All compression bomb attack vectors blocked
    // - Extreme ratios rejected (500x limit)
    // - Oversized outputs rejected (512MB limit)
    // - Malformed LZ4 data handled gracefully
    // - No panics, crashes, or memory exhaustion
});
