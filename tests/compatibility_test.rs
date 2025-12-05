//! Cross-version compatibility tests
//!
//! Verifies that data compressed by Python (using cachekit._rust_serializer)
//! can be decompressed by Rust (cachekit-core directly).
//!
//! This ensures forward/backward compatibility across version boundaries.

use std::fs;
use std::path::Path;

#[cfg(all(feature = "compression", feature = "checksum"))]
use cachekit_core::ByteStorage;

/// Test vector structure matching Python generation format
#[derive(serde::Deserialize)]
struct TestVector {
    original_data: String, // Hex-encoded original data
    #[allow(dead_code)]
    original_data_text: String, // Human-readable text (for reference)
    original_data_size: usize, // Original byte size
    compressed_data: String, // Hex-encoded compressed envelope
    #[allow(dead_code)]
    compressed_data_size: usize, // Compressed envelope byte size
    format: String,        // Format identifier (e.g., "msgpack")
}

#[test]
#[ignore = "Format changed: Blake3 (32 bytes) → xxHash3-64 (8 bytes). Regenerate test vector after Python update."]
#[cfg(all(feature = "compression", feature = "checksum"))]
fn test_python_generated_data_decompresses_correctly() {
    // Read test vector JSON
    let test_vector_path = Path::new("tests/compatibility/test_vector.json");

    if !test_vector_path.exists() {
        eprintln!(
            "Test vector not found at {}. Run: cd /Users/68824/code/27B/cachekit-workspace/cachekit && uv run python /Users/68824/code/27B/cachekit-workspace/generate_test_vectors.py",
            test_vector_path.display()
        );
        panic!("Test vector file missing");
    }

    let vector_json =
        fs::read_to_string(test_vector_path).expect("Failed to read test vector file");

    let vector: TestVector =
        serde_json::from_str(&vector_json).expect("Failed to parse test vector JSON");

    // Decode hex strings to bytes
    let original_data =
        hex::decode(&vector.original_data).expect("Failed to decode original_data hex");

    let compressed_envelope =
        hex::decode(&vector.compressed_data).expect("Failed to decode compressed_data hex");

    // Verify expected format
    assert_eq!(
        vector.format, "msgpack",
        "Test vector format should be msgpack"
    );

    // Initialize ByteStorage with matching format
    let storage = ByteStorage::new(Some(vector.format.clone()));

    // CRITICAL TEST: Decompress Python-generated data
    let decompressed_result = storage.retrieve(&compressed_envelope);

    assert!(
        decompressed_result.is_ok(),
        "Failed to decompress Python-generated data: {:?}",
        decompressed_result.err()
    );

    let (decompressed_data, retrieved_format) = decompressed_result.unwrap();

    // Verify decompressed data matches original
    assert_eq!(
        decompressed_data,
        original_data,
        "Decompressed data does not match original.\n\
         Original:     {:?}\n\
         Decompressed: {:?}",
        String::from_utf8_lossy(&original_data),
        String::from_utf8_lossy(&decompressed_data)
    );

    // Verify format was preserved
    assert_eq!(
        retrieved_format, vector.format,
        "Format mismatch: expected '{}', got '{}'",
        vector.format, retrieved_format
    );

    // Verify size
    assert_eq!(
        decompressed_data.len(),
        vector.original_data_size,
        "Decompressed size does not match original"
    );

    println!(
        "✓ Cross-version compatibility verified:\n  \
         Original: {} bytes\n  \
         Compressed: {} bytes\n  \
         Decompressed: {} bytes\n  \
         Format: {}",
        original_data.len(),
        vector.compressed_data_size,
        decompressed_data.len(),
        retrieved_format
    );
}

#[test]
#[cfg(all(feature = "compression", feature = "checksum"))]
fn test_roundtrip_data_integrity() {
    // Generate test data directly in Rust
    let test_data = b"Hello, this is test data for compatibility verification.";

    let storage = ByteStorage::new(Some("msgpack".to_string()));

    // Store (compress)
    let compressed = storage
        .store(test_data, None)
        .expect("Failed to store test data");

    // Retrieve (decompress)
    let (decompressed, format) = storage
        .retrieve(&compressed)
        .expect("Failed to retrieve test data");

    // Verify integrity
    assert_eq!(
        &decompressed[..],
        test_data,
        "Roundtrip data integrity check failed"
    );

    assert_eq!(format, "msgpack", "Format mismatch in roundtrip test");

    println!(
        "✓ Roundtrip integrity verified:\n  \
         Original: {} bytes\n  \
         Compressed: {} bytes",
        test_data.len(),
        compressed.len()
    );
}

#[test]
#[cfg(all(feature = "compression", feature = "checksum"))]
fn test_format_preservation() {
    // Test that format string is preserved through compression/decompression

    let storage = ByteStorage::new(Some("msgpack".to_string()));
    let test_data = b"test";

    let compressed = storage.store(test_data, None).expect("Failed to store");

    let (_, retrieved_format) = storage.retrieve(&compressed).expect("Failed to retrieve");

    assert_eq!(retrieved_format, "msgpack");

    println!("✓ Format preservation verified: msgpack");
}
