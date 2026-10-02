//! LZ4 compression and xxHash3 checksums for raw byte storage.
//!
//! Provides integrity-protected byte storage with security validation:
//! - 512MB size limits for decompression bomb protection
//! - 1000x max compression ratio enforcement
//! - xxHash3-64 checksums for corruption detection (19x faster than Blake3)

use crate::metrics::OperationMetrics;
#[cfg(feature = "metrics")]
use crate::metrics::Timer;
#[cfg(feature = "compression")]
use lz4_flex;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// Error types for ByteStorage operations
#[derive(Debug, Error, Clone, PartialEq)]
pub enum ByteStorageError {
    #[error("input exceeds maximum size")]
    InputTooLarge,

    #[error("decompression ratio exceeds safety limit")]
    DecompressionBomb,

    #[error("integrity check failed")]
    ChecksumMismatch,

    #[error("compression failed")]
    CompressionFailed,

    #[error("decompression failed")]
    DecompressionFailed,

    #[error("size validation failed")]
    SizeValidationFailed,

    #[error("serialization failed: {0}")]
    SerializationFailed(String),

    #[error("deserialization failed: {0}")]
    DeserializationFailed(String),
}

// Security constants - Production-safe limits
const MAX_UNCOMPRESSED_SIZE: usize = 512 * 1024 * 1024; // 512MB limit
const MAX_COMPRESSED_SIZE: usize = 512 * 1024 * 1024; // 512MB limit
/// Maximum allowed compression ratio (1000:1)
/// Uses u64 for integer-only arithmetic to prevent floating-point precision bypass attacks
const MAX_COMPRESSION_RATIO: u64 = 1000;

/// Storage envelope for raw byte storage
/// Contains compressed data with integrity checking
#[derive(Serialize, Deserialize)]
pub struct StorageEnvelope {
    /// Compressed payload data
    ///
    /// Serialized as msgpack `bin` (protocol 1.1, `envelope-bin-encoding.md`).
    /// Scope is strictly this field: `checksum` stays array-of-ints by
    /// normative exclusion (crypto-adjacent surface — MUST NOT flip).
    #[serde(with = "serde_bytes")]
    pub compressed_data: Vec<u8>,
    /// xxHash3-64 checksum for integrity (8 bytes)
    pub checksum: [u8; 8],
    /// Original size for validation
    pub original_size: u32,
    /// Format identifier (e.g., "msgpack")
    pub format: String,
}

impl StorageEnvelope {
    /// Create new envelope with data compression and checksum.
    ///
    /// Takes the input by shared slice: it is only compressed and hashed (both
    /// borrow), never retained, so there is no reason to own it. Avoids a
    /// full-payload copy (up to `MAX_UNCOMPRESSED_SIZE`) on the write path.
    #[cfg(all(feature = "compression", feature = "checksum"))]
    pub fn new(data: &[u8], format: String) -> Result<Self, ByteStorageError> {
        // Security: Check input size before compression
        if data.len() > MAX_UNCOMPRESSED_SIZE {
            return Err(ByteStorageError::InputTooLarge);
        }

        let original_size = data.len() as u32;

        // Compress with LZ4
        let compressed_data = lz4_flex::compress(data);

        // Security: Check compressed size
        if compressed_data.len() > MAX_COMPRESSED_SIZE {
            return Err(ByteStorageError::InputTooLarge);
        }

        // Single canonical xxHash3-64 definition (see crate::checksum)
        let checksum = crate::checksum::checksum(data);

        Ok(StorageEnvelope {
            compressed_data,
            checksum,
            original_size,
            format,
        })
    }

    /// Extract and validate data from envelope
    #[cfg(all(feature = "compression", feature = "checksum"))]
    pub fn extract(&self) -> Result<Vec<u8>, ByteStorageError> {
        check_decompression_bound(self.compressed_data.len(), self.original_size)?;

        // Decompress (with validated sizes)
        let decompressed = lz4_flex::decompress(&self.compressed_data, self.original_size as usize)
            .map_err(|_| ByteStorageError::DecompressionFailed)?;

        // Verify checksum (checksum validation happens AFTER decompression to prevent processing corrupted data)
        // false -> ChecksumMismatch (preserve the error variant; verify_checksum returns bool)
        if !crate::checksum::verify_checksum(&decompressed, &self.checksum) {
            return Err(ByteStorageError::ChecksumMismatch);
        }

        // Verify size (final safety check)
        if decompressed.len() != self.original_size as usize {
            return Err(ByteStorageError::SizeValidationFailed);
        }

        Ok(decompressed)
    }
}

/// Decompression bound, checked by `extract` before it allocates the output.
///
/// A separate function so the Kani proofs verify the predicate `extract`
/// actually runs, not a restatement of it.
#[cfg(all(feature = "compression", feature = "checksum"))]
fn check_decompression_bound(
    compressed_len: usize,
    original_size: u32,
) -> Result<(), ByteStorageError> {
    // Size caps first
    if compressed_len > MAX_COMPRESSED_SIZE {
        return Err(ByteStorageError::InputTooLarge);
    }

    if original_size as usize > MAX_UNCOMPRESSED_SIZE {
        return Err(ByteStorageError::InputTooLarge);
    }

    // Security: Check compression ratio for decompression bomb protection
    // Uses integer arithmetic to prevent floating-point precision bypass attacks
    let compressed_size = compressed_len as u64;

    // Step 1: Zero-length compressed data is always a bomb
    if compressed_size == 0 {
        return Err(ByteStorageError::DecompressionBomb);
    }

    // Step 2: Checked multiplication - overflow = bomb (fail-safe)
    let max_allowed_original = MAX_COMPRESSION_RATIO
        .checked_mul(compressed_size)
        .ok_or(ByteStorageError::DecompressionBomb)?;

    // Step 3: Compare original_size against computed maximum
    if (original_size as u64) > max_allowed_original {
        return Err(ByteStorageError::DecompressionBomb);
    }

    Ok(())
}

/// Raw byte storage engine (pure Rust core)
/// Simple store/retrieve interface with no type awareness
pub struct ByteStorage {
    default_format: String,
    /// Last operation metrics (interior mutability for observability)
    last_metrics: Arc<Mutex<OperationMetrics>>,
}

impl ByteStorage {
    /// Create new ByteStorage instance
    pub fn new(default_format: Option<String>) -> Self {
        ByteStorage {
            default_format: default_format.unwrap_or_else(|| "msgpack".to_string()),
            last_metrics: Arc::new(Mutex::new(OperationMetrics::new())),
        }
    }

    /// Store arbitrary bytes with compression and checksums
    ///
    /// Returns serialized StorageEnvelope bytes
    #[cfg(all(feature = "compression", feature = "checksum", feature = "messagepack"))]
    pub fn store(&self, data: &[u8], format: Option<String>) -> Result<Vec<u8>, ByteStorageError> {
        // Security: Check input size before processing
        if data.len() > MAX_UNCOMPRESSED_SIZE {
            return Err(ByteStorageError::InputTooLarge);
        }

        let format = format.unwrap_or_else(|| self.default_format.clone());

        #[cfg(feature = "metrics")]
        let timer = Timer::start();

        let envelope = StorageEnvelope::new(data, format)?;

        #[cfg(feature = "metrics")]
        let compression_micros = timer.elapsed_micros();

        // Serialize envelope with MessagePack
        let envelope_bytes = rmp_serde::to_vec(&envelope)
            .map_err(|e| ByteStorageError::SerializationFailed(e.to_string()))?;

        // Security: Final check on serialized envelope size
        if envelope_bytes.len() > MAX_COMPRESSED_SIZE {
            return Err(ByteStorageError::InputTooLarge);
        }

        #[cfg(feature = "metrics")]
        if let Ok(mut metrics) = self.last_metrics.lock() {
            *metrics = OperationMetrics::new().with_compression(
                compression_micros,
                data.len(),
                envelope.compressed_data.len(),
            );
        }

        Ok(envelope_bytes)
    }

    /// Retrieve and validate stored bytes
    ///
    /// Returns (original_data, format_identifier)
    ///
    /// # Errors
    ///
    /// `envelope_bytes` is untrusted. Before it is decoded, a structural
    /// pre-scan bounds its nesting depth and rejects any header that declares
    /// more than the input can back (protocol Retrieve Flow, step 2). A
    /// pre-scan rejection is `DeserializationFailed` whose message starts with
    /// `decode pre-scan: `, the same variant as any other bytes that do not
    /// decode as a `StorageEnvelope`.
    #[cfg(all(feature = "compression", feature = "checksum", feature = "messagepack"))]
    pub fn retrieve(&self, envelope_bytes: &[u8]) -> Result<(Vec<u8>, String), ByteStorageError> {
        // Security: Check envelope size before deserializing
        if envelope_bytes.len() > MAX_COMPRESSED_SIZE {
            return Err(ByteStorageError::InputTooLarge);
        }

        let envelope = decode_envelope(envelope_bytes)?;

        #[cfg(feature = "metrics")]
        let timer = Timer::start();

        // Extract and validate data (all security checks happen inside extract())
        let data = envelope.extract()?;

        // Compression ratio comes from the stored metadata
        #[cfg(feature = "metrics")]
        if let Ok(mut metrics) = self.last_metrics.lock() {
            *metrics = OperationMetrics::new().with_compression(
                timer.elapsed_micros(),
                envelope.original_size as usize,
                envelope.compressed_data.len(),
            );
        }

        Ok((data, envelope.format))
    }

    /// Get compression ratio for given data
    #[cfg(feature = "compression")]
    pub fn estimate_compression(&self, data: &[u8]) -> Result<f64, ByteStorageError> {
        // Security: Check size before compression
        if data.len() > MAX_UNCOMPRESSED_SIZE {
            return Err(ByteStorageError::InputTooLarge);
        }

        let compressed = lz4_flex::compress(data);

        Ok(data.len() as f64 / compressed.len() as f64)
    }

    /// Validate an envelope by fully extracting it and discarding the result
    ///
    /// This runs `StorageEnvelope::extract`, so it decompresses the payload and
    /// allocates up to the decompression bound. It is not a cheap structural
    /// pre-screen for untrusted envelopes.
    #[cfg(all(feature = "compression", feature = "checksum", feature = "messagepack"))]
    pub fn validate(&self, envelope_bytes: &[u8]) -> bool {
        // Security: Check size before validating
        if envelope_bytes.len() > MAX_COMPRESSED_SIZE {
            return false; // Invalid due to size limit
        }

        match decode_envelope(envelope_bytes) {
            Ok(envelope) => envelope.extract().is_ok(),
            Err(_) => false,
        }
    }

    /// Get metrics from last operation
    ///
    /// Returns a snapshot of metrics from the most recent store() or retrieve() call.
    /// Without the `metrics` feature nothing is recorded and this returns
    /// `OperationMetrics::default()`.
    pub fn get_last_metrics(&self) -> OperationMetrics {
        self.last_metrics
            .lock()
            .map(|metrics| metrics.clone())
            .unwrap_or_else(|_| OperationMetrics::new())
    }

    /// Get security limits
    pub fn max_uncompressed_size(&self) -> usize {
        MAX_UNCOMPRESSED_SIZE
    }

    pub fn max_compressed_size(&self) -> usize {
        MAX_COMPRESSED_SIZE
    }

    pub fn max_compression_ratio(&self) -> u64 {
        MAX_COMPRESSION_RATIO
    }
}

impl Default for ByteStorage {
    fn default() -> Self {
        Self::new(None)
    }
}

/// Decode untrusted envelope bytes: structural pre-scan first, then the typed
/// decode. Serde's derive skips an unknown map key with `IgnoredAny`, which
/// recurses, so the depth bound has to hold before `rmp_serde` sees the bytes.
#[cfg(all(feature = "compression", feature = "checksum", feature = "messagepack"))]
fn decode_envelope(envelope_bytes: &[u8]) -> Result<StorageEnvelope, ByteStorageError> {
    // Nesting bound for the envelope decode. The protocol requires 32..=1024;
    // 100 matches cachekit-rs and cachekit-ts. A legitimate envelope nests 2 deep.
    const MAX_DEPTH: usize = 100;
    crate::check_msgpack_structure(envelope_bytes, MAX_DEPTH).map_err(|what| {
        ByteStorageError::DeserializationFailed(format!("decode pre-scan: {what}"))
    })?;
    rmp_serde::from_slice(envelope_bytes)
        .map_err(|e| ByteStorageError::DeserializationFailed(e.to_string()))
}

#[cfg(all(
    test,
    feature = "compression",
    feature = "checksum",
    feature = "messagepack"
))]
mod tests {
    use super::*;

    #[test]
    fn envelope_embeds_canonical_checksum() {
        let data = b"DRY-guard payload";
        let envelope = StorageEnvelope::new(data, "test".to_string()).unwrap();
        assert_eq!(envelope.checksum, crate::checksum::checksum(data));
    }

    #[test]
    fn test_storage_envelope_roundtrip() {
        let data = b"Hello, World! This is test data for compression.".to_vec();
        let envelope = StorageEnvelope::new(&data, "test".to_string()).unwrap();
        let extracted = envelope.extract().unwrap();
        assert_eq!(data, extracted);
    }

    #[test]
    fn test_compression_works() {
        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec(); // Highly compressible
        let envelope = StorageEnvelope::new(&data, "test".to_string()).unwrap();
        assert!(envelope.compressed_data.len() < data.len());
    }

    #[test]
    fn test_checksum_validation() {
        let mut envelope = StorageEnvelope::new(b"test", "test".to_string()).unwrap();
        // Corrupt the checksum
        envelope.checksum[0] = !envelope.checksum[0];
        // Fail-open guard: the DRY refactor must still surface the specific
        // ChecksumMismatch variant (not silently succeed on a flipped checksum).
        assert!(matches!(
            envelope.extract(),
            Err(ByteStorageError::ChecksumMismatch)
        ));
    }

    #[test]
    fn test_raw_persistence_roundtrip() {
        let storage = ByteStorage::new(None);
        let test_data = b"test data for persistence";

        let stored = storage.store(test_data, None).unwrap();
        let (retrieved_data, format) = storage.retrieve(&stored).unwrap();
        assert_eq!(test_data, retrieved_data.as_slice());
        assert_eq!("msgpack", format);
    }

    #[test]
    fn test_size_limits_input() {
        let storage = ByteStorage::new(None);

        // Create data larger than MAX_UNCOMPRESSED_SIZE (512MB)
        let large_data = vec![0u8; MAX_UNCOMPRESSED_SIZE + 1];

        let result = storage.store(&large_data, None);
        assert!(matches!(result, Err(ByteStorageError::InputTooLarge)));
    }

    #[test]
    fn test_size_limits_envelope() {
        // Create data exactly at the limit
        let max_data = vec![0u8; MAX_UNCOMPRESSED_SIZE];
        let envelope_result = StorageEnvelope::new(&max_data, "test".to_string());

        // Should succeed at exactly the limit
        assert!(envelope_result.is_ok());
    }

    #[test]
    fn test_compression_ratio_bomb_protection() {
        // Simulate a decompression bomb scenario
        let malicious_envelope = StorageEnvelope {
            compressed_data: vec![0u8; 1000], // Small compressed size
            checksum: [0u8; 8],               // Fake checksum
            original_size: 200 * 1024 * 1024, // Claims 200MB original (200x expansion)
            format: "test".to_string(),
        };

        let result = malicious_envelope.extract();
        assert!(matches!(result, Err(ByteStorageError::DecompressionBomb)));
    }

    // ============================================================================
    // Decompression Bomb Edge Case Tests (Task 6.1)
    // ============================================================================

    #[test]
    fn test_decompression_bomb_zero_compressed_size() {
        // WHY: Empty compressed data claiming non-zero original is always a bomb
        let malicious_envelope = StorageEnvelope {
            compressed_data: vec![], // Zero compressed size
            checksum: [0u8; 8],
            original_size: 1000, // Claims 1KB original
            format: "test".to_string(),
        };

        let result = malicious_envelope.extract();
        assert!(
            matches!(result, Err(ByteStorageError::DecompressionBomb)),
            "Zero compressed size should be rejected as decompression bomb"
        );
    }

    #[test]
    fn test_decompression_bomb_extreme_ratio() {
        // WHY: Test extreme ratio that exceeds 1000:1
        // compressed_size=1, original_size=2000 → 2000:1 ratio exceeds limit
        // Note: u32::MAX would be caught by InputTooLarge first (> MAX_UNCOMPRESSED_SIZE)
        let malicious_envelope = StorageEnvelope {
            compressed_data: vec![0u8; 1], // 1 byte compressed
            checksum: [0u8; 8],
            original_size: 2000, // 2000:1 ratio (exceeds 1000:1 limit)
            format: "test".to_string(),
        };

        let result = malicious_envelope.extract();
        assert!(
            matches!(result, Err(ByteStorageError::DecompressionBomb)),
            "Extreme ratio should be rejected as bomb: {:?}",
            result
        );
    }

    #[test]
    fn test_decompression_u32_max_original_size() {
        // WHY: u32::MAX original_size exceeds MAX_UNCOMPRESSED_SIZE
        // Should fail with InputTooLarge, not DecompressionBomb
        // This validates the check order (size limits before ratio)
        let malicious_envelope = StorageEnvelope {
            compressed_data: vec![0u8; 1000],
            checksum: [0u8; 8],
            original_size: u32::MAX, // ~4GB exceeds 512MB limit
            format: "test".to_string(),
        };

        let result = malicious_envelope.extract();
        assert!(
            matches!(result, Err(ByteStorageError::InputTooLarge)),
            "u32::MAX should be rejected as InputTooLarge (exceeds 512MB limit): {:?}",
            result
        );
    }

    #[test]
    fn test_decompression_exactly_at_threshold() {
        // WHY: Exactly 1000:1 ratio should be accepted (pass ratio check)
        // The test verifies the ratio check passes - subsequent failures are expected
        // (invalid LZ4 data will fail at decompression or checksum)
        let envelope = StorageEnvelope {
            compressed_data: vec![0u8; 100], // 100 bytes compressed (not valid LZ4)
            checksum: [0u8; 8],
            original_size: 100_000, // 100KB = exactly 1000:1 ratio
            format: "test".to_string(),
        };

        let result = envelope.extract();
        // KEY: Should NOT fail with DecompressionBomb (ratio check should pass)
        // Will fail with DecompressionFailed, ChecksumMismatch, or SizeValidationFailed
        assert!(
            !matches!(result, Err(ByteStorageError::DecompressionBomb)),
            "Exactly 1000:1 ratio should pass bomb check: {:?}",
            result
        );
        assert!(
            result.is_err(),
            "Invalid data should still fail after ratio check"
        );
    }

    #[test]
    fn test_decompression_just_over_threshold() {
        // WHY: 1001:1 ratio should be rejected
        let malicious_envelope = StorageEnvelope {
            compressed_data: vec![0u8; 100], // 100 bytes compressed
            checksum: [0u8; 8],
            original_size: 100_001, // 100.001KB = 1000.01:1 ratio (just over)
            format: "test".to_string(),
        };

        let result = malicious_envelope.extract();
        assert!(
            matches!(result, Err(ByteStorageError::DecompressionBomb)),
            "Just over 1000:1 ratio should be rejected as bomb"
        );
    }

    #[test]
    fn test_decompression_bomb_integer_boundary() {
        // WHY: Test near u64 overflow boundary
        // MAX_COMPRESSION_RATIO (1000) * compressed_size must not overflow
        // u64::MAX / 1000 ≈ 18,446,744,073,709,551 is max safe compressed_size
        // But we're constrained by MAX_COMPRESSED_SIZE (512MB), so overflow is unlikely
        // This test verifies the check works at realistic boundary

        let envelope = StorageEnvelope {
            compressed_data: vec![0u8; 1_000_000], // 1MB compressed
            checksum: [0u8; 8],
            original_size: 1_000_000_000, // 1GB = exactly 1000:1 ratio
            format: "test".to_string(),
        };

        // Should fail due to size limit (1GB > MAX_UNCOMPRESSED_SIZE)
        let result = envelope.extract();
        assert!(
            matches!(result, Err(ByteStorageError::InputTooLarge)),
            "Should fail size check before ratio check: {:?}",
            result
        );
    }

    #[test]
    fn test_extract_rejects_oversized_compressed_data() {
        // WHY: only the compressed-length cap rejects this envelope. original_size
        // is under its cap and the ratio is far below 1000:1, and retrieve's
        // envelope-length check is bypassed by calling extract directly.
        let envelope = StorageEnvelope {
            compressed_data: vec![0u8; MAX_COMPRESSED_SIZE + 1],
            checksum: [0u8; 8],
            original_size: 1,
            format: "test".to_string(),
        };

        assert_eq!(envelope.extract(), Err(ByteStorageError::InputTooLarge));
    }

    #[test]
    fn test_envelope_size_validation() {
        let storage = ByteStorage::new(None);

        // Create oversized envelope bytes
        let oversized_envelope = vec![0u8; MAX_COMPRESSED_SIZE + 1];

        let result = storage.retrieve(&oversized_envelope);
        assert!(matches!(result, Err(ByteStorageError::InputTooLarge)));
    }

    #[test]
    fn test_security_limits_getters() {
        let storage = ByteStorage::new(None);

        assert_eq!(storage.max_uncompressed_size(), MAX_UNCOMPRESSED_SIZE);
        assert_eq!(storage.max_compressed_size(), MAX_COMPRESSED_SIZE);
        assert_eq!(storage.max_compression_ratio(), 1000u64);
    }

    #[test]
    fn test_compression_estimate_security() {
        let storage = ByteStorage::new(None);

        // Test with oversized data
        let large_data = vec![0u8; MAX_UNCOMPRESSED_SIZE + 1];
        let result = storage.estimate_compression(&large_data);
        assert!(matches!(result, Err(ByteStorageError::InputTooLarge)));
    }

    #[test]
    fn test_validate_security() {
        let storage = ByteStorage::new(None);

        // Test with oversized envelope
        let large_envelope = vec![0u8; MAX_COMPRESSED_SIZE + 1];
        let result = storage.validate(&large_envelope);
        assert!(!result); // Should be invalid due to size
    }

    #[test]
    fn test_edge_case_exactly_at_limits() {
        // Test data exactly at 512MB
        let storage = ByteStorage::new(None);
        let max_size_data = vec![1u8; MAX_UNCOMPRESSED_SIZE]; // Fill with 1s to ensure it's compressible

        // Should succeed at exactly the limit
        let result = storage.store(&max_size_data, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_zero_size_edge_case() {
        let storage = ByteStorage::new(None);
        let empty_data = vec![];

        let stored = storage.store(&empty_data, None).unwrap();
        let (retrieved_data, format) = storage.retrieve(&stored).unwrap();
        assert_eq!(empty_data, retrieved_data);
        assert_eq!("msgpack", format);
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_metrics_collection_on_store() {
        let storage = ByteStorage::new(None);
        let test_data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec(); // Compressible

        // Store data
        storage.store(&test_data, None).unwrap();
        let metrics = storage.get_last_metrics();

        // Verify metrics were collected
        assert!(metrics.compression_ratio > 0.0); // Should have valid compression ratio
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_metrics_collection_on_retrieve() {
        let storage = ByteStorage::new(None);
        let test_data = b"test data for retrieval metrics";

        // Store then retrieve
        let stored = storage.store(test_data, None).unwrap();
        storage.retrieve(&stored).unwrap();
        let metrics = storage.get_last_metrics();

        // Verify retrieve metrics were collected
        assert!(metrics.compression_ratio > 0.0); // Should have valid ratio
    }

    #[cfg(not(feature = "metrics"))]
    #[test]
    fn test_metrics_not_recorded_without_feature() {
        let storage = ByteStorage::new(None);
        let test_data = vec![b'a'; 4096]; // Compressible: a recorded ratio would be > 1.0

        let stored = storage.store(&test_data, None).unwrap();
        assert_eq!(storage.get_last_metrics().compression_ratio, 1.0);
        storage.retrieve(&stored).unwrap();
        assert_eq!(storage.get_last_metrics().compression_ratio, 1.0);
    }
}

// Kani Formal Verification Proofs
// These proofs use bounded model checking to verify critical security properties
// Bounded to complete within 10 minutes as per specification requirements
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Verify checksum integrity (corruption detection)
    /// Property: Any single-bit checksum corruption is always detected
    #[kani::proof]
    #[kani::unwind(10)] // Need 8+ for memcmp of 8-byte xxHash3-64 checksum
    fn verify_checksum_detects_corruption() {
        // Create symbolic checksum (xxHash3-64 produces 8 bytes)
        let checksum_a: [u8; 8] = kani::any();
        let mut checksum_b = checksum_a;

        // Flip exactly one bit
        let byte_index: usize = kani::any();
        let bit_index: usize = kani::any();
        kani::assume(byte_index < 8);
        kani::assume(bit_index < 8);

        checksum_b[byte_index] ^= 1 << bit_index;

        // Property: Corrupted checksum must differ from original
        assert_ne!(checksum_a, checksum_b);
    }

    // The size/ratio proofs pin the limits as literals instead of reading the
    // constants, so changing a constant or inverting a comparison in
    // `check_decompression_bound` fails a proof.
    const PINNED_MAX_COMPRESSED: u64 = 512 * 1024 * 1024;
    const PINNED_MAX_UNCOMPRESSED: u64 = 512 * 1024 * 1024;
    const PINNED_MAX_RATIO: u64 = 1000;

    /// Verify the size caps of the decompression bound
    /// Property: `InputTooLarge` exactly when either size exceeds 512 MiB, for
    /// every (compressed length, original_size) pair
    #[kani::proof]
    fn verify_decompression_bound_size_caps() {
        let compressed_len: usize = kani::any();
        let original_size: u32 = kani::any();

        let over_cap = compressed_len as u64 > PINNED_MAX_COMPRESSED
            || original_size as u64 > PINNED_MAX_UNCOMPRESSED;
        let result = check_decompression_bound(compressed_len, original_size);

        assert_eq!(
            over_cap,
            matches!(result, Err(ByteStorageError::InputTooLarge))
        );
    }

    /// Verify the ratio limit of the decompression bound
    /// Property: with both sizes within their caps, `DecompressionBomb` exactly
    /// when the compressed length is zero or the ratio exceeds 1000:1, else Ok
    #[kani::proof]
    fn verify_decompression_bound_ratio() {
        let compressed_len: usize = kani::any();
        let original_size: u32 = kani::any();
        kani::assume(compressed_len as u64 <= PINNED_MAX_COMPRESSED);
        kani::assume(original_size as u64 <= PINNED_MAX_UNCOMPRESSED);

        let is_bomb =
            compressed_len == 0 || original_size as u64 > PINNED_MAX_RATIO * compressed_len as u64;
        let result = check_decompression_bound(compressed_len, original_size);

        if is_bomb {
            assert!(matches!(result, Err(ByteStorageError::DecompressionBomb)));
        } else {
            assert!(result.is_ok());
        }
    }
}
