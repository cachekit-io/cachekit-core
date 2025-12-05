//! Test fixtures and constants for cachekit-serializer tests.
//!
//! This module provides common test data used across ByteStorage, encryption,
//! integration, and property-based tests. All fixtures are const/static for
//! compile-time initialization and zero runtime cost.

// ============================================================================
// Common Test Data
// ============================================================================

/// Empty data - minimal test case for boundary conditions
pub const EMPTY_DATA: &[u8] = b"";

/// Small data - typical short string for basic validation
pub const SMALL_DATA: &[u8] = b"hello world";

/// Unicode data - validates UTF-8 handling with emoji and international characters
pub const UNICODE_DATA: &[u8] = "Hello 世界 🚀 Rust".as_bytes();

/// Size for large data tests (10MB) - validates compression performance
/// without creating actual large constants (generated in tests as needed)
pub const LARGE_DATA_SIZE: usize = 10_000_000;

// ============================================================================
// Encryption Test Key Material
// ============================================================================

/// Test master key for encryption tests (32 bytes for AES-256)
/// Generated from: blake3("test-master-key-for-cachekit-tests")
pub const TEST_MASTER_KEY: &[u8; 32] = &[
    0x3e, 0x5a, 0x89, 0x7f, 0x2c, 0x1d, 0x4b, 0x91, 0xa2, 0x6f, 0x3c, 0xd4, 0x8e, 0x5b, 0x72, 0x19,
    0xf6, 0x4a, 0x21, 0x98, 0xc7, 0x65, 0x3d, 0xb0, 0x84, 0x59, 0x2e, 0xd1, 0xa6, 0x7b, 0x30, 0xe5,
];

/// Test tenant ID for tenant A (multi-tenant isolation tests)
pub const TEST_TENANT_A: &[u8] = b"tenant_alice";

/// Test tenant ID for tenant B (multi-tenant isolation tests)
pub const TEST_TENANT_B: &[u8] = b"tenant_bob";

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate deterministic large data for testing (filled with pattern byte)
///
/// This function creates large test data without storing it as a constant.
/// The pattern byte allows verification while maintaining high compressibility.
pub fn generate_large_data(size: usize, pattern: u8) -> Vec<u8> {
    vec![pattern; size]
}

/// Generate random-looking incompressible data (for compression ratio tests)
///
/// Uses a simple PRNG (not cryptographically secure) to create data that
/// won't compress well. Deterministic seed ensures reproducibility.
pub fn generate_incompressible_data(size: usize, seed: u64) -> Vec<u8> {
    let mut rng = SimplePcg::new(seed);
    (0..size).map(|_| rng.next_byte()).collect()
}

// Simple PCG random number generator (deterministic, not crypto-secure)
struct SimplePcg {
    state: u64,
}

impl SimplePcg {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_byte(&mut self) -> u8 {
        // PCG algorithm: https://www.pcg-random.org/
        let old_state = self.state;
        self.state = old_state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let xor_shifted = (((old_state >> 18) ^ old_state) >> 27) as u32;
        let rot = (old_state >> 59) as u32;
        (xor_shifted.rotate_right(rot) & 0xff) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixture_constants() {
        // Verify fixture data is as expected
        assert_eq!(EMPTY_DATA, b"");
        assert_eq!(SMALL_DATA, b"hello world");
        assert!(UNICODE_DATA.len() > SMALL_DATA.len());
        assert_eq!(LARGE_DATA_SIZE, 10_000_000);
        assert_eq!(TEST_MASTER_KEY.len(), 32);
        assert_eq!(TEST_TENANT_A, b"tenant_alice");
        assert_eq!(TEST_TENANT_B, b"tenant_bob");
        assert_ne!(TEST_TENANT_A, TEST_TENANT_B);
    }

    #[test]
    fn test_generate_large_data() {
        let data = generate_large_data(1000, 0x42);
        assert_eq!(data.len(), 1000);
        assert!(data.iter().all(|&b| b == 0x42));
    }

    #[test]
    fn test_generate_incompressible_data() {
        let data1 = generate_incompressible_data(1000, 12345);
        let data2 = generate_incompressible_data(1000, 12345);
        let data3 = generate_incompressible_data(1000, 54321);

        // Same seed produces same data (deterministic)
        assert_eq!(data1, data2);

        // Different seed produces different data
        assert_ne!(data1, data3);

        // Data should have variety (not all same byte)
        let unique_bytes: std::collections::HashSet<u8> = data1.iter().copied().collect();
        assert!(
            unique_bytes.len() > 10,
            "Incompressible data should have variety"
        );
    }
}
