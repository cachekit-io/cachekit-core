//! Observability metrics for Rust operations
//!
//! Tracks performance and resource usage of compression, checksums, and encryption.
//! Recording is opt-in via the `metrics` cargo feature. Without it, no clock is
//! read and no lock is taken per operation, and the `get_last_metrics()` getters
//! return `OperationMetrics::default()`.

use serde::{Deserialize, Serialize};

/// Operation metrics for visibility into Rust layer performance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationMetrics {
    /// Compression operation time in microseconds (0 if not performed)
    pub compression_time_micros: u64,

    /// Compression ratio (original_size / compressed_size, >1.0 means compression helped)
    pub compression_ratio: f64,

    /// Checksum (xxHash3-64) operation time in microseconds
    pub checksum_time_micros: u64,

    /// Encryption operation time in microseconds (None if not performed)
    pub encryption_time_micros: Option<u64>,

    /// Whether the CPU reports AES hardware (AES-NI / Armv8 Crypto Extension).
    /// Informational only: the crypto backend dispatches on its own detection.
    pub hardware_accelerated: bool,
}

impl OperationMetrics {
    /// Create new empty metrics
    pub fn new() -> Self {
        OperationMetrics {
            compression_time_micros: 0,
            compression_ratio: 1.0,
            checksum_time_micros: 0,
            encryption_time_micros: None,
            hardware_accelerated: false,
        }
    }

    /// Set compression metrics
    pub fn with_compression(
        mut self,
        time_micros: u64,
        original_size: usize,
        compressed_size: usize,
    ) -> Self {
        self.compression_time_micros = time_micros;
        if compressed_size > 0 {
            self.compression_ratio = original_size as f64 / compressed_size as f64;
        }
        self
    }

    /// Set checksum metrics
    pub fn with_checksum(mut self, time_micros: u64) -> Self {
        self.checksum_time_micros = time_micros;
        self
    }

    /// Set encryption metrics
    pub fn with_encryption(mut self, time_micros: u64, hw_accel: bool) -> Self {
        self.encryption_time_micros = Some(time_micros);
        self.hardware_accelerated = hw_accel;
        self
    }

    /// Total operation time in microseconds
    pub fn total_time_micros(&self) -> u64 {
        let mut total = self.compression_time_micros + self.checksum_time_micros;
        if let Some(enc_time) = self.encryption_time_micros {
            total += enc_time;
        }
        total
    }
}

impl Default for OperationMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-operation timer; reports 0 on wasm32, where `Instant` is unavailable.
#[cfg(feature = "metrics")]
pub(crate) struct Timer(#[cfg(not(target_arch = "wasm32"))] std::time::Instant);

#[cfg(feature = "metrics")]
impl Timer {
    pub(crate) fn start() -> Self {
        Timer(
            #[cfg(not(target_arch = "wasm32"))]
            std::time::Instant::now(),
        )
    }

    pub(crate) fn elapsed_micros(&self) -> u64 {
        #[cfg(not(target_arch = "wasm32"))]
        return self.0.elapsed().as_micros() as u64;
        #[cfg(target_arch = "wasm32")]
        return 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = OperationMetrics::new();
        assert_eq!(metrics.compression_time_micros, 0);
        assert_eq!(metrics.checksum_time_micros, 0);
        assert_eq!(metrics.compression_ratio, 1.0);
        assert_eq!(metrics.encryption_time_micros, None);
    }

    #[test]
    fn test_compression_metrics() {
        let metrics = OperationMetrics::new().with_compression(100, 1000, 250);

        assert_eq!(metrics.compression_time_micros, 100);
        assert!((metrics.compression_ratio - 4.0).abs() < 0.01); // 1000/250 = 4.0
    }

    #[test]
    fn test_total_time() {
        let metrics = OperationMetrics::new()
            .with_compression(100, 1000, 250)
            .with_checksum(50)
            .with_encryption(200, true);

        assert_eq!(metrics.total_time_micros(), 350); // 100 + 50 + 200
    }
}
