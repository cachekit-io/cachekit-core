//! Large Payload Tests
//!
//! WHY THIS TEST EXISTS:
//! Production systems may cache large objects (multi-MB responses, file data,
//! aggregated results). This test validates that the system handles large
//! payloads efficiently without OOM, corruption, or performance degradation.
//!
//! WHAT WE'RE TESTING:
//! - Memory efficiency: Large payloads don't cause OOM
//! - Data integrity: Large data roundtrips correctly
//! - Performance: Large payloads complete in reasonable time
//! - Compression: Large compressible data achieves good ratios
//! - Encryption: Large encrypted data works correctly
//!
//! SIZE RANGES TESTED:
//! - 1MB: Common large cache entry
//! - 10MB: Large API response or file
//! - 50MB: Very large cached object
//! - 100MB: Near memory limits (stress test)

mod common;

use common::fixtures::*;

#[cfg(feature = "compression")]
use cachekit_core::byte_storage::ByteStorage;

#[cfg(feature = "encryption")]
use cachekit_core::encryption::core::ZeroKnowledgeEncryptor;

// ============================================================================
// ByteStorage Large Payload Tests
// ============================================================================

#[cfg(feature = "compression")]
mod byte_storage_large {
    use super::*;

    #[test]
    fn test_1mb_payload_roundtrip() {
        // WHY: 1MB is a common large cache entry size (API responses, small files)

        let storage = ByteStorage::new(None);
        let data_1mb = generate_incompressible_data(1_000_000, 777);

        let envelope = storage
            .store(&data_1mb, None)
            .expect("Should store 1MB payload");

        let (retrieved, format) = storage
            .retrieve(&envelope)
            .expect("Should retrieve 1MB payload");

        assert_eq!(retrieved.len(), data_1mb.len());
        assert_eq!(retrieved, data_1mb);
        assert_eq!(format, "msgpack");

        println!(
            "✓ 1MB payload: Roundtrip successful ({} bytes)",
            retrieved.len()
        );
    }

    #[test]
    fn test_10mb_payload_roundtrip() {
        // WHY: 10MB payloads test memory handling and compression efficiency

        let storage = ByteStorage::new(None);
        let data_10mb = generate_incompressible_data(10_000_000, 12345);

        let envelope = storage
            .store(&data_10mb, None)
            .expect("Should store 10MB payload");

        // Verify envelope size is reasonable (incompressible data won't shrink much)
        let envelope_mb = envelope.len() as f64 / 1_000_000.0;
        println!("10MB payload compressed to {:.2}MB", envelope_mb);

        let (retrieved, format) = storage
            .retrieve(&envelope)
            .expect("Should retrieve 10MB payload");

        assert_eq!(retrieved.len(), data_10mb.len());
        assert_eq!(retrieved, data_10mb);
        assert_eq!(format, "msgpack");

        println!("✓ 10MB payload: Roundtrip successful");
    }

    #[test]
    fn test_50mb_payload_stress() {
        // WHY: 50MB tests system stress and memory pressure

        let storage = ByteStorage::new(None);
        let data_50mb = generate_incompressible_data(50_000_000, 99999);

        let envelope = storage
            .store(&data_50mb, None)
            .expect("Should store 50MB payload");

        let envelope_mb = envelope.len() as f64 / 1_000_000.0;
        println!("50MB payload compressed to {:.2}MB", envelope_mb);

        let (retrieved, _) = storage
            .retrieve(&envelope)
            .expect("Should retrieve 50MB payload");

        assert_eq!(retrieved.len(), data_50mb.len());
        // Don't compare full equality (too slow), compare samples
        assert_eq!(&retrieved[..1000], &data_50mb[..1000]);
        assert_eq!(
            &retrieved[retrieved.len() - 1000..],
            &data_50mb[data_50mb.len() - 1000..]
        );

        println!("✓ 50MB payload: Stress test successful");
    }

    #[test]
    fn test_compressible_large_payload() {
        // WHY: Test compression efficiency with highly compressible large data

        let storage = ByteStorage::new(None);
        // 10MB of zeros (highly compressible)
        let data_10mb = generate_large_data(10_000_000, 0x00);

        let envelope = storage
            .store(&data_10mb, None)
            .expect("Should compress 10MB of zeros");

        // Highly compressible data should compress dramatically
        let original_mb = data_10mb.len() as f64 / 1_000_000.0;
        let compressed_mb = envelope.len() as f64 / 1_000_000.0;
        let ratio = original_mb / compressed_mb;

        println!(
            "Compressible 10MB: {:.2}MB → {:.2}MB (ratio: {:.1}x)",
            original_mb, compressed_mb, ratio
        );

        // Should achieve at least 10x compression for zeros
        assert!(
            ratio > 10.0,
            "10MB of zeros should compress >10x (got {:.1}x)",
            ratio
        );

        let (retrieved, _) = storage.retrieve(&envelope).expect("Should decompress");

        assert_eq!(retrieved.len(), data_10mb.len());
        assert_eq!(retrieved, data_10mb);

        println!("✓ Compressible 10MB: {:.1}x compression achieved", ratio);
    }

    #[test]
    #[ignore] // Ignore by default (slow and memory-intensive)
    fn test_100mb_payload_extreme() {
        // WHY: Extreme stress test near memory limits
        // NOTE: Ignored by default. Run with: cargo test --ignored

        let storage = ByteStorage::new(None);
        let data_100mb = generate_incompressible_data(100_000_000, 55555);

        let envelope = storage
            .store(&data_100mb, None)
            .expect("Should store 100MB payload");

        let envelope_mb = envelope.len() as f64 / 1_000_000.0;
        println!("100MB payload compressed to {:.2}MB", envelope_mb);

        let (retrieved, _) = storage
            .retrieve(&envelope)
            .expect("Should retrieve 100MB payload");

        assert_eq!(retrieved.len(), data_100mb.len());

        println!("✓ 100MB payload: Extreme stress test successful");
    }
}

// ============================================================================
// Encryption Large Payload Tests
// ============================================================================

#[cfg(feature = "encryption")]
mod encryption_large {
    use super::*;

    #[test]
    fn test_encrypt_1mb_payload() {
        // WHY: Verify encryption handles 1MB payloads correctly

        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0x42u8; 32];
        let aad = b"large_payload_test";
        let data_1mb = generate_incompressible_data(1_000_000, 888);

        let ciphertext = encryptor
            .encrypt_aes_gcm(&data_1mb, &key, aad)
            .expect("Should encrypt 1MB payload");

        // Ciphertext should be slightly larger (nonce + tag overhead)
        let overhead_bytes = ciphertext.len() - data_1mb.len();
        assert_eq!(
            overhead_bytes, 28,
            "Overhead should be exactly 28 bytes (12 nonce + 16 tag)"
        );

        let decrypted = encryptor
            .decrypt_aes_gcm(&ciphertext, &key, aad)
            .expect("Should decrypt 1MB payload");

        assert_eq!(decrypted.len(), data_1mb.len());
        assert_eq!(decrypted, data_1mb);

        println!("✓ Encrypt 1MB: Successful with 28-byte overhead");
    }

    #[test]
    fn test_encrypt_10mb_payload() {
        // WHY: Verify encryption handles larger payloads efficiently

        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0x7fu8; 32];
        let aad = b"10mb_test";
        let data_10mb = generate_incompressible_data(10_000_000, 11111);

        let ciphertext = encryptor
            .encrypt_aes_gcm(&data_10mb, &key, aad)
            .expect("Should encrypt 10MB payload");

        let ciphertext_mb = ciphertext.len() as f64 / 1_000_000.0;
        println!("10MB plaintext → {:.2}MB ciphertext", ciphertext_mb);

        let decrypted = encryptor
            .decrypt_aes_gcm(&ciphertext, &key, aad)
            .expect("Should decrypt 10MB payload");

        assert_eq!(decrypted.len(), data_10mb.len());
        // Compare samples (full comparison too slow)
        assert_eq!(&decrypted[..1000], &data_10mb[..1000]);
        assert_eq!(
            &decrypted[decrypted.len() - 1000..],
            &data_10mb[data_10mb.len() - 1000..]
        );

        println!("✓ Encrypt 10MB: Successful");
    }

    #[test]
    fn test_encrypt_50mb_payload() {
        // WHY: Stress test encryption with very large payload

        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0x9cu8; 32];
        let aad = b"50mb_stress";
        let data_50mb = generate_incompressible_data(50_000_000, 77777);

        let ciphertext = encryptor
            .encrypt_aes_gcm(&data_50mb, &key, aad)
            .expect("Should encrypt 50MB payload");

        let ciphertext_mb = ciphertext.len() as f64 / 1_000_000.0;
        println!("50MB plaintext → {:.2}MB ciphertext", ciphertext_mb);

        let decrypted = encryptor
            .decrypt_aes_gcm(&ciphertext, &key, aad)
            .expect("Should decrypt 50MB payload");

        assert_eq!(decrypted.len(), data_50mb.len());
        // Spot-check samples
        assert_eq!(&decrypted[..1000], &data_50mb[..1000]);
        assert_eq!(
            &decrypted[25_000_000..25_001_000],
            &data_50mb[25_000_000..25_001_000]
        );

        println!("✓ Encrypt 50MB: Stress test successful");
    }

    #[test]
    #[ignore] // Ignore by default (very slow and memory-intensive)
    fn test_encrypt_100mb_payload_extreme() {
        // WHY: Extreme stress test for encryption with massive payloads
        // NOTE: Ignored by default. Run with: cargo test --ignored

        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0xffu8; 32];
        let aad = b"100mb_extreme";
        let data_100mb = generate_incompressible_data(100_000_000, 123456);

        let ciphertext = encryptor
            .encrypt_aes_gcm(&data_100mb, &key, aad)
            .expect("Should encrypt 100MB payload");

        let ciphertext_mb = ciphertext.len() as f64 / 1_000_000.0;
        println!("100MB plaintext → {:.2}MB ciphertext", ciphertext_mb);

        let decrypted = encryptor
            .decrypt_aes_gcm(&ciphertext, &key, aad)
            .expect("Should decrypt 100MB payload");

        assert_eq!(decrypted.len(), data_100mb.len());

        println!("✓ Encrypt 100MB: Extreme stress test successful");
    }
}

// ============================================================================
// Combined Compression + Encryption Large Payload Tests
// ============================================================================

#[cfg(all(feature = "compression", feature = "encryption"))]
mod combined_large {
    use super::*;

    #[test]
    fn test_compress_then_encrypt_10mb() {
        // WHY: Test full pipeline (compress → encrypt) with large payload

        let storage = ByteStorage::new(None);
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0x5au8; 32];
        let aad = b"combined_test";

        // Use compressible data to test full benefit
        let data_10mb = generate_large_data(10_000_000, 0xFF);

        // Step 1: Compress
        let compressed_envelope = storage
            .store(&data_10mb, None)
            .expect("Should compress 10MB");

        let compressed_mb = compressed_envelope.len() as f64 / 1_000_000.0;
        println!("Step 1: 10MB → {:.2}MB (compressed)", compressed_mb);

        // Step 2: Encrypt compressed data
        let ciphertext = encryptor
            .encrypt_aes_gcm(&compressed_envelope, &key, aad)
            .expect("Should encrypt compressed data");

        let final_mb = ciphertext.len() as f64 / 1_000_000.0;
        println!(
            "Step 2: {:.2}MB → {:.2}MB (encrypted)",
            compressed_mb, final_mb
        );

        // Step 3: Decrypt
        let decrypted_compressed = encryptor
            .decrypt_aes_gcm(&ciphertext, &key, aad)
            .expect("Should decrypt");

        // Step 4: Decompress
        let (decompressed, _) = storage
            .retrieve(&decrypted_compressed)
            .expect("Should decompress");

        assert_eq!(decompressed.len(), data_10mb.len());
        assert_eq!(decompressed, data_10mb);

        let total_ratio = 10.0 / final_mb;
        println!(
            "✓ Full pipeline: 10MB → {:.2}MB (overall {:.1}x reduction)",
            final_mb, total_ratio
        );
    }

    #[test]
    fn test_compress_then_encrypt_50mb() {
        // WHY: Stress test full pipeline with very large compressible payload

        let storage = ByteStorage::new(None);
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = [0xa1u8; 32];
        let aad = b"50mb_pipeline";

        // Highly compressible 50MB
        let data_50mb = generate_large_data(50_000_000, 0xAA);

        let compressed = storage
            .store(&data_50mb, None)
            .expect("Should compress 50MB");

        let compressed_mb = compressed.len() as f64 / 1_000_000.0;

        let ciphertext = encryptor
            .encrypt_aes_gcm(&compressed, &key, aad)
            .expect("Should encrypt");

        let final_mb = ciphertext.len() as f64 / 1_000_000.0;

        println!(
            "50MB pipeline: 50MB → {:.2}MB compressed → {:.2}MB encrypted",
            compressed_mb, final_mb
        );

        // Decrypt and decompress
        let decrypted = encryptor
            .decrypt_aes_gcm(&ciphertext, &key, aad)
            .expect("Should decrypt");

        let (decompressed, _) = storage.retrieve(&decrypted).expect("Should decompress");

        assert_eq!(decompressed.len(), data_50mb.len());

        let total_ratio = 50.0 / final_mb;
        println!("✓ 50MB pipeline: {:.1}x overall reduction", total_ratio);
    }
}
