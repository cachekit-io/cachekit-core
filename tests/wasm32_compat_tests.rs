//! wasm32 compatibility smoke tests.
//!
//! These tests verify core ByteStorage round-trip functionality works correctly.
//! They run on native targets and serve as a baseline before wasm32 compilation.

#[cfg(all(feature = "compression", feature = "checksum", feature = "messagepack"))]
mod byte_storage_roundtrip {
    use cachekit_core::ByteStorage;

    #[test]
    fn test_wasm32_compat_basic_roundtrip() {
        let storage = ByteStorage::new(None);
        let data = b"Hello wasm32! This is a round-trip test.";

        let stored = storage.store(data, None).expect("store must succeed");
        let (retrieved, format) = storage.retrieve(&stored).expect("retrieve must succeed");

        assert_eq!(data as &[u8], retrieved.as_slice());
        assert_eq!("msgpack", format);
    }

    #[test]
    fn test_wasm32_compat_empty_payload() {
        let storage = ByteStorage::new(None);
        let data: &[u8] = b"";

        let stored = storage.store(data, None).expect("store empty must succeed");
        let (retrieved, _) = storage
            .retrieve(&stored)
            .expect("retrieve empty must succeed");

        assert_eq!(data, retrieved.as_slice());
    }

    #[test]
    fn test_wasm32_compat_binary_payload() {
        let storage = ByteStorage::new(None);
        let data: Vec<u8> = (0u8..=255u8).collect();

        let stored = storage
            .store(&data, None)
            .expect("store binary must succeed");
        let (retrieved, _) = storage
            .retrieve(&stored)
            .expect("retrieve binary must succeed");

        assert_eq!(data, retrieved);
    }

    #[test]
    fn test_wasm32_compat_custom_format() {
        let storage = ByteStorage::new(None);
        let data = b"custom format test";

        let stored = storage
            .store(data, Some("cbor".to_string()))
            .expect("store with custom format must succeed");
        let (retrieved, format) = storage
            .retrieve(&stored)
            .expect("retrieve with custom format must succeed");

        assert_eq!(data as &[u8], retrieved.as_slice());
        assert_eq!("cbor", format);
    }
}

/// Verify that aes-gcm (wasm32 backend) produces wire-format-compatible
/// output that ring (native backend) can decrypt, and vice versa.
#[cfg(feature = "encryption")]
#[test]
fn cross_backend_wire_format_compatibility() {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce as AesGcmNonce,
    };
    use cachekit_core::ZeroKnowledgeEncryptor;

    let key = [0x42u8; 32];
    let nonce_bytes = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let plaintext = b"cross-backend wire format test";
    let aad = b"test_aad_domain";

    // Encrypt with aes-gcm (simulating wasm32 path)
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce = AesGcmNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext[..],
                aad: &aad[..],
            },
        )
        .unwrap();

    // Build wire format: nonce(12) || ciphertext || tag(16)
    let mut wire = Vec::new();
    wire.extend_from_slice(&nonce_bytes);
    wire.extend_from_slice(&ct);

    // Decrypt with ring (native path) via ZeroKnowledgeEncryptor
    let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
    let decrypted = encryptor.decrypt_aes_gcm(&wire, &key, aad).unwrap();
    assert_eq!(decrypted, plaintext);

    // Also test the reverse: ring encrypts, aes-gcm decrypts
    let ring_ciphertext = encryptor.encrypt_aes_gcm(plaintext, &key, aad).unwrap();

    // Extract nonce and ciphertext+tag from ring output
    let ring_nonce = &ring_ciphertext[..12];
    let ring_ct_tag = &ring_ciphertext[12..];

    let nonce2 = AesGcmNonce::from_slice(ring_nonce);
    let decrypted2 = cipher
        .decrypt(
            nonce2,
            Payload {
                msg: ring_ct_tag,
                aad: &aad[..],
            },
        )
        .unwrap();
    assert_eq!(decrypted2, plaintext);
}
