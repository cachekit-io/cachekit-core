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
        let (retrieved, _) = storage.retrieve(&stored).expect("retrieve empty must succeed");

        assert_eq!(data, retrieved.as_slice());
    }

    #[test]
    fn test_wasm32_compat_binary_payload() {
        let storage = ByteStorage::new(None);
        let data: Vec<u8> = (0u8..=255u8).collect();

        let stored = storage.store(&data, None).expect("store binary must succeed");
        let (retrieved, _) = storage.retrieve(&stored).expect("retrieve binary must succeed");

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
