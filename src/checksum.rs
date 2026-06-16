//! Standalone xxHash3-64 integrity primitive.
//!
//! Non-cryptographic corruption detection, decoupled from compression. The same
//! function backs `StorageEnvelope`'s embedded checksum, so the wire value is
//! identical whether you compute it directly or via `ByteStorage::store`.

use xxhash_rust::xxh3::xxh3_64;

/// Compute the xxHash3-64 checksum of `data`, big-endian (xxhash canonical
/// byte order — the value embedded in every `StorageEnvelope`).
///
/// Non-cryptographic: detects corruption, not tampering. For tamper-resistance
/// use AES-256-GCM (the auth tag), not this checksum. Intentionally unbounded —
/// a single-pass, allocation-free O(n) hash over caller-materialized bytes; the
/// `MAX_UNCOMPRESSED_SIZE` cap is `StorageEnvelope`'s decompression-bomb concern.
pub fn checksum(data: &[u8]) -> [u8; 8] {
    xxh3_64(data).to_be_bytes()
}

/// Verify `data` against an expected xxHash3-64 checksum.
///
/// Plain (non-constant-time) equality, consistent with the non-cryptographic
/// threat model — do NOT change to constant-time (would imply a security
/// property this primitive does not have).
pub fn verify_checksum(data: &[u8], expected: &[u8; 8]) -> bool {
    &checksum(data) == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_is_deterministic() {
        let data = b"cachekit checksum determinism vector";
        assert_eq!(checksum(data), checksum(data));
    }

    #[test]
    fn checksum_handles_empty_input() {
        assert_eq!(checksum(b""), checksum(b""));
    }

    #[test]
    fn verify_checksum_accepts_matching() {
        let data = b"payload bytes";
        assert!(verify_checksum(data, &checksum(data)));
    }

    #[test]
    fn verify_checksum_rejects_single_bit_flip() {
        let data = b"payload bytes";
        let mut corrupted = checksum(data);
        corrupted[0] ^= 0x01;
        assert!(!verify_checksum(data, &corrupted));
    }

    #[test]
    fn verify_checksum_rejects_wrong_data() {
        let expected = checksum(b"original");
        assert!(!verify_checksum(b"tampered", &expected));
    }

    #[test]
    fn checksum_known_answer_locks_endianness() {
        // Captured from checksum(b"cachekit-kat"); pins algorithm + big-endian order.
        assert_eq!(
            checksum(b"cachekit-kat"),
            [209u8, 35, 204, 155, 190, 157, 164, 177]
        );
    }
}
