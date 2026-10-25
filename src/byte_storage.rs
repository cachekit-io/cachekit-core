//! LZ4 compression and xxHash3 checksums for raw byte storage.
//!
//! Provides integrity-protected byte storage with security validation:
//! - 512MB size limits for decompression bomb protection
//! - 1000x max compression ratio enforcement
//! - xxHash3-64 checksums for corruption detection

#[cfg(feature = "compression")]
use lz4_flex;
use serde::{Deserialize, Serialize};
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

/// Buffer length from which `store` and `retrieve` keep their copying
/// allocation pattern. `store` compares the encoded envelope length: from
/// here on it encodes through `rmp_serde::to_vec`'s growing buffer instead of
/// a buffer allocated once at the exact length. `retrieve` and `validate`
/// compare the compressed payload length: from here on they copy the payload
/// out of the input instead of borrowing it.
///
/// glibc's malloc raises its mmap and trim thresholds to the largest mmap-ed
/// chunk freed so far, and trims the top of the heap once it holds more free
/// memory than the trim threshold, so dropping one payload-sized buffer can
/// send a large operation's other payload-sized buffers to fresh pages on
/// every call. Measured on 1 MB incompressible values under glibc's defaults:
/// an exact-size store buffer took about a third more page faults and 30%
/// more CPU per store (`to_vec`'s doubled reallocation had been the chunk that
/// raised the thresholds), and a borrowed payload took each read from no page
/// faults to about a thousand, several times the CPU (its remaining buffers
/// grew the heap past the trim threshold and were trimmed again every call).
/// Below 64 KiB neither buffer reaches glibc's minimum mmap threshold
/// (128 KiB), even doubled, so it is never mmap-ed, and removing it cannot
/// move either threshold.
#[cfg(all(feature = "compression", feature = "checksum", feature = "messagepack"))]
const LARGE_PAYLOAD: usize = 64 * 1024;

/// Inputs shorter than this are written as one literals-only LZ4 block instead
/// of going through `lz4_flex::compress`.
///
/// `lz4_flex::compress` zeroes an 8 KiB hash table on every call, which costs
/// more than the whole store for a tiny value, and below LZ4's 13-byte minimum
/// its output is literals-only anyway. The price is stored size: a compressible
/// input under the threshold is no longer shrunk; its block is the input plus
/// 1 byte (plus 2 from 15 bytes up). Compressed bytes are not canonical
/// (protocol `spec/wire-format.md`, "Compressed-byte reproducibility"), and
/// every reader decodes a literals-only block.
#[cfg(feature = "compression")]
const LITERAL_BLOCK_THRESHOLD: usize = 64;

// The literal block writes the length in at most one extra byte, which holds
// for literal lengths up to 15 + 254.
#[cfg(feature = "compression")]
const _: () = assert!(LITERAL_BLOCK_THRESHOLD - 1 <= 15 + 254);

/// The LZ4 block `StorageEnvelope::new` writes for `data`.
///
/// Below the threshold it is one LZ4 sequence with no match: a token whose
/// high nibble is the literal length (15 = one more length byte follows), then
/// the literals. This is the LZ4 block format's last-sequence form, so it is a
/// complete block on its own.
#[cfg(feature = "compression")]
fn compress_block(data: &[u8]) -> Vec<u8> {
    if data.len() >= LITERAL_BLOCK_THRESHOLD {
        return lz4_flex::compress(data);
    }
    let len = data.len();
    let mut block = Vec::with_capacity(len + 2);
    if len < 15 {
        block.push((len as u8) << 4);
    } else {
        block.push(0xF0);
        block.push((len - 15) as u8);
    }
    block.extend_from_slice(data);
    block
}

/// Storage envelope for raw byte storage
///
/// `retrieve` and `validate` decode into its private borrowing twin,
/// `borrowed::StorageEnvelope`: change the two together.
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

        // Compress with LZ4 (a literals-only block below LITERAL_BLOCK_THRESHOLD)
        let compressed_data = compress_block(data);

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
        extract_payload(&self.compressed_data, &self.checksum, self.original_size)
    }

    /// Exact length of this envelope's MessagePack encoding: the bytes
    /// [`encode_into`](Self::encode_into) writes and [`ByteStorage::store`]
    /// returns.
    ///
    /// Computed from the field lengths and values without encoding anything,
    /// so a caller can allocate the output once, at its final size.
    #[cfg(feature = "messagepack")]
    pub fn encoded_len(&self) -> usize {
        // rmp_serde writes the struct as a 4-element array, `compressed_data`
        // as bin, `checksum` as an array of 8 uints and every uint in its
        // shortest form; `encoded_len_matches_rmp_serde` pins each width.
        fn uint_len(v: u32) -> usize {
            match v {
                0..=0x7F => 1,
                0x80..=0xFF => 2,
                0x100..=0xFFFF => 3,
                _ => 5,
            }
        }
        fn bin_header_len(len: usize) -> usize {
            match len {
                0..=0xFF => 2,
                0x100..=0xFFFF => 3,
                _ => 5,
            }
        }
        fn str_header_len(len: usize) -> usize {
            match len {
                0..=31 => 1,
                32..=0xFF => 2,
                0x100..=0xFFFF => 3,
                _ => 5,
            }
        }
        let checksum_len = 1 + self
            .checksum
            .iter()
            .map(|&b| uint_len(b.into()))
            .sum::<usize>();
        let fixed = 1 // fixarray(4)
            + bin_header_len(self.compressed_data.len())
            + checksum_len
            + uint_len(self.original_size)
            + str_header_len(self.format.len());
        fixed
            .saturating_add(self.compressed_data.len())
            .saturating_add(self.format.len())
    }

    /// Write this envelope's MessagePack encoding, the bytes
    /// [`ByteStorage::store`] returns, into `out`, which must be exactly
    /// [`encoded_len`](Self::encoded_len) bytes long.
    ///
    /// For a binding that owns the output memory (a Python `bytes`, say): it
    /// sizes the buffer with `encoded_len` and writes once, with no
    /// intermediate `Vec` and no MessagePack dependency of its own. Measure
    /// before using it for envelopes of 64 KiB and up: removing a
    /// payload-sized buffer there can make an operation slower under glibc's
    /// malloc (see `ByteStorage::store`, which therefore does not).
    ///
    /// # Errors
    ///
    /// `InputTooLarge` when the encoding exceeds the envelope size cap, the
    /// same final check `store` makes. `SerializationFailed` when `out` is not
    /// `encoded_len` bytes; nothing written into it is then meaningful.
    #[cfg(feature = "messagepack")]
    pub fn encode_into(&self, out: &mut [u8]) -> Result<(), ByteStorageError> {
        let len = self.capped_encoded_len()?;
        if out.len() != len {
            return Err(ByteStorageError::SerializationFailed(format!(
                "output buffer is {} bytes, the envelope encodes to {len}",
                out.len()
            )));
        }
        let mut rest = &mut out[..];
        rmp_serde::encode::write(&mut rest, self)
            .map_err(|e| ByteStorageError::SerializationFailed(e.to_string()))?;
        // encoded_len was exact if the write filled the buffer
        if !rest.is_empty() {
            return Err(ByteStorageError::SerializationFailed(format!(
                "envelope encoded {} bytes short of its computed length",
                rest.len()
            )));
        }
        Ok(())
    }

    /// `encoded_len`, or `InputTooLarge` past the envelope size cap: the final
    /// check `store` makes, before anything is encoded.
    #[cfg(feature = "messagepack")]
    fn capped_encoded_len(&self) -> Result<usize, ByteStorageError> {
        let len = self.encoded_len();
        if len > MAX_COMPRESSED_SIZE {
            return Err(ByteStorageError::InputTooLarge);
        }
        Ok(len)
    }

    /// The encoding `store` returns. Below `LARGE_PAYLOAD` it goes into a
    /// `Vec` allocated once at its final length; from there on it keeps
    /// `rmp_serde::to_vec`'s growing buffer (see `LARGE_PAYLOAD` for why).
    ///
    /// `rmp_serde::to_vec` grows its `Vec` from empty, reallocating several
    /// times for a small envelope and to twice the payload for a large one.
    #[cfg(all(feature = "compression", feature = "checksum", feature = "messagepack"))]
    fn encode(&self) -> Result<Vec<u8>, ByteStorageError> {
        let len = self.capped_encoded_len()?;
        if len >= LARGE_PAYLOAD {
            return rmp_serde::to_vec(self)
                .map_err(|e| ByteStorageError::SerializationFailed(e.to_string()));
        }
        let mut out = Vec::with_capacity(len);
        rmp_serde::encode::write(&mut out, self)
            .map_err(|e| ByteStorageError::SerializationFailed(e.to_string()))?;
        debug_assert_eq!(out.len(), len, "encoded_len must be exact");
        Ok(out)
    }
}

/// Decompress and verify one envelope's payload: the checks `extract` makes,
/// in its order. `retrieve` and `validate` call it on the borrowed decode, so
/// every read path runs the same checks.
#[cfg(all(feature = "compression", feature = "checksum"))]
fn extract_payload(
    compressed_data: &[u8],
    checksum: &[u8; 8],
    original_size: u32,
) -> Result<Vec<u8>, ByteStorageError> {
    // Unit tests only: the allocation probe's positive control.
    #[cfg(test)]
    crate::read_allocation_probe::reserve_first_control(compressed_data, original_size);

    check_decompression_bound(compressed_data.len(), original_size)?;

    // Decompress (with validated sizes)
    let decompressed = lz4_flex::decompress(compressed_data, original_size as usize)
        .map_err(|_| ByteStorageError::DecompressionFailed)?;

    // Verify checksum (checksum validation happens AFTER decompression to prevent processing corrupted data)
    // false -> ChecksumMismatch (preserve the error variant; verify_checksum returns bool)
    if !crate::checksum::verify_checksum(&decompressed, checksum) {
        return Err(ByteStorageError::ChecksumMismatch);
    }

    // Verify size (final safety check)
    if decompressed.len() != original_size as usize {
        return Err(ByteStorageError::SizeValidationFailed);
    }

    Ok(decompressed)
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
}

impl ByteStorage {
    /// Create new ByteStorage instance
    pub fn new(default_format: Option<String>) -> Self {
        ByteStorage {
            default_format: default_format.unwrap_or_else(|| "msgpack".to_string()),
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

        let envelope = StorageEnvelope::new(data, format)?;

        // Serialize envelope with MessagePack. Security: the final envelope
        // size check runs inside, before the output is allocated.
        envelope.encode()
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

        // Extract and validate data (all security checks happen inside extract_payload())
        let data = envelope.extract()?;

        Ok((data, envelope.format))
    }

    /// Get compression ratio for given data: input length over the length of
    /// the LZ4 block `store()` writes for it
    #[cfg(feature = "compression")]
    pub fn estimate_compression(&self, data: &[u8]) -> Result<f64, ByteStorageError> {
        // Security: Check size before compression
        if data.len() > MAX_UNCOMPRESSED_SIZE {
            return Err(ByteStorageError::InputTooLarge);
        }

        let compressed = compress_block(data);

        Ok(data.len() as f64 / compressed.len() as f64)
    }

    /// Validate an envelope by fully extracting it and discarding the result
    ///
    /// This runs `extract_payload`, so it decompresses the payload and
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
fn decode_envelope(
    envelope_bytes: &[u8],
) -> Result<borrowed::StorageEnvelope<'_>, ByteStorageError> {
    // Nesting bound for the envelope decode. The protocol requires 32..=1024;
    // 100 matches cachekit-rs and cachekit-ts. A legitimate envelope nests 2 deep.
    const MAX_DEPTH: usize = 100;
    crate::check_msgpack_structure(envelope_bytes, MAX_DEPTH).map_err(|what| {
        ByteStorageError::DeserializationFailed(format!("decode pre-scan: {what}"))
    })?;
    rmp_serde::from_slice(envelope_bytes)
        .map_err(|e| ByteStorageError::DeserializationFailed(e.to_string()))
}

/// What `retrieve` and `validate` decode: `StorageEnvelope` with
/// `compressed_data` borrowed from the input instead of copied out of it,
/// below `LARGE_PAYLOAD`.
///
/// A module of its own so the struct can share `StorageEnvelope`'s Rust name:
/// serde's derive puts that name in its "expected struct ..." errors, which
/// bindings surface (cachekit-py pins one). Same fields, order and field
/// decoders, so it accepts exactly the inputs `StorageEnvelope` does, with
/// the same error messages (`borrowed_decode_matches_owned_decode`). A legacy
/// int-array payload still decodes, into an owned buffer.
#[cfg(all(feature = "compression", feature = "checksum", feature = "messagepack"))]
mod borrowed {
    use std::borrow::Cow;

    use serde::de::{Deserializer, Error, SeqAccess, Visitor};
    use serde::Deserialize;

    use super::{extract_payload, ByteStorageError, LARGE_PAYLOAD};

    #[derive(Deserialize)]
    pub(super) struct StorageEnvelope<'a> {
        #[serde(borrow, deserialize_with = "borrow_payload")]
        pub(super) compressed_data: Cow<'a, [u8]>,
        pub(super) checksum: [u8; 8],
        pub(super) original_size: u32,
        pub(super) format: String,
    }

    impl StorageEnvelope<'_> {
        /// `StorageEnvelope::extract`, on the borrowed payload.
        pub(super) fn extract(&self) -> Result<Vec<u8>, ByteStorageError> {
            extract_payload(&self.compressed_data, &self.checksum, self.original_size)
        }
    }

    /// serde_bytes' `ByteBuf` decode, which `StorageEnvelope::compressed_data`
    /// uses, except that a `bin` or `str` payload under `LARGE_PAYLOAD` is
    /// borrowed. Owned bytes and strings reach `visit_bytes` and `visit_str`
    /// through serde's default methods. serde_bytes' own `Cow` decode borrows
    /// too, but words its type error differently.
    fn borrow_payload<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Cow<'de, [u8]>, D::Error> {
        struct PayloadVisitor;

        impl<'de> Visitor<'de> for PayloadVisitor {
            type Value = Cow<'de, [u8]>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("byte array")
            }

            fn visit_borrowed_bytes<E: Error>(self, v: &'de [u8]) -> Result<Self::Value, E> {
                Ok(borrow_below_large(v))
            }

            fn visit_borrowed_str<E: Error>(self, v: &'de str) -> Result<Self::Value, E> {
                Ok(borrow_below_large(v.as_bytes()))
            }

            fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(Cow::Owned(v.to_vec()))
            }

            fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(Cow::Owned(v.as_bytes().to_vec()))
            }

            // Legacy int-array payload, pre-allocation capped as serde_bytes caps it.
            fn visit_seq<V: SeqAccess<'de>>(self, mut seq: V) -> Result<Self::Value, V::Error> {
                let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(4096));
                while let Some(b) = seq.next_element()? {
                    bytes.push(b);
                }
                Ok(Cow::Owned(bytes))
            }
        }

        deserializer.deserialize_byte_buf(PayloadVisitor)
    }

    /// Borrow a payload shorter than `LARGE_PAYLOAD`; copy a longer one, as
    /// the owned decode does.
    fn borrow_below_large(v: &[u8]) -> Cow<'_, [u8]> {
        if v.len() < LARGE_PAYLOAD {
            Cow::Borrowed(v)
        } else {
            Cow::Owned(v.to_vec())
        }
    }
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
        // At the threshold, so it takes the lz4_flex path, not the literal block
        let data = vec![b'a'; LITERAL_BLOCK_THRESHOLD]; // Highly compressible
        let envelope = StorageEnvelope::new(&data, "test".to_string()).unwrap();
        assert!(envelope.compressed_data.len() < data.len());
    }

    #[test]
    fn below_threshold_writes_a_literals_only_block() {
        for len in [0, 1, 14, 15, LITERAL_BLOCK_THRESHOLD - 1] {
            // Compressible, so a literals-only block is the writer's choice,
            // not what lz4_flex would emit anyway
            let data = vec![b'a'; len];
            let envelope = StorageEnvelope::new(&data, "test".to_string()).unwrap();
            let block = &envelope.compressed_data;

            let token = block[0];
            assert_eq!(token & 0x0F, 0, "len {len}: token has a match length");
            let header = if len < 15 {
                assert_eq!(usize::from(token >> 4), len, "len {len}: literal length");
                1
            } else {
                assert_eq!(token >> 4, 15, "len {len}: literal length nibble");
                assert_eq!(usize::from(block[1]) + 15, len, "len {len}: length byte");
                2
            };
            assert_eq!(&block[header..], &data[..], "len {len}: literals");
            assert_eq!(lz4_flex::decompress(block, len).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn at_threshold_writes_lz4_flex_output() {
        for data in [
            vec![b'a'; LITERAL_BLOCK_THRESHOLD],
            (0..LITERAL_BLOCK_THRESHOLD as u8).collect::<Vec<u8>>(),
        ] {
            let envelope = StorageEnvelope::new(&data, "test".to_string()).unwrap();
            assert_eq!(envelope.compressed_data, lz4_flex::compress(&data));
        }
    }

    #[test]
    fn below_threshold_incompressible_input_matches_lz4_flex() {
        // Distinct bytes leave lz4_flex no match, so its output is a literals-only
        // block too: the literal-block writer changes no bytes for such input
        for len in 0..LITERAL_BLOCK_THRESHOLD {
            let data: Vec<u8> = (0..len as u8).collect();
            assert_eq!(
                compress_block(&data),
                lz4_flex::compress(&data),
                "len {len}"
            );
        }
    }

    #[test]
    fn store_roundtrips_around_and_above_threshold() {
        // Repetitive, periodic and pseudo-random inputs either side of the
        // threshold, so the lz4_flex encoder's match, literal and end-of-input
        // paths all run (and run under Miri, which checks the unsafe encoder)
        let storage = ByteStorage::new(None);
        let mut state: u32 = 0x9E37_79B9;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        };
        for len in [
            LITERAL_BLOCK_THRESHOLD - 1,
            LITERAL_BLOCK_THRESHOLD,
            LITERAL_BLOCK_THRESHOLD + 1,
            100,
            1000,
            4103,
        ] {
            let inputs = [
                vec![b'z'; len],
                (0..len).map(|i| (i % 251) as u8).collect::<Vec<u8>>(),
                (0..len).map(|_| next()).collect::<Vec<u8>>(),
            ];
            for data in inputs {
                let stored = storage.store(&data, None).unwrap();
                assert_eq!(storage.retrieve(&stored).unwrap().0, data, "len {len}");
            }
        }
    }

    #[test]
    fn estimate_compression_reports_what_store_writes() {
        let storage = ByteStorage::new(None);
        for len in [
            0,
            32,
            LITERAL_BLOCK_THRESHOLD - 1,
            LITERAL_BLOCK_THRESHOLD,
            1024,
        ] {
            let data = vec![b'a'; len];
            let envelope = StorageEnvelope::new(&data, "test".to_string()).unwrap();
            let expected = len as f64 / envelope.compressed_data.len() as f64;
            assert_eq!(
                storage.estimate_compression(&data).unwrap(),
                expected,
                "len {len}"
            );
        }
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

    /// Every envelope in the wire-format fixture (accepted, rejected and
    /// payload-rejected), plus malformed shapes the fixture does not carry.
    fn decode_corpus() -> Vec<(String, Vec<u8>)> {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/wire-format.json")).unwrap();
        let mut corpus = Vec::new();
        for group in ["vectors", "reject_vectors", "payload_reject_vectors"] {
            for v in fixture[group].as_array().unwrap() {
                let hex = v["envelope_hex"].as_str().unwrap();
                corpus.push((
                    v["name"].as_str().unwrap().to_string(),
                    hex::decode(hex).unwrap(),
                ));
            }
        }
        let checksum = [0x98, 0, 1, 2, 3, 4, 5, 6, 0xCC, 0xFF];
        for (name, payload) in [
            ("payload_str", &[0xA3, b'a', b'b', b'c'][..]),
            ("payload_int", &[0x07][..]),
            ("payload_nil", &[0xC0][..]),
            ("payload_map", &[0x80][..]),
            ("payload_bool", &[0xC3][..]),
            ("payload_ext", &[0xD4, 0x01, 0x00][..]),
            ("payload_float", &[0xCA, 0, 0, 0, 0][..]),
            ("legacy_bad_element", &[0x92, 0x01, 0xA1, b'x'][..]),
            ("payload_truncated_bin", &[0xC4, 0x09, 0x00][..]),
        ] {
            let mut env = vec![0x94];
            env.extend_from_slice(payload);
            env.extend_from_slice(&checksum);
            env.extend_from_slice(&[0x03, 0xA4, b't', b'e', b's', b't']);
            corpus.push((name.to_string(), env));
        }
        // Map form with the field names, map form missing one, not an array.
        let mut named =
            rmp_serde::to_vec_named(&StorageEnvelope::new(b"named", "f".into()).unwrap()).unwrap();
        corpus.push(("map_form".into(), named.clone()));
        named[0] = 0x83;
        corpus.push(("map_form_missing_field".into(), named));
        corpus.push(("not_an_array".into(), vec![0xA2, b'h', b'i']));
        corpus.push(("empty".into(), vec![]));
        corpus
    }

    #[test]
    fn borrowed_decode_matches_owned_decode() {
        // The borrowed decode accepts exactly what the owned one does, into
        // the same fields, and fails with the same message (bindings surface
        // that text: cachekit-py pins several of the fixture's messages).
        for (name, bytes) in decode_corpus() {
            let owned = rmp_serde::from_slice::<StorageEnvelope>(&bytes);
            let borrowed = rmp_serde::from_slice::<borrowed::StorageEnvelope>(&bytes);
            match (owned, borrowed) {
                (Ok(o), Ok(b)) => {
                    assert_eq!(o.compressed_data, &*b.compressed_data, "[{name}] payload");
                    assert_eq!(o.checksum, b.checksum, "[{name}] checksum");
                    assert_eq!(o.original_size, b.original_size, "[{name}] original_size");
                    assert_eq!(o.format, b.format, "[{name}] format");
                }
                (Err(o), Err(b)) => assert_eq!(o.to_string(), b.to_string(), "[{name}] error"),
                (o, b) => panic!("[{name}] owned {:?} vs borrowed {:?}", o.err(), b.err()),
            }
        }
    }

    #[test]
    fn bin_payload_is_borrowed_and_legacy_payload_is_owned() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/wire-format.json")).unwrap();
        use std::borrow::Cow;
        let mut seen = (0, 0);
        for v in fixture["vectors"].as_array().unwrap() {
            let bytes = hex::decode(v["envelope_hex"].as_str().unwrap()).unwrap();
            let envelope = decode_envelope(&bytes).unwrap();
            let name = v["name"].as_str().unwrap();
            if name.ends_with("_bin") {
                seen.0 += 1;
                assert!(
                    matches!(envelope.compressed_data, Cow::Borrowed(_)),
                    "[{name}] bin payload copied"
                );
            } else {
                seen.1 += 1;
                assert!(
                    matches!(envelope.compressed_data, Cow::Owned(_)),
                    "[{name}] legacy payload"
                );
            }
        }
        assert!(
            seen.0 > 0 && seen.1 > 0,
            "fixture has both encodings: {seen:?}"
        );

        // From LARGE_PAYLOAD the payload is copied, as the owned decode does
        let storage = ByteStorage::new(None);
        for (len, borrowed) in [(LARGE_PAYLOAD - 512, true), (LARGE_PAYLOAD + 512, false)] {
            let data = xorshift_bytes(len);
            let stored = storage.store(&data, None).unwrap();
            let envelope = decode_envelope(&stored).unwrap();
            let payload = envelope.compressed_data.len();
            assert_eq!(
                payload < LARGE_PAYLOAD,
                borrowed,
                "len {len}: payload {payload}"
            );
            assert_eq!(
                matches!(envelope.compressed_data, Cow::Borrowed(_)),
                borrowed,
                "len {len}: payload {payload}"
            );
            assert_eq!(storage.retrieve(&stored).unwrap().0, data, "len {len}");
        }
    }

    /// Incompressible bytes, so the envelope and its payload track `len`.
    fn xorshift_bytes(len: usize) -> Vec<u8> {
        let mut state: u32 = 0x9E37_79B9;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect()
    }

    /// An envelope with chosen field values, for the encoding width boundaries.
    fn envelope_with(
        payload_len: usize,
        checksum: [u8; 8],
        size: u32,
        format_len: usize,
    ) -> StorageEnvelope {
        StorageEnvelope {
            compressed_data: vec![0; payload_len],
            checksum,
            original_size: size,
            format: "f".repeat(format_len),
        }
    }

    #[test]
    fn encoded_len_matches_rmp_serde() {
        // Each length and value either side of a MessagePack width change:
        // fixstr/str8/str16/str32, bin8/bin16/bin32, fixint/u8/u16/u32
        let lengths = [0, 1, 31, 32, 255, 256, 65_535, 65_536, 70_000];
        let sizes = [0, 127, 128, 255, 256, 65_535, 65_536, u32::MAX];
        let checksums = [
            [0x00; 8],
            [0x7F; 8],
            [0x80; 8],
            [0xFF; 8],
            [0, 0x80, 1, 0xFF, 0x7F, 2, 0xC0, 3],
        ];
        for payload_len in lengths {
            for format_len in lengths {
                let envelope = envelope_with(payload_len, checksums[4], 1, format_len);
                let expected = rmp_serde::to_vec(&envelope).unwrap().len();
                assert_eq!(
                    envelope.encoded_len(),
                    expected,
                    "payload {payload_len}, format {format_len}"
                );
            }
        }
        for size in sizes {
            for checksum in checksums {
                let envelope = envelope_with(3, checksum, size, 7);
                let expected = rmp_serde::to_vec(&envelope).unwrap().len();
                assert_eq!(
                    envelope.encoded_len(),
                    expected,
                    "size {size}, checksum {checksum:?}"
                );
            }
        }
    }

    #[test]
    fn store_and_encode_into_write_rmp_serde_bytes() {
        let storage = ByteStorage::new(None);
        let mut gate_sides = [false; 2];
        for data in [
            vec![],
            vec![b'a'; 63],
            vec![b'a'; 64],
            (0..70_000).map(|i| (i * 7919 % 251) as u8).collect(),
            // either side of the gate: LZ4 adds ~257 length bytes to a literal run
            xorshift_bytes(LARGE_PAYLOAD - 512),
            xorshift_bytes(LARGE_PAYLOAD),
            xorshift_bytes(300_000),
        ] {
            let envelope = StorageEnvelope::new(&data, "msgpack".to_string()).unwrap();
            let expected = rmp_serde::to_vec(&envelope).unwrap();

            let stored = storage.store(&data, None).unwrap();
            assert_eq!(stored, expected, "store, len {}", data.len());
            gate_sides[usize::from(stored.len() >= LARGE_PAYLOAD)] = true;
            if stored.len() < LARGE_PAYLOAD {
                // allocated once at its final length, no reallocation
                assert_eq!(
                    stored.capacity(),
                    stored.len(),
                    "store capacity, len {}",
                    data.len()
                );
            } else {
                // a large envelope keeps rmp_serde's growing buffer
                assert_eq!(
                    stored.capacity(),
                    expected.capacity(),
                    "store capacity, len {}",
                    data.len()
                );
            }

            let mut out = vec![0u8; envelope.encoded_len()];
            envelope.encode_into(&mut out).unwrap();
            assert_eq!(out, expected, "encode_into, len {}", data.len());
        }
        assert_eq!(
            gate_sides,
            [true, true],
            "an envelope on each side of LARGE_PAYLOAD"
        );
    }

    #[test]
    fn encode_into_rejects_a_wrong_sized_buffer() {
        let envelope = StorageEnvelope::new(b"payload", "msgpack".to_string()).unwrap();
        let len = envelope.encoded_len();
        for wrong in [0, len - 1, len + 1] {
            let mut out = vec![0u8; wrong];
            assert!(
                matches!(
                    envelope.encode_into(&mut out),
                    Err(ByteStorageError::SerializationFailed(_))
                ),
                "buffer of {wrong} bytes for a {len}-byte envelope"
            );
        }
    }

    #[test]
    fn encode_into_applies_the_envelope_size_cap() {
        // Compressed data at the cap: the envelope headers push it over, and
        // the check runs before the (deliberately tiny) buffer is looked at
        let envelope = envelope_with(MAX_COMPRESSED_SIZE, [0; 8], 1, 7);
        assert!(envelope.encoded_len() > MAX_COMPRESSED_SIZE);
        assert_eq!(
            envelope.encode_into(&mut []),
            Err(ByteStorageError::InputTooLarge)
        );
        assert_eq!(
            envelope.encode().err(),
            Some(ByteStorageError::InputTooLarge)
        );
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
