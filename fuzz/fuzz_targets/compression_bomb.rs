#![no_main]

//! Decompression-bound oracle for `StorageEnvelope::extract` and
//! `ByteStorage::retrieve`.
//!
//! Every input yields exactly one expected result, computed independently of
//! the crate, and both calls must return it. The size classes each build an
//! envelope that only one of the three bound checks rejects, so deleting or
//! weakening any one of them makes this target fail.

use arbitrary::Arbitrary;
use cachekit_core::byte_storage::{ByteStorage, ByteStorageError, StorageEnvelope};
use libfuzzer_sys::fuzz_target;

// Pinned as literals, not read from the crate: changing a limit must fail here.
const MAX_COMPRESSED_SIZE: usize = 512 * 1024 * 1024;
const MAX_UNCOMPRESSED_SIZE: usize = 512 * 1024 * 1024;
const MAX_COMPRESSION_RATIO: u64 = 1000;

/// Smallest compressed length whose 1000:1 allowance exceeds the
/// `original_size` cap, so the cap alone can reject a declared size.
const MIN_LEN_FOR_ORIGINAL_CAP: usize = 536_871;

#[derive(Arbitrary, Debug)]
enum Case {
    /// Arbitrary bytes and declared size: malformed LZ4, small ratios.
    Raw {
        compressed_data: Vec<u8>,
        original_size: u32,
        checksum: [u8; 8],
        format: String,
    },
    /// A valid stream from `StorageEnvelope::new`, then its declared size
    /// replaced and/or its checksum altered.
    Valid {
        data: Vec<u8>,
        declared_size: Option<u32>,
        checksum_xor: [u8; 8],
    },
    /// `compressed_data.len()` over its cap; nothing else rejects it.
    CompressedOverCap {
        extra: u8,
        original_size: u16,
        fill: u8,
    },
    /// `compressed_data.len()` exactly at its cap: `extract` gets past the
    /// bound, but the serialized envelope exceeds `retrieve`'s length check.
    CompressedAtCap { original_size: u16, fill: u8 },
    /// `original_size` in (cap, 1000 × len]; nothing else rejects it.
    OriginalOverCap { extra_len: u16, size: u32, fill: u8 },
    /// Both sizes within their caps, ratio over 1000:1.
    RatioOver { len: u16, excess: u32, fill: u8 },
}

/// The bound, in `extract`'s check order.
fn expected_bound(compressed_len: usize, original_size: u32) -> Result<(), ByteStorageError> {
    if compressed_len > MAX_COMPRESSED_SIZE || original_size as usize > MAX_UNCOMPRESSED_SIZE {
        return Err(ByteStorageError::InputTooLarge);
    }
    if compressed_len == 0 || original_size as u64 > MAX_COMPRESSION_RATIO * compressed_len as u64 {
        return Err(ByteStorageError::DecompressionBomb);
    }
    Ok(())
}

/// Expected `extract` result for an envelope whose payload is not known.
fn expected_extract(envelope: &StorageEnvelope) -> Result<Vec<u8>, ByteStorageError> {
    expected_bound(envelope.compressed_data.len(), envelope.original_size)?;
    let size = envelope.original_size as usize;
    let out = lz4_flex::decompress(&envelope.compressed_data, size)
        .map_err(|_| ByteStorageError::DecompressionFailed)?;
    if cachekit_core::checksum(&out) != envelope.checksum {
        return Err(ByteStorageError::ChecksumMismatch);
    }
    if out.len() != size {
        return Err(ByteStorageError::SizeValidationFailed);
    }
    Ok(out)
}

/// Expected `extract` result for a valid stream of `data` whose declared size
/// and checksum were then changed. `lz4_flex::decompress` fails when the
/// declared size is too small and returns only the decoded bytes when it is
/// too large, so the checksum still matches and the size check fires.
fn expected_valid(
    data: &[u8],
    envelope: &StorageEnvelope,
    checksum_altered: bool,
) -> Result<Vec<u8>, ByteStorageError> {
    expected_bound(envelope.compressed_data.len(), envelope.original_size)?;
    let declared = envelope.original_size as usize;
    if declared < data.len() {
        return Err(ByteStorageError::DecompressionFailed);
    }
    if checksum_altered {
        return Err(ByteStorageError::ChecksumMismatch);
    }
    if declared > data.len() {
        return Err(ByteStorageError::SizeValidationFailed);
    }
    Ok(data.to_vec())
}

/// Debug form that never prints a payload (they reach 512 MiB).
fn describe<T>(result: &Result<T, ByteStorageError>) -> String {
    match result {
        Ok(_) => "Ok(..)".to_string(),
        Err(e) => format!("Err({e:?})"),
    }
}

fn assert_outcome(
    storage: &ByteStorage,
    envelope: &StorageEnvelope,
    expected: Result<Vec<u8>, ByteStorageError>,
) {
    let context = format!(
        "compressed_len={} original_size={}",
        envelope.compressed_data.len(),
        envelope.original_size
    );

    let extracted = envelope.extract();
    assert!(
        extracted == expected,
        "extract: expected {}, got {} ({context})",
        describe(&expected),
        describe(&extracted)
    );

    let bytes = rmp_serde::to_vec(envelope).expect("envelope serializes");
    let expected = if bytes.len() > MAX_COMPRESSED_SIZE {
        Err(ByteStorageError::InputTooLarge)
    } else {
        expected.map(|data| (data, envelope.format.clone()))
    };
    let retrieved = storage.retrieve(&bytes);
    assert!(
        retrieved == expected,
        "retrieve: expected {}, got {} ({context}, envelope_len={})",
        describe(&expected),
        describe(&retrieved),
        bytes.len()
    );
}

fn envelope(compressed_data: Vec<u8>, original_size: u32) -> StorageEnvelope {
    StorageEnvelope {
        compressed_data,
        checksum: [0u8; 8],
        original_size,
        format: "fuzz".to_string(),
    }
}

fuzz_target!(|case: Case| {
    let storage = ByteStorage::new(Some("fuzz".to_string()));

    match case {
        Case::Raw {
            compressed_data,
            original_size,
            checksum,
            format,
        } => {
            let envelope = StorageEnvelope {
                compressed_data,
                checksum,
                original_size,
                format,
            };
            let expected = expected_extract(&envelope);
            assert_outcome(&storage, &envelope, expected);
        }
        Case::Valid {
            data,
            declared_size,
            checksum_xor,
        } => {
            let mut envelope =
                StorageEnvelope::new(&data, "fuzz".to_string()).expect("small input compresses");
            if let Some(size) = declared_size {
                envelope.original_size = size;
            }
            for (byte, xor) in envelope.checksum.iter_mut().zip(checksum_xor) {
                *byte ^= xor;
            }
            let expected = expected_valid(&data, &envelope, checksum_xor != [0u8; 8]);
            assert_outcome(&storage, &envelope, expected);
        }
        Case::CompressedOverCap {
            extra,
            original_size,
            fill,
        } => {
            let len = MAX_COMPRESSED_SIZE + 1 + extra as usize;
            let envelope = envelope(vec![fill; len], original_size as u32);
            assert_outcome(&storage, &envelope, Err(ByteStorageError::InputTooLarge));
        }
        Case::CompressedAtCap {
            original_size,
            fill,
        } => {
            let envelope = envelope(vec![fill; MAX_COMPRESSED_SIZE], original_size as u32);
            let expected = expected_extract(&envelope);
            assert_outcome(&storage, &envelope, expected);
        }
        Case::OriginalOverCap {
            extra_len,
            size,
            fill,
        } => {
            let len = MIN_LEN_FOR_ORIGINAL_CAP + extra_len as usize;
            let allowance = (MAX_COMPRESSION_RATIO * len as u64).min(u32::MAX as u64);
            let span = allowance - MAX_UNCOMPRESSED_SIZE as u64;
            let original_size = MAX_UNCOMPRESSED_SIZE as u64 + 1 + size as u64 % span;
            let envelope = envelope(vec![fill; len], original_size as u32);
            assert_outcome(&storage, &envelope, Err(ByteStorageError::InputTooLarge));
        }
        Case::RatioOver { len, excess, fill } => {
            let allowance = MAX_COMPRESSION_RATIO * len as u64;
            let span = MAX_UNCOMPRESSED_SIZE as u64 - allowance;
            let original_size = allowance + 1 + excess as u64 % span;
            let envelope = envelope(vec![fill; len as usize], original_size as u32);
            assert_outcome(
                &storage,
                &envelope,
                Err(ByteStorageError::DecompressionBomb),
            );
        }
    }
});
