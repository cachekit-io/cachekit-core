//! Structural pre-scan for untrusted MessagePack.
//!
//! `ByteStorage::retrieve` runs it before the envelope decode; it is exported
//! for SDK bindings that decode untrusted MessagePack themselves. The bounds are
//! `spec/interop-mode.md` → Decode bounds, pinned by
//! `tests/vectors/decode-bounds.json`.

/// Why [`check_msgpack_structure`] rejected its input.
///
/// `Display` is the bare reason with no prefix (for example
/// `nests deeper than 100 levels`), so each caller adds its own. The wording is
/// stable within a minor version: callers may match on its leading words.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct MsgpackStructureError(String);

fn reject(reason: impl Into<String>) -> MsgpackStructureError {
    MsgpackStructureError(reason.into())
}

/// Checks that `bytes` hold one MessagePack document whose declared structure
/// the input can actually back, before any decoder sees them.
///
/// A header-only walk: str/bin/ext payloads are skipped by offset, never read,
/// and nothing is decoded. It keeps one `u64` per open non-empty collection, so
/// at most `min(max_depth, bytes.len())` of them (8 KiB at a depth of 1024), and
/// allocates nothing proportional to any declared length.
///
/// Trailing bytes after the root element are left to the decoder.
///
/// `max_depth` is the caller's bound. The protocol (`spec/interop-mode.md` →
/// Decode bounds) requires one in `32..=1024`; this function does not enforce
/// that range and applies whatever value it is given.
///
/// # Errors
///
/// Returns a [`MsgpackStructureError`] naming the violated bound. It rejects:
/// - nesting deeper than `max_depth`, counting every array or map header on
///   the path (an empty one included);
/// - a header declaring more payload bytes than the input holds;
/// - more pending elements (across every open collection) than the remaining
///   bytes can back. Every element costs at least one byte, so a decoder's
///   total container pre-allocation is bounded by the input length rather
///   than by `depth × declared length`;
/// - the reserved marker `0xc1`, and input that ends mid-document.
///
/// # Examples
///
/// ```
/// use cachekit_core::check_msgpack_structure;
///
/// // [[[]]]: three levels, because the empty innermost array counts as one.
/// let doc = [0x91, 0x91, 0x90];
/// assert_eq!(check_msgpack_structure(&doc, 3), Ok(()));
/// assert_eq!(
///     check_msgpack_structure(&doc, 2).unwrap_err().to_string(),
///     "nests deeper than 2 levels"
/// );
///
/// // An array32 header claiming 2^32 - 1 elements, in five bytes.
/// assert_eq!(
///     check_msgpack_structure(&[0xdd, 0xff, 0xff, 0xff, 0xff], 100)
///         .unwrap_err()
///         .to_string(),
///     "declares more elements than the input can back"
/// );
/// ```
pub fn check_msgpack_structure(
    bytes: &[u8],
    max_depth: usize,
) -> Result<(), MsgpackStructureError> {
    fn be(bytes: &[u8], pos: usize, width: usize) -> Result<u64, MsgpackStructureError> {
        let end = pos
            .checked_add(width)
            .filter(|e| *e <= bytes.len())
            .ok_or_else(|| reject("ends inside a length prefix"))?;
        Ok(bytes[pos..end]
            .iter()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
    }

    let mut pos = 0usize;
    let mut pending: u64 = 1; // elements owed across all open collections (the root is one)
    let mut open: Vec<u64> = Vec::new(); // elements still owed per open collection = depth
    while pending > 0 {
        while open.last() == Some(&0) {
            open.pop();
        }
        let marker = *bytes
            .get(pos)
            .ok_or_else(|| reject("ends before the document is complete"))?;
        pos += 1;
        pending -= 1;
        if let Some(innermost) = open.last_mut() {
            *innermost -= 1;
        }
        // (length-prefix bytes, payload bytes after the prefix, child elements)
        let (prefix, payload, children): (usize, u64, u64) = match marker {
            0x00..=0x7f | 0xc0 | 0xc2 | 0xc3 | 0xe0..=0xff => (0, 0, 0),
            0x80..=0x8f => (0, 0, 2 * u64::from(marker & 0x0f)),
            0x90..=0x9f => (0, 0, u64::from(marker & 0x0f)),
            0xa0..=0xbf => (0, u64::from(marker & 0x1f), 0),
            0xc1 => return Err(reject("contains the reserved marker 0xc1")),
            0xc4 | 0xd9 => (1, be(bytes, pos, 1)?, 0),
            0xc5 | 0xda => (2, be(bytes, pos, 2)?, 0),
            0xc6 | 0xdb => (4, be(bytes, pos, 4)?, 0),
            0xc7 => (1, be(bytes, pos, 1)? + 1, 0), // ext: length prefix, then type byte + data
            0xc8 => (2, be(bytes, pos, 2)? + 1, 0),
            0xc9 => (4, be(bytes, pos, 4)? + 1, 0),
            0xca..=0xd3 => (0, 1u64 << (marker & 0x03), 0), // f32/f64/u8..u64/i8..i64: 4,8,1,2,4,8,1,2,4,8
            0xd4..=0xd8 => (0, 1 + (1u64 << (marker - 0xd4)), 0), // fixext: type byte + 1/2/4/8/16
            0xdc => (2, 0, be(bytes, pos, 2)?),
            0xdd => (4, 0, be(bytes, pos, 4)?),
            0xde => (2, 0, 2 * be(bytes, pos, 2)?),
            0xdf => (4, 0, 2 * be(bytes, pos, 4)?),
        };
        // An empty collection is still a level (spec: depth counts collection
        // headers), so the bound is checked before the `children > 0` push.
        if matches!(marker, 0x80..=0x9f | 0xdc..=0xdf) && open.len() >= max_depth {
            return Err(reject(format!("nests deeper than {max_depth} levels")));
        }
        pos += prefix;
        let remaining = (bytes.len() - pos) as u64;
        if payload > remaining {
            return Err(reject("declares more bytes than the input holds"));
        }
        // Unreachable while the check above holds (`remaining` came from a
        // usize); checked rather than cast so a future edit cannot truncate.
        pos += usize::try_from(payload)
            .map_err(|_| reject("declares more bytes than the input holds"))?;
        if children > 0 {
            open.push(children);
        }
        pending += children;
        if pending > remaining - payload {
            return Err(reject("declares more elements than the input can back"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The envelope's bound; any bound in the protocol's range would do here.
    const MAX_DEPTH: usize = 100;

    #[test]
    fn the_error_is_a_std_error() {
        fn is_error<E: std::error::Error + Send + Sync + 'static>() {}
        is_error::<MsgpackStructureError>();
    }

    fn check(bytes: &[u8]) -> Result<(), String> {
        check_msgpack_structure(bytes, MAX_DEPTH).map_err(|e| e.to_string())
    }

    /// `count` copies of a collection header, then `tail`.
    fn nested(header: &[u8], count: usize, tail: &[u8]) -> Vec<u8> {
        [header.repeat(count), tail.to_vec()].concat()
    }

    /// (one level of nesting: fixarray(1) or fixmap(1) with key "", its empty form)
    const LEVELS: [(&[u8], u8); 2] = [(&[0x91], 0x90), (&[0x81, 0xa0], 0x80)];

    #[test]
    fn accepts_every_scalar_marker_class() {
        let docs: &[&[u8]] = &[
            &[0x00],
            &[0x7f],
            &[0xe0],
            &[0xff],
            &[0xc0],
            &[0xc2],
            &[0xc3],
            &[0xa3, b'a', b'b', b'c'],
            &[0xd9, 0x01, b'x'],
            &[0xda, 0x00, 0x01, b'x'],
            &[0xdb, 0x00, 0x00, 0x00, 0x01, b'x'],
            &[0xc4, 0x02, 0x01, 0x02],
            &[0xc5, 0x00, 0x00],
            &[0xc6, 0x00, 0x00, 0x00, 0x00],
            &[0xc7, 0x01, 0x05, 0xaa],
            &[0xc8, 0x00, 0x00, 0x05],
            &[0xc9, 0x00, 0x00, 0x00, 0x00, 0x05],
            &[0xca, 0, 0, 0, 0],
            &[0xcb, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0xcc, 0],
            &[0xcd, 0, 0],
            &[0xce, 0, 0, 0, 0],
            &[0xcf, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0xd0, 0],
            &[0xd1, 0, 0],
            &[0xd2, 0, 0, 0, 0],
            &[0xd3, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0xd4, 0x05, 0],
            &[0xd8, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0xdc, 0x00, 0x01, 0xc0],
            &[0xdd, 0x00, 0x00, 0x00, 0x01, 0xc0],
            &[0xde, 0x00, 0x01, 0xa0, 0xc0],
            &[0xdf, 0x00, 0x00, 0x00, 0x01, 0xa0, 0xc0],
        ];
        for doc in docs {
            assert_eq!(check(doc), Ok(()), "{doc:02x?}");
        }
    }

    #[test]
    fn rejects_every_truncation_of_a_fixed_width_marker() {
        let docs: &[&[u8]] = &[
            &[0xd9],
            &[0xda, 0x00],
            &[0xdb, 0x00, 0x00, 0x00],
            &[0xc7],
            &[0xcb, 0, 0, 0, 0, 0, 0, 0],
            &[0xd8, 0x05, 0],
            &[0xdd, 0x00, 0x00],
            &[0xa3, b'a', b'b'],
            &[],
        ];
        for doc in docs {
            assert!(check(doc).is_err(), "{doc:02x?}");
        }
    }

    #[test]
    fn rejects_the_reserved_marker() {
        assert_eq!(
            check(&[0x91, 0xc1]),
            Err("contains the reserved marker 0xc1".to_owned())
        );
    }

    #[test]
    fn leaves_trailing_bytes_to_the_decoder() {
        assert_eq!(check(&[0xc0, 0xc1, 0xff]), Ok(()));
    }

    #[test]
    fn depth_bound_is_inclusive_for_arrays_and_maps() {
        let too_deep = Err(format!("nests deeper than {MAX_DEPTH} levels"));
        for (header, _) in LEVELS {
            assert_eq!(check(&nested(header, MAX_DEPTH, &[0xc0])), Ok(()));
            assert_eq!(check(&nested(header, MAX_DEPTH + 1, &[0xc0])), too_deep);
        }
    }

    #[test]
    fn an_empty_innermost_collection_counts_as_a_level() {
        let too_deep = Err(format!("nests deeper than {MAX_DEPTH} levels"));
        for (header, empty) in LEVELS {
            assert_eq!(check(&nested(header, MAX_DEPTH - 1, &[empty])), Ok(()));
            assert_eq!(check(&nested(header, MAX_DEPTH, &[empty])), too_deep);
        }
    }

    #[test]
    fn map_pairs_cost_two_slots() {
        assert_eq!(check(&[0x81, 0xa0, 0xc0]), Ok(()));
        assert!(check(&[0x81, 0xa0]).is_err());
    }

    #[test]
    fn widest_claims_do_not_overflow() {
        // 2^32 − 1 pairs (2 × (2^32 − 1) slots) and a u32::MAX ext length,
        // computed in u64.
        assert_eq!(
            check(&[0xdf, 0xff, 0xff, 0xff, 0xff]),
            Err("declares more elements than the input can back".to_owned())
        );
        assert_eq!(
            check(&[0xc9, 0xff, 0xff, 0xff, 0xff, 0x05]),
            Err("declares more bytes than the input holds".to_owned())
        );
    }

    #[cfg(all(feature = "compression", feature = "checksum", feature = "messagepack"))]
    #[test]
    fn every_real_envelope_and_every_strict_prefix_of_one() {
        // The walk admits what writers emit, and nothing that ends early:
        // every strict prefix of a complete document is incomplete.
        let storage = crate::ByteStorage::new(None);
        let bin = storage
            .store(b"pre-scan admits real envelopes", None)
            .unwrap();
        let e: crate::StorageEnvelope = rmp_serde::from_slice(&bin).unwrap();
        // Legacy writers encoded `compressed_data` as an array of ints.
        let legacy =
            rmp_serde::to_vec(&(&e.compressed_data, e.checksum, e.original_size, &e.format))
                .unwrap();
        assert!(storage.retrieve(&legacy).is_ok());
        for doc in [bin, legacy] {
            assert_eq!(check(&doc), Ok(()));
            for end in 0..doc.len() {
                assert!(
                    check(&doc[..end]).is_err(),
                    "prefix of {end} bytes admitted"
                );
            }
        }
    }
}
