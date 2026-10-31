//! Structural pre-scan for untrusted MessagePack.
//!
//! `ByteStorage::retrieve` runs it before the envelope decode; it is exported
//! for SDK bindings that decode untrusted MessagePack themselves. The bounds are
//! `spec/interop-mode.md` → Decode bounds, pinned by
//! `tests/vectors/decode-bounds.json`.

/// Why [`check_msgpack_structure`] or [`msgpack_document_len`] rejected its
/// input.
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

/// Checks that `bytes` begin with one MessagePack document whose declared structure
/// the input can actually back, before any decoder sees them.
///
/// A header-only walk: str/bin/ext payloads are skipped by offset, never read,
/// and nothing is decoded. It keeps one `u64` per open non-empty collection, so
/// at most `min(max_depth, bytes.len())` of them (8 KiB at a depth of 1024), and
/// allocates nothing proportional to any declared length. The first 8 live on
/// the call stack, so a document that nests no deeper than that (a
/// `ByteStorage` envelope nests 2 deep) allocates nothing at all.
///
/// Bytes after the document are neither read nor rejected. To find where the
/// document ends, call [`msgpack_document_len`], which runs this same walk.
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
    msgpack_document_len(bytes, max_depth).map(|_| ())
}

/// Open collections the walk keeps on the call stack before it spills to the heap.
const INLINE_LEVELS: usize = 8;

/// Elements still owed per open collection, innermost last; `len` is the
/// depth. The outermost [`INLINE_LEVELS`] live inline and deeper ones in
/// `spill`, so a shallow document never allocates. `spill` holds exactly the
/// levels past the inline ones.
struct OpenCollections {
    inline: [u64; INLINE_LEVELS],
    len: usize,
    spill: Vec<u64>,
}

impl OpenCollections {
    fn new() -> Self {
        Self {
            inline: [0; INLINE_LEVELS],
            len: 0,
            spill: Vec::new(),
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn last_mut(&mut self) -> Option<&mut u64> {
        match self.len {
            0 => None,
            n @ 1..=INLINE_LEVELS => Some(&mut self.inline[n - 1]),
            _ => self.spill.last_mut(),
        }
    }

    fn push(&mut self, owed: u64) {
        if self.len < INLINE_LEVELS {
            self.inline[self.len] = owed;
        } else {
            self.spill.push(owed);
        }
        self.len += 1;
    }

    fn pop(&mut self) {
        if self.len > INLINE_LEVELS {
            self.spill.pop();
        }
        self.len -= 1;
    }
}

/// Runs the walk [`check_msgpack_structure`] describes and returns the length,
/// in bytes, of the document at the start of `bytes`.
///
/// It accepts and rejects exactly what [`check_msgpack_structure`] does. The
/// walk stops where the document ends, so the length is at least 1 and at most
/// `bytes.len()`, and a length below `bytes.len()` means trailing bytes follow.
/// A caller that requires the input to be exactly one document compares the
/// two instead of walking the input a second time.
///
/// # Errors
///
/// The same [`MsgpackStructureError`], for the same inputs, as
/// [`check_msgpack_structure`].
///
/// # Examples
///
/// ```
/// use cachekit_core::msgpack_document_len;
///
/// // nil, then two bytes the walk never reads (so 0xc1 is not rejected here).
/// let input = [0xc0, 0xc1, 0xff];
/// assert_eq!(msgpack_document_len(&input, 100), Ok(1));
///
/// // [[nil], "x"]: five bytes, the whole input.
/// let doc = [0x92, 0x91, 0xc0, 0xa1, b'x'];
/// assert_eq!(msgpack_document_len(&doc, 100), Ok(doc.len()));
/// ```
pub fn msgpack_document_len(
    bytes: &[u8],
    max_depth: usize,
) -> Result<usize, MsgpackStructureError> {
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
    let mut open = OpenCollections::new();
    while pending > 0 {
        while open.last_mut() == Some(&mut 0) {
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
    Ok(pos)
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

    fn doc_len(bytes: &[u8]) -> Result<usize, String> {
        msgpack_document_len(bytes, MAX_DEPTH).map_err(|e| e.to_string())
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
            assert_eq!(doc_len(doc), Ok(doc.len()), "{doc:02x?}");
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
    fn stops_where_the_document_ends_and_reports_its_length() {
        // The trailing 0xc1 is never read, so it is not the reserved-marker error.
        assert_eq!(check(&[0xc0, 0xc1, 0xff]), Ok(()));
        assert_eq!(doc_len(&[0xc0, 0xc1, 0xff]), Ok(1));
        // {"a": [nil, bin8(2)]}, then a trailing fixmap(1) the walk never opens.
        let doc = [0x81, 0xa1, b'a', 0x92, 0xc0, 0xc4, 0x02, 0xff, 0xff];
        assert_eq!(doc_len(&doc), Ok(doc.len()));
        assert_eq!(doc_len(&[&doc[..], &[0x81]].concat()), Ok(doc.len()));
    }

    #[test]
    fn both_entry_points_reject_alike() {
        let too_deep = nested(&[0x91], MAX_DEPTH + 1, &[0xc0]);
        let cases: &[&[u8]] = &[
            &[],
            &[0x91, 0xc1],
            &[0xdd, 0xff, 0xff, 0xff, 0xff],
            &too_deep,
        ];
        for bytes in cases {
            assert!(check(bytes).is_err(), "{bytes:02x?}");
            assert_eq!(doc_len(bytes).map(|_| ()), check(bytes), "{bytes:02x?}");
        }
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
    fn depth_bound_is_exact_where_the_stack_spills_to_the_heap() {
        for max_depth in INLINE_LEVELS - 1..=INLINE_LEVELS + 1 {
            let too_deep = Err(format!("nests deeper than {max_depth} levels"));
            for (header, empty) in LEVELS {
                let at = |levels, tail: &[u8]| {
                    check_msgpack_structure(&nested(header, levels, tail), max_depth)
                        .map_err(|e| e.to_string())
                };
                assert_eq!(at(max_depth, &[0xc0]), Ok(()), "max_depth {max_depth}");
                assert_eq!(
                    at(max_depth + 1, &[0xc0]),
                    too_deep,
                    "max_depth {max_depth}"
                );
                assert_eq!(at(max_depth - 1, &[empty]), Ok(()), "max_depth {max_depth}");
                assert_eq!(at(max_depth, &[empty]), too_deep, "max_depth {max_depth}");
            }
        }
    }

    #[test]
    fn a_sibling_after_a_spilled_subtree_is_measured_from_its_own_parent() {
        // [a levels of [..[nil]..], b levels of the same]: depth is 1 + max(a, b).
        // An `a` past the inline slots spills the stack to the heap and drains
        // it again before `b` starts.
        let max_depth = INLINE_LEVELS + 2;
        for a in 0..=max_depth {
            for b in 0..=max_depth {
                let doc = [
                    vec![0x92],
                    nested(&[0x91], a, &[0xc0]),
                    nested(&[0x91], b, &[0xc0]),
                ]
                .concat();
                let expected = if a.max(b) < max_depth {
                    Ok(doc.len())
                } else {
                    Err(format!("nests deeper than {max_depth} levels"))
                };
                let got = msgpack_document_len(&doc, max_depth).map_err(|e| e.to_string());
                assert_eq!(got, expected, "a {a}, b {b}");
            }
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
            assert_eq!(doc_len(&doc), Ok(doc.len()));
            assert_eq!(doc_len(&[&doc[..], &doc[..]].concat()), Ok(doc.len()));
            for end in 0..doc.len() {
                assert!(
                    check(&doc[..end]).is_err(),
                    "prefix of {end} bytes admitted"
                );
            }
        }
    }
}
