//! Dual-decode proof for the StorageEnvelope `compressed_data` bin encoding.
//!
//! Protocol 1.1 (`protocol/decisions/envelope-bin-encoding.md`) flips
//! `compressed_data` from the legacy msgpack array-of-integers encoding to
//! msgpack `bin` — readers first, then the writer (LAB-866, shipped). This
//! file is the permanent CI proof: under the locked decoder stack
//! (rmp-serde with serde_bytes), BOTH reader shapes accept BOTH encodings,
//! so `bin` envelopes from 1.1+ writers are readable by pre-1.1 readers and
//! legacy envelopes stay readable forever.
//!
//! The full matrix, executed against the byte-pinned protocol vectors:
//!
//! | Reader                              | legacy wire (array) | new wire (bin) |
//! |-------------------------------------|---------------------|----------------|
//! | legacy (plain `Vec<u8>`, pre-1.1)   | proven here         | proven here    |
//! | shipped (`serde_bytes`, 1.1 writer) | proven here         | proven here    |
//! |   …incl. `ByteStorage::retrieve()`  | proven here         | proven here    |
//!
//! Seeded from the LAB-764 toolchain experiment (`dual_decode_experiment.rs`,
//! attached to the decision memo on that issue); throughput evidence lives in
//! the LAB-510 harness (`benches/hot_path.rs`, 64 MiB incompressible group).
//!
//! Width boundaries: the fixture's `*_bin` twins all fit in a bin8 header
//! (`0xc4`, ≤ 255 B). The `width_boundary_*` tests cover the bin16 (`0xc5`)
//! and bin32 (`0xc6`) headers with real LZ4 output from the real writer, per
//! the MUST recorded in the decision record.

#![cfg(all(feature = "compression", feature = "checksum", feature = "messagepack"))]

use cachekit_core::{ByteStorage, StorageEnvelope};
use serde::Deserialize;

const FIXTURE: &str = include_str!("vectors/wire-format.json");

/// Pre-1.1 reader stand-in: identical shape to StorageEnvelope but with a
/// plain `Vec<u8>` (no `serde_bytes`) on `compressed_data` — the shape every
/// pre-writer-flip SDK shipped. Kept forever: these matrix legs are the proof
/// that legacy readers accept `bin` wire and that legacy wire still decodes.
#[derive(Deserialize, PartialEq, Debug)]
struct StorageEnvelopeLegacy {
    compressed_data: Vec<u8>,
    checksum: [u8; 8],
    original_size: u32,
    format: String,
}

#[derive(serde::Deserialize)]
struct WireFormatFixture {
    vectors: Vec<Vector>,
}

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    input_hex: String,
    envelope_hex: String,
    envelope_encoding: Option<String>,
}

fn load_vectors() -> Vec<Vector> {
    serde_json::from_str::<WireFormatFixture>(FIXTURE)
        .expect("fixture parses")
        .vectors
}

/// Assert one envelope's bytes decode identically through every reader shape:
/// legacy struct, shipped struct, and the full shipped `retrieve()` path
/// (checksum validation + decompression-ratio guard included).
fn assert_all_readers_decode(name: &str, wire: &[u8], expected_payload: &[u8]) {
    let legacy: StorageEnvelopeLegacy = rmp_serde::from_slice(wire)
        .unwrap_or_else(|e| panic!("[{name}] legacy reader (plain Vec<u8>) failed: {e}"));
    let shipped: StorageEnvelope = rmp_serde::from_slice(wire)
        .unwrap_or_else(|e| panic!("[{name}] shipped reader (serde_bytes) failed: {e}"));
    assert_eq!(legacy.compressed_data, shipped.compressed_data, "[{name}]");
    assert_eq!(legacy.checksum, shipped.checksum, "[{name}]");
    assert_eq!(legacy.original_size, shipped.original_size, "[{name}]");
    assert_eq!(legacy.format, shipped.format, "[{name}]");

    let storage = ByteStorage::new(None);
    let (payload, _format) = storage
        .retrieve(wire)
        .unwrap_or_else(|e| panic!("[{name}] shipped retrieve() rejected envelope: {e:?}"));
    assert_eq!(
        payload, expected_payload,
        "[{name}] payload mismatch via retrieve()"
    );
}

/// The 4-cell matrix over the legacy pinned vectors: decode each with both
/// reader shapes, re-encode through the shipped (serde_bytes) writer shape to
/// produce bin wire, and prove that bin wire decodes through both reader
/// shapes AND the shipped `retrieve()`.
#[test]
fn dual_decode_matrix_against_legacy_vectors() {
    let vectors = load_vectors();
    let legacy: Vec<&Vector> = vectors
        .iter()
        .filter(|v| v.envelope_encoding.is_none())
        .collect();
    assert!(legacy.len() >= 6, "expected the pinned legacy vector set");

    for v in legacy {
        let old_wire = hex::decode(&v.envelope_hex)
            .unwrap_or_else(|e| panic!("[{}] envelope_hex must decode: {e}", v.name));
        let input = hex::decode(&v.input_hex)
            .unwrap_or_else(|e| panic!("[{}] input_hex must decode: {e}", v.name));

        // Cells: old reader <- old wire (baseline), new reader <- old wire
        // (the readers-first claim), plus retrieve() on the pinned bytes.
        assert_all_readers_decode(&v.name, &old_wire, &input);

        // Produce new wire the way the shipped writer does.
        let new_from_old: StorageEnvelope = rmp_serde::from_slice(&old_wire)
            .unwrap_or_else(|e| panic!("[{}] shipped reader must decode legacy wire: {e}", v.name));
        let new_wire = rmp_serde::to_vec(&new_from_old)
            .unwrap_or_else(|e| panic!("[{}] shipped shape must serialize: {e}", v.name));

        // compressed_data (element [0], right after the 0x94 fixarray marker)
        // must now carry a bin marker.
        assert_eq!(
            new_wire[0], 0x94,
            "[{}] outer fixarray(4) preserved",
            v.name
        );
        assert_eq!(
            // 0xc4 = msgpack bin8. Every pinned twin's compressed_data is small
            // enough to be bin8; a wider marker here is a width-selection
            // regression that would break cross-SDK byte-identity.
            new_wire[1],
            0xc4,
            "[{}] compressed_data not bin8-encoded: 0x{:02x}",
            v.name,
            new_wire[1]
        );
        // Documented micro-regression: bin costs at most +1 B, and only on the
        // smallest envelopes. A <=15 B compressed_data goes from a 1 B fixarray
        // header to a 2 B bin8 header (+1); any array >=16 B already carried a
        // 3 B array16 header, so bin8's 2 B header shrinks it. Measured worst
        // case on the pinned set is exactly +1 (`empty`, 25 -> 26 B); every
        // other vector ties or shrinks. This +1 B ceiling is the micro-
        // regression contract accepted by the writer flip (LAB-764/LAB-866),
        // so keep it tight — a +2/+3 bloat regression must not slip through
        // green.
        assert!(
            new_wire.len() <= old_wire.len() + 1,
            "[{}] new wire exceeds the +1 B bin8-header ceiling",
            v.name
        );

        // Cells: old reader <- new wire (rollout-order bonus), new reader <-
        // new wire (round-trip), retrieve() <- new wire (API-level proof).
        assert_all_readers_decode(&v.name, &new_wire, &input);
    }
}

/// The pinned `*_bin` twins through the same reader matrix. Re-encode
/// byte-identity for this set lives in `tests/wire_format_vectors.rs`
/// (`vectors_reencode_byte_identical` at store() level,
/// `envelope_codec_roundtrip_byte_identical` at codec level).
#[test]
fn dual_decode_matrix_against_bin_vectors() {
    let vectors = load_vectors();
    let bin: Vec<&Vector> = vectors
        .iter()
        .filter(|v| v.envelope_encoding.is_some())
        .collect();
    assert!(bin.len() >= 6, "expected the pinned *_bin twin set");

    for v in bin {
        let wire = hex::decode(&v.envelope_hex)
            .unwrap_or_else(|e| panic!("[{}] envelope_hex must decode: {e}", v.name));
        let input = hex::decode(&v.input_hex)
            .unwrap_or_else(|e| panic!("[{}] input_hex must decode: {e}", v.name));

        assert_all_readers_decode(&v.name, &wire, &input);
    }
}

/// Deterministic xorshift64* stream — incompressible payload without a rand
/// dependency (same generator as the LAB-764 experiment).
fn incompressible(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x9e3779b97f4a7c15;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.wrapping_mul(0x2545f4914f6cdd1d).to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Build a real envelope (real LZ4 output) from an incompressible payload,
/// bin-encode it via the shipped writer shape, and assert the expected bin
/// width marker before running the full reader matrix on it.
fn assert_width_tier(name: &str, payload_len: usize, expected_marker: u8) {
    let payload = incompressible(payload_len);
    let env = StorageEnvelope::new(&payload, "msgpack".to_string())
        .unwrap_or_else(|e| panic!("[{name}] envelope construction failed: {e:?}"));
    let compressed_len = env.compressed_data.len();

    let wire = rmp_serde::to_vec(&env)
        .unwrap_or_else(|e| panic!("[{name}] shipped shape must serialize: {e}"));
    assert_eq!(wire[0], 0x94, "[{name}] outer fixarray(4) preserved");
    assert_eq!(
        wire[1], expected_marker,
        "[{name}] expected bin marker 0x{expected_marker:02x} for compressed_data of {compressed_len} B, got 0x{:02x}",
        wire[1]
    );

    assert_all_readers_decode(name, &wire, &payload);
}

/// bin8/bin16 boundary: the fixture twins never leave bin8 territory (all
/// compressed_data <= 255 B), so sweep real LZ4 outputs across the 255/256 B
/// boundary and prove both header widths decode through every reader shape.
/// LZ4 adds a few bytes of literal-run overhead on incompressible input, so
/// the sweep brackets the boundary regardless of the exact overhead.
#[test]
fn width_boundary_bin8_bin16() {
    let mut seen_bin8 = false;
    let mut seen_bin16 = false;
    for payload_len in 230..=270 {
        let payload = incompressible(payload_len);
        let env = StorageEnvelope::new(&payload, "msgpack".to_string()).unwrap_or_else(|e| {
            panic!("[sweep len={payload_len}] envelope construction failed: {e:?}")
        });
        let expected = if env.compressed_data.len() <= 255 {
            seen_bin8 = true;
            0xc4 // bin8
        } else {
            seen_bin16 = true;
            0xc5 // bin16
        };
        assert_width_tier(
            &format!("bin8/bin16 sweep len={payload_len}"),
            payload_len,
            expected,
        );
    }
    assert!(
        seen_bin8 && seen_bin16,
        "sweep must land on both sides of the 255 B boundary (bin8 seen: {seen_bin8}, bin16 seen: {seen_bin16})"
    );
}

/// bin16/bin32 boundary: compressed_data > 65,535 B forces the bin32 header.
/// One representative envelope per side, full reader matrix on each.
#[test]
fn width_boundary_bin16_bin32() {
    // The 0xc5 / 0xc6 marker assert inside assert_width_tier already proves the
    // tier: rmp selects the bin width purely by length, so marker <=> range.
    // A separate range assert on the returned length would only restate that.

    // Comfortably inside bin16 (compressed ~4 KiB).
    assert_width_tier("bin16 tier", 4 * 1024, 0xc5);

    // Incompressible 68 KiB compresses to > 65,535 B (LZ4 overhead is
    // positive on incompressible input), forcing bin32.
    assert_width_tier("bin32 tier", 68 * 1024, 0xc6);
}
