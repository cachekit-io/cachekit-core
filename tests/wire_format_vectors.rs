//! Canonical ByteStorage wire-format vectors.
//!
//! Verifies this crate — the canonical ByteStorage implementation — against the
//! byte-canonical envelope vectors pinned by the protocol spec
//! (`protocol/spec/wire-format.md`). Every vector must decode to the expected
//! payload bytes, so any decoding regression fails CI here instead of breaking
//! cross-version reads in production.
//!
//! Since protocol 1.1 (`decisions/envelope-bin-encoding.md`) the fixture pins
//! two encodings of `compressed_data`: legacy array-of-integers vectors
//! (no `envelope_encoding` field, retained forever as legacy-read proof) and
//! their `*_bin` twins (`"envelope_encoding": "bin"`, canonical for 1.1+
//! writers). Decode-identity runs against BOTH sets, forever. Re-encode
//! byte-identity runs against the set matching this crate's CURRENT writer
//! encoding — `bin` since the writer flip (`serde_bytes` on
//! `compressed_data`, LAB-866), so those assertions target the `*_bin` set.
//!
//! Since protocol 1.3 the fixture also carries `reject_vectors`: six envelopes
//! a conforming reader must reject, each asserted below to fail through
//! `ByteStorage::retrieve` with the error the spec names. Its
//! `constructed_vectors` group runs in `wire_format_constructed.rs`, and the
//! allocation bound on the size-cap and ratio reject vectors runs in the
//! crate's unit tests (`src/read_allocation_probe.rs`), where the probe's
//! positive control can hook the read path.
//!
//! Fixture provenance: vendored from
//! <https://github.com/cachekit-io/protocol> `test-vectors/wire-format.json`
//! at commit `efe56e54723cdfb5292a2e9352157d4141a08421`, integrity-pinned by
//! sha256 below. To update: copy the file from a newer protocol ref, update
//! `FIXTURE_SHA256` and this comment's commit hash together.

#![cfg(all(feature = "compression", feature = "checksum", feature = "messagepack"))]

use std::collections::{BTreeSet, HashMap, HashSet};
use std::mem::discriminant;

use cachekit_core::byte_storage::ByteStorageError;
use cachekit_core::{ByteStorage, StorageEnvelope};
use sha2::{Digest, Sha256};

/// Compiled-in fixture: no runtime path resolution, so the test can never be
/// silently skipped by a missing file.
const FIXTURE: &str = include_str!("vectors/wire-format.json");

/// sha256 of the vendored fixture — must match the protocol repo's copy.
const FIXTURE_SHA256: &str = "5d72ca1ff27202ab46aa501f54abf77e535f275d2ea4443966ad464f3c020cd7";

#[derive(serde::Deserialize)]
struct WireFormatFixture {
    limits: Limits,
    vectors: Vec<Vector>,
    /// Defaulted so a fixture without the group fails the named-set assert in
    /// `reject_vectors_fail_with_the_spec_error`, not a serde error.
    #[serde(default)]
    reject_vectors: Vec<RejectVector>,
    version: String,
}

#[derive(serde::Deserialize)]
struct Limits {
    max_compressed_size: usize,
    max_compression_ratio: u64,
    max_uncompressed_size: usize,
}

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    format: String,
    input_hex: String,
    input_size: usize,
    envelope_hex: String,
    envelope_size: usize,
    /// `None` = legacy array-of-integers encoding; `Some("bin")` = msgpack bin
    /// (canonical for protocol 1.1+ writers).
    envelope_encoding: Option<String>,
    /// For `*_bin` twins: the legacy vector they were derived from.
    derived_from: Option<String>,
}

#[derive(serde::Deserialize)]
struct RejectVector {
    name: String,
    envelope_hex: String,
    envelope_size: usize,
}

impl Vector {
    /// Encoded with the legacy array-of-integers `compressed_data` — what
    /// pre-1.1 writers emitted; retained forever as legacy-read proof.
    fn is_legacy(&self) -> bool {
        self.envelope_encoding.is_none()
    }
}

fn load_fixture() -> WireFormatFixture {
    serde_json::from_str(FIXTURE).expect("wire-format.json fixture must parse")
}

#[test]
fn fixture_integrity_pinned_sha256() {
    let digest = hex::encode(Sha256::digest(FIXTURE.as_bytes()));
    assert_eq!(
        digest, FIXTURE_SHA256,
        "vendored wire-format.json drifted from its pinned sha256 — \
         re-vendor from the protocol repo and update FIXTURE_SHA256 deliberately"
    );
}

#[test]
fn fixture_is_current_version_with_vectors() {
    let fixture = load_fixture();
    assert_eq!(fixture.version, "1.3.0");
    let legacy: HashSet<&str> = fixture
        .vectors
        .iter()
        .filter(|v| v.is_legacy())
        .map(|v| v.name.as_str())
        .collect();
    let bin = fixture.vectors.len() - legacy.len();
    assert!(
        legacy.len() >= 6,
        "legacy vectors are retained forever as legacy-read proof; expected at least the original 6, got {}",
        legacy.len()
    );
    assert!(
        bin >= 6,
        "protocol 1.1 pins a *_bin twin per legacy vector; expected at least 6, got {bin}"
    );
    // Equal totals alone would admit duplicate twins or orphaned parents, so
    // key every *_bin vector by `derived_from` and require exactly one twin
    // per legacy vector.
    let mut twins: HashMap<&str, usize> = HashMap::new();
    for vector in fixture.vectors.iter().filter(|v| !v.is_legacy()) {
        let parent = vector.derived_from.as_deref().unwrap_or_else(|| {
            panic!(
                "[{}] bin vector must name its legacy parent in derived_from",
                vector.name
            )
        });
        assert!(
            legacy.contains(parent),
            "[{}] derived_from {parent:?} names no legacy vector",
            vector.name
        );
        *twins.entry(parent).or_insert(0) += 1;
    }
    for name in &legacy {
        assert_eq!(
            twins.get(name).copied().unwrap_or(0),
            1,
            "legacy vector {name:?} must have exactly one *_bin twin"
        );
    }
    // LAB-868's deliverable, pinned by name: the bin16 width-boundary pair
    // must survive any future re-vendor.
    for required in ["width_boundary_bin16", "width_boundary_bin16_bin"] {
        assert!(
            fixture.vectors.iter().any(|v| v.name == required),
            "fixture must retain the {required:?} vector"
        );
    }
}

#[test]
fn fixture_limits_match_implementation() {
    let fixture = load_fixture();
    let storage = ByteStorage::new(None);
    assert_eq!(
        fixture.limits.max_uncompressed_size,
        storage.max_uncompressed_size()
    );
    assert_eq!(
        fixture.limits.max_compressed_size,
        storage.max_compressed_size()
    );
    assert_eq!(
        fixture.limits.max_compression_ratio,
        storage.max_compression_ratio()
    );
}

/// Decode direction: every canonical envelope — BOTH legacy array-of-integers
/// vectors and their `*_bin` twins — must retrieve to the exact original
/// payload bytes, format, and size. This set never shrinks: legacy vectors are
/// legacy-read proof, bin vectors prove readers accept the 1.1+ canonical
/// writer encoding before any writer emits it (readers-first rollout).
#[test]
fn vectors_decode_to_expected_payload() {
    let storage = ByteStorage::new(None);
    for vector in load_fixture().vectors {
        let input = hex::decode(&vector.input_hex).expect("input_hex must decode");
        let envelope = hex::decode(&vector.envelope_hex).expect("envelope_hex must decode");
        assert_eq!(
            input.len(),
            vector.input_size,
            "[{}] input_size mismatch",
            vector.name
        );
        assert_eq!(
            envelope.len(),
            vector.envelope_size,
            "[{}] envelope_size mismatch",
            vector.name
        );

        let (payload, format) = storage
            .retrieve(&envelope)
            .unwrap_or_else(|e| panic!("[{}] retrieve failed: {e:?}", vector.name));
        assert_eq!(
            payload, input,
            "[{}] decoded payload differs from input",
            vector.name
        );
        assert_eq!(format, vector.format, "[{}] format mismatch", vector.name);
        assert!(
            storage.validate(&envelope),
            "[{}] validate() rejected canonical envelope",
            vector.name
        );
    }
}

/// Encode direction: storing the original payload must reproduce the exact
/// envelope bytes. The full path (LZ4 block encoding + positional-array
/// MessagePack) is deterministic; a failure here means the wire bytes changed
/// and cross-version reads are at risk — regenerate vectors deliberately in
/// the protocol repo, never adjust expectations here.
///
/// `*_bin` vectors only: this asserts against the encoding the writer
/// CURRENTLY emits — msgpack `bin` since the writer flip (`serde_bytes` on
/// `compressed_data`, LAB-866).
#[test]
fn vectors_reencode_byte_identical() {
    let storage = ByteStorage::new(None);
    for vector in load_fixture()
        .vectors
        .into_iter()
        .filter(|v| !v.is_legacy())
    {
        let input = hex::decode(&vector.input_hex).expect("input_hex must decode");
        let expected = hex::decode(&vector.envelope_hex).expect("envelope_hex must decode");

        let encoded = storage
            .store(&input, Some(vector.format.clone()))
            .unwrap_or_else(|e| panic!("[{}] store failed: {e:?}", vector.name));
        assert_eq!(
            hex::encode(&encoded),
            hex::encode(&expected),
            "[{}] re-encoded envelope is not byte-identical to the canonical vector",
            vector.name
        );
    }
}

/// Envelope-codec identity, independent of LZ4: deserializing the canonical
/// bytes into StorageEnvelope and re-serializing must be byte-identical. When
/// `vectors_reencode_byte_identical` fails, this localizes the regression —
/// codec test failing too means the MessagePack layout changed (protocol#11
/// territory); codec test passing means the LZ4 block encoding changed.
///
/// `*_bin` vectors only, same reason as `vectors_reencode_byte_identical`:
/// re-serialization emits the writer's current encoding (`bin`), so
/// byte-identity can only hold for the set that matches it.
#[test]
fn envelope_codec_roundtrip_byte_identical() {
    for vector in load_fixture()
        .vectors
        .into_iter()
        .filter(|v| !v.is_legacy())
    {
        let canonical = hex::decode(&vector.envelope_hex).expect("envelope_hex must decode");
        let envelope: StorageEnvelope = rmp_serde::from_slice(&canonical)
            .unwrap_or_else(|e| panic!("[{}] envelope must deserialize: {e}", vector.name));
        let reserialized = rmp_serde::to_vec(&envelope)
            .unwrap_or_else(|e| panic!("[{}] envelope must reserialize: {e}", vector.name));
        assert_eq!(
            hex::encode(&reserialized),
            hex::encode(&canonical),
            "[{}] MessagePack envelope layout is not byte-stable",
            vector.name
        );
    }
}

/// Every `*_bin` twin must carry an actual msgpack bin marker on
/// `compressed_data` (element [0], right after the 0x94 fixarray header) and
/// deserialize to a StorageEnvelope field-identical to its legacy parent —
/// the fixture's "identical fields, different encoding" contract. Guards
/// against a regenerated fixture silently shipping twins that don't actually
/// exercise the bin decode path.
#[test]
fn bin_twins_are_bin_encoded_and_field_identical_to_legacy() {
    let fixture = load_fixture();
    let twins: Vec<&Vector> = fixture.vectors.iter().filter(|v| !v.is_legacy()).collect();
    assert!(
        !twins.is_empty(),
        "protocol 1.1 fixture must carry *_bin twins"
    );

    for twin in twins {
        assert_eq!(
            twin.envelope_encoding.as_deref(),
            Some("bin"),
            "[{}] unknown envelope_encoding",
            twin.name
        );
        let parent_name = twin
            .derived_from
            .as_deref()
            .unwrap_or_else(|| panic!("[{}] *_bin twin missing derived_from", twin.name));
        let parent = fixture
            .vectors
            .iter()
            .find(|v| v.name == parent_name)
            .unwrap_or_else(|| {
                panic!(
                    "[{}] derived_from '{parent_name}' not in fixture",
                    twin.name
                )
            });

        let twin_bytes = hex::decode(&twin.envelope_hex).expect("envelope_hex must decode");
        let twin_env: StorageEnvelope = rmp_serde::from_slice(&twin_bytes)
            .unwrap_or_else(|e| panic!("[{}] twin must deserialize: {e}", twin.name));
        assert_eq!(
            twin_bytes[0], 0x94,
            "[{}] outer fixarray(4) marker",
            twin.name
        );
        assert_eq!(
            twin_bytes[1],
            match twin_env.compressed_data.len() {
                0..=255 => 0xc4,
                256..=65_535 => 0xc5,
                _ => 0xc6,
            },
            "[{}] compressed_data does not use the shortest bin marker: 0x{:02x}",
            twin.name,
            twin_bytes[1]
        );

        let parent_bytes = hex::decode(&parent.envelope_hex).expect("envelope_hex must decode");
        let parent_env: StorageEnvelope = rmp_serde::from_slice(&parent_bytes)
            .unwrap_or_else(|e| panic!("[{parent_name}] parent must deserialize: {e}"));
        assert_eq!(
            twin_env.compressed_data, parent_env.compressed_data,
            "[{}]",
            twin.name
        );
        assert_eq!(twin_env.checksum, parent_env.checksum, "[{}]", twin.name);
        assert_eq!(
            twin_env.original_size, parent_env.original_size,
            "[{}]",
            twin.name
        );
        assert_eq!(twin_env.format, parent_env.format, "[{}]", twin.name);
    }
}

/// The six reject vectors, each with the rejection `spec/wire-format.md` →
/// Reject vectors requires an SDK test to assert. Compared by variant, so a
/// message is not part of the assertion. Pinned by name, so an emptied or
/// renamed group fails here instead of iterating nothing.
const REJECT_EXPECTATIONS: [(&str, ByteStorageError); 6] = [
    // Retrieve Flow step 4: original_size one byte over the 512 MiB cap.
    (
        "reject_original_size_over_cap",
        ByteStorageError::InputTooLarge,
    ),
    // original_size 2^32 + 16 as uint64 fails the range-checked decode into
    // `StorageEnvelope::original_size: u32` (step 2), before decompression.
    // The spec accepts that in place of the size-cap error; a length or
    // checksum error would mean the value was truncated.
    (
        "reject_original_size_wraps_u32",
        ByteStorageError::DeserializationFailed(String::new()),
    ),
    // The zero-length and ratio checks share `DecompressionBomb`, but each
    // vector can only reach its own: with original_size 0 the ratio check
    // cannot fire (0 > 1000 * 0 is false), and reject_ratio_bomb has 1,000 B
    // of compressed_data, so the zero-length check cannot fire.
    (
        "reject_zero_length_compressed_data",
        ByteStorageError::DecompressionBomb,
    ),
    ("reject_ratio_bomb", ByteStorageError::DecompressionBomb),
    // A length error, never a checksum error: the checksum matches the 16 B
    // the block decodes to.
    (
        "reject_decompressed_length_mismatch",
        ByteStorageError::SizeValidationFailed,
    ),
    (
        "reject_checksum_mismatch",
        ByteStorageError::ChecksumMismatch,
    ),
];

/// Every reject vector fails through the envelope read path,
/// `ByteStorage::retrieve`, with the error the spec names for it, at this
/// spec's limits. `validate` must agree.
#[test]
fn reject_vectors_fail_with_the_spec_error() {
    let fixture = load_fixture();
    let names: BTreeSet<&str> = fixture
        .reject_vectors
        .iter()
        .map(|v| v.name.as_str())
        .collect();
    let expected: BTreeSet<&str> = REJECT_EXPECTATIONS.iter().map(|(n, _)| *n).collect();
    assert_eq!(
        names, expected,
        "wire-format.json reject_vectors must be exactly the six pinned names"
    );
    assert_eq!(
        fixture.reject_vectors.len(),
        expected.len(),
        "duplicate reject vector name"
    );

    let storage = ByteStorage::new(None);
    for (name, expected) in REJECT_EXPECTATIONS {
        let vector = fixture
            .reject_vectors
            .iter()
            .find(|v| v.name == name)
            .expect("checked above");
        let envelope = hex::decode(&vector.envelope_hex).expect("envelope_hex must decode");
        assert_eq!(
            envelope.len(),
            vector.envelope_size,
            "[{name}] envelope_size mismatch"
        );

        match storage.retrieve(&envelope) {
            Ok(_) => panic!("[{name}] retrieve accepted a reject vector"),
            Err(e) => assert_eq!(
                discriminant(&e),
                discriminant(&expected),
                "[{name}] rejected with {e:?}, expected {expected:?}"
            ),
        }
        assert!(
            !storage.validate(&envelope),
            "[{name}] validate() accepted a reject vector"
        );
    }
}
