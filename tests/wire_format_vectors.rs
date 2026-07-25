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
//! encoding — legacy today; the writer-flip diff (`serde_bytes` on
//! `compressed_data`) switches those assertions to the `*_bin` set.
//!
//! Fixture provenance: vendored from
//! <https://github.com/cachekit-io/protocol> `test-vectors/wire-format.json`
//! at commit `6863495d3565ccd9f28827baa1351782575e770d`, integrity-pinned by
//! sha256 below. To update: copy the file from a newer protocol ref, update
//! `FIXTURE_SHA256` and this comment's commit hash together.

#![cfg(all(feature = "compression", feature = "checksum", feature = "messagepack"))]

use cachekit_core::{ByteStorage, StorageEnvelope};
use sha2::{Digest, Sha256};

/// Compiled-in fixture: no runtime path resolution, so the test can never be
/// silently skipped by a missing file.
const FIXTURE: &str = include_str!("vectors/wire-format.json");

/// sha256 of the vendored fixture — must match the protocol repo's copy.
const FIXTURE_SHA256: &str = "d6184a945d8cb22491b5c937414fe4d01e682d084ccec9dae9526d0ffba650cb";

#[derive(serde::Deserialize)]
struct WireFormatFixture {
    limits: Limits,
    vectors: Vec<Vector>,
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

impl Vector {
    /// Encoded with the legacy array-of-integers `compressed_data` — the
    /// encoding this crate's writer currently emits.
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
    assert_eq!(fixture.version, "1.1.0");
    let legacy = fixture.vectors.iter().filter(|v| v.is_legacy()).count();
    let bin = fixture.vectors.len() - legacy;
    assert!(
        legacy >= 6,
        "legacy vectors are retained forever as legacy-read proof; expected at least the original 6, got {legacy}"
    );
    assert!(
        bin >= 6,
        "protocol 1.1 pins a *_bin twin per legacy vector; expected at least 6, got {bin}"
    );
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
/// Legacy vectors only: this asserts against the encoding the writer CURRENTLY
/// emits. The writer-flip diff switches this filter to the `*_bin` set in the
/// same PR that adds `serde_bytes` to `compressed_data`.
#[test]
fn vectors_reencode_byte_identical() {
    let storage = ByteStorage::new(None);
    for vector in load_fixture().vectors.into_iter().filter(Vector::is_legacy) {
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
/// Legacy vectors only, same reason as `vectors_reencode_byte_identical`:
/// re-serialization emits the writer's current encoding, so byte-identity can
/// only hold for the set that matches it.
#[test]
fn envelope_codec_roundtrip_byte_identical() {
    for vector in load_fixture().vectors.into_iter().filter(Vector::is_legacy) {
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
        assert_eq!(
            twin_bytes[0], 0x94,
            "[{}] outer fixarray(4) marker",
            twin.name
        );
        assert!(
            // 0xc4/0xc5/0xc6 = msgpack bin8/bin16/bin32
            matches!(twin_bytes[1], 0xc4..=0xc6),
            "[{}] compressed_data is not bin-encoded: marker 0x{:02x}",
            twin.name,
            twin_bytes[1]
        );

        let parent_bytes = hex::decode(&parent.envelope_hex).expect("envelope_hex must decode");
        let twin_env: StorageEnvelope = rmp_serde::from_slice(&twin_bytes)
            .unwrap_or_else(|e| panic!("[{}] twin must deserialize: {e}", twin.name));
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
