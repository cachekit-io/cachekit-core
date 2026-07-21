//! Canonical ByteStorage wire-format vectors.
//!
//! Verifies this crate — the canonical ByteStorage implementation — against the
//! byte-canonical envelope vectors pinned by the protocol spec
//! (`protocol/spec/wire-format.md`). Every vector must decode to the expected
//! payload bytes AND re-encode to the exact envelope bytes, so any encoding
//! regression (e.g. the positional-fixarray / int-array facts corrected in
//! protocol#11) fails CI here instead of breaking cross-version reads in
//! production.
//!
//! Fixture provenance: vendored from
//! <https://github.com/cachekit-io/protocol> `test-vectors/wire-format.json`
//! at commit `b0270b999bf827f8aa5fcc2d8640735196510326`, integrity-pinned by
//! sha256 below. To update: copy the file from a newer protocol ref, update
//! `FIXTURE_SHA256` and this comment's commit hash together.

#![cfg(all(feature = "compression", feature = "checksum", feature = "messagepack"))]

use cachekit_core::{ByteStorage, StorageEnvelope};
use sha2::{Digest, Sha256};

/// Compiled-in fixture: no runtime path resolution, so the test can never be
/// silently skipped by a missing file.
const FIXTURE: &str = include_str!("vectors/wire-format.json");

/// sha256 of the vendored fixture — must match the protocol repo's copy.
const FIXTURE_SHA256: &str = "f83a8a18c5067c6353b7c13f0a47b4e5cefec11f4ab881b12079483174e6e0b8";

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
    assert_eq!(fixture.version, "1.0.0");
    assert!(
        fixture.vectors.len() >= 6,
        "vector set is append-only; expected at least the original 6, got {}",
        fixture.vectors.len()
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

/// Decode direction: every canonical envelope must retrieve to the exact
/// original payload bytes, format, and size.
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
#[test]
fn vectors_reencode_byte_identical() {
    let storage = ByteStorage::new(None);
    for vector in load_fixture().vectors {
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
#[test]
fn envelope_codec_roundtrip_byte_identical() {
    for vector in load_fixture().vectors {
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
