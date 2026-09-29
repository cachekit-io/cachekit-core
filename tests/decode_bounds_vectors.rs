//! Decode-bounds vectors through `ByteStorage::retrieve`.
//!
//! `retrieve` is the untrusted envelope decode that cachekit-py and cachekit-ts
//! (NAPI and wasm) reach, so the protocol requires it to pre-scan the envelope
//! bytes before materialising a `StorageEnvelope` (`protocol/spec/wire-format.md`
//! → Retrieve Flow, step 2; the bounds are `spec/interop-mode.md` → Decode
//! bounds). Asserting only that a reject vector fails would not show that: a
//! bare decoder fails on every one of them too, after it has started
//! materialising. Each reject vector must therefore fail with the message
//! prefix that only the pre-scan produces.
//!
//! Fixture provenance: vendored from
//! <https://github.com/cachekit-io/protocol> `test-vectors/decode-bounds.json`
//! at commit `1729eb7e94909e2df4e22d1da090de0001cc7bdf`, integrity-pinned by
//! sha256 below. To update: copy the file from a newer protocol ref, update
//! `FIXTURE_SHA256` and this comment's commit hash together.

#![cfg(all(feature = "compression", feature = "checksum", feature = "messagepack"))]

use cachekit_core::byte_storage::ByteStorageError;
use cachekit_core::{ByteStorage, StorageEnvelope};
use sha2::{Digest, Sha256};

/// Compiled-in fixture: no runtime path resolution, so the test can never be
/// silently skipped by a missing file.
const FIXTURE: &str = include_str!("vectors/decode-bounds.json");

/// sha256 of the vendored fixture — must match the protocol repo's copy.
const FIXTURE_SHA256: &str = "907b025d2b270a0f60abd9296a8a1c864e69057c553ac7a70206b44256558916"; // pragma: allowlist secret

/// Prefix of every pre-scan rejection. A decoder error can echo attacker
/// bytes (a string value in an "invalid type" message), but never at the start
/// of the message, so only a `starts_with` match is unforgeable.
const PRE_SCAN: &str = "decode pre-scan: ";

/// The crate's nesting bound, pinned here so a change to it is deliberate.
const MAX_DEPTH: usize = 100;

#[derive(serde::Deserialize)]
struct Fixture {
    version: String,
    reject_vectors: Vec<Vector>,
    accept_vectors: Vec<Vector>,
}

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    input_hex: String,
    input_len: usize,
    #[serde(default)]
    reject_reasons: Vec<String>,
}

impl Vector {
    fn input(&self) -> Vec<u8> {
        let bytes = hex::decode(&self.input_hex).expect("input_hex must be hex");
        assert_eq!(bytes.len(), self.input_len, "[{}] input_len", self.name);
        bytes
    }
}

fn load_fixture() -> Fixture {
    serde_json::from_str(FIXTURE).expect("decode-bounds.json fixture must parse")
}

fn pre_scan_message(result: &Result<(Vec<u8>, String), ByteStorageError>) -> Option<&str> {
    match result {
        Err(ByteStorageError::DeserializationFailed(msg)) => msg.strip_prefix(PRE_SCAN),
        _ => None,
    }
}

#[test]
fn fixture_integrity_pinned_sha256() {
    let digest = hex::encode(Sha256::digest(FIXTURE.as_bytes()));
    assert_eq!(
        digest, FIXTURE_SHA256,
        "vendored decode-bounds.json drifted from its pinned sha256 — \
         re-vendor from the protocol repo and update FIXTURE_SHA256 deliberately"
    );
}

#[test]
fn fixture_is_current_version_with_vectors() {
    let fixture = load_fixture();
    assert_eq!(fixture.version, "1.1.0");
    assert_eq!(fixture.reject_vectors.len(), 17);
    assert_eq!(fixture.accept_vectors.len(), 3);
}

#[test]
fn every_reject_vector_is_rejected_by_the_pre_scan() {
    let storage = ByteStorage::new(None);
    for vector in load_fixture().reject_vectors {
        let result = storage.retrieve(&vector.input());
        let reason = pre_scan_message(&result).unwrap_or_else(|| {
            panic!("[{}] not rejected by the pre-scan: {result:?}", vector.name)
        });
        // A depth-only vector is structurally complete, so nothing but the
        // depth bound can reject it. An overclaim-only vector must trip the
        // slot budget, not merely run out of input at the end: a walk that
        // checks each header against the bytes after it alone still reaches
        // end of input on `nested_array16_each_header_fits_sum_overclaims`.
        match vector.reject_reasons.as_slice() {
            [r] if r == "depth" => assert_eq!(
                reason,
                format!("nests deeper than {MAX_DEPTH} levels"),
                "[{}]",
                vector.name
            ),
            [r] if r == "overclaim" => {
                assert!(
                    reason.starts_with("declares more "),
                    "[{}] {reason}",
                    vector.name
                )
            }
            _ => {}
        }
        assert!(!storage.validate(&vector.input()), "[{}]", vector.name);
    }
}

#[test]
fn every_accept_vector_passes_the_pre_scan() {
    // Not envelopes, so the typed decode still rejects them; the pre-scan must not.
    let storage = ByteStorage::new(None);
    for vector in load_fixture().accept_vectors {
        let result = storage.retrieve(&vector.input());
        assert_eq!(
            pre_scan_message(&result),
            None,
            "[{}] {result:?}",
            vector.name
        );
    }
}

/// A real envelope in map form with one extra, unknown key whose value nests
/// `depth - 1` arrays, so the whole document nests `depth` deep (the root map
/// is one level). Serde's derive skips the unknown key with `IgnoredAny`,
/// which recurses once per level.
fn map_form_envelope_nested(storage: &ByteStorage, payload: &[u8], depth: usize) -> Vec<u8> {
    let envelope: StorageEnvelope =
        rmp_serde::from_slice(&storage.store(payload, None).unwrap()).unwrap();
    let mut doc = rmp_serde::to_vec_named(&envelope).unwrap();
    assert_eq!(
        doc[0], 0x84,
        "to_vec_named must emit a fixmap of the 4 fields"
    );
    doc[0] = 0x85;
    doc.push(0xa0); // key ""
    doc.extend(std::iter::repeat_n(0x91, depth - 1));
    doc.push(0xc0);
    doc
}

#[test]
fn complete_envelope_at_the_depth_bound_decodes_on_small_stacks() {
    // The pre-scan admits a document nested exactly MAX_DEPTH deep, so the
    // typed decode must survive that nesting. 1 MiB is wasm32's default stack.
    for stack in [2 << 20, 1 << 20] {
        let result = std::thread::Builder::new()
            .stack_size(stack)
            .spawn(|| {
                let storage = ByteStorage::new(None);
                let at_bound = map_form_envelope_nested(&storage, b"at the bound", MAX_DEPTH);
                let past_bound = map_form_envelope_nested(&storage, b"at the bound", MAX_DEPTH + 1);
                (storage.retrieve(&at_bound), storage.retrieve(&past_bound))
            })
            .unwrap()
            .join()
            .expect("retrieve panicked");
        let (at_bound, past_bound) = result;
        assert_eq!(
            at_bound,
            Ok((b"at the bound".to_vec(), "msgpack".to_owned())),
            "stack {stack}"
        );
        assert_eq!(
            pre_scan_message(&past_bound),
            Some(format!("nests deeper than {MAX_DEPTH} levels").as_str()),
            "stack {stack}"
        );
    }
}
