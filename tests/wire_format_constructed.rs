//! wire-format.json `constructed_vectors`: the 32-bit ratio-product vector.
//!
//! `envelope_ratio_product_wraps_32_bits` has 4,294,968 B of `compressed_data`,
//! the first length at which `1000 * compressed_size` overflows 32 bits, and
//! an `original_size` inside the 1000:1 bound. A reader that computes the
//! ratio product in 32 bits gets 704 and rejects it as a bomb. On a 64-bit
//! host a pointer-width product is exact, so a pass there proves nothing about
//! a 32-bit target: the spec requires this vector to pass on each 32-bit
//! target the crate supports, which for this crate is wasm32. This file runs
//! natively under libtest and on `wasm32-unknown-unknown` under
//! `wasm-bindgen-test` (see the `wasm32` job in `.github/workflows/ci.yml`).
//!
//! The fixture is the same vendored file `wire_format_vectors.rs` pins by
//! sha256.

#![cfg(all(feature = "compression", feature = "checksum", feature = "messagepack"))]

use cachekit_core::ByteStorage;

const FIXTURE: &str = include_str!("vectors/wire-format.json");

const VECTOR: &str = "envelope_ratio_product_wraps_32_bits";

#[derive(serde::Deserialize)]
struct Fixture {
    /// Defaulted so a fixture without the group fails the named assert below,
    /// not a serde error.
    #[serde(default)]
    constructed_vectors: Vec<ConstructedVector>,
}

#[derive(serde::Deserialize)]
struct ConstructedVector {
    name: String,
    format: String,
    original_size: usize,
    compressed_size: usize,
    envelope_size: usize,
    checksum_hex: String,
    envelope_construction: Vec<Segment>,
    input_construction: Vec<Segment>,
}

/// `count` repetitions of the bytes in `hex`.
#[derive(serde::Deserialize)]
struct Segment {
    hex: String,
    count: usize,
}

fn build(segments: &[Segment]) -> Vec<u8> {
    let mut out = Vec::new();
    for segment in segments {
        let bytes = hex::decode(&segment.hex).expect("segment hex must decode");
        for _ in 0..segment.count {
            out.extend_from_slice(&bytes);
        }
    }
    out
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn envelope_ratio_product_wraps_32_bits() {
    let fixture: Fixture =
        serde_json::from_str(FIXTURE).expect("wire-format.json fixture must parse");
    assert!(
        !fixture.constructed_vectors.is_empty(),
        "wire-format.json constructed_vectors group is missing or empty"
    );
    let vector = fixture
        .constructed_vectors
        .iter()
        .find(|v| v.name == VECTOR)
        .unwrap_or_else(|| panic!("constructed_vectors has no {VECTOR:?} vector"));

    let envelope = build(&vector.envelope_construction);
    let input = build(&vector.input_construction);
    assert_eq!(
        envelope.len(),
        vector.envelope_size,
        "envelope_size mismatch"
    );
    assert_eq!(input.len(), vector.original_size, "original_size mismatch");
    // The point of the vector: the product overflows 32 bits.
    assert!(
        (1000u64 * vector.compressed_size as u64) > u64::from(u32::MAX),
        "compressed_size no longer overflows a 32-bit ratio product"
    );
    assert_eq!(
        hex::encode(cachekit_core::checksum(&input)),
        vector.checksum_hex,
        "input_construction does not match checksum_hex"
    );

    let (payload, format) = ByteStorage::new(None)
        .retrieve(&envelope)
        .unwrap_or_else(|e| panic!("[{VECTOR}] retrieve failed: {e:?}"));
    // Not assert_eq!: a failure would print two 8 MB vectors.
    assert!(
        payload == input,
        "[{VECTOR}] decoded payload differs from the constructed input ({} B vs {} B)",
        payload.len(),
        input.len()
    );
    assert_eq!(format, vector.format, "[{VECTOR}] format mismatch");
}
