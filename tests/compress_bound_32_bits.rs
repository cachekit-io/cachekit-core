//! The LZ4 encoder's output bound on 32-bit targets.
//!
//! `StorageEnvelope::new` sends every input of 64 B or more through
//! `lz4_flex`, which sizes its output as `16 + 4 + input_len * 110 / 100`.
//! lz4_flex 0.12 computed that product in `usize`, so on a 32-bit target it
//! overflowed for any input above 39,045,157 B, far inside the crate's 512 MiB
//! input cap: a debug build panicked on the multiply and a release build
//! panicked on the undersized buffer. 0.13 computes it in `u64`. The test input
//! is one byte past that boundary. On a 64-bit host the product never
//! overflows, so only a 32-bit run proves anything. This file runs natively
//! under libtest and on `wasm32-unknown-unknown` under `wasm-bindgen-test`
//! (see the `wasm32` job in `.github/workflows/ci.yml`).

#![cfg(all(feature = "compression", feature = "checksum", feature = "messagepack"))]

use cachekit_core::ByteStorage;

/// The smallest input whose `input_len * 110` exceeds `u32::MAX`.
const FIRST_OVERFLOWING_LEN: usize = 39_045_158;

const _: () = assert!(39_045_157u64 * 110 <= u32::MAX as u64);
const _: () = assert!(FIRST_OVERFLOWING_LEN as u64 * 110 > u32::MAX as u64);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn store_retrieve_past_32_bit_compress_bound() {
    // A repeating 251-byte cycle: compressible, so the run stays fast in a
    // debug build, and position-dependent, so a shifted round trip fails.
    let data: Vec<u8> = (0..FIRST_OVERFLOWING_LEN)
        .map(|i| (i % 251) as u8)
        .collect();

    let storage = ByteStorage::new(None);
    let stored = storage.store(&data, None).expect("store must succeed");
    let (retrieved, format) = storage.retrieve(&stored).expect("retrieve must succeed");

    assert_eq!(format, "msgpack");
    assert!(retrieved == data, "round trip changed the data");
}
