//! Payload generators shared by the bench targets. `hot_path` (Criterion wall
//! clock) and `perf_ir` (instruction counts) must measure the same bytes, or
//! their figures cannot be read against each other.

use serde::Serialize;

pub fn xorshift(mut state: u64) -> u64 {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state
}

/// A typical cached row: what the SDKs hand ByteStorage after msgpack-encoding
/// a dict/object with string keys.
#[derive(Serialize)]
struct Record {
    id: u64,
    user: String,
    email: String,
    score: f64,
    active: bool,
    tags: Vec<&'static str>,
    created_at: String,
}

/// Realistic payload: a stream of msgpack-named records with deterministic,
/// varied values, truncated to `size`. ByteStorage treats the payload as
/// opaque bytes, so the cut tail does not affect what is measured.
pub fn msgpack_payload(size: usize) -> Vec<u8> {
    const TAGS: &[&str] = &["free", "pro", "trial", "eu", "us", "beta", "admin"];
    let mut state: u64 = 0x2545f4914f6cdd1d;
    let mut out = Vec::with_capacity(size + 256);
    let mut id = 0u64;
    while out.len() < size {
        state = xorshift(state);
        id += 1;
        let record = Record {
            id: 1_000_000 + id,
            user: format!("user_{:x}", state % 0xff_ffff),
            email: format!("u{}@example{}.com", state % 100_000, state % 7),
            score: (state % 10_000) as f64 / 100.0,
            active: state % 3 != 0,
            tags: (0..(state % 4) as usize)
                .map(|i| TAGS[(state as usize >> (8 * i)) % TAGS.len()])
                .collect(),
            created_at: format!(
                "2026-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                1 + state % 12,
                1 + (state >> 8) % 28,
                (state >> 16) % 24,
                (state >> 24) % 60,
                (state >> 32) % 60
            ),
        };
        out.extend_from_slice(&rmp_serde::to_vec_named(&record).unwrap());
    }
    out.truncate(size);
    out
}
