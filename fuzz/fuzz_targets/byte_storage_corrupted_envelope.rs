#![no_main]

use cachekit_core::byte_storage::assert_one_pass_matches_full_decode;
use cachekit_core::ByteStorage;
use libfuzzer_sys::fuzz_target;

// Attack: malformed and corrupted envelopes through the envelope decode.
// Validates: fail-closed rejection without panics, and that the one-pass decode agrees with the full decode.

fuzz_target!(|data: &[u8]| {
    // The input as envelope bytes.
    assert_one_pass_matches_full_decode(data);

    // The input as an envelope `store` writes, then corrupted, which reaches
    // the one-pass decode's boundaries far more often than raw bytes do. The
    // first byte picks up to three 3-byte edits (a position and a byte) and
    // what they do; the rest is the stored value.
    let Some((&plan, rest)) = data.split_first() else {
        return;
    };
    let Some((edits, value)) = rest.split_at_checked(usize::from(plan % 4) * 3) else {
        return;
    };
    let mut envelope = ByteStorage::new(None).store(value, None).unwrap();
    for edit in edits.chunks_exact(3) {
        // Up to one past the end, so an edit can also append.
        let pos = usize::from(u16::from_be_bytes([edit[0], edit[1]])) % (envelope.len() + 1);
        match plan >> 2 & 3 {
            0 if pos < envelope.len() => envelope[pos] = edit[2],
            1 => envelope.truncate(pos),
            _ => envelope.insert(pos, edit[2]),
        }
    }
    assert_one_pass_matches_full_decode(&envelope);
});
