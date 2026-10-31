#![no_main]

use cachekit_core::byte_storage::{fuzz_envelope_decodes, StorageEnvelope};
use cachekit_core::ByteStorage;
use libfuzzer_sys::fuzz_target;

// Attack: malformed and near-canonical envelopes through the envelope decode.
// Validates, besides fail-closed rejection without panics, that the one-pass
// decode `retrieve` tries first agrees with the pre-scan plus serde decode it
// falls back to: it accepts only what that decode accepts, into the same
// fields, and `retrieve` returns what that decode would give it, error text
// included.

fuzz_target!(|data: &[u8]| {
    // The input as envelope bytes.
    check(data);

    // The input as an envelope `store` writes, then corrupted, which reaches
    // the one-pass decode's boundaries far more often than raw bytes do. The
    // first byte picks up to three 3-byte edits (a position and a byte) and
    // what they do; the rest is the stored value.
    let Some((&plan, rest)) = data.split_first() else {
        return;
    };
    let edit_bytes = usize::from(plan % 4) * 3;
    let Some((edits, value)) = rest.split_at_checked(edit_bytes) else {
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
    check(&envelope);
});

fn check(bytes: &[u8]) {
    let (one_pass, full, decoded) = fuzz_envelope_decodes(bytes);
    match (&one_pass, &full) {
        (Some(one), Ok(full)) => assert_eq!(one, full, "one-pass and full decodes differ"),
        (Some(_), Err(e)) => panic!("one-pass decode accepted what the full decode rejects: {e}"),
        _ => {}
    }
    assert_eq!(decoded, full, "decode_envelope differs from the full decode");

    // `retrieve` is the full decode's fields, extracted.
    let expected = full.and_then(|(compressed_data, checksum, original_size, format)| {
        let envelope = StorageEnvelope {
            compressed_data,
            checksum,
            original_size,
            format,
        };
        envelope.extract().map(|data| (data, envelope.format))
    });
    assert_eq!(ByteStorage::new(None).retrieve(bytes), expected);
}
