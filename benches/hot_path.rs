//! Criterion benchmark suite for cachekit-core hot paths.
//!
//! Run with: `cargo bench -p cachekit-core --features encryption`
//! Output: `target/criterion/<bench_id>/report/index.html`
//!
//! This is the PGO training workload — extend with new groups as hot
//! paths are identified. Sizes chosen to span the realistic cache-payload
//! distribution (64B keys, 1KB values, 64KB large objects).

use cachekit_core::{ByteStorage, StorageEnvelope, ZeroKnowledgeEncryptor};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

const SIZES: &[usize] = &[64, 256, 1024, 4 * 1024, 16 * 1024, 64 * 1024];

fn make_payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Deterministic xorshift64* stream — incompressible payload without a rand
/// dependency (same generator as tests/dual_decode.rs).
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

/// Protocol 1.1 bin-encoding proof workload (LAB-764 / LAB-866): 64 MiB
/// incompressible payload, where compressed_data dominates the envelope and
/// the array-of-ints vs msgpack-bin difference is fully visible. Measures the
/// envelope codec in isolation (rmp encode/decode of StorageEnvelope) and the
/// full store()/retrieve() e2e paths.
fn bench_envelope_codec_64mib(c: &mut Criterion) {
    const SIZE: usize = 64 * 1024 * 1024;
    let storage = ByteStorage::new(None);
    let payload = incompressible(SIZE);
    let wire = storage.store(&payload, None).unwrap();
    let envelope: StorageEnvelope = rmp_serde::from_slice(&wire).unwrap();
    // Self-enforcing workload check: LZ4 overhead is positive on incompressible
    // input, so a generator regression toward compressible data fails here
    // instead of silently benchmarking the wrong workload.
    assert!(
        envelope.compressed_data.len() >= SIZE,
        "bench payload must be incompressible"
    );
    eprintln!(
        "64mib_incompressible: compressed_data {} B, envelope wire {} B (ratio {:.4})",
        envelope.compressed_data.len(),
        wire.len(),
        wire.len() as f64 / envelope.compressed_data.len() as f64
    );

    let mut group = c.benchmark_group("byte_storage/64mib_incompressible");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(SIZE as u64));
    group.bench_function("envelope_encode", |b| {
        b.iter(|| black_box(rmp_serde::to_vec(black_box(&envelope)).unwrap()));
    });
    group.bench_function("envelope_decode", |b| {
        b.iter(|| black_box(rmp_serde::from_slice::<StorageEnvelope>(black_box(&wire)).unwrap()));
    });
    group.bench_function("store_e2e", |b| {
        b.iter(|| black_box(storage.store(black_box(&payload), None).unwrap()));
    });
    group.bench_function("retrieve_e2e", |b| {
        b.iter(|| black_box(storage.retrieve(black_box(&wire)).unwrap()));
    });
    group.finish();
}

fn bench_byte_storage_roundtrip(c: &mut Criterion) {
    let storage = ByteStorage::new(None);
    let mut group = c.benchmark_group("byte_storage/roundtrip");
    for &size in SIZES {
        let data = make_payload(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let envelope = storage.store(black_box(data), None).unwrap();
                let (out, _fmt) = storage.retrieve(black_box(&envelope)).unwrap();
                black_box(out);
            });
        });
    }
    group.finish();
}

fn bench_encrypt_decrypt(c: &mut Criterion) {
    let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
    let key = [0x42u8; 32];
    let aad = b"bench-aad";
    let mut group = c.benchmark_group("encryption/aes_gcm_roundtrip");
    for &size in SIZES {
        let plaintext = make_payload(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| {
                let ct = encryptor.encrypt_aes_gcm(black_box(pt), &key, aad).unwrap();
                let pt2 = encryptor
                    .decrypt_aes_gcm(black_box(&ct), &key, aad)
                    .unwrap();
                black_box(pt2);
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_byte_storage_roundtrip,
    bench_encrypt_decrypt,
    bench_envelope_codec_64mib
);
criterion_main!(benches);
