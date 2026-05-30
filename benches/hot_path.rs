//! Criterion benchmark suite for cachekit-core hot paths.
//!
//! Run with: `cargo bench -p cachekit-core --features encryption`
//! Output: `target/criterion/<bench_id>/report/index.html`
//!
//! This is the PGO training workload — extend with new groups as hot
//! paths are identified. Sizes chosen to span the realistic cache-payload
//! distribution (64B keys, 1KB values, 64KB large objects).

use cachekit_core::{ByteStorage, ZeroKnowledgeEncryptor};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

const SIZES: &[usize] = &[64, 256, 1024, 4 * 1024, 16 * 1024, 64 * 1024];

fn make_payload(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
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

criterion_group!(benches, bench_byte_storage_roundtrip, bench_encrypt_decrypt);
criterion_main!(benches);
