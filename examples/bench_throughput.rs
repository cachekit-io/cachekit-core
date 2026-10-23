//! Wall-clock figures for the README's Performance table.
//!
//! Run with: `cargo run --release --example bench_throughput --features encryption`
//!
//! Times cachekit-core's own calls on the realistic msgpack payload that
//! `benches/hot_path.rs` and `benches/perf_ir.rs` use, so all three measure the
//! same bytes. Each figure is the median of 21 batches, and the median batch
//! runs for at least 10 ms.
//! Inputs and results go through `black_box`, so the optimizer cannot drop
//! the work being timed. The output is a Markdown table.

use std::hint::black_box;
use std::time::{Duration, Instant};

use cachekit_core::{derive_domain_key, ByteStorage, StorageEnvelope, ZeroKnowledgeEncryptor};

#[path = "../benches/common/mod.rs"]
mod common;
use common::msgpack_payload;

/// A typical cached value and a large object.
const SIZES: [usize; 2] = [1024, 64 * 1024];
const BATCHES: usize = 21;
const MIN_BATCH: Duration = Duration::from_millis(10);

// The key, tenant and AAD fixtures of benches/perf_ir.rs.
const MASTER_KEY: [u8; 32] = [0x42; 32];
const TENANT: &str = "tenant-123";
const AAD: &[u8] = b"\x03\x00\x00\x00\x0atenant-123\x00\x00\x00\x10ns:bench:func:x";

/// Median nanoseconds per call of `op`.
fn ns_per_op(mut op: impl FnMut()) -> f64 {
    // Double the batch until one takes MIN_BATCH; this also warms up.
    let mut n: u32 = 1;
    loop {
        let start = Instant::now();
        for _ in 0..n {
            op();
        }
        if start.elapsed() >= MIN_BATCH {
            break;
        }
        n *= 2;
    }
    loop {
        let mut samples: Vec<f64> = (0..BATCHES)
            .map(|_| {
                let start = Instant::now();
                for _ in 0..n {
                    op();
                }
                start.elapsed().as_nanos() as f64 / f64::from(n)
            })
            .collect();
        samples.sort_by(f64::total_cmp);
        let median = samples[BATCHES / 2];
        // A pause during calibration can leave `n` too small. Judge the batches
        // as timed, by their median rather than one by one, so no sample is
        // dropped for being fast.
        if median * f64::from(n) >= MIN_BATCH.as_nanos() as f64 {
            return median;
        }
        n *= 2;
    }
}

/// "1.23 µs · 0.83 GB/s". One byte per nanosecond is one GB/s.
fn cell(ns: f64, bytes: usize) -> String {
    let time = if ns < 1_000.0 {
        format!("{ns:.0} ns")
    } else if ns < 1_000_000.0 {
        format!("{:.2} µs", ns / 1_000.0)
    } else {
        format!("{:.2} ms", ns / 1_000_000.0)
    };
    format!("{time} · {:.2} GB/s", bytes as f64 / ns)
}

fn main() {
    let storage = ByteStorage::new(None);
    let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
    let key = derive_domain_key(&MASTER_KEY, "encryption", TENANT.as_bytes()).unwrap();

    let mut rows = [
        ("`ByteStorage::store`", Vec::new()),
        ("`ByteStorage::retrieve`", Vec::new()),
        ("`encrypt_aes_gcm`", Vec::new()),
        ("`decrypt_aes_gcm`", Vec::new()),
    ];
    let mut ratios = Vec::new();
    for size in SIZES {
        let payload = msgpack_payload(size);
        let envelope = storage.store(&payload, None).unwrap();
        let ciphertext = encryptor.encrypt_aes_gcm(&payload, &key, AAD).unwrap();
        let compressed = rmp_serde::from_slice::<StorageEnvelope>(&envelope)
            .unwrap()
            .compressed_data
            .len();
        ratios.push(format!("{:.2}", compressed as f64 / size as f64));

        let timings = [
            ns_per_op(|| {
                black_box(storage.store(black_box(&payload), None).unwrap());
            }),
            ns_per_op(|| {
                black_box(storage.retrieve(black_box(&envelope)).unwrap());
            }),
            ns_per_op(|| {
                black_box(
                    encryptor
                        .encrypt_aes_gcm(black_box(&payload), &key, AAD)
                        .unwrap(),
                );
            }),
            ns_per_op(|| {
                black_box(
                    encryptor
                        .decrypt_aes_gcm(black_box(&ciphertext), &key, AAD)
                        .unwrap(),
                );
            }),
        ];
        for (row, ns) in rows.iter_mut().zip(timings) {
            row.1.push(cell(ns, size));
        }
    }

    let accel = if encryptor.hardware_acceleration_enabled() {
        "yes"
    } else {
        "no"
    };
    println!(
        "cachekit-core {} on {}/{}, AES hardware acceleration: {accel}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
    );
    let ratios = ratios.join(", ");
    println!("LZ4 compressed/raw ratio: {ratios} (1 KiB, 64 KiB)\n");
    println!("| Operation | 1 KiB | 64 KiB |");
    println!("|:----------|------:|-------:|");
    for (name, cells) in rows {
        println!("| {name} | {} |", cells.join(" | "));
    }
}
