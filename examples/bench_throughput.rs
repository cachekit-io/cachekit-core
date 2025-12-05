//! Quick throughput verification - run with: cargo run --release --example bench_throughput --all-features
use std::time::Instant;

fn bench_size(size: usize, iterations: usize) {
    // Compressible data (repeating pattern)
    let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
    // Pseudo-random data for encryption
    let random: Vec<u8> = (0..size).map(|i| ((i * 17 + 31) % 256) as u8).collect();

    let size_label = if size >= 1024 * 1024 {
        format!("{}MB", size / 1024 / 1024)
    } else if size >= 1024 {
        format!("{}KB", size / 1024)
    } else {
        format!("{}B", size)
    };

    println!("\n=== {} data, {} iterations ===", size_label, iterations);

    // LZ4 Compress
    {
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = lz4_flex::compress_prepend_size(&data);
        }
        let elapsed = start.elapsed();
        let bytes_per_sec = (size * iterations) as f64 / elapsed.as_secs_f64();
        println!("LZ4 compress:    {:.2} GB/s", bytes_per_sec / 1e9);
    }

    // LZ4 Decompress
    {
        let compressed = lz4_flex::compress_prepend_size(&data);
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = lz4_flex::decompress_size_prepended(&compressed).unwrap();
        }
        let elapsed = start.elapsed();
        let bytes_per_sec = (size * iterations) as f64 / elapsed.as_secs_f64();
        println!("LZ4 decompress:  {:.2} GB/s", bytes_per_sec / 1e9);
    }

    // xxHash3-64
    {
        use xxhash_rust::xxh3::xxh3_64;
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = xxh3_64(&data);
        }
        let elapsed = start.elapsed();
        let bytes_per_sec = (size * iterations) as f64 / elapsed.as_secs_f64();
        println!("xxHash3-64:      {:.2} GB/s", bytes_per_sec / 1e9);
    }

    // AES-256-GCM Encrypt
    #[cfg(feature = "encryption")]
    {
        use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
        let key_bytes = [0u8; 32];
        let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
        let key = LessSafeKey::new(unbound);
        let nonce_bytes = [0u8; 12];

        let start = Instant::now();
        for _ in 0..iterations {
            let mut buf = random.clone();
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let _ = key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf);
        }
        let elapsed = start.elapsed();
        let bytes_per_sec = (size * iterations) as f64 / elapsed.as_secs_f64();
        println!("AES-GCM enc:     {:.2} GB/s", bytes_per_sec / 1e9);
    }

    // AES-256-GCM Decrypt
    #[cfg(feature = "encryption")]
    {
        use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
        let key_bytes = [0u8; 32];
        let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
        let key = LessSafeKey::new(unbound);
        let nonce_bytes = [0u8; 12];

        let mut encrypted = random.clone();
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut encrypted)
            .unwrap();

        let start = Instant::now();
        for _ in 0..iterations {
            let mut buf = encrypted.clone();
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let _ = key.open_in_place(nonce, Aad::empty(), &mut buf);
        }
        let elapsed = start.elapsed();
        let bytes_per_sec = (size * iterations) as f64 / elapsed.as_secs_f64();
        println!("AES-GCM dec:     {:.2} GB/s", bytes_per_sec / 1e9);
    }

    // Suppress unused variable warning when encryption feature is disabled
    let _ = random;
}

fn main() {
    println!("Throughput benchmark on Apple M2 Max\n");

    // Small data (call overhead visible)
    bench_size(1024, 100_000); // 1KB

    // Medium data (more realistic)
    bench_size(64 * 1024, 10_000); // 64KB

    // Large data (peak throughput)
    bench_size(1024 * 1024, 100); // 1MB

    println!("\nNote: 1KB shows call overhead; larger sizes show peak throughput.");
}
