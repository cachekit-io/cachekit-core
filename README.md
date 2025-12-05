# cachekit-core

<div align="center">

**LZ4 compression, xxHash3 integrity, AES-256-GCM encryption — for arbitrary byte payloads.**

[![Crates.io](https://img.shields.io/crates/v/cachekit-core.svg)](https://crates.io/crates/cachekit-core)
[![Documentation](https://docs.rs/cachekit-core/badge.svg)](https://docs.rs/cachekit-core)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0.html)

[Features](#features) · [Quick Start](#quick-start) · [FFI](#c-ffi) · [Security](#security) · [Architecture](#architecture)

</div>

---

## Overview

`cachekit-core` transforms byte payloads: compress them, verify their integrity, encrypt them. Bytes in, bytes out.

| Component | What it does |
|:----------|:-------------|
| **ByteStorage** | `&[u8]` → LZ4 compress → xxHash3 checksum → `Vec<u8>` envelope |
| **Encryption** | `&[u8]` → AES-256-GCM encrypt → `Vec<u8>` ciphertext |
| **Key Derivation** | Master key → HKDF-SHA256 → derived key per tenant/domain |

> [!TIP]
> For Redis caching with Python decorators, see [`cachekit`](https://github.com/cachekit-io/cachekit).

---

## Features

| Feature | Description | Default |
|:--------|:------------|:-------:|
| `compression` | LZ4 compression via [`lz4_flex`](https://crates.io/crates/lz4_flex) | ✅ |
| `checksum` | [`xxhash-rust`](https://crates.io/crates/xxhash-rust) integrity verification | ✅ |
| `encryption` | AES-256-GCM via [`ring`](https://crates.io/crates/ring) + HKDF-SHA256 | ❌ |
| `ffi` | C header generation | ❌ |

```toml
# Cargo.toml - defaults only
[dependencies]
cachekit-core = "0.1"

# With encryption
[dependencies]
cachekit-core = { version = "0.1", features = ["encryption"] }

# For C FFI development
[dependencies]
cachekit-core = { version = "0.1", features = ["ffi", "encryption"] }
```

---

## Quick Start

### Basic Storage (Compress + Checksum)

```rust
use cachekit_core::ByteStorage;

// Create storage with default format
let storage = ByteStorage::new(None);

// Store data (compresses + checksums automatically)
let data = b"Hello, cachekit!";
let envelope = storage.store(data, None)?;

// Retrieve data (decompresses + verifies checksum)
let (retrieved, format) = storage.retrieve(&envelope)?;
assert_eq!(data.as_slice(), retrieved.as_slice());
```

### With Encryption (Zero-Knowledge)

```rust
use cachekit_core::{ByteStorage, ZeroKnowledgeEncryptor, derive_domain_key};

// Derive tenant-isolated key from master secret
let master_key = [0u8; 32]; // Use secure key in production!
let tenant_key = derive_domain_key(
    &master_key,
    "cache",           // domain separation
    b"tenant-12345",   // tenant isolation
)?;

// Encrypt sensitive data
let encryptor = ZeroKnowledgeEncryptor::new();
let plaintext = b"sensitive user data";
let aad = b"tenant-12345"; // Additional authenticated data

let ciphertext = encryptor.encrypt_aes_gcm(plaintext, &tenant_key, aad)?;

// Decrypt (fails if AAD doesn't match)
let decrypted = encryptor.decrypt_aes_gcm(&ciphertext, &tenant_key, aad)?;
assert_eq!(plaintext.as_slice(), decrypted.as_slice());
```

> [!IMPORTANT]
> **Key Management**: Never hardcode keys. Use environment variables or a secrets manager. The `CACHEKIT_MASTER_KEY` environment variable is the recommended approach.

<details>
<summary><strong>Full Pipeline: Compress → Encrypt → Store</strong></summary>

```rust
use cachekit_core::{ByteStorage, ZeroKnowledgeEncryptor, derive_domain_key};

fn cache_sensitive_data(
    data: &[u8],
    master_key: &[u8],
    tenant_id: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Step 1: Compress + checksum
    let storage = ByteStorage::new(None);
    let compressed = storage.store(data, None)?;

    // Step 2: Derive tenant key
    let tenant_key = derive_domain_key(master_key, "cache", tenant_id.as_bytes())?;

    // Step 3: Encrypt compressed envelope
    let encryptor = ZeroKnowledgeEncryptor::new();
    let ciphertext = encryptor.encrypt_aes_gcm(
        &compressed,
        &tenant_key,
        tenant_id.as_bytes(),
    )?;

    Ok(ciphertext)
}
```

</details>

---

## C FFI

Build with FFI feature to generate `include/cachekit.h`:

```bash
cargo build --release --features ffi
```

This produces:
- `target/release/libcachekit_core.{so,dylib,dll}` — Shared library
- `include/cachekit.h` — C header file

<details>
<summary><strong>Example C Usage</strong></summary>

```c
#include "cachekit.h"
#include <stdio.h>

int main() {
    // Create storage handle
    CachekitByteStorage* storage = cachekit_byte_storage_new(NULL);

    // Store data
    const uint8_t data[] = "Hello from C!";
    uint8_t* envelope = NULL;
    size_t envelope_len = 0;

    CachekitError err = cachekit_byte_storage_store(
        storage, data, sizeof(data) - 1, NULL, &envelope, &envelope_len
    );

    if (err != CACHEKIT_OK) {
        printf("Store failed: %d\n", err);
        return 1;
    }

    // Retrieve data
    uint8_t* retrieved = NULL;
    size_t retrieved_len = 0;

    err = cachekit_byte_storage_retrieve(
        storage, envelope, envelope_len, &retrieved, &retrieved_len
    );

    // Cleanup
    cachekit_byte_storage_free(storage);
    cachekit_free_buffer(envelope);
    cachekit_free_buffer(retrieved);

    return 0;
}
```

**Compile:**
```bash
gcc -o example example.c -L target/release -lcachekit_core -I include
```

</details>

---

## Security

```
┌─────────────────────────────────────────────────────────────────┐
│                     Security Architecture                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Master Key ──┬──► HKDF-SHA256 ──► Tenant Key A                 │
│               │                                                  │
│               ├──► HKDF-SHA256 ──► Tenant Key B                 │
│               │                                                  │
│               └──► HKDF-SHA256 ──► Tenant Key N                 │
│                                                                  │
│  Each tenant key provides:                                       │
│  • Cryptographic isolation (compromise one ≠ compromise all)    │
│  • Domain separation (cache vs auth vs sessions)                │
│  • Forward secrecy with key rotation                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

| Property | Implementation |
|:---------|:---------------|
| **Encryption** | AES-256-GCM (AEAD) via [`ring`](https://crates.io/crates/ring) |
| **Key Derivation** | HKDF-SHA256 (RFC 5869) via [`hkdf`](https://crates.io/crates/hkdf) |
| **Integrity** | [`xxhash-rust`](https://crates.io/crates/xxhash-rust) (xxHash3-64) |
| **Nonce Safety** | Counter-based + random IV (no reuse) |
| **Memory Safety** | [`zeroize`](https://crates.io/crates/zeroize) on drop for all key material |
| **Timing Safety** | Constant-time comparisons via [`ring`](https://crates.io/crates/ring) |

> [!WARNING]
> **Nonce Counter**: Each `ZeroKnowledgeEncryptor` instance supports 2³² encryptions before requiring rotation. The FFI layer returns `CACHEKIT_ROTATION_NEEDED` at 2³¹ operations as an early warning.

<details>
<summary><strong>Decompression Bomb Protection</strong></summary>

All decompression operations enforce:

| Limit | Value | Purpose |
|:------|:------|:--------|
| Max uncompressed size | 512 MB | Memory exhaustion prevention |
| Max compressed size | 512 MB | Input validation |
| Max compression ratio | 1000x | Decompression bomb detection |

Malicious payloads claiming `original_size: 500GB` with 100 bytes of data are rejected **before** decompression.

</details>

---

## Architecture

```
cachekit-core/
├── src/
│   ├── lib.rs              # Public API exports
│   ├── byte_storage.rs     # LZ4 + xxHash3 storage envelope
│   ├── metrics.rs          # Operation timing & statistics
│   │
│   ├── encryption/         # (feature = "encryption")
│   │   ├── mod.rs          # Module exports
│   │   ├── core.rs         # AES-256-GCM implementation
│   │   ├── key_derivation.rs # HKDF-SHA256 + tenant isolation
│   │   └── key_rotation.rs # Graceful key rotation support
│   │
│   └── ffi/                # (feature = "ffi")
│       ├── mod.rs          # FFI exports
│       ├── error.rs        # C-compatible error codes
│       ├── handles.rs      # Opaque handle management
│       ├── byte_storage.rs # ByteStorage FFI bindings
│       └── encryption.rs   # Encryption FFI bindings
│
├── include/
│   └── cachekit.h          # Generated C header
│
├── fuzz/                   # Fuzzing targets (16 targets)
│   └── fuzz_targets/
│
└── tests/                  # Integration & property tests
```

---

## Performance

Benchmarks on Apple M2 Max (64KB payload, compressible data):

| Operation | Throughput | Notes |
|:----------|:-----------|:------|
| LZ4 compress | ~15 GB/s | Highly compressible data |
| LZ4 decompress | ~37 GB/s | |
| xxHash3-64 | ~36 GB/s | 19x faster than Blake3 |
| AES-256-GCM encrypt | ~6 GB/s | ARM Crypto Extensions |
| AES-256-GCM decrypt | ~6 GB/s | ARM Crypto Extensions |

<details>
<summary><strong>1KB payload (per-call overhead visible)</strong></summary>

| Operation | Throughput |
|:----------|:-----------|
| LZ4 compress | ~2 GB/s |
| LZ4 decompress | ~14 GB/s |
| xxHash3-64 | ~10 GB/s |
| AES-256-GCM encrypt | ~3.6 GB/s |
| AES-256-GCM decrypt | ~4.4 GB/s |

</details>

> [!TIP]
> Hardware acceleration is auto-detected. ARM64 uses ARM Crypto Extensions; x86-64 uses AES-NI.

---

## Testing

```bash
# Run all tests
cargo test --all-features

# Run with specific feature
cargo test --features encryption

# Property-based tests
cargo test --all-features -- --include-ignored proptest

# Fuzzing (requires cargo-fuzz)
cd fuzz && cargo fuzz run byte_storage_corrupted_envelope
```

See [`fuzz/README.md`](fuzz/README.md) for comprehensive fuzzing documentation.

---

## Minimum Supported Rust Version

This crate requires **Rust 1.85** or later (Edition 2024).

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**[Documentation](https://docs.rs/cachekit-core)** · **[Crates.io](https://crates.io/crates/cachekit-core)** · **[GitHub](https://github.com/cachekit-io/cachekit-core)**

</div>
