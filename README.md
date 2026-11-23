# cachekit-core

[![Crates.io](https://img.shields.io/crates/v/cachekit-core.svg)](https://crates.io/crates/cachekit-core) [![Documentation](https://docs.rs/cachekit-core/badge.svg)](https://docs.rs/cachekit-core) [![MSRV](https://img.shields.io/badge/MSRV-1.91-blue.svg)](https://blog.rust-lang.org/2025/10/30/Rust-1.91.0/) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

LZ4 compression, xxHash3 integrity, AES-256-GCM encryption — for arbitrary byte payloads.

## Requirements

New releases support the latest stable Rust. This release requires **Rust 1.91** or later: `rust-version` in `Cargo.toml` is the oldest toolchain CI tests, and any release may raise it when a dependency needs a newer one.

## Installation

```bash
# Defaults only
cargo add cachekit-core

# With encryption
cargo add cachekit-core --features encryption

# For C FFI development
cargo add cachekit-core --features ffi,encryption
```

| Feature | Description | Default |
|:--------|:------------|:-------:|
| `compression` | LZ4 compression via [`lz4_flex`](https://crates.io/crates/lz4_flex) | ✅ |
| `checksum` | [`xxhash-rust`](https://crates.io/crates/xxhash-rust) integrity verification | ✅ |
| `encryption` | AES-256-GCM ([`ring`](https://crates.io/crates/ring) on native, [`aes-gcm`](https://crates.io/crates/aes-gcm) on wasm32) + HKDF-SHA256 ([`hkdf`](https://crates.io/crates/hkdf)) | ❌ |
| `ffi` | C header generation | ❌ |

## Quick start

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

// Or, when the format identifier is not needed (bindings, most callers):
// the same checks and errors, without allocating the format String
let retrieved = storage.retrieve_data(&envelope)?;
```

### With Encryption (Zero-Knowledge)

```rust
use cachekit_core::{ByteStorage, ZeroKnowledgeEncryptor, derive_domain_key};
use zeroize::Zeroizing; // add the zeroize crate to your Cargo.toml

// Derive tenant-isolated key from master secret
// From your secret manager or CACHEKIT_MASTER_KEY, hex-decoded to 32 raw bytes.
// Never hard-code it, and never pass the hex string's bytes.
// Zeroizing wipes each key from memory when it is dropped.
let master_key = Zeroizing::new(load_master_key_from_secret_manager()?);
let tenant_key = Zeroizing::new(derive_domain_key(
    master_key.as_slice(),
    "cache",           // domain separation
    b"tenant-12345",   // tenant isolation
)?);

// Encrypt sensitive data
let encryptor = ZeroKnowledgeEncryptor::new()?;
let plaintext = b"sensitive user data";
let aad = b"tenant-12345"; // Additional authenticated data

let ciphertext = encryptor.encrypt_aes_gcm(plaintext, tenant_key.as_slice(), aad)?;

// Decrypt (fails if AAD doesn't match)
let decrypted = encryptor.decrypt_aes_gcm(&ciphertext, tenant_key.as_slice(), aad)?;
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
    let encryptor = ZeroKnowledgeEncryptor::new()?;
    let ciphertext = encryptor.encrypt_aes_gcm(
        &compressed,
        &tenant_key,
        tenant_id.as_bytes(),
    )?;

    Ok(ciphertext)
}
```

</details>

## Features

`cachekit-core` transforms byte payloads: compress them, verify their integrity, encrypt them. Bytes in, bytes out.

| Component | What it does |
|:----------|:-------------|
| **ByteStorage** | `&[u8]` → LZ4 compress → xxHash3 checksum → `Vec<u8>` envelope |
| **Encryption** | `&[u8]` → AES-256-GCM encrypt → `Vec<u8>` ciphertext |
| **Key Derivation** | Master key → HKDF-SHA256 → derived key per tenant/domain |

> [!TIP]
> For decorator-based caching in Python, see [`cachekit-py`](https://github.com/cachekit-io/cachekit-py).

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

## Encryption

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
│  • Master-key rotation via decrypt-only keyring (grace window)  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

| Property | Implementation |
|:---------|:---------------|
| **Encryption** | AES-256-GCM (AEAD) via [`ring`](https://crates.io/crates/ring) on native, [`aes-gcm`](https://crates.io/crates/aes-gcm) on wasm32 |
| **Key Derivation** | HKDF-SHA256 (RFC 5869) via [`hkdf`](https://crates.io/crates/hkdf) |
| **Integrity** | [`xxhash-rust`](https://crates.io/crates/xxhash-rust) (xxHash3-64) |
| **Nonce Safety** | Counter-based + random IV (no reuse) |
| **Memory Safety** | [`zeroize`](https://crates.io/crates/zeroize) on drop for all key material |
| **Timing Safety** | Constant-time AEAD tag verification: [`ring`](https://crates.io/crates/ring) on native, [`aes-gcm`](https://crates.io/crates/aes-gcm) on wasm32 |

> [!WARNING]
> **Nonce Counter**: Each `ZeroKnowledgeEncryptor` instance supports 2³² encryptions before requiring rotation. The FFI layer returns `CACHEKIT_ROTATION_NEEDED` at 2³¹ operations as an early warning.

## Untrusted input

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

<details>
<summary><strong>Envelope Decode Bounds</strong></summary>

`retrieve()`, `retrieve_data()` and `validate()` read an envelope in any encoding `store()` writes
in one pass, which checks each declared length against the input before reading
it and allocates nothing until the whole envelope has been read. Every input
that read declines gets a header-only structural pre-scan **before** MessagePack
decoding: nesting
deeper than 100 levels, headers declaring more elements or bytes than the input
can back, the reserved marker `0xc1` and truncated input are all rejected
before decoding, without allocating in proportion to any declared length. A
pre-scan rejection is `ByteStorageError::DeserializationFailed` with the message prefix
`decode pre-scan: `. The one-pass read accepts only envelopes the pre-scan and
the typed decode accept, into the same fields, and leaves every rejection to
them, so every input within the size cap gets their result and error. The pre-scan's walk is public as
`check_msgpack_structure(bytes, max_depth)` for callers that decode untrusted
MessagePack themselves; it returns a `MsgpackStructureError` whose `Display` is
the bare reason, with no prefix. `msgpack_document_len(bytes, max_depth)` runs
the same walk and returns the document's length, so a caller that must reject
trailing bytes compares it with `bytes.len()` instead of walking twice. The walk
allocates nothing for a document that nests at most 8 levels deep, and for a
deeper one allocates only for the levels past 8; a rejection allocates its error
message. See
[`SECURITY.md`](SECURITY.md#envelope-decode-bounds).

</details>

## Performance

Single-threaded time per call of cachekit-core's own operations, and the payload bytes each one processes per second, measured with `examples/bench_throughput.rs` on GitHub-hosted runners with Rust 1.99.1.

**x86-64 Linux**: `ubuntu-latest` runner, AMD EPYC 7763 (4 vCPUs), AES-NI

| Operation | 1 KiB | 64 KiB |
|:----------|------:|-------:|
| `ByteStorage::store` | 1.46 µs · 0.70 GB/s | 63.31 µs · 1.04 GB/s |
| `ByteStorage::retrieve` | 555 ns · 1.84 GB/s | 25.26 µs · 2.59 GB/s |
| `encrypt_aes_gcm` | 444 ns · 2.31 GB/s | 10.93 µs · 5.99 GB/s |
| `decrypt_aes_gcm` | 455 ns · 2.25 GB/s | 10.52 µs · 6.23 GB/s |

**arm64 macOS**: `macos-latest` runner, Apple M1 (virtual, 3 vCPUs), ARM Crypto Extensions

| Operation | 1 KiB | 64 KiB |
|:----------|------:|-------:|
| `ByteStorage::store` | 1.81 µs · 0.57 GB/s | 98.92 µs · 0.66 GB/s |
| `ByteStorage::retrieve` | 602 ns · 1.70 GB/s | 21.46 µs · 3.05 GB/s |
| `encrypt_aes_gcm` | 526 ns · 1.95 GB/s | 13.79 µs · 4.75 GB/s |
| `decrypt_aes_gcm` | 568 ns · 1.80 GB/s | 13.26 µs · 4.94 GB/s |

- `store` compresses with LZ4 (an input under 64 bytes is written as one literals-only LZ4 block, without running the compressor; with a format of at most 255 bytes it goes straight into the envelope, so its store allocates only the returned bytes; from 64 bytes to under 4 KiB the compressor reuses one 8 KiB hash table and one 4,524-byte output buffer per thread, kept for the life of the thread), checksums with xxHash3-64 and wraps both in the MessagePack envelope. `retrieve` checks the envelope, decompresses and verifies the checksum.
- `encrypt_aes_gcm` and `decrypt_aes_gcm` are `ZeroKnowledgeEncryptor`'s AES-256-GCM calls with a 34-byte AAD.
- The payload is MessagePack-encoded records (`benches/common/mod.rs`), the corpus `hot_path` and `perf_ir` also use. LZ4 compresses it to 0.57 of its size at 1 KiB and to 0.38 at 64 KiB.
- Each figure is the median of 21 timed batches, from one run on the CPU named. Two runs of this code on the EPYC 7763 agreed within 2% on every cell but one (`decrypt_aes_gcm` at 64 KiB, 23%); three arm64 runs varied by up to 30% on a cell.
- Hosted runners are shared virtual machines, and x86-64 ones also come with other CPU models (AMD EPYC 9V74 and 9V45, Intel Xeon 6973P-C). On those, the same calls took different times, for example 0.6 times as long (`decrypt_aes_gcm` at 64 KiB on the 9V45) and 1.4 times as long (`store` at 64 KiB on the Xeon). Other machines give other figures.

To print the table for your own machine, run `cargo run --release --example bench_throughput --features encryption`, or run the **Bench** workflow from the Actions tab.

> [!NOTE]
> Earlier versions of this table timed the raw LZ4, xxHash3 and AES primitives, not cachekit-core's calls, on a 256-byte repeating pattern that LZ4 compresses almost perfectly. At 64 KiB they read about 15 GB/s for LZ4 compression and 37 GB/s for decompression; on real payloads, `store` and `retrieve` in the tables above move 0.6 to 3.1 GB/s.

> [!TIP]
> Hardware acceleration is auto-detected. ARM64 uses ARM Crypto Extensions; x86-64 uses AES-NI.

## Architecture

```
cachekit-core/
├── src/
│   ├── lib.rs              # Public API exports
│   ├── byte_storage.rs     # LZ4 + xxHash3 storage envelope
│   ├── msgpack_bounds.rs   # Structural pre-scan (public check_msgpack_structure, msgpack_document_len), run before the fallback envelope decode
│   ├── checksum.rs         # Standalone xxHash3 checksum/verify primitive (feature = "checksum")
│   │
│   ├── encryption/         # (feature = "encryption")
│   │   ├── mod.rs          # Module exports
│   │   ├── core.rs         # AES-256-GCM implementation
│   │   ├── key_derivation.rs # HKDF-SHA256 + tenant isolation
│   │   └── keyring.rs      # Multi-key decrypt keyring (master-key rotation)
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
├── benches/
│   ├── hot_path.rs         # Criterion wall-clock suite (make bench)
│   └── perf_ir.rs          # Per-op instruction counts and their gate (make perf-ir)
│
├── fuzz/                   # Fuzzing targets (16 targets)
│   └── fuzz_targets/
│
└── tests/                  # Integration & property tests
```

## Documentation

- [API reference on docs.rs](https://docs.rs/cachekit-core)
- [Protocol specification](https://github.com/cachekit-io/protocol): the canonical cache-key format, wire format, encryption and test vectors shared by every CacheKit SDK

### In this repository

- [`SECURITY.md`](SECURITY.md): security policy, threat model, decompression limits and envelope decode bounds
- [`CHANGELOG.md`](CHANGELOG.md): release notes

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development setup, tests, fuzzing, benchmarks and the crate's performance practices.

User-facing docs in this repository follow CacheKit's shared rule on what belongs in them:
[What belongs in these docs](https://docs.cachekit.io/contributing/#what-belongs-in-these-docs).

## License

MIT License — see [LICENSE](LICENSE) for details.
