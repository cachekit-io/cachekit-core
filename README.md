# cachekit-core

<div align="center">

**LZ4 compression, xxHash3 integrity, AES-256-GCM encryption — for arbitrary byte payloads.**

[![Crates.io](https://img.shields.io/crates/v/cachekit-core.svg)](https://crates.io/crates/cachekit-core)
[![Documentation](https://docs.rs/cachekit-core/badge.svg)](https://docs.rs/cachekit-core)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.91-blue.svg)](https://blog.rust-lang.org/2025/10/30/Rust-1.91.0/)

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
> For decorator-based caching in Python, see [`cachekit-py`](https://github.com/cachekit-io/cachekit-py).

---

## Features

| Feature | Description | Default |
|:--------|:------------|:-------:|
| `compression` | LZ4 compression via [`lz4_flex`](https://crates.io/crates/lz4_flex) | ✅ |
| `checksum` | [`xxhash-rust`](https://crates.io/crates/xxhash-rust) integrity verification | ✅ |
| `encryption` | AES-256-GCM ([`ring`](https://crates.io/crates/ring) on native, [`aes-gcm`](https://crates.io/crates/aes-gcm) on wasm32) + HKDF-SHA256 ([`hkdf`](https://crates.io/crates/hkdf)) | ❌ |
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
trailing bytes compares it with `bytes.len()` instead of walking twice. See
[`SECURITY.md`](SECURITY.md#envelope-decode-bounds).

</details>

---

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

---

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

The Criterion suite in `benches/hot_path.rs` needs the `encryption` feature (`make bench`, or `cargo bench --features encryption`; a plain `cargo bench` skips it). It runs the ByteStorage roundtrip on three corpora side by side: `byte_storage/roundtrip` (synthetic ramp, kept for history), `byte_storage/roundtrip_msgpack` (realistic msgpack records, about 0.38 LZ4 ratio at 64 KB) and `byte_storage/roundtrip_incompressible`. The bench profile keeps symbols, so callgrind and perf attribute cost to functions.

### Instruction counts

`make perf-ir` counts the instructions each hot path executes per call and fails when a case costs **1% or more** above its committed budget. It warns from 0.2%. Wall clock on a shared machine moves by far more than 1% between identical runs, and Criterion picks its iteration count from wall time; instruction counts at a fixed iteration count are exact. It needs valgrind (`apt install valgrind`).

| Case | What one call does |
|:-----|:-------------------|
| `store/<size>`, `retrieve/<size>` | `ByteStorage::store` / `retrieve` on the realistic msgpack payload `hot_path` uses |
| `retrieve_data/<size>` | `ByteStorage::retrieve_data`, the bindings' call, on the same envelope as `retrieve` |
| `prescan/<size>` | `check_msgpack_structure` on the envelope, the pre-scan `retrieve` and `retrieve_data` run on every envelope their one-pass read declines |
| `encrypt/<size>`, `decrypt/<size>` | `ZeroKnowledgeEncryptor` AES-256-GCM |
| `keyring_decrypt/<size>` | `Keyring::decrypt_indexed`, which re-derives the tenant key (HKDF) on every call |
| `tenant_keyring_decrypt/<size>` | `TenantKeyring::decrypt_indexed`, key derived once at `for_tenant` |
| `hkdf` | `derive_domain_key` (takes no payload, so it has no size) |

Sizes are 64 B, 1 KiB and 64 KiB. `store`, `retrieve` and `retrieve_data` also run at 40 B, below the 64-byte literals-only block threshold, and at 1 MiB. `ByteStorage` switches to its copying allocation pattern once the envelope or the compressed payload reaches 64 KiB. The 64 KiB payload compresses to a 24,702-byte envelope and never gets there; the 1 MiB one compresses to 383,893 bytes. One case at a time: `make perf-ir ARGS="--case store/1024"`. The bench binary is built with fat LTO, so its cases shape each other's code. Because both `retrieve` and `retrieve_data` call the envelope decode, it stays out of line, and `retrieve` costs 68 to 77 Ir/op more at 40 B to 1 KiB (2.6% at 40 B) than in a binary that calls `retrieve` alone. A consumer that calls only one of the two gets the decode inlined.

**Method** (`benches/perf_ir.rs`): each case runs in its own process under `valgrind --tool=cachegrind --cache-sim=no`, once with N calls and once with none, after the same setup and one warm-up call. N is 1,000, or 20 for a 1 MiB case. Ir/op is `(Ir[N] - Ir[0]) / N`, so process start, setup and exit cancel. The counts are exact, so N sets the run time, not the precision. The measured process gets an empty environment, so neither the shell nor a `VALGRIND_OPTS` changes what is counted.

**Page faults:** instruction counts leave out the kernel's work, and from 64 KiB up the allocator decides whether a call reuses memory or gets fresh pages, which costs a trap and a zeroed 4 KiB page each. So every case from 64 KiB up also runs natively, outside valgrind, and records its minor page faults (`getrusage`) over 1,000 calls, whatever its size. Counting starts after 1,001 calls, because the first calls after the warm-up can still grow the heap once. A case fails when its faults rise by at least one page per call (1,000 faults) and by 1%. A smaller rise never moves the verdict: on a busy host a run has taken up to 4 stray faults in 1,000 calls. With glibc's default thresholds, every case takes 0. Setting `MALLOC_MMAP_THRESHOLD_=131072` turns glibc's adaptive threshold off, and then a 1 MiB `store` takes 188 faults per call and a 1 MiB `retrieve` takes 351. That is the regression this check catches.

**Reproducibility:** two runs of the same build agree exactly on every case. Between builds, the heap moves with the size of the binary, and alignment-dependent code in AES-GCM and memcpy follows it: `encrypt/1024` moves by up to 0.19%, every other case by at most 0.02%. The counts also depend on the compiler, the locked dependencies, the CPU features the binary is compiled for and the ones valgrind passes through. Budgets are keyed by architecture, OS and any compiled-in CPU features (a `-C target-cpu=x86-64-v3` build gets its own set), and each set records the rustc and valgrind versions it was taken with; the gate prints a note when yours differ. Other `RUSTFLAGS` and profile overrides are not detected, so measure the default build.

**Budgets** live in `benches/perf_ir_baselines.json`. After a change that makes a path cheaper, `make perf-ir-update` ratchets its budget down. It never raises one: an increase you mean takes `make perf-ir-update ARGS=--allow-increase`. Ratcheting works only on the rustc and valgrind the budgets were recorded with; on a new toolchain, re-record every case with `make perf-ir-update ARGS=--allow-increase` (no `--case`). Instruction counts ignore cache misses and branch mispredictions, so a claimed wall-clock win still needs a wall-clock A/B.

**In CI** the `perf-ir` job runs `make perf-ir-vs-base` on a GitHub-hosted `ubuntu-latest` runner for every pull request. Committed budgets hold only on the machine they were recorded on, so the job does not use them: it measures the library at the pull request's merge-base with `main` in a temporary worktree, then gates the pull request against those figures, on the same runner, toolchain and valgrind. A case fails at +1% Ir/op, or when its page faults per call rise by a page and by 1%, as above. Both sides run the pull request's `benches/`, so a change to a case's fixture or method applies to both and cannot pass as a library improvement; the base keeps its own `Cargo.toml` and `Cargo.lock`, so dependency changes are measured. If those benches cannot build against the base (they call API the base lacks, or the change edits bench dev-dependencies or `[[bench]]` targets), the job fails as not comparable and the change needs a human call. Run the same comparison locally with `make perf-ir-vs-base` (default base `origin/main`; `PERF_IR_BASE=<ref>` for another). The gate's `--baselines <path>` option, which the script uses, reads and writes a budget file other than the committed one.

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

### Protocol wire-format vectors

`tests/wire_format_vectors.rs` byte-verifies this crate against the canonical
ByteStorage envelope vectors from
[`cachekit-io/protocol`](https://github.com/cachekit-io/protocol)
(`test-vectors/wire-format.json`). Since protocol 1.1 the fixture pins two
`compressed_data` encodings — legacy array-of-integers vectors and their
`*_bin` twins (msgpack `bin`, canonical for 1.1+ writers): every vector in
both sets must decode to the exact payload bytes, while re-encode
byte-identity is asserted against the set matching this crate's current
writer encoding — msgpack `bin`, since the protocol 1.1 `serde_bytes`
writer flip (`checksum` deliberately stays array-of-ints per the
protocol's normative scope exclusion). Legacy envelopes remain readable
forever.
`tests/dual_decode.rs` proves both reader shapes accept both encodings,
including bin16/bin32 width headers. The fixture is vendored at
`tests/vectors/wire-format.json` and integrity-pinned by sha256 — to update
it, re-copy from the protocol repo and change the pinned hash in the same
commit.

Since protocol 1.3 the fixture also carries `reject_vectors` (14 as of
protocol 1.4), which `tests/wire_format_vectors.rs` drives through
`retrieve()`, asserting the error the protocol names for each.
`reject_envelope_slots_overclaim` must fail with the pre-scan's own
summed-slot message, `decode pre-scan: declares more elements than the input
can back`: any decoder, and the pre-scan's end-of-input check, rejects that
envelope too, so only the exact message proves the slot check ran.
`src/read_allocation_probe.rs` (unit tests only) bounds what the size-cap and
ratio reads allocate, with a positive control, and pins what an accepted
msgpack-`bin` `retrieve_data` and `retrieve` below 64 KiB allocate.
`tests/wire_format_constructed.rs` runs the fixture's constructed 32-bit
ratio-product vector natively and, in CI, on `wasm32-unknown-unknown` under
`wasm-bindgen-test`; `tests/wire_format_vectors.rs` decodes the constructed
bin16/bin32 and legacy array32 boundary vectors natively.

`tests/decode_bounds_vectors.rs` drives every reject and accept vector in the
protocol's `test-vectors/decode-bounds.json` (vendored the same way, at
`tests/vectors/decode-bounds.json`) through `retrieve()`. Each reject vector
must fail with the pre-scan's `decode pre-scan: ` message prefix; failing
somewhere inside the decoder does not count.

---

## Minimum Supported Rust Version

New releases support the latest stable Rust. This release requires **Rust 1.91** or later: `rust-version` in `Cargo.toml` is the oldest toolchain CI tests, and any release may raise it when a dependency needs a newer one.

---

## Contributing

User-facing docs in this repository follow CacheKit's shared rule on what belongs in them:
[What belongs in these docs](https://docs.cachekit.io/contributing/#what-belongs-in-these-docs).
`prek install` (or `pre-commit install`) sets up hooks that reject internal references in README
files, `docs/` and commit messages.

### Performance practices

The SDKs call this crate on their store, retrieve and encryption paths, so a per-call cost here
reaches all of them. Each practice names the pull request, in this crate or an SDK, that measured
it. Measure as [Instruction counts](#instruction-counts) describes, and put the figures in the
pull request.

**Give small values their own path.** Most cached values are small, and a fixed per-call cost
dominates them. Below 64 B, `store` writes one literals-only LZ4 block instead of running the
compressor, which zeroes its hash table on every call: −80.8% instructions on a 63 B store
([#128]). The trade: compressible inputs under 64 B are stored uncompressed and grow. From 64 B
to under 4 KiB, the compressor reuses one hash table and one output scratch per thread: −27.5% on
a 64 B store ([#144]). `make perf-ir` has no case below 64 B or above 64 KiB, so a change that
branches on size also measures each side of its threshold and 1 MiB, as [#128] and [#144] did.
Per-thread reuse has its own traps, all from [#144]:

- Reuse stopped paying at about 6 KiB, because the copy out grows with the block while the saving
  stays fixed. The 4 KiB bound also keeps the table in lz4_flex's 16-bit class: lz4_flex upgrades
  a 16-bit table to the 32-bit class for a longer input and never downgrades it, which would change
  every later small block on that thread.
- macOS aligns thread locals to at most 16 B, so lz4_flex's `#[repr(align(64))]` table is boxed.
- The scratch keeps the tail of earlier blocks for the life of the thread. Memory that is reused
  and can hold payload bytes is listed in [`SECURITY.md`](SECURITY.md#threat-model).

**Allocate once, and borrow instead of copying.** Size a buffer once, write in place, and borrow
from the input. Sealing native encrypt in one buffer (one allocation and one plaintext copy, down
from three allocations and up to three copies) took encrypt at 64 KiB from 33.80 µs to 10.93 µs
([#127]). `StorageEnvelope::encoded_len` and `encode_into` ([#131]) let a binding write the
envelope into memory it owns, without a `Vec` in between. A borrowed twin of a public type keeps
its Rust name: serde's derive puts the struct name into its error text and an SDK pins that text,
so the private borrowed `StorageEnvelope` in [#132] has the public one's name, fields and decoders.

**Know glibc's thresholds before removing a large allocation.** glibc raises its mmap and trim
thresholds to the largest mmap-ed chunk freed so far, so the allocation you remove may be the one
that kept the other buffers off fresh pages. At 1 MB, an exact-size envelope made incompressible
stores about 30% slower (702 → 945 page faults per store, [#131]), and borrowing the payload made
each retrieve about 7× slower (0 → 947 page faults per read, [#132]). Both changes stop at 64 KiB,
because below it no buffer, doubled or not, reaches glibc's minimum mmap threshold of 128 KiB.
Measure page faults at 64 KiB and up, under default malloc and with `MALLOC_MMAP_THRESHOLD_` and
`MALLOC_TRIM_THRESHOLD_` pinned.

**Do per-call work once.** Work that depends only on the key, the tenant or the configuration
belongs where the handle is built. `Keyring::decrypt_indexed` re-derives the tenant key with HKDF
on every call; a `TenantKeyring` from `Keyring::for_tenant` derives it once. Moving its encrypted
reads to `TenantKeyring` took a 64 B encrypted L1 hit in cachekit-rs from 34,178 to 5,124
instructions (−85%, [cachekit-rs#185]). Return what a pass already found: `msgpack_document_len`
([#120]) hands a reader the length the structural walk computed, so rejecting trailing bytes takes
one walk instead of two.

**Keep 64-bit-only code 64-bit only.** On 64-bit targets the LZ4 encoder is lz4_flex's unsafe one:
`store` −17.36% at 1 KiB and −28.43% at 64 KiB ([#128]). Targets narrower than 64 bits, wasm32
included, keep `safe-encode`: in lz4_flex 0.12, `input_len * 110 / 100` wrapped `usize` above about
37 MiB on 32-bit targets, inside this crate's 512 MiB input cap. `fuzz/Cargo.toml` declares
lz4_flex with the crate's native features, because default features would unify `safe-encode` back
in and the fuzzers would exercise the wrong encoder. An `unsafe` change ships with Miri, fuzzing and
a byte-identity diff against `main`, as [#128] did.

**Measure it, or it didn't happen.**

- Build each arm of an A/B in its own target directory. With a shared one, cargo's mtime check
  reused the base binary for the head, and the gate compared base with base ([#118]).
- Run an A/A arm. With the code unchanged, code layout alone moved `retrieve` at 64 KB to 1 MB by
  −4% to +5% across four build pairs ([#144]). Time wall clock with paired, interleaved runs.
- Instruction counts undercount memory wins. At 1 MiB the reallocation [#127] removed was a kernel
  page remap, so Ir read only −3.2%. Count page faults too.
- Pass inputs and results through `black_box`. Without it, a benchmark reported 230 to 290 GB/s,
  faster than memory ([#117]).

**Title an additive API `perf` or `fix`, not `feat`.** Adding a public item to a 0.y crate is a
patch-level change under Cargo's SemVer rules, so the SDKs' caret requirements already accept it.
Under this repository's release-please settings a `feat` title cuts a new minor version instead,
and every SDK must move its requirement for a change that breaks nothing ([#120]). Only a crate
that calls the new item raises its minimum version.

**List the sibling paths.** A fix to one path tends to leave its siblings slow. A perf pull
request lists the sibling paths in its description and says which it changed and which it did not
measure: `store` and `retrieve`, encrypt and decrypt, native and wasm32, 64-bit and 32-bit targets.
[#127] sealed native encrypt in one buffer and left wasm32 as it was; [#129] gave wasm32 the same
change. [#131] changed `store` and [#132] `retrieve`. [#144] says wasm32 was not measured.

[#117]: https://github.com/cachekit-io/cachekit-core/pull/117
[#118]: https://github.com/cachekit-io/cachekit-core/pull/118
[#120]: https://github.com/cachekit-io/cachekit-core/pull/120
[#127]: https://github.com/cachekit-io/cachekit-core/pull/127
[#128]: https://github.com/cachekit-io/cachekit-core/pull/128
[#129]: https://github.com/cachekit-io/cachekit-core/pull/129
[#131]: https://github.com/cachekit-io/cachekit-core/pull/131
[#132]: https://github.com/cachekit-io/cachekit-core/pull/132
[#144]: https://github.com/cachekit-io/cachekit-core/pull/144
[cachekit-rs#185]: https://github.com/cachekit-io/cachekit-rs/pull/185

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**[Documentation](https://docs.rs/cachekit-core)** · **[Crates.io](https://crates.io/crates/cachekit-core)** · **[GitHub](https://github.com/cachekit-io/cachekit-core)**

</div>
