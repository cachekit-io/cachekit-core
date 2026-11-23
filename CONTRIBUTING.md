# Contributing to cachekit-core

This guide is for working on cachekit-core itself: setting up the hooks, running the tests, fuzzing and benchmarks, and the performance practices a change to this crate follows. For using the crate, see the [README](README.md).

## Development setup

`prek install` (or `pre-commit install`) sets up hooks that reject internal references in README
files, `docs/` and commit messages.

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
ratio reads allocate, with a positive control, pins what an accepted
msgpack-`bin` `retrieve_data` and `retrieve` below 64 KiB allocate, and
checks that a read whose envelope decode fails copies none of a `bin` or `str`
payload of 64 KiB or more.
`tests/wire_format_constructed.rs` runs the fixture's constructed 32-bit
ratio-product vector natively and, in CI, on `wasm32-unknown-unknown` under
`wasm-bindgen-test`; `tests/wire_format_vectors.rs` decodes the constructed
bin16/bin32 and legacy array32 boundary vectors natively.

`tests/decode_bounds_vectors.rs` drives every reject and accept vector in the
protocol's `test-vectors/decode-bounds.json` (vendored the same way, at
`tests/vectors/decode-bounds.json`) through `retrieve()`. Each reject vector
must fail with the pre-scan's `decode pre-scan: ` message prefix; failing
somewhere inside the decoder does not count.

## Benchmarks

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

Sizes are 64 B, 1 KiB and 64 KiB. `store`, `retrieve` and `retrieve_data` also run at 40 B, below the 64-byte literals-only block threshold, and at 1 MiB. `ByteStorage` switches to its copying allocation pattern once the envelope or the compressed payload reaches 64 KiB. The 64 KiB payload compresses to a 24,702-byte envelope and never gets there; the 1 MiB one compresses to 383,893 bytes. One case at a time: `make perf-ir ARGS="--case store/1024"`. The bench binary is built with fat LTO, so its cases shape each other's code. Because both `retrieve` and `retrieve_data` call the envelope decode, it stays out of line, and `retrieve` costs 26 to 27 Ir/op more at 40 B to 1 KiB (2.8% at 40 B, rustc 1.99.1) than in a binary that calls `retrieve` alone. A consumer that calls only one of the two gets the decode inlined.

**Method** (`benches/perf_ir.rs`): each case runs in its own process under `valgrind --tool=cachegrind --cache-sim=no`, once with N calls and once with none, after the same setup and one warm-up call. N is 1,000, or 20 for a 1 MiB case. Ir/op is `(Ir[N] - Ir[0]) / N`, so process start, setup and exit cancel. The counts are exact, so N sets the run time, not the precision. The measured process gets an empty environment, so neither the shell nor a `VALGRIND_OPTS` changes what is counted.

**Page faults:** instruction counts leave out the kernel's work, and from 64 KiB up the allocator decides whether a call reuses memory or gets fresh pages, which costs a trap and a zeroed 4 KiB page each. So every case from 64 KiB up also runs natively, outside valgrind, and records its minor page faults (`getrusage`) over 1,000 calls, whatever its size. Counting starts after 1,001 calls, because the first calls after the warm-up can still grow the heap once. A case fails when its faults rise by at least one page per call (1,000 faults) and by 1%. A smaller rise never moves the verdict: on a busy host a run has taken up to 4 stray faults in 1,000 calls. With glibc's default thresholds, every case takes 0. Setting `MALLOC_MMAP_THRESHOLD_=131072` turns glibc's adaptive threshold off, and then a 1 MiB `store` takes 188 faults per call and a 1 MiB `retrieve` takes 351. That is the regression this check catches.

**Reproducibility:** two runs of the same build agree exactly on every case. Between builds, the heap moves with the size of the binary, and alignment-dependent code in AES-GCM and memcpy follows it: `encrypt/1024` moves by up to 0.19%, every other case by at most 0.02%. The counts also depend on the compiler, the locked dependencies, the CPU features the binary is compiled for and the ones valgrind passes through. Budgets are keyed by architecture, OS and any compiled-in CPU features (a `-C target-cpu=x86-64-v3` build gets its own set), and each set records the rustc and valgrind versions it was taken with; the gate prints a note when yours differ. Other `RUSTFLAGS` and profile overrides are not detected, so measure the default build.

**Budgets** live in `benches/perf_ir_baselines.json`. After a change that makes a path cheaper, `make perf-ir-update` ratchets its budget down. It never raises one: an increase you mean takes `make perf-ir-update ARGS=--allow-increase`. Ratcheting works only on the rustc and valgrind the budgets were recorded with; on a new toolchain, re-record every case with `make perf-ir-update ARGS=--allow-increase` (no `--case`). Instruction counts ignore cache misses and branch mispredictions, so a claimed wall-clock win still needs a wall-clock A/B.

**In CI** the `perf-ir` job runs `make perf-ir-vs-base` on a GitHub-hosted `ubuntu-latest` runner for every pull request. Committed budgets hold only on the machine they were recorded on, so the job does not use them: it measures the library at the pull request's merge-base with `main` in a temporary worktree, then gates the pull request against those figures, on the same runner, toolchain and valgrind. A case fails at +1% Ir/op, or when its page faults per call rise by a page and by 1%, as above. Both sides run the pull request's `benches/`, so a change to a case's fixture or method applies to both and cannot pass as a library improvement; the base keeps its own `Cargo.toml` and `Cargo.lock`, so dependency changes are measured. If those benches cannot build against the base (they call API the base lacks, or the change edits bench dev-dependencies or `[[bench]]` targets), the job fails as not comparable and the change needs a human call. Run the same comparison locally with `make perf-ir-vs-base` (default base `origin/main`; `PERF_IR_BASE=<ref>` for another). The gate's `--baselines <path>` option, which the script uses, reads and writes a budget file other than the committed one.

## Performance practices

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
