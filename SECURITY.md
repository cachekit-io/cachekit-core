# Security Policy

## Supported Versions

| Version | Supported |
|:--------|:---------:|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report security issues via:

1. **Email**: security@cachekit.io
2. **GitHub Security Advisories**: [Report a vulnerability](https://github.com/cachekit-io/cachekit-core/security/advisories/new)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

| Stage | Timeline |
|:------|:---------|
| Initial response | 48 hours |
| Triage & assessment | 7 days |
| Fix development | 14-30 days |
| Public disclosure | After fix released |

## Security Model

### Cryptographic Guarantees

| Component | Algorithm | Notes |
|:----------|:----------|:------|
| Encryption | AES-256-GCM | AEAD via `ring` crate |
| Key Derivation | HKDF-SHA256 | RFC 5869 compliant |
| Integrity | xxHash3-64 | Non-cryptographic (corruption detection) |
| Nonce | Counter + Random IV | Unique per encryption |

### Threat Model

This crate protects against:

- **Data tampering**: GCM authentication tags (when encryption enabled); xxHash3 detects accidental corruption only
- **Data disclosure**: AES-256-GCM encryption (when enabled)
- **Key compromise isolation**: HKDF domain separation per tenant
- **Decompression bombs**: Size limits + ratio validation (see [Decompression limits](#decompression-limits))
- **Memory disclosure**: `zeroize` on drop for key material

This crate does **not** protect against:

- Side-channel attacks on the host system
- Compromise of the master key
- Denial of service via resource exhaustion (partial protection only)
- Attacks requiring physical access

### Decompression limits

`StorageEnvelope::extract` bounds LZ4 decompression **before** calling
`lz4_flex::decompress`, so a forged envelope cannot expand without limit:

| Limit | Value | Enforced on |
|:------|:------|:------------|
| `MAX_COMPRESSED_SIZE` | 512 MiB | `compressed_data.len()` |
| `MAX_UNCOMPRESSED_SIZE` | 512 MiB | declared `original_size` |
| `MAX_COMPRESSION_RATIO` | 1000:1 | `original_size` vs `compressed_data.len()` |

The same `MAX_COMPRESSED_SIZE` constant also bounds the *serialized* envelope
before MessagePack deserialization — but that check lives in
`ByteStorage::retrieve` and `ByteStorage::validate`, not on `StorageEnvelope`.
`StorageEnvelope` is public with public fields, so a caller who deserializes it
directly gets no such bound and must impose one.

The ratio product is computed in `u64` via `checked_mul` (overflow is treated
as a bomb — though the 512 MiB compressed-size check above already puts the
product near 2^39, so that branch is belt-and-braces rather than a live
defense), and zero-length compressed data is rejected outright regardless of
what `original_size` claims — the check is unconditional, so an envelope
declaring `original_size == 0` is rejected on the same branch rather than
decompressing to an empty result. `lz4_flex` returns `OutputTooSmall` rather
than growing past the allocation, so the decompressed output is bounded by
`min(512 MiB, 1000 × compressed_data.len())` regardless of what the envelope
claims — a property of `lz4_flex`'s default `safe-decode` path, which this
crate must not opt out of (`default-features = false` moves bounds enforcement
into the separate `checked-decode` feature and swaps the fixed-length buffer
for `with_capacity` + `set_len`),
and `extract` re-checks the produced length afterwards — a decompressor's
size argument sizes a buffer, it never asserts the decoded length.

- **`original_size` does not act as a bound.** It is attacker-controlled on any
  backend an attacker can write to. It *does* size the allocation, but only
  within the absolute and ratio limits already checked above — so a forged
  envelope can still make a reader allocate up to `1000 × compressed_data.len()`
  before the LZ4 stream is validated. That allocation amplification is the
  sizing question in LAB-2505, not a bypass of the bound. Note that
  `ByteStorage::validate()` reaches the same allocation — it calls `extract()`
  and discards the result — so despite its name and its "validate envelope
  without extracting data" doc comment it is *not* a cheap structural
  pre-screen for untrusted envelopes.
- **xxHash3-64 is not a control here.** It is unkeyed, so anyone who can
  forge an envelope recomputes it. It detects accidental corruption, not
  forgery. Authentication comes from AES-256-GCM, and only for secure caches.

**The ceiling is server-class.** 512 MiB assumes a host that can absorb a
512 MiB allocation. It does *not* prevent an out-of-memory kill in a
constrained runtime — a Cloudflare Workers isolate has ~128 MiB, so a payload
well inside these limits can still exhaust it, and on `wasm32` the allocation
is an eager `memory.grow` that needs no valid LZ4 stream behind it. On `wasm32`
that is worse than a spike: linear memory never shrinks, so a single large
extract permanently raises the isolate's floor for every subsequent request it
serves. Deployments on constrained runtimes must bound payload size at the
caller. Making these constants environment-aware or configurable is tracked in
LAB-2505.

These properties are exercised by the `compression_bomb` fuzz target
(`fuzz/fuzz_targets/compression_bomb.rs`) — but read its assertions before
crediting them:

- It asserts `extract` never panics. That one is unconditional and real.
- It asserts the output never exceeds 512 MiB. Vacuous in this target: with
  `compressed_size` a `u16`, compressed input caps at 64 KiB, so the ratio
  bound already holds output under ~62.5 MiB. The assertion cannot fire.
- It asserts rejections are one of `DecompressionBomb`, `InputTooLarge`, or
  `DecompressionFailed` — but **only** for inputs that already violate the
  declared-size or ratio limit. Both variant checks sit behind guards. Every
  other rejection is unconstrained, and `extract`'s two remaining failure
  variants, `ChecksumMismatch` and `SizeValidationFailed`, are never asserted
  against at all.

On which bounds it reaches: `compressed_size` is a `u16`, so the 512 MiB
`MAX_COMPRESSED_SIZE` boundary is never approached. `original_size` is a `u32`,
which does range past 512 MiB, so the target does reach `MAX_UNCOMPRESSED_SIZE`'s
*rejection* branch. It exercises the **ratio** bound and that rejection path —
not the compressed-size limit, and not the output bound.

Be precise about how much CI coverage that buys: the `quick-fuzz` matrix in
`.github/workflows/security.yml` runs on pull requests and on pushes to `main`
(not on feature-branch pushes), and `fuzz/.gitignore` excludes `corpus/*/`, so
on a fresh checkout the corpus is empty. libFuzzer seeds an empty corpus with a
single newline input and executes it before the run-limit check, so `-runs=0`
is not literally zero executions — but it performs no mutation, so the job
generates no inputs of its own. At PR time it therefore proves little beyond
the target still **building**.

Input coverage comes from the weekly deep-fuzz run — though that job does not
persist its corpus either (it uploads `fuzz/artifacts/` only, and the cache key
covers `fuzz/target/`), so each week restarts cold from the same seed and
coverage does not accumulate — and from the unit tests in `src/byte_storage.rs`,
which call `extract` directly. Those unit tests are the only thing in this repo
that executes the bound at merge time.

**The Kani proofs are weaker than they look, and are not a merge-time gate.**
The `kani` job runs only on `schedule` and `workflow_dispatch`, never on a pull
request. More importantly, three of the four size/ratio harnesses assign the
same predicate to two bindings and assert the two are equal — for example
`let exceeds_limit = size > MAX_UNCOMPRESSED_SIZE; let should_reject = size >
MAX_UNCOMPRESSED_SIZE; assert_eq!(exceeds_limit, should_reject);`. That is a
tautology: it holds for any predicate, and would still pass if the comparison
were inverted or the constant were wrong. `verify_decompression_bomb_protection`
additionally assumes `compressed_size <= 1000`, which makes `checked_mul`
infallible and leaves its overflow branch unreachable and stubbed `assert!(true)`.

What Kani does buy is its default check set — no panic, no arithmetic overflow —
over the harness bodies. What it does not buy is any evidence that the predicates
are the *right* ones, and it never executes `StorageEnvelope::extract`, so it
cannot catch a divergence between the modelled predicate and the shipped one.
Treat these as smoke checks, not as verification of the bound.

### Dependencies

Security-critical dependencies are audited via `cargo-deny`:

```bash
cargo deny check advisories
```

See `deny.toml` for the full security policy.

### Software Bill of Materials

A CycloneDX 1.6 SBOM is generated by `cargo-sbom` during publish and attested
against the packaged crate via
[`actions/attest-sbom`](https://github.com/actions/attest-sbom). The attestation
is the verifiable artifact — verify it against the crate as published:

```bash
# Download the published crate, then verify the SBOM attestation against it.
curl -sSLO https://static.crates.io/crates/cachekit-core/cachekit-core-0.4.0.crate
gh attestation verify cachekit-core-0.4.0.crate --repo cachekit-io/cachekit-core \
  --predicate-type https://cyclonedx.org/bom
```

Note the predicate type carries no version suffix: `actions/attest-sbom` records
CycloneDX as `https://cyclonedx.org/bom` regardless of spec version (the version
lives in the document's own `specVersion`). Provenance is attested separately
under `https://slsa.dev/provenance/v1` against the same subject.

GitHub releases for this repository carry no SBOM file as a downloadable asset.
Immutable releases are enabled here, which seals a release's assets at publish
time, so an SBOM cannot be attached after the fact. Use the attestation above.

## Vulnerability Disclosure History

No vulnerabilities have been disclosed yet.
