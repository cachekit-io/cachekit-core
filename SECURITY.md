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

The ratio product is computed in `u64` via `checked_mul` (overflow is treated
as a bomb), and zero-length compressed data with a non-zero `original_size` is
rejected outright. `lz4_flex` returns `OutputTooSmall` rather than growing past
the allocation, so the decompressed output is bounded by
`min(512 MiB, 1000 × compressed_len)` regardless of what the envelope claims,
and `extract` re-checks the produced length afterwards — a decompressor's
size argument sizes a buffer, it never asserts the decoded length.

- **`original_size` does not act as a bound.** It is attacker-controlled on any
  backend an attacker can write to. It *does* size the allocation, but only
  within the absolute and ratio limits already checked above — so a forged
  envelope can still make a reader allocate up to `1000 ×` its wire size before
  the LZ4 stream is validated. That allocation amplification is the sizing
  question in LAB-2505, not a bypass of the bound.
- **xxHash3-64 is not a control here.** It is unkeyed, so anyone who can
  forge an envelope recomputes it. It detects accidental corruption, not
  forgery. Authentication comes from AES-256-GCM, and only for secure caches.

**The ceiling is server-class.** 512 MiB assumes a host that can absorb a
512 MiB allocation. It does *not* prevent an out-of-memory kill in a
constrained runtime — a Cloudflare Workers isolate has ~128 MiB, so a payload
well inside these limits can still exhaust it, and on `wasm32` the allocation
is an eager `memory.grow` that needs no valid LZ4 stream behind it. Deployments
on constrained runtimes must bound payload size at the caller. Making these
constants environment-aware or configurable is tracked in LAB-2505.

These properties are exercised by the `compression_bomb` fuzz target
(`fuzz/fuzz_targets/compression_bomb.rs`), which asserts that `extract` never
panics and never emits more than 512 MiB, and that rejections are one of
`DecompressionBomb`, `InputTooLarge`, or `DecompressionFailed`. Its
`compressed_size` is a `u16`, so it caps compressed input at 64 KiB and
therefore exercises the **ratio** bound, not the 512 MiB absolute one.

Be precise about how much CI coverage that buys: the `quick-fuzz` matrix in
`.github/workflows/security.yml` runs on pull requests and on pushes to `main`
(not on feature-branch pushes), and `fuzz/.gitignore` excludes `corpus/*/`, so
on a fresh checkout the corpus is empty and `cargo fuzz run … -runs=0`
generates no inputs. At PR time the job therefore proves the target still
**builds**; the input coverage comes from the weekly deep-fuzz run, and from
the unit tests and Kani proofs in `src/byte_storage.rs`, which do assert the
bound directly.

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
