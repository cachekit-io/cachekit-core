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

The ratio product is computed in `u64` via `checked_mul`, and overflow is
treated as a bomb. Zero-length compressed data is rejected unconditionally,
including when the envelope declares `original_size == 0`.

`lz4_flex` returns `OutputTooSmall` rather than growing past the allocation, so
the decompressed output is bounded by `min(512 MiB, 1000 × compressed_data.len())`
regardless of what the envelope claims. `extract` then re-checks the produced
length, because a decompressor's size argument sizes a buffer; it never asserts
the decoded length. Keep `lz4_flex`'s default `safe-decode` feature on: it
decodes into a zero-filled fixed-length buffer, where the non-safe decoder uses
`with_capacity` + `set_len`.

- **`original_size` does not act as a bound.** It is attacker-controlled on any
  backend an attacker can write to. It *does* size the allocation, but only
  within the absolute and ratio limits already checked above — so a forged
  envelope can still make a reader allocate up to `1000 × compressed_data.len()`
  before the LZ4 stream is validated. That is allocation amplification within
  the bound, not a bypass of it. Note that `ByteStorage::validate()` reaches the
  same allocation — it calls `extract()` and discards the result — so it is
  *not* a cheap structural pre-screen for untrusted envelopes.
- **xxHash3-64 is not a control here.** It is unkeyed, so anyone who can
  forge an envelope recomputes it. It detects accidental corruption, not
  forgery. Authentication comes from AES-256-GCM, and only for secure caches.

**The ceiling is server-class.** `ByteStorage::retrieve` holds the serialized
envelope, the deserialized `compressed_data` copy and the decompressed output at
the same time, so a single call can peak well above 512 MiB — up to roughly
1.5 GiB at the limits. That does *not* fit a constrained runtime: a Cloudflare
Workers isolate has ~128 MiB, so a payload well inside these limits can still
exhaust it, and on `wasm32` the allocation is an eager `memory.grow` that needs
no valid LZ4 stream behind it. On `wasm32` that is worse than a spike: linear
memory never shrinks, so a single large extract permanently raises the
isolate's floor for every subsequent request it serves. Deployments on
constrained runtimes must bound payload size at the caller. Making these
constants environment-aware or configurable is tracked as a follow-up.

**Test coverage.** The unit tests in `src/byte_storage.rs` call `extract`
directly and are the only merge-time enforcement of the bound. The
`compression_bomb` fuzz target (`fuzz/fuzz_targets/compression_bomb.rs`) is a
build-and-smoke check at pull-request time, and its weekly deep run restarts
from an empty corpus. The Kani harnesses never run on pull requests, never
execute `StorageEnvelope::extract`, and cannot detect a wrong predicate. Treat both as
smoke checks, not as verification of the bound.

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
