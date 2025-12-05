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
- **Decompression bombs**: Size limits + ratio validation
- **Memory disclosure**: `zeroize` on drop for key material

This crate does **not** protect against:

- Side-channel attacks on the host system
- Compromise of the master key
- Denial of service via resource exhaustion (partial protection only)
- Attacks requiring physical access

### Dependencies

Security-critical dependencies are audited via `cargo-deny`:

```bash
cargo deny check advisories
```

See `deny.toml` for the full security policy.

## Vulnerability Disclosure History

No vulnerabilities have been disclosed yet.
