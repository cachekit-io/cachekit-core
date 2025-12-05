# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0](https://github.com/cachekit-io/cachekit-core/compare/cachekit-core-v0.0.1...cachekit-core-v0.1.0) (2025-12-05)


### Features

* initial release ([4e0a5af](https://github.com/cachekit-io/cachekit-core/commit/4e0a5af911ea458fac4239a4bec51f41e3b310ca))

## [Unreleased]

### Added

- **ByteStorage**: LZ4 compression with xxHash3-64 checksums
  - Automatic compression/decompression
  - Integrity verification on retrieval
  - Decompression bomb protection (512MB limit, 1000x ratio limit)

- **ZeroKnowledgeEncryptor**: AES-256-GCM encryption
  - Counter-based nonce generation (prevents reuse)
  - Hardware acceleration detection (AES-NI, ARM Crypto)
  - Operation metrics for observability

- **Key Derivation**: HKDF-SHA256 (RFC 5869)
  - Domain separation for multi-use keys
  - Tenant isolation via salt
  - Key fingerprinting for rotation support

- **C FFI Layer**: Multi-language support
  - Opaque handle management
  - Panic-safe error handling
  - Auto-generated `cachekit.h` header

- **Security Infrastructure**
  - 16 fuzz targets covering all attack surfaces
  - Kani formal verification proofs
  - Property-based testing with proptest
  - `cargo-deny` supply chain security

### Security

- All key material zeroized on drop
- Constant-time operations for encryption via `ring`
- No panics in library code (Result-based error handling)
- FFI boundary hardened with `catch_unwind`

[Unreleased]: https://github.com/cachekit-io/cachekit-core/compare/main...HEAD
