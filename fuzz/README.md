# Rust Fuzzing Infrastructure

Comprehensive fuzzing infrastructure for cachekit's ByteStorage and encryption modules, designed to detect security vulnerabilities before production deployment.

## Overview

This fuzzing suite provides **14 fuzz targets** covering:
- **ByteStorage attacks**: Corrupted envelopes, integer overflow, checksum collision, format injection, empty data edge cases
- **Encryption attacks**: Key derivation, nonce reuse, truncated ciphertext, AAD injection, large payloads
- **Integration testing**: Layered security (compression + encryption)

**Security Model**: Fail-closed - all malicious inputs must be safely rejected without panics or undefined behavior.

## Quick Start

### Prerequisites
```bash
# Install cargo-fuzz (libfuzzer-based; targets build on the nightly toolchain)
cargo install cargo-fuzz
```

### Basic Fuzzing Workflow
Run these from the repository root.
```bash
# Quick corpus-only smoke test (up to 120s per target, every target)
make fuzz-quick

# Fuzz single target for development (60s by default; set TIME=<seconds>)
cd fuzz && make target TARGET=byte_storage_corrupted_envelope

# Deep fuzzing of one target (8 hours, production validation)
cd fuzz && make target TARGET=encryption_key_derivation TIME=28800

# Generate coverage report
cd fuzz && make coverage
```

## Fuzz Targets

### ByteStorage Targets

**byte_storage_corrupted_envelope.rs**
- Attack: Malformed MessagePack `StorageEnvelope` deserialization
- Validates: Safe rejection of corrupted serialization without panics
- Tests: Invalid MessagePack structures, truncated data, type confusion

**byte_storage_integer_overflow.rs**
- Attack: Decompression bomb via oversized `original_size` (u32::MAX, boundary cases)
- Validates: Size limit enforcement, integer overflow protection
- Tests: u32::MAX, MAX_UNCOMPRESSED_SIZE ± 1, suspicious compression ratios

**byte_storage_checksum_collision.rs**
- Attack: Data corruption with manipulated xxHash3-64 checksums
- Validates: Integrity verification detects mismatches
- Tests: Bit flips, truncation, zero checksums, partial corruption

**byte_storage_empty_data.rs**
- Attack: Inconsistent envelope state (empty data + non-zero size)
- Validates: Envelope consistency checks
- Tests: Empty compressed_data with original_size=1000, vice versa, both empty

**byte_storage_format_injection.rs**
- Attack: Malicious format identifiers (path traversal, nulls, control chars)
- Validates: Format string treated as opaque identifier
- Tests: "../../../etc/passwd", null bytes, CRLF, Unicode attacks, 10KB+ strings

### Encryption Targets

**encryption_key_derivation.rs**
- Attack: Malicious tenant IDs in key derivation
- Validates: Deterministic key derivation without crashes
- Tests: Nulls, path traversal, Unicode, empty strings, 10KB+ length

**encryption_nonce_reuse.rs**
- Attack: Nonce uniqueness verification (encrypt same plaintext 100x)
- Validates: Cryptographic randomness, no ciphertext repetition
- Tests: Multiple encryptions with same key+plaintext produce distinct outputs

**encryption_truncated_ciphertext.rs**
- Attack: Partial/incomplete ciphertext (truncated auth tags)
- Validates: Authentication failure detection
- Tests: Truncation at nonce, ciphertext body, auth tag boundaries

**encryption_aad_injection.rs**
- Attack: Additional Authenticated Data with nulls, control chars, Unicode
- Validates: AAD cryptographic binding (wrong AAD = decrypt fails)
- Tests: Null bytes, control characters, Unicode, 1-bit AAD modification

**encryption_large_payload.rs**
- Attack: Production-scale payloads (1MB, 10MB, 100MB)
- Validates: Performance and correctness at scale
- Tests: Large allocations, memory efficiency, no artificial 4KB limits

### Integration Targets

**integration_layered_security.rs**
- Attack: Corruption at multiple layers (plaintext → compression → encryption)
- Validates: Proper error attribution per layer
- Tests: Pre-compression corruption, post-compression corruption, ciphertext tampering

## Corpus Management

### Directory Structure
```
fuzz/corpus/
├── byte_storage/
│   ├── valid_envelopes/         # Valid MessagePack envelopes
│   ├── corrupted_envelopes/     # Known corruption patterns
│   ├── size_edge_cases/         # MIN, MAX, boundary sizes
│   └── format_strings/          # Valid + malicious format identifiers
├── encryption/
│   ├── key_material/            # Valid 32-byte keys, edge cases
│   ├── tenant_ids/              # Realistic + malicious tenant IDs
│   ├── aad_patterns/            # Normal + injected AAD
│   └── ciphertext_samples/      # Valid + truncated ciphertext
└── integration/
    └── layered_data/            # Compressed-then-encrypted samples
```

### Corpus Scripts
Run these from the repository root.
```bash
# Generate initial corpus from test fixtures
cd fuzz && ./scripts/generate_corpus.sh

# Minimize corpus (deduplicate, reduce size)
cd fuzz && ./scripts/minimize_corpus.sh

# Validate corpus integrity (< 10MB total)
cd fuzz && ./scripts/validate_corpus.sh
```

**Corpus Size Limit**: Total corpus should remain under 10MB for fast CI smoke tests.

## CI Integration

### Smoke Tests (PR Validation)
The `quick-fuzz` job in `.github/workflows/security.yml` runs on every push and pull request:
- One job per target, corpus only (`-runs=0`), up to 120 seconds each
- Catches fuzzing regressions before merge

```bash
# Simulate CI smoke tests locally (from the repository root)
make fuzz-quick
```

### Deep Fuzzing (Production Validation)
Run before releases or periodically, from the repository root:
```bash
# Every target, 30 minutes each
make fuzz-deep

# One target, 8 hours (production-grade validation)
cd fuzz && make target TARGET=encryption_key_derivation TIME=28800
```

## Crash Triage

### Automated Crash Analysis
```bash
# Triage crashes: deduplicate, minimize, generate regression tests (from the repository root)
cd fuzz && ./scripts/triage_crashes.sh

# Output: fuzz/triage_report.txt (git-ignored) with stack traces and minimized inputs
```

The script exits 0 when it finds no crashes, and 1 when it finds crashes or `fuzz/artifacts/` does not exist.

**Workflow:**
1. Find all crash artifacts in `artifacts/`
2. Extract and hash stack traces for deduplication
3. Minimize unique crashes with `cargo fuzz cmin`
4. Generate regression test templates (`#[test] #[should_panic]`)

### Manual Crash Reproduction
Run these from the `fuzz/` directory.
```bash
# Reproduce specific crash
cargo +nightly fuzz run byte_storage_corrupted_envelope artifacts/byte_storage_corrupted_envelope/crash-xyz

# Minimize crash input
cargo +nightly fuzz tmin byte_storage_corrupted_envelope artifacts/byte_storage_corrupted_envelope/crash-xyz
```

## Coverage Reporting

```bash
# Generate LLVM coverage report (from the repository root)
cd fuzz && make coverage

# View HTML report
open fuzz/coverage/html/index.html
```

**Note**: Fuzzing coverage measures code paths explored, not test quality. Use this to identify untested paths.

## Troubleshooting

### Common Issues

**"cargo-fuzz not found"**
```bash
cargo install cargo-fuzz
```

**"Corpus too large (>10MB)"**
```bash
cd fuzz && ./scripts/minimize_corpus.sh
```

**"Fuzzing too slow"**
- Reduce input size limits in targets (e.g., `if data.len() > 1024 { return; }`)
- Use `make fuzz-quick` for rapid iteration
- Check for expensive operations in hot paths

**"Crash can't be reproduced"**
```bash
# Ensure same libfuzzer version (from the fuzz/ directory)
cargo +nightly fuzz run TARGET artifacts/TARGET/crash-xyz -- -exact_artifact_path=artifacts/TARGET/crash-xyz
```

### Performance Tips

1. **Start small**: Use `make fuzz-quick` to verify targets compile and run
2. **Parallelize**: Run multiple targets simultaneously on multi-core machines
3. **Seed wisely**: Good corpus seeds improve coverage 10-100x faster
4. **Monitor coverage**: Use `make coverage` in `fuzz/` to identify unexplored paths

## Architecture Notes

### Why Separate Targets?

Each target focuses on **one specific attack vector** for maximum coverage depth:
- Deep exploration of single attack surface (vs shallow exploration of many)
- Clear failure attribution (which attack succeeded?)
- Independent corpus optimization per attack type
- Easier crash triage and minimization

### Fail-Closed Security Model

All fuzz targets enforce fail-closed behavior:
- **Malicious input** → Safe rejection (`Err(...)`, no panic)
- **Panic** = Test failure (fuzzer reports bug)
- **Undefined behavior** = Instant failure (sanitizers catch)

## Contributing

When adding new fuzz targets:
1. Follow naming convention: `<module>_<attack_vector>.rs`
2. Add target to `Cargo.toml` [[bin]] section
3. Create corpus subdirectory with `.gitkeep`
4. Document attack vector in this README
5. Add target to `FUZZ_TARGETS` list in `fuzz/Makefile` and to the `quick-fuzz` matrix in `.github/workflows/security.yml`
6. Verify with `cd fuzz && make target TARGET=your_new_target`

## References

- [Rust Fuzz Book](https://rust-fuzz.github.io/book/)
- [libfuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [cachekit security architecture](../SECURITY.md)
