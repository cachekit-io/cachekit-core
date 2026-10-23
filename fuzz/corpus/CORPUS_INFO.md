# Fuzzing Corpus Information

## Overview

This directory contains the initial fuzzing corpus for cachekit's Rust security layer.

**Generated**: 2025-11-07
**Total Size**: 6.9MB (under 10MB target)
**Total Files**: 1,758 samples

## Corpus Organization

### ByteStorage Corpus (`byte_storage/`)
- **valid_envelopes/** (3 files, 12K): Valid MessagePack envelopes for baseline testing
- **corrupted_envelopes/** (4 files, 16K): Malformed MessagePack structures
- **size_edge_cases/** (8 files, 28K): Size boundary testing (0 bytes, 1 byte, u32::MAX, suspicious ratios)
- **format_strings/** (5 files, 28K): Format identifier injection patterns

**Edge Cases Added**:
- Empty file (0 bytes)
- Single byte file
- 100 null bytes
- u32::MAX representation

### Encryption Corpus (`encryption/`)
- **key_material/** (3 files, 12K): Master key samples
- **tenant_ids/** (10 files, 48K): Tenant identifier patterns (normal, malicious, Unicode)
- **aad_patterns/** (5 files, 24K): Additional authenticated data samples
- **ciphertext_samples/** (4 files, 12K): Valid and corrupted ciphertext

**Edge Cases Added**:
- Unicode mixed (Korean + Japanese)
- Emoji
- RTL override character (U+202E)
- Embedded null bytes

### Integration Corpus (`integration/`)
- **layered_data/** (2 files, 8K): Combined compression + encryption samples

## Corpus Generation

Corpus was generated from:
1. **Automated extraction** (`scripts/generate_corpus.sh`):
   - Production test fixtures from `tests/critical/`
   - Synthetic edge cases (size boundaries, format injection)
   - Encryption patterns (tenant IDs, AAD, ciphertext)

2. **Manual additions**:
   - Empty files
   - Unicode edge cases
   - Null byte patterns
   - Platform-specific edge cases

## Validation

Validated with `scripts/validate_corpus.sh`:
- Total size under 10MB target
- Sufficient sample diversity (1,758 files)
- Proper directory organization
- 3 empty files (intentional edge cases)

## Usage

Run these from the repository root.

### Quick Fuzzing (corpus only, up to 120s per target)
```bash
rustup run nightly make fuzz-quick
```

### Deep Fuzzing (30 min per target)
```bash
rustup run nightly make fuzz-deep
```

### Corpus Maintenance
```bash
# Minimize corpus (remove redundancy)
cd fuzz && ./scripts/minimize_corpus.sh

# Re-validate after changes
cd fuzz && ./scripts/validate_corpus.sh
```

## Maintenance Notes

- **Corpus growth**: Fuzzing will discover new inputs and add them to corpus automatically
- **Minimization**: Run `minimize_corpus.sh` periodically to deduplicate and reduce size
- **Edge cases**: Add new attack patterns to appropriate subdirectories
- **Size limit**: Keep total corpus under 10MB for CI efficiency

## References

- Fuzzing guide: `fuzz/README.md`
