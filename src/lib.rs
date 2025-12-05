//! # cachekit-core
//!
//! LZ4 compression, xxHash3 integrity, AES-256-GCM encryption — for arbitrary byte payloads.
//!
//! This crate transforms bytes: compress them, verify their integrity, encrypt them.
//! Bytes in, bytes out.
//!
//! ## Features
//!
//! | Feature | Description | Default |
//! |:--------|:------------|:-------:|
//! | `compression` | LZ4 compression via `lz4_flex` | Yes |
//! | `checksum` | xxHash3-64 integrity verification | Yes |
//! | `encryption` | AES-256-GCM + HKDF-SHA256 | No |
//! | `ffi` | C header generation | No |
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use cachekit_core::ByteStorage;
//!
//! let storage = ByteStorage::new(None);
//! let data = b"Hello, cachekit!";
//!
//! // Store: compress + checksum
//! let envelope = storage.store(data, None).unwrap();
//!
//! // Retrieve: decompress + verify
//! let (retrieved, _format) = storage.retrieve(&envelope).unwrap();
//! assert_eq!(data.as_slice(), retrieved.as_slice());
//! ```
//!
//! ## With Encryption
//!
//! ```rust,ignore
//! use cachekit_core::{ZeroKnowledgeEncryptor, derive_domain_key};
//!
//! // Derive tenant-isolated key
//! let master_key = [0u8; 32]; // Use secure key in production!
//! let tenant_key = derive_domain_key(&master_key, "cache", b"tenant-123").unwrap();
//!
//! // Encrypt
//! let encryptor = ZeroKnowledgeEncryptor::new();
//! let ciphertext = encryptor.encrypt_aes_gcm(b"secret", &tenant_key, b"tenant-123").unwrap();
//!
//! // Decrypt
//! let plaintext = encryptor.decrypt_aes_gcm(&ciphertext, &tenant_key, b"tenant-123").unwrap();
//! ```
//!
//! ## Security Properties
//!
//! - **AES-256-GCM**: Authenticated encryption via `ring`
//! - **HKDF-SHA256**: Key derivation with tenant isolation (RFC 5869)
//! - **xxHash3-64**: Fast non-cryptographic checksums (corruption detection)
//! - **Nonce safety**: Counter-based + random IV prevents reuse
//! - **Memory safety**: `zeroize` on drop for all key material

// Metrics and observability
pub mod metrics;
pub use metrics::OperationMetrics;

// Core byte storage layer
pub mod byte_storage;
pub use byte_storage::{ByteStorage, StorageEnvelope};

// Encryption module (feature-gated)
#[cfg(feature = "encryption")]
pub mod encryption;
#[cfg(feature = "encryption")]
pub use encryption::{
    EncryptionError, EncryptionHeader, KeyDerivationError, KeyDomain, KeyRotationState,
    RotationAwareHeader, ZeroKnowledgeEncryptor, derive_domain_key,
};

// C FFI layer (feature-gated)
#[cfg(feature = "ffi")]
pub mod ffi;
#[cfg(feature = "ffi")]
pub use ffi::CachekitError;
