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
//! | `encryption` | AES-256-GCM (ring on native, aes-gcm on wasm32) + HKDF-SHA256 (hkdf) | No |
//! | `ffi` | C header generation | No |
//!
//! ## Platform Support
//!
//! Compiles on both native targets and `wasm32-unknown-unknown` (Cloudflare Workers).
//! On wasm32, encryption uses RustCrypto's `aes-gcm` (pure Rust) instead of `ring`.
//! Both backends produce identical AES-256-GCM wire format.
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
//! use zeroize::Zeroizing; // add the zeroize crate to your Cargo.toml
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Derive tenant-isolated key
//!     // From your secret manager or CACHEKIT_MASTER_KEY, hex-decoded to 32 raw bytes.
//!     // Never hard-code it, and never pass the hex string's bytes.
//!     // Zeroizing wipes each key from memory when it is dropped.
//!     let master_key = Zeroizing::new(load_master_key_from_secret_manager()?);
//!     let tenant_key = Zeroizing::new(derive_domain_key(master_key.as_slice(), "cache", b"tenant-123")?);
//!
//!     // Encrypt
//!     let encryptor = ZeroKnowledgeEncryptor::new()?;
//!     let ciphertext = encryptor.encrypt_aes_gcm(b"secret", tenant_key.as_slice(), b"tenant-123")?;
//!
//!     // Decrypt
//!     let plaintext = encryptor.decrypt_aes_gcm(&ciphertext, tenant_key.as_slice(), b"tenant-123")?;
//!     assert_eq!(plaintext, b"secret");
//!     Ok(())
//! }
//! ```
//!
//! ## Security Properties
//!
//! - **AES-256-GCM**: Authenticated encryption via `ring` on native, `aes-gcm` on wasm32
//! - **HKDF-SHA256**: Key derivation with tenant isolation (RFC 5869)
//! - **xxHash3-64**: Fast non-cryptographic checksums (corruption detection), available standalone via [`checksum`]/[`verify_checksum`] without compression.
//! - **Nonce safety**: Counter-based + random IV prevents reuse
//! - **Memory safety**: `zeroize` on drop for all key material

// Standalone integrity primitive (usable without compression/messagepack)
#[cfg(feature = "checksum")]
pub mod checksum;
#[cfg(feature = "checksum")]
pub use checksum::{checksum, verify_checksum};

// Core byte storage layer
pub mod byte_storage;
pub use byte_storage::{ByteStorage, StorageEnvelope};

// Unit-test allocation probe for the reject vectors (test builds only)
#[cfg(all(test, feature = "compression", feature = "checksum"))]
mod read_allocation_probe;

// Structural pre-scan for untrusted MessagePack (no optional dependency)
mod msgpack_bounds;
pub use msgpack_bounds::{check_msgpack_structure, MsgpackStructureError};

// Encryption module (feature-gated)
#[cfg(feature = "encryption")]
pub mod encryption;
#[cfg(feature = "encryption")]
pub use encryption::{
    derive_domain_key, EncryptionError, KeyDerivationError, KeyDomain, Keyring, TenantKeyring,
    ZeroKnowledgeEncryptor, MAX_DECRYPT_ONLY_KEYS,
};

// C FFI layer (feature-gated)
#[cfg(feature = "ffi")]
pub mod ffi;
#[cfg(feature = "ffi")]
pub use ffi::CachekitError;
