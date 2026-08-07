//! Zero-Knowledge Encryption Module
//!
//! Provides client-side encryption using AES-256-GCM with HKDF-SHA256 key derivation
//! and domain separation following security best practices.
//!
//! # Features
//! - **AES-256-GCM. Not configurable by design.** Authenticated encryption with ring library
//! - HKDF-SHA256 key derivation with domain separation (RFC 5869)
//! - Hardware acceleration detection and usage (AES-NI)
//! - Per-tenant key isolation with cryptographic guarantees
//! - Zero-knowledge guarantees: storage never sees plaintext or keys

pub mod core;
pub mod key_derivation;
pub mod keyring;

// Re-exports for convenience
pub use core::{EncryptionError, ZeroKnowledgeEncryptor};
pub use key_derivation::{derive_domain_key, KeyDerivationError};
pub use keyring::{Keyring, MAX_DECRYPT_ONLY_KEYS};

/// Domain contexts for key derivation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDomain {
    /// Keys for data encryption
    Encryption,
    /// Keys for authentication/MAC
    Authentication,
    /// Keys for cache key derivation
    CacheKeys,
}

impl KeyDomain {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyDomain::Encryption => "encryption",
            KeyDomain::Authentication => "authentication",
            KeyDomain::CacheKeys => "cache_keys",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_strings() {
        assert_eq!(KeyDomain::Encryption.as_str(), "encryption");
        assert_eq!(KeyDomain::Authentication.as_str(), "authentication");
        assert_eq!(KeyDomain::CacheKeys.as_str(), "cache_keys");
    }
}
