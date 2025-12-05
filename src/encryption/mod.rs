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
pub mod key_rotation;

// Re-exports for convenience
pub use core::{EncryptionError, ZeroKnowledgeEncryptor};
pub use key_derivation::{KeyDerivationError, derive_domain_key};
pub use key_rotation::{KeyRotationState, RotationAwareHeader};

// RotationAwareHeader is the canonical encryption header
pub type EncryptionHeader = RotationAwareHeader;

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
    fn test_encryption_header_roundtrip() {
        // RotationAwareHeader (now canonical EncryptionHeader) with version 0 for non-rotated
        let header = RotationAwareHeader::new([0x12; 16], [0x34; 8], *b"ench", 0);

        let bytes = header.to_bytes();
        let decoded = RotationAwareHeader::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.key_fingerprint, [0x12; 16]);
        assert_eq!(decoded.domain, *b"ench");
        assert_eq!(decoded.key_version, 0); // Non-rotated data
        // Verify algorithm is always AES-256-GCM (byte value 0)
        assert_eq!(bytes[1], 0);
    }

    #[test]
    fn test_unsupported_algorithm_rejected() {
        let mut bytes = [0u8; RotationAwareHeader::SIZE];
        bytes[0] = 1; // version
        bytes[1] = 99; // unsupported algorithm

        let result = RotationAwareHeader::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_domain_strings() {
        assert_eq!(KeyDomain::Encryption.as_str(), "encryption");
        assert_eq!(KeyDomain::Authentication.as_str(), "authentication");
        assert_eq!(KeyDomain::CacheKeys.as_str(), "cache_keys");
    }
}
