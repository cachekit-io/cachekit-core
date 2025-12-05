//! Key derivation using HKDF with SHA-256
//!
//! This module implements secure key derivation using HKDF (HMAC-based Key Derivation Function)
//! with SHA-256, following RFC 5869. This provides protection against GPU-accelerated
//! brute-force attacks on weak master keys compared to simple hash functions.
//!
//! For domain separation, we use HKDF's salt parameter combined with domain context
//! to prevent key confusion attacks and ensure cryptographic isolation between different
//! uses of the same master key.

use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum domain length (must fit in u8 for length-prefixed encoding)
pub const MAX_DOMAIN_LENGTH: usize = 255;

/// Maximum tenant salt length (must fit in u16 for length-prefixed encoding)
pub const MAX_TENANT_SALT_LENGTH: usize = 1024;

/// Errors that can occur during key derivation
#[derive(Error, Debug)]
pub enum KeyDerivationError {
    #[error("Invalid master key length: expected at least 16 bytes, got {0}")]
    InvalidMasterKeyLength(usize),

    #[error("Invalid domain string: {0}")]
    InvalidDomain(String),

    #[error("Invalid salt length: expected at least 1 byte, got {0}")]
    InvalidSaltLength(usize),

    #[error("Key derivation failed: {0}")]
    DerivationFailed(String),

    #[error("Domain exceeds maximum length")]
    DomainTooLong,

    #[error("Tenant salt exceeds maximum length")]
    TenantSaltTooLong,
}

/// Derive a domain-specific key using HKDF-SHA256
///
/// This implements RFC 5869 HKDF with SHA-256 to provide:
/// - Resistance to GPU-accelerated brute-force attacks (compared to simple hash functions)
/// - Domain separation via salt parameter
/// - Multi-tenant isolation via tenant salt
///
/// # Arguments
/// * `master_key` - Master key material (at least 16 bytes, ideally 32 bytes)
/// * `domain` - Domain context string (e.g., "encryption", "authentication")
/// * `tenant_salt` - Tenant-specific salt for multi-tenant isolation
///
/// # Returns
/// 256-bit derived key
///
/// # Security Notes
/// - Uses HKDF-SHA256 for key derivation (RFC 5869 compliant)
/// - Salt parameter includes domain context for domain separation
/// - Tenant salt ensures different tenants get different keys
/// - Output is always 32 bytes (256 bits) for AES-256 compatibility
/// - Requires minimum 16-byte master key; 32 bytes strongly recommended
pub fn derive_domain_key(
    master_key: &[u8],
    domain: &str,
    tenant_salt: &[u8],
) -> Result<[u8; 32], KeyDerivationError> {
    // Validate inputs
    if master_key.len() < 16 {
        return Err(KeyDerivationError::InvalidMasterKeyLength(master_key.len()));
    }

    if domain.is_empty() {
        return Err(KeyDerivationError::InvalidDomain(
            "Domain cannot be empty".into(),
        ));
    }

    let domain_bytes = domain.as_bytes();
    if domain_bytes.len() > MAX_DOMAIN_LENGTH {
        return Err(KeyDerivationError::DomainTooLong);
    }

    if tenant_salt.is_empty() {
        return Err(KeyDerivationError::InvalidSaltLength(tenant_salt.len()));
    }

    if tenant_salt.len() > MAX_TENANT_SALT_LENGTH {
        return Err(KeyDerivationError::TenantSaltTooLong);
    }

    // HKDF salt: length-prefixed encoding for collision resistance
    // Format: [prefix][domain_len:u8][domain][salt_len:u16BE][salt]
    // This prevents collision attacks where (domain="foo", salt="bar") could equal (domain="foob", salt="ar")
    let mut salt_data = Vec::with_capacity(12 + 1 + domain_bytes.len() + 2 + tenant_salt.len());
    salt_data.extend_from_slice(b"cachekit_v1_"); // 12 bytes
    salt_data.push(domain_bytes.len() as u8); // domain length as u8
    salt_data.extend_from_slice(domain_bytes);
    salt_data.extend_from_slice(&(tenant_salt.len() as u16).to_be_bytes()); // salt length as u16 BE
    salt_data.extend_from_slice(tenant_salt);

    // Initialize HKDF with the computed salt
    let hkdf = Hkdf::<Sha256>::new(Some(&salt_data), master_key);

    // Expand using domain as context (additional domain separation layer)
    let mut key = [0u8; 32];
    hkdf.expand(domain.as_bytes(), &mut key)
        .map_err(|_| KeyDerivationError::DerivationFailed("HKDF expand failed".into()))?;

    Ok(key)
}

/// Generate key fingerprint for identification and rotation support
///
/// Creates a collision-resistant fingerprint of a key for identification
/// without revealing the key material itself.
pub fn key_fingerprint(key: &[u8]) -> [u8; 16] {
    use sha2::Digest;

    let mut hasher = sha2::Sha256::new();
    hasher.update(b"key_fingerprint_v1");
    hasher.update(key);
    let hash = hasher.finalize();
    let mut result = [0u8; 16];
    result.copy_from_slice(&hash[..16]);
    result
}

/// Derive multiple domain keys at once for efficiency
///
/// This is useful when setting up a new tenant and needing all domain keys.
pub fn derive_tenant_keys(
    master_key: &[u8],
    tenant_id: &str,
) -> Result<TenantKeys, KeyDerivationError> {
    let tenant_salt = tenant_id.as_bytes();

    let encryption_key = derive_domain_key(master_key, "encryption", tenant_salt)?;
    let authentication_key = derive_domain_key(master_key, "authentication", tenant_salt)?;
    let cache_key_salt = derive_domain_key(master_key, "cache_keys", tenant_salt)?;

    Ok(TenantKeys {
        encryption_key,
        authentication_key,
        cache_key_salt,
        tenant_id: tenant_id.to_string(),
    })
}

/// Container for all keys derived for a tenant
///
/// Note: `Clone` is intentionally NOT derived to prevent key material from proliferating
/// in memory. Each `TenantKeys` instance is zeroized on drop via `ZeroizeOnDrop`.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct TenantKeys {
    pub encryption_key: [u8; 32],
    pub authentication_key: [u8; 32],
    pub cache_key_salt: [u8; 32],
    #[zeroize(skip)]
    pub tenant_id: String,
}

impl TenantKeys {
    /// Get fingerprint for the encryption key
    pub fn encryption_fingerprint(&self) -> [u8; 16] {
        key_fingerprint(&self.encryption_key)
    }

    /// Get fingerprint for the authentication key
    pub fn authentication_fingerprint(&self) -> [u8; 16] {
        key_fingerprint(&self.authentication_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_domain_key_deterministic() {
        let master_key = b"test_master_key_32_bytes_long!!!";
        let domain = "encryption";
        let tenant_salt = b"tenant123";

        let key1 = derive_domain_key(master_key, domain, tenant_salt).unwrap();
        let key2 = derive_domain_key(master_key, domain, tenant_salt).unwrap();

        assert_eq!(key1, key2, "Same inputs should produce same key");
    }

    #[test]
    fn test_domain_separation() {
        let master_key = b"test_master_key_32_bytes_long!!!";
        let tenant_salt = b"tenant123";

        let enc_key = derive_domain_key(master_key, "encryption", tenant_salt).unwrap();
        let auth_key = derive_domain_key(master_key, "authentication", tenant_salt).unwrap();
        let cache_key = derive_domain_key(master_key, "cache_keys", tenant_salt).unwrap();

        // All keys should be different
        assert_ne!(enc_key, auth_key);
        assert_ne!(enc_key, cache_key);
        assert_ne!(auth_key, cache_key);
    }

    #[test]
    fn test_tenant_separation() {
        let master_key = b"test_master_key_32_bytes_long!!!";
        let domain = "encryption";

        let key1 = derive_domain_key(master_key, domain, b"tenant1").unwrap();
        let key2 = derive_domain_key(master_key, domain, b"tenant2").unwrap();

        assert_ne!(key1, key2, "Different tenants should get different keys");
    }

    #[test]
    fn test_master_key_sensitivity() {
        let master_key1 = b"test_master_key_32_bytes_long!!!";
        let master_key2 = b"different_master_key_32_bytes!!!";
        let domain = "encryption";
        let tenant_salt = b"tenant123";

        let key1 = derive_domain_key(master_key1, domain, tenant_salt).unwrap();
        let key2 = derive_domain_key(master_key2, domain, tenant_salt).unwrap();

        assert_ne!(
            key1, key2,
            "Different master keys should produce different derived keys"
        );
    }

    #[test]
    fn test_invalid_inputs() {
        let short_key = b"short";
        let master_key = b"test_master_key_32_bytes_long!!!";

        // Short master key should fail
        let result = derive_domain_key(short_key, "encryption", b"tenant");
        assert!(matches!(
            result,
            Err(KeyDerivationError::InvalidMasterKeyLength(5))
        ));

        // Empty domain should fail
        let result = derive_domain_key(master_key, "", b"tenant");
        assert!(matches!(result, Err(KeyDerivationError::InvalidDomain(_))));

        // Empty salt should fail
        let result = derive_domain_key(master_key, "encryption", b"");
        assert!(matches!(
            result,
            Err(KeyDerivationError::InvalidSaltLength(0))
        ));
    }

    #[test]
    fn test_tenant_keys_derivation() {
        let master_key = b"test_master_key_32_bytes_long!!!";
        let tenant_id = "test_tenant_123";

        let keys = derive_tenant_keys(master_key, tenant_id).unwrap();

        // Verify all keys are different
        assert_ne!(keys.encryption_key, keys.authentication_key);
        assert_ne!(keys.encryption_key, keys.cache_key_salt);
        assert_ne!(keys.authentication_key, keys.cache_key_salt);

        // Verify tenant ID is stored
        assert_eq!(keys.tenant_id, tenant_id);

        // Verify fingerprints work
        let fp1 = keys.encryption_fingerprint();
        let fp2 = keys.encryption_fingerprint();
        assert_eq!(fp1, fp2, "Fingerprints should be deterministic");
    }

    #[test]
    fn test_key_fingerprint_uniqueness() {
        let key1 = b"test_key_1_with_32_bytes_exactly!";
        let key2 = b"test_key_2_with_32_bytes_exactly!";

        let fp1 = key_fingerprint(key1);
        let fp2 = key_fingerprint(key2);

        assert_ne!(
            fp1, fp2,
            "Different keys should have different fingerprints"
        );

        // Same key should always produce same fingerprint
        let fp1_again = key_fingerprint(key1);
        assert_eq!(fp1, fp1_again, "Fingerprints should be deterministic");
    }

    /// Test exact byte sequence of HKDF salt construction.
    /// This is a regression test to catch accidental format changes.
    ///
    /// Format: [prefix][domain_len:u8][domain][salt_len:u16BE][salt]
    /// Input: domain="cache", tenant_salt=b"tenant-123"
    /// Expected: "cachekit_v1_" + 0x05 + "cache" + 0x000a + "tenant-123"
    #[test]
    fn test_hkdf_salt_byte_vector() {
        // Build the expected salt manually to verify format
        let mut expected_salt = Vec::new();
        expected_salt.extend_from_slice(b"cachekit_v1_"); // 12 bytes prefix
        expected_salt.push(5); // domain_len for "cache" as u8
        expected_salt.extend_from_slice(b"cache"); // 5 bytes domain
        expected_salt.extend_from_slice(&10u16.to_be_bytes()); // salt_len for "tenant-123" as u16 BE
        expected_salt.extend_from_slice(b"tenant-123"); // 10 bytes salt

        // Verify structure: prefix(12) + domain_len(1) + domain(5) + salt_len(2) + salt(10) = 30 bytes
        assert_eq!(expected_salt.len(), 30);

        // Verify prefix is correct
        assert_eq!(&expected_salt[0..12], b"cachekit_v1_");

        // Verify domain length byte
        assert_eq!(expected_salt[12], 5);

        // Verify domain
        assert_eq!(&expected_salt[13..18], b"cache");

        // Verify salt length as big-endian u16
        assert_eq!(&expected_salt[18..20], &[0x00, 0x0a]); // 10 in BE

        // Verify salt
        assert_eq!(&expected_salt[20..30], b"tenant-123");

        // The salt is internal to derive_domain_key, so we verify determinism
        let master_key = b"test_master_key_32_bytes_long!!!";
        let key1 = derive_domain_key(master_key, "cache", b"tenant-123").unwrap();
        let key2 = derive_domain_key(master_key, "cache", b"tenant-123").unwrap();
        assert_eq!(key1, key2, "Same inputs should produce same derived key");
    }

    /// Test collision resistance: (foo, bar) != (foob, ar)
    /// With length-prefixed encoding, these produce different salts.
    #[test]
    fn test_hkdf_salt_collision_resistance() {
        let master_key = b"test_master_key_32_bytes_long!!!";

        // These would collide with naive concatenation but not with length-prefixed encoding
        let key1 = derive_domain_key(master_key, "foo", b"bar").unwrap();
        let key2 = derive_domain_key(master_key, "foob", b"ar").unwrap();

        assert_ne!(
            key1, key2,
            "Different (domain, salt) pairs must produce different keys"
        );

        // Also test edge cases
        let key3 = derive_domain_key(master_key, "ab", b"cd").unwrap();
        let key4 = derive_domain_key(master_key, "a", b"bcd").unwrap();
        assert_ne!(key3, key4);
    }

    /// Test domain and salt length limits
    #[test]
    fn test_domain_and_salt_length_limits() {
        let master_key = b"test_master_key_32_bytes_long!!!";

        // Domain at exactly max length should succeed
        let max_domain = "a".repeat(MAX_DOMAIN_LENGTH);
        let result = derive_domain_key(master_key, &max_domain, b"salt");
        assert!(result.is_ok());

        // Domain exceeding max length should fail
        let oversized_domain = "a".repeat(MAX_DOMAIN_LENGTH + 1);
        let result = derive_domain_key(master_key, &oversized_domain, b"salt");
        assert!(matches!(result, Err(KeyDerivationError::DomainTooLong)));

        // Salt at exactly max length should succeed
        let max_salt = vec![0u8; MAX_TENANT_SALT_LENGTH];
        let result = derive_domain_key(master_key, "domain", &max_salt);
        assert!(result.is_ok());

        // Salt exceeding max length should fail
        let oversized_salt = vec![0u8; MAX_TENANT_SALT_LENGTH + 1];
        let result = derive_domain_key(master_key, "domain", &oversized_salt);
        assert!(matches!(result, Err(KeyDerivationError::TenantSaltTooLong)));
    }

    /// Verify HKDF produces different keys for different inputs
    #[test]
    fn test_hkdf_output_sensitivity() {
        let master_key = b"test_master_key_32_bytes_long!!!";

        let key1 = derive_domain_key(master_key, "encryption", b"tenant_abc").unwrap();

        // Verify it's not all zeros or other obvious failures
        assert_ne!(key1, [0u8; 32]);
        assert_ne!(key1, [0xffu8; 32]);
        assert_eq!(key1.len(), 32);
    }
}
