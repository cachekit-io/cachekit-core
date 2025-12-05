//! Key rotation support for AES-256-GCM encryption
//!
//! Enables zero-downtime key rotation using dual-key mode:
//! - Read from both old and new keys (backward compatibility)
//! - Write only with new key (migration forward)
//! - Key version bytes in ciphertext header track which key was used

use std::convert::TryInto;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Encryption header with key version support for rotation
///
/// Format: `[version(1)][algorithm(1)][fingerprint(16)][tenant_hash(8)][domain(4)][key_version(1)][reserved(1)]` = 32 bytes
#[derive(Debug, Clone)]
pub struct RotationAwareHeader {
    pub version: u8,
    pub algorithm: u8,
    pub key_fingerprint: [u8; 16],
    pub tenant_id_hash: [u8; 8],
    pub domain: [u8; 4],
    /// Which key version encrypted this data: 0 = original, 1 = rotated
    pub key_version: u8,
}

impl RotationAwareHeader {
    pub const SIZE: usize = 32;

    pub fn new(
        key_fingerprint: [u8; 16],
        tenant_id_hash: [u8; 8],
        domain: [u8; 4],
        key_version: u8,
    ) -> Self {
        Self {
            version: 1,
            algorithm: 0, // AES-256-GCM
            key_fingerprint,
            tenant_id_hash,
            domain,
            key_version,
        }
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0] = self.version;
        bytes[1] = self.algorithm;
        bytes[2..18].copy_from_slice(&self.key_fingerprint);
        bytes[18..26].copy_from_slice(&self.tenant_id_hash);
        bytes[26..30].copy_from_slice(&self.domain);
        bytes[30] = self.key_version;
        // bytes[31] reserved
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, super::EncryptionError> {
        if bytes.len() < Self::SIZE {
            return Err(super::EncryptionError::InvalidHeader(
                "Header too short".into(),
            ));
        }

        let version = bytes[0];
        let algorithm = bytes[1];

        if version != 1 {
            return Err(super::EncryptionError::UnsupportedVersion(version));
        }

        if algorithm != 0 {
            return Err(super::EncryptionError::UnsupportedAlgorithm(algorithm));
        }

        let key_fingerprint: [u8; 16] = bytes[2..18]
            .try_into()
            .map_err(|_| super::EncryptionError::InvalidHeader("Invalid fingerprint".into()))?;
        let tenant_id_hash: [u8; 8] = bytes[18..26]
            .try_into()
            .map_err(|_| super::EncryptionError::InvalidHeader("Invalid tenant hash".into()))?;
        let domain: [u8; 4] = bytes[26..30]
            .try_into()
            .map_err(|_| super::EncryptionError::InvalidHeader("Invalid domain".into()))?;
        let key_version = bytes[30];

        Ok(Self {
            version,
            algorithm,
            key_fingerprint,
            tenant_id_hash,
            domain,
            key_version,
        })
    }
}

/// State for managing key rotation with dual-key mode
///
/// During rotation:
/// - `old_key`: Optional previous key (for decryption only, backward compatibility)
/// - `new_key`: Current active key (for encryption and decryption)
///
/// Rotation strategy:
/// 1. Set `new_key` to rotated master key
/// 2. Keep `old_key` for reading old ciphertext
/// 3. All new encryptions use `new_key`
/// 4. After migration window, remove `old_key`
///
/// # Security
/// Key material is securely erased from memory on drop via `ZeroizeOnDrop`.
/// Clone is intentionally not derived to prevent key proliferation in memory.
///
/// ```compile_fail
/// use cachekit_core::encryption::key_rotation::KeyRotationState;
/// let state = KeyRotationState::new([0u8; 32]);
/// let cloned = state.clone(); // ERROR: Clone not implemented
/// ```
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct KeyRotationState {
    /// Old key for reading legacy ciphertext (backward compatibility during migration)
    pub old_key: Option<[u8; 32]>,
    /// New key for all encryption and decryption after rotation
    pub new_key: [u8; 32],
    /// Indicates if rotation is currently active (old_key exists)
    #[zeroize(skip)]
    pub rotation_active: bool,
}

impl KeyRotationState {
    /// Create a new rotation state with just the initial key
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            old_key: None,
            new_key: key,
            rotation_active: false,
        }
    }

    /// Start key rotation: set new key, keep old for backward compatibility
    pub fn start_rotation(&mut self, new_key: [u8; 32]) {
        self.old_key = Some(self.new_key);
        self.new_key = new_key;
        self.rotation_active = true;
    }

    /// Complete key rotation: remove old key, finalize migration
    pub fn complete_rotation(&mut self) {
        self.old_key = None;
        self.rotation_active = false;
    }

    /// Get the key to use for encryption (always new key)
    pub fn encryption_key(&self) -> &[u8; 32] {
        &self.new_key
    }

    /// Get key for decryption based on version byte in ciphertext
    pub fn decryption_key(&self, key_version: u8) -> Option<&[u8; 32]> {
        match key_version {
            0 => {
                // Original key: use old_key if available (during rotation), otherwise new_key
                if self.rotation_active {
                    self.old_key.as_ref()
                } else {
                    Some(&self.new_key)
                }
            }
            1 => {
                // New key: use new_key
                Some(&self.new_key)
            }
            _ => None, // Unknown version
        }
    }

    /// Check if rotation is still in progress
    pub fn is_rotating(&self) -> bool {
        self.rotation_active && self.old_key.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotation_aware_header_roundtrip() {
        let header = RotationAwareHeader::new([0x12; 16], [0x34; 8], *b"ench", 1);

        let bytes = header.to_bytes();
        let decoded = RotationAwareHeader::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.algorithm, 0);
        assert_eq!(decoded.key_version, 1);
        assert_eq!(decoded.domain, *b"ench");
    }

    #[test]
    fn test_key_rotation_state_new() {
        let key = [0xAB; 32];
        let state = KeyRotationState::new(key);

        assert_eq!(state.new_key, key);
        assert_eq!(state.old_key, None);
        assert!(!state.rotation_active);
    }

    #[test]
    fn test_key_rotation_start() {
        let old_key = [0xAA; 32];
        let new_key = [0xBB; 32];

        let mut state = KeyRotationState::new(old_key);
        state.start_rotation(new_key);

        assert_eq!(state.new_key, new_key);
        assert_eq!(state.old_key, Some(old_key));
        assert!(state.rotation_active);
    }

    #[test]
    fn test_key_rotation_decryption_keys() {
        let old_key = [0xAA; 32];
        let new_key = [0xBB; 32];

        let mut state = KeyRotationState::new(old_key);
        state.start_rotation(new_key);

        // Version 0 should use old key during rotation
        assert_eq!(state.decryption_key(0), Some(&old_key));
        // Version 1 should use new key
        assert_eq!(state.decryption_key(1), Some(&new_key));
        // Unknown versions return None
        assert_eq!(state.decryption_key(2), None);
    }

    #[test]
    fn test_key_rotation_complete() {
        let old_key = [0xAA; 32];
        let new_key = [0xBB; 32];

        let mut state = KeyRotationState::new(old_key);
        state.start_rotation(new_key);
        state.complete_rotation();

        assert_eq!(state.new_key, new_key);
        assert_eq!(state.old_key, None);
        assert!(!state.rotation_active);
    }

    #[test]
    fn test_encryption_always_uses_new_key() {
        let old_key = [0xAA; 32];
        let new_key = [0xBB; 32];

        let mut state = KeyRotationState::new(old_key);
        state.start_rotation(new_key);

        // Encryption should always use new key
        assert_eq!(state.encryption_key(), &new_key);
    }

    /// Test that KeyRotationState can be created and dropped.
    /// The actual memory zeroization is verified by the zeroize crate's guarantees.
    /// We cannot verify memory is zeroed in safe Rust.
    #[test]
    fn test_key_rotation_state_zeroization_drop() {
        // Create state with key material
        let key = [0xDE; 32];
        let old_key = [0xAD; 32];

        {
            let mut state = KeyRotationState::new(key);
            state.start_rotation(old_key);

            // Verify keys are set
            assert_eq!(state.new_key, old_key);
            assert_eq!(state.old_key, Some(key));
            assert!(state.rotation_active);

            // State drops here - ZeroizeOnDrop should securely erase key material
        }

        // If we got here, drop was called successfully.
        // Actual memory zeroization relies on zeroize crate correctness.
    }

    /// Compile-time verification that Clone is NOT implemented.
    /// This test documents the compile_fail doctest on the struct.
    /// The actual verification is done by the compile_fail doctest on KeyRotationState.
    #[test]
    fn test_clone_not_implemented() {
        // Note: We can't easily assert !Clone in stable Rust without negative trait bounds.
        // The compile_fail doctest on KeyRotationState verifies Clone is unavailable.
        // This test exists to document that behavior and ensure the tests module compiles.
    }
}
