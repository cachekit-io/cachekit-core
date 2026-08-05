//! Multi-key decrypt keyring for master-key rotation
//!
//! Implements the client-side keyring from the protocol spec
//! (`spec/encryption.md` → "Key Rotation (Keyring)", decision record
//! `decisions/key-rotation.md`): one **current** master key that encrypts and
//! decrypts, plus an ordered list of at most [`MAX_DECRYPT_ONLY_KEYS`]
//! **decrypt-only** master keys retained during a rotation grace window.
//!
//! Rotation state is configuration, not a state machine: writes always use the
//! current key; reads attempt keyring keys sequentially, current first, with
//! identical AAD per attempt. Old-key entries age out via TTL or re-encrypt on
//! the next write. Nothing on the wire changes — the ciphertext format and AAD
//! carry no key identity.
//!
//! All master-key material held by the keyring zeroizes on drop, decrypt-only
//! entries included, so SDK bindings can keep every keyring key behind the
//! native boundary.

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::core::{EncryptionError, ZeroKnowledgeEncryptor};
use super::key_derivation::{derive_domain_key, key_fingerprint};
use super::KeyDomain;

/// Maximum number of decrypt-only keys a keyring accepts.
///
/// Bounds worst-case sequential decrypt attempts and resident key material
/// while still allowing a forced mid-window second rotation (e.g. an
/// offboarding landing during a long-TTL compliance window). Exceeding the cap
/// is a configuration error, rejected at construction — never truncated.
pub const MAX_DECRYPT_ONLY_KEYS: usize = 3;

/// A master-key keyring: one current key plus decrypt-only previous keys.
///
/// Each entry independently derives per-tenant keys via the crate's HKDF
/// construction ([`derive_domain_key`]); salts, domains, and fingerprints are
/// unchanged from single-key operation. Entry order is current key first, then
/// the decrypt-only keys in the order supplied.
///
/// # Invariants (enforced at construction)
///
/// - At most [`MAX_DECRYPT_ONLY_KEYS`] decrypt-only keys
///   ([`EncryptionError::KeyringCapExceeded`]).
/// - The current key must not appear in the decrypt-only list — the detectable
///   subset of the forward-only rule: a key that ever occupied the encrypting
///   slot is never re-promoted, because that would resume a used, unknowable
///   AES-GCM nonce budget ([`EncryptionError::CurrentKeyInDecryptOnlyList`]).
/// - Every key is at least 16 bytes
///   ([`EncryptionError::InvalidMasterKeyLength`]).
///
/// # Examples
///
/// A value encrypted under a retiring key stays readable through rotation as
/// long as that key remains in the decrypt-only list:
///
/// ```
/// use cachekit_core::{derive_domain_key, Keyring, ZeroKnowledgeEncryptor};
///
/// let k1 = [0x11u8; 32]; // retiring master key
/// let k2 = [0x22u8; 32]; // current master key after rotation
/// let encryptor = ZeroKnowledgeEncryptor::new()?;
///
/// // Encrypted under k1, before the rotation...
/// let tenant_key = derive_domain_key(&k1, "encryption", b"tenant-123")?;
/// let ciphertext = encryptor.encrypt_aes_gcm(b"cached value", &tenant_key, b"aad")?;
///
/// // ...still decrypts with keyring [current=k2, decrypt-only=[k1]].
/// let keyring = Keyring::new(&k2, &[&k1])?;
/// let plaintext = keyring.decrypt(&encryptor, &ciphertext, "tenant-123", b"aad")?;
/// assert_eq!(plaintext, b"cached value");
///
/// // A hard cut-over (empty decrypt-only list) cannot read the old entry.
/// let cut_over = Keyring::new(&k2, &[])?;
/// assert!(cut_over.decrypt(&encryptor, &ciphertext, "tenant-123", b"aad").is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Keyring {
    current: Vec<u8>,
    decrypt_only: Vec<Vec<u8>>,
}

impl Keyring {
    /// Create a keyring from a current master key and decrypt-only master keys.
    ///
    /// `decrypt_only` is ordered: on sequential decrypt, keys are attempted
    /// current first, then in the order given here.
    ///
    /// # Errors
    ///
    /// - [`EncryptionError::KeyringCapExceeded`] if more than
    ///   [`MAX_DECRYPT_ONLY_KEYS`] decrypt-only keys are supplied.
    /// - [`EncryptionError::CurrentKeyInDecryptOnlyList`] if the current key
    ///   also appears in the decrypt-only list.
    /// - [`EncryptionError::InvalidMasterKeyLength`] if any key is shorter
    ///   than 16 bytes.
    pub fn new(current: &[u8], decrypt_only: &[&[u8]]) -> Result<Self, EncryptionError> {
        if decrypt_only.len() > MAX_DECRYPT_ONLY_KEYS {
            return Err(EncryptionError::KeyringCapExceeded(decrypt_only.len()));
        }

        for key in std::iter::once(current).chain(decrypt_only.iter().copied()) {
            if key.len() < 16 {
                return Err(EncryptionError::InvalidMasterKeyLength(key.len()));
            }
        }

        // Plain equality is fine here: both operands are operator-supplied
        // configuration this process already holds, so there is no timing
        // oracle — this is config validation, not a secret comparison.
        if decrypt_only.contains(&current) {
            return Err(EncryptionError::CurrentKeyInDecryptOnlyList);
        }

        Ok(Self {
            current: current.to_vec(),
            decrypt_only: decrypt_only.iter().map(|key| key.to_vec()).collect(),
        })
    }

    /// Total number of keyring entries (1 current + decrypt-only keys).
    pub fn entry_count(&self) -> usize {
        1 + self.decrypt_only.len()
    }

    /// Number of decrypt-only keys.
    pub fn decrypt_only_count(&self) -> usize {
        self.decrypt_only.len()
    }

    /// Keyring entries in attempt order: current key first.
    fn entries(&self) -> impl Iterator<Item = &[u8]> {
        std::iter::once(self.current.as_slice())
            .chain(self.decrypt_only.iter().map(|key| key.as_slice()))
    }

    /// Per-entry fingerprints of the HKDF-derived per-tenant **encryption**
    /// key, in attempt order (current key first).
    ///
    /// The fingerprint is computed over the derived per-tenant encryption key,
    /// not the master key — this matches the per-entry key fingerprint that
    /// cachekit-py stores as frame metadata, so fingerprint-based keyring
    /// selection compares like with like.
    pub fn encryption_fingerprints(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<[u8; 16]>, EncryptionError> {
        self.entries()
            .map(|master| {
                let mut key = derive_encryption_key(master, tenant_id)?;
                let fingerprint = key_fingerprint(&key);
                key.zeroize();
                Ok(fingerprint)
            })
            .collect()
    }

    /// Decrypt with a specific keyring entry (0 = current key).
    ///
    /// For fingerprint-based selection: match the entry via
    /// [`encryption_fingerprints`](Self::encryption_fingerprints), then decrypt
    /// with exactly that entry. A fingerprint match is binding — if the matched
    /// key fails AES-GCM authentication the failure is terminal; do not fall
    /// back to other entries.
    ///
    /// # Errors
    ///
    /// [`EncryptionError::DecryptionFailed`] for an out-of-range index or a
    /// key-derivation failure; [`EncryptionError::AuthenticationFailed`] (or a
    /// structural ciphertext error) from the underlying AES-GCM decrypt.
    pub fn decrypt_at(
        &self,
        index: usize,
        encryptor: &ZeroKnowledgeEncryptor,
        ciphertext: &[u8],
        tenant_id: &str,
        aad: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let master = self.entries().nth(index).ok_or_else(|| {
            EncryptionError::DecryptionFailed(format!(
                "keyring entry index {index} out of range (entry count {})",
                self.entry_count()
            ))
        })?;
        let mut key = derive_encryption_key(master, tenant_id)?;
        let result = encryptor.decrypt_aes_gcm(ciphertext, &key, aad);
        key.zeroize();
        result
    }

    /// Decrypt by sequential keyring attempts: current key first, then each
    /// decrypt-only key in order, rebuilding nothing between attempts — every
    /// attempt uses the identical `aad`.
    ///
    /// Only an AES-GCM authentication failure (the wrong-key signal) advances
    /// to the next key. Structural errors (e.g. ciphertext too short) are
    /// terminal immediately: they would fail identically under every key.
    ///
    /// # Errors
    ///
    /// [`EncryptionError::AuthenticationFailed`] when no keyring key decrypts
    /// the ciphertext — the caller's existing fail-open / fail-closed policy
    /// applies, no new failure mode.
    pub fn decrypt(
        &self,
        encryptor: &ZeroKnowledgeEncryptor,
        ciphertext: &[u8],
        tenant_id: &str,
        aad: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        for index in 0..self.entry_count() {
            match self.decrypt_at(index, encryptor, ciphertext, tenant_id, aad) {
                Err(EncryptionError::AuthenticationFailed) => continue,
                other => return other,
            }
        }
        Err(EncryptionError::AuthenticationFailed)
    }
}

/// Derive the per-tenant encryption key for one keyring entry.
///
/// Identical to the `encryption_key` produced by
/// [`derive_tenant_keys`](super::key_derivation::derive_tenant_keys) — same
/// HKDF construction, same salt/domain — so keyring-derived keys and
/// fingerprints agree byte-for-byte with single-key operation.
fn derive_encryption_key(master: &[u8], tenant_id: &str) -> Result<[u8; 32], EncryptionError> {
    derive_domain_key(master, KeyDomain::Encryption.as_str(), tenant_id.as_bytes())
        .map_err(|e| EncryptionError::DecryptionFailed(format!("key derivation failed: {e}")))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::super::key_derivation::derive_tenant_keys;
    use super::*;

    const K1: [u8; 32] = [0x11; 32];
    const K2: [u8; 32] = [0x22; 32];
    const TENANT: &str = "tenant-123";
    const AAD: &[u8] = b"test_aad";

    fn encrypt_under(master: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let key = derive_encryption_key(master, TENANT).unwrap();
        encryptor.encrypt_aes_gcm(plaintext, &key, AAD).unwrap()
    }

    #[test]
    fn test_previous_key_entry_decrypts_after_rotation() {
        // AC: value encrypted under k1 decrypts with keyring [current=k2, prev=[k1]] ...
        let ciphertext = encrypt_under(&K1, b"secret");
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();

        let keyring = Keyring::new(&K2, &[&K1]).unwrap();
        let plaintext = keyring
            .decrypt(&encryptor, &ciphertext, TENANT, AAD)
            .unwrap();
        assert_eq!(plaintext, b"secret");

        // ... and the same value FAILS with keyring [current=k2, prev=[]] (hard cut-over)
        let cut_over = Keyring::new(&K2, &[]).unwrap();
        let result = cut_over.decrypt(&encryptor, &ciphertext, TENANT, AAD);
        assert!(matches!(result, Err(EncryptionError::AuthenticationFailed)));
    }

    #[test]
    fn test_current_key_decrypts_first() {
        let ciphertext = encrypt_under(&K2, b"fresh write");
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();

        let keyring = Keyring::new(&K2, &[&K1]).unwrap();
        // Entry 0 is the current key — decrypt_at(0) must succeed directly.
        let plaintext = keyring
            .decrypt_at(0, &encryptor, &ciphertext, TENANT, AAD)
            .unwrap();
        assert_eq!(plaintext, b"fresh write");
    }

    #[test]
    fn test_cap_rejected_never_truncated() {
        // AC: more than MAX_DECRYPT_ONLY_KEYS decrypt-only keys is an error.
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let c = [0x03u8; 32];
        let d = [0x04u8; 32];

        // At the cap: fine.
        assert!(Keyring::new(&K2, &[&a, &b, &c]).is_ok());

        // One over the cap: rejected with the offending count, never truncated.
        let result = Keyring::new(&K2, &[&a, &b, &c, &d]);
        assert!(matches!(
            result,
            Err(EncryptionError::KeyringCapExceeded(4))
        ));
    }

    #[test]
    fn test_current_key_in_decrypt_only_list_rejected() {
        // AC: detectable subset of the forward-only invariant.
        let result = Keyring::new(&K2, &[&K1, &K2]);
        assert!(matches!(
            result,
            Err(EncryptionError::CurrentKeyInDecryptOnlyList)
        ));
    }

    #[test]
    fn test_short_master_key_rejected() {
        let short = [0x01u8; 15];
        assert!(matches!(
            Keyring::new(&short, &[]),
            Err(EncryptionError::InvalidMasterKeyLength(15))
        ));
        assert!(matches!(
            Keyring::new(&K2, &[&short[..]]),
            Err(EncryptionError::InvalidMasterKeyLength(15))
        ));
    }

    #[test]
    fn test_fingerprints_are_derived_key_fingerprints() {
        // AC: per-entry fingerprint == fingerprint of that entry's derived
        // tenant_keys.encryption_key (NOT the master key), in attempt order.
        let keyring = Keyring::new(&K2, &[&K1]).unwrap();
        let fingerprints = keyring.encryption_fingerprints(TENANT).unwrap();

        let k2_tenant = derive_tenant_keys(&K2, TENANT).unwrap();
        let k1_tenant = derive_tenant_keys(&K1, TENANT).unwrap();

        assert_eq!(fingerprints.len(), 2);
        assert_eq!(fingerprints[0], k2_tenant.encryption_fingerprint());
        assert_eq!(fingerprints[1], k1_tenant.encryption_fingerprint());

        // And explicitly NOT the master-key fingerprints.
        assert_ne!(fingerprints[0], key_fingerprint(&K2));
        assert_ne!(fingerprints[1], key_fingerprint(&K1));
    }

    #[test]
    fn test_identical_aad_required_across_all_attempts() {
        // Spec: sequential attempts rebuild the identical AAD; a different AAD
        // must fail even though the encrypting key is present in the keyring.
        let ciphertext = encrypt_under(&K1, b"secret");
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();

        let keyring = Keyring::new(&K2, &[&K1]).unwrap();
        let result = keyring.decrypt(&encryptor, &ciphertext, TENANT, b"different_aad");
        assert!(matches!(result, Err(EncryptionError::AuthenticationFailed)));
    }

    #[test]
    fn test_structural_error_is_terminal() {
        // A too-short ciphertext is not a wrong-key signal — it must surface
        // as InvalidCiphertext, not be retried into AuthenticationFailed.
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let keyring = Keyring::new(&K2, &[&K1]).unwrap();

        let result = keyring.decrypt(&encryptor, b"too short", TENANT, AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidCiphertext(_))));
    }

    #[test]
    fn test_decrypt_at_out_of_range() {
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let keyring = Keyring::new(&K2, &[]).unwrap();
        let ciphertext = encrypt_under(&K2, b"x");

        let result = keyring.decrypt_at(1, &encryptor, &ciphertext, TENANT, AAD);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed(_))));
    }

    #[test]
    fn test_all_key_material_zeroizes() {
        // AC: keyring key material zeroizes, decrypt-only entries included.
        // ZeroizeOnDrop runs this same Zeroize impl on drop; verifying the
        // explicit zeroize() proves every field is covered (reading freed
        // memory after an actual drop would be UB).
        let mut keyring = Keyring::new(&K2, &[&K1]).unwrap();
        keyring.zeroize();

        assert!(keyring.current.iter().all(|&b| b == 0) || keyring.current.is_empty());
        assert!(keyring
            .decrypt_only
            .iter()
            .all(|key| key.iter().all(|&b| b == 0) || key.is_empty()));

        // Compile-time proof the drop guarantee exists at all.
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Keyring>();
    }

    #[test]
    fn test_entry_counts() {
        let keyring = Keyring::new(&K2, &[&K1]).unwrap();
        assert_eq!(keyring.entry_count(), 2);
        assert_eq!(keyring.decrypt_only_count(), 1);

        let solo = Keyring::new(&K2, &[]).unwrap();
        assert_eq!(solo.entry_count(), 1);
        assert_eq!(solo.decrypt_only_count(), 0);
    }
}
