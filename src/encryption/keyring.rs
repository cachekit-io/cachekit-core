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
//!
//! For steady-state decryption, bind the keyring to its tenant with
//! [`Keyring::for_tenant`]: per-tenant key derivation runs exactly once, at
//! construction, and the resulting [`TenantKeyring`] decrypts with no
//! per-attempt HKDF and no master keys left resident.

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
    ///
    /// Private on purpose: bindings that need the count get it as
    /// `encryption_fingerprints().len()`, which they must fetch for selection
    /// anyway.
    fn entry_count(&self) -> usize {
        1 + self.decrypt_only.len()
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
    /// - [`EncryptionError::KeyringIndexOutOfRange`] for an out-of-range index
    ///   — a caller bug, deliberately distinct from any crypto failure.
    /// - [`EncryptionError::KeyDerivation`] if per-tenant key derivation fails
    ///   (e.g. an invalid `tenant_id`) — a configuration error, not a miss.
    /// - [`EncryptionError::AuthenticationFailed`] when this entry's key does
    ///   not authenticate the ciphertext.
    /// - [`EncryptionError::InvalidCiphertext`] for malformed ciphertext.
    pub fn decrypt_at(
        &self,
        index: usize,
        encryptor: &ZeroKnowledgeEncryptor,
        ciphertext: &[u8],
        tenant_id: &str,
        aad: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let master = self
            .entries()
            .nth(index)
            .ok_or(EncryptionError::KeyringIndexOutOfRange {
                index,
                count: self.entry_count(),
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
    /// - [`EncryptionError::AuthenticationFailed`] when no keyring key decrypts
    ///   the ciphertext — the caller's existing fail-open / fail-closed policy
    ///   applies, no new failure mode.
    /// - Terminal (never retried across keys): structural ciphertext errors
    ///   ([`EncryptionError::InvalidCiphertext`]) and configuration errors
    ///   ([`EncryptionError::KeyDerivation`], e.g. an invalid `tenant_id`).
    pub fn decrypt(
        &self,
        encryptor: &ZeroKnowledgeEncryptor,
        ciphertext: &[u8],
        tenant_id: &str,
        aad: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        self.decrypt_indexed(encryptor, ciphertext, tenant_id, aad)
            .map(|(plaintext, _)| plaintext)
    }

    /// [`decrypt`](Self::decrypt), additionally reporting **which keyring
    /// entry** satisfied the read (0 = current key, 1.. = decrypt-only keys in
    /// list order).
    ///
    /// This is the rotation **drain-observability** surface: during a rotation
    /// grace window, count reads that return a non-zero index (previous-key
    /// hits). When that rate reaches zero — every live entry has aged out via
    /// TTL or been re-encrypted on write — the retiring key is no longer
    /// serving reads and can be dropped from the decrypt-only list safely,
    /// instead of guessing and risking a hard cut-over.
    ///
    /// Attempt sequencing is identical to [`decrypt`](Self::decrypt) — same
    /// order, identical AAD per attempt, only
    /// [`EncryptionError::AuthenticationFailed`] advances, structural and
    /// configuration errors terminal, exhaustion yields plain
    /// `AuthenticationFailed`. The index reveals only the position that
    /// decrypted; no key material or fingerprint accompanies it.
    ///
    /// # Errors
    ///
    /// Identical to [`decrypt`](Self::decrypt).
    ///
    /// # Examples
    ///
    /// A read served by the retiring key reports a non-zero index — the drain
    /// signal that says the grace window is still live:
    ///
    /// ```
    /// use cachekit_core::{derive_domain_key, Keyring, ZeroKnowledgeEncryptor};
    /// use zeroize::Zeroize;
    ///
    /// let mut k1 = [0x11u8; 32]; // retiring master key
    /// let mut k2 = [0x22u8; 32]; // current master key after rotation
    /// let encryptor = ZeroKnowledgeEncryptor::new()?;
    ///
    /// // Encrypted under k1, before the rotation...
    /// let mut tenant_key = derive_domain_key(&k1, "encryption", b"tenant-123")?;
    /// let ciphertext = encryptor.encrypt_aes_gcm(b"cached value", &tenant_key, b"aad")?;
    /// tenant_key.zeroize();
    ///
    /// // ...a keyring [current=k2, decrypt-only=[k1]] serves it from entry 1:
    /// // the retiring key is still draining, not yet safe to drop.
    /// let keyring = Keyring::new(&k2, &[&k1])?;
    /// k1.zeroize(); // the keyring holds copies — wipe the caller-owned buffers
    /// k2.zeroize();
    /// let (plaintext, index) = keyring.decrypt_indexed(&encryptor, &ciphertext, "tenant-123", b"aad")?;
    /// assert_eq!(plaintext, b"cached value");
    /// assert_eq!(index, 1);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn decrypt_indexed(
        &self,
        encryptor: &ZeroKnowledgeEncryptor,
        ciphertext: &[u8],
        tenant_id: &str,
        aad: &[u8],
    ) -> Result<(Vec<u8>, usize), EncryptionError> {
        for index in 0..self.entry_count() {
            match self.decrypt_at(index, encryptor, ciphertext, tenant_id, aad) {
                Ok(plaintext) => return Ok((plaintext, index)),
                Err(EncryptionError::AuthenticationFailed) => continue,
                Err(err) => return Err(err),
            }
        }
        Err(EncryptionError::AuthenticationFailed)
    }

    /// Bind this keyring to one tenant, deriving every per-tenant encryption
    /// key exactly once and consuming the master keys.
    ///
    /// This is the steady-state decrypt surface: [`Keyring::decrypt`] re-runs
    /// HKDF per attempt on every call, so a client that decrypts through the
    /// keyring pays a fresh derivation on every read — L1 hits included, since
    /// L1 stores ciphertext. `for_tenant` moves that cost to construction: the
    /// returned [`TenantKeyring`] holds only the ≤ 1 + [`MAX_DECRYPT_ONLY_KEYS`]
    /// derived per-tenant keys and performs **no** HKDF on decrypt.
    ///
    /// Consuming `self` drops the keyring, zeroizing all master-key material —
    /// after construction only derived per-tenant keys remain resident. One
    /// tenant per binding: build a fresh `Keyring` to bind another tenant.
    ///
    /// Attempt order, AAD handling, and error classes are identical to the
    /// unbound keyring; only the timing of derivation errors moves — an invalid
    /// `tenant_id` surfaces here as [`EncryptionError::KeyDerivation`] instead
    /// of at first decrypt.
    ///
    /// # Errors
    ///
    /// - [`EncryptionError::KeyDerivation`] if per-tenant key derivation fails
    ///   (e.g. an invalid `tenant_id`) — a configuration error, not a miss.
    ///
    /// # Examples
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
    /// // ...still decrypts through the tenant-bound ring: derivation ran once,
    /// // at for_tenant; this decrypt (and every one after) performs no HKDF.
    /// let ring = Keyring::new(&k2, &[&k1])?.for_tenant("tenant-123")?;
    /// let plaintext = ring.decrypt(&encryptor, &ciphertext, b"aad")?;
    /// assert_eq!(plaintext, b"cached value");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn for_tenant(self, tenant_id: &str) -> Result<TenantKeyring, EncryptionError> {
        let mut keys: Vec<[u8; 32]> = Vec::with_capacity(self.entry_count());
        for master in self.entries() {
            match derive_encryption_key(master, tenant_id) {
                Ok(key) => keys.push(key),
                Err(err) => {
                    // Wipe any keys already derived before surfacing the error.
                    keys.zeroize();
                    return Err(err);
                }
            }
        }
        Ok(TenantKeyring { keys })
        // `self` drops here: ZeroizeOnDrop wipes the master keys.
    }
}

/// A keyring bound to one tenant: derived per-tenant encryption keys only.
///
/// Built by [`Keyring::for_tenant`]. Holds the HKDF-derived per-tenant
/// encryption key for each keyring entry, in attempt order (current key
/// first) — no master-key material. Decrypt semantics are byte-identical to
/// the unbound [`Keyring`]: same attempt order, identical AAD per attempt,
/// only [`EncryptionError::AuthenticationFailed`] advances, structural errors
/// terminal, exhaustion = plain `AuthenticationFailed`. All derived keys
/// zeroize on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TenantKeyring {
    /// Derived per-tenant encryption keys in attempt order (current first).
    keys: Vec<[u8; 32]>,
}

impl TenantKeyring {
    /// Per-entry fingerprints of the derived per-tenant encryption keys, in
    /// attempt order (current key first).
    ///
    /// Byte-identical to [`Keyring::encryption_fingerprints`] for the bound
    /// tenant — same derived keys, same fingerprint construction — but
    /// infallible and derivation-free: the keys were derived at construction.
    pub fn encryption_fingerprints(&self) -> Vec<[u8; 16]> {
        self.keys.iter().map(|key| key_fingerprint(key)).collect()
    }

    /// Decrypt with a specific keyring entry (0 = current key).
    ///
    /// Same fingerprint-binding contract as [`Keyring::decrypt_at`]: a
    /// fingerprint match is binding — if the matched key fails AES-GCM
    /// authentication the failure is terminal; do not fall back.
    ///
    /// # Errors
    ///
    /// - [`EncryptionError::KeyringIndexOutOfRange`] for an out-of-range index
    ///   — a caller bug, deliberately distinct from any crypto failure.
    /// - [`EncryptionError::AuthenticationFailed`] when this entry's key does
    ///   not authenticate the ciphertext.
    /// - [`EncryptionError::InvalidCiphertext`] for malformed ciphertext.
    pub fn decrypt_at(
        &self,
        index: usize,
        encryptor: &ZeroKnowledgeEncryptor,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let key = self
            .keys
            .get(index)
            .ok_or(EncryptionError::KeyringIndexOutOfRange {
                index,
                count: self.keys.len(),
            })?;
        encryptor.decrypt_aes_gcm(ciphertext, key, aad)
    }

    /// Decrypt by sequential attempts against the derived ring: current key
    /// first, then each decrypt-only entry in order, identical `aad` per
    /// attempt — no HKDF anywhere on this path.
    ///
    /// Only an AES-GCM authentication failure advances to the next key;
    /// structural errors are terminal immediately (they would fail identically
    /// under every key).
    ///
    /// # Errors
    ///
    /// - [`EncryptionError::AuthenticationFailed`] when no entry decrypts the
    ///   ciphertext.
    /// - Terminal (never retried across keys): structural ciphertext errors
    ///   ([`EncryptionError::InvalidCiphertext`]).
    pub fn decrypt(
        &self,
        encryptor: &ZeroKnowledgeEncryptor,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        self.decrypt_indexed(encryptor, ciphertext, aad)
            .map(|(plaintext, _)| plaintext)
    }

    /// [`decrypt`](Self::decrypt), additionally reporting **which keyring
    /// entry** satisfied the read (0 = current key, 1.. = decrypt-only keys in
    /// list order).
    ///
    /// The rotation drain-observability surface on the tenant-bound
    /// (steady-state) path — same contract and purpose as
    /// [`Keyring::decrypt_indexed`], with this type's deltas: no HKDF anywhere
    /// on the path, and no `KeyDerivation` class (derivation already happened
    /// at [`Keyring::for_tenant`]).
    ///
    /// # Errors
    ///
    /// Identical to [`decrypt`](Self::decrypt).
    pub fn decrypt_indexed(
        &self,
        encryptor: &ZeroKnowledgeEncryptor,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, usize), EncryptionError> {
        for index in 0..self.keys.len() {
            match self.decrypt_at(index, encryptor, ciphertext, aad) {
                Ok(plaintext) => return Ok((plaintext, index)),
                Err(EncryptionError::AuthenticationFailed) => continue,
                Err(err) => return Err(err),
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
    // Thread-local so parallel tests can't pollute each other's counts; this
    // is the single choke point every keyring HKDF derivation routes through.
    #[cfg(all(test, not(target_arch = "wasm32")))]
    tests::HKDF_DERIVATIONS.with(|count| count.set(count.get() + 1));

    // Surfaces as EncryptionError::KeyDerivation — a configuration error kept
    // deliberately distinct from AuthenticationFailed/DecryptionFailed so a bad
    // tenant_id cannot masquerade as a cache miss under fail-open policies.
    Ok(derive_domain_key(
        master,
        KeyDomain::Encryption.as_str(),
        tenant_id.as_bytes(),
    )?)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::super::key_derivation::derive_tenant_keys;
    use super::*;

    thread_local! {
        /// Count of HKDF derivations performed by this thread's keyring calls
        /// (incremented inside `derive_encryption_key`). Thread-local because
        /// `cargo test` runs tests on separate threads — counts can't bleed
        /// across tests.
        pub(super) static HKDF_DERIVATIONS: std::cell::Cell<usize> =
            const { std::cell::Cell::new(0) };
    }

    fn hkdf_derivations() -> usize {
        HKDF_DERIVATIONS.with(|count| count.get())
    }

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
        assert!(matches!(
            result,
            Err(EncryptionError::KeyringIndexOutOfRange { index: 1, count: 1 })
        ));
    }

    #[test]
    fn test_bad_tenant_id_is_config_error_not_miss() {
        // A derivation failure (empty tenant_id) must surface as KeyDerivation,
        // never as AuthenticationFailed — a bad config cannot masquerade as a
        // cache miss under a fail-open SDK policy.
        let ciphertext = encrypt_under(&K2, b"x");
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let keyring = Keyring::new(&K2, &[&K1]).unwrap();

        let result = keyring.decrypt(&encryptor, &ciphertext, "", AAD);
        assert!(matches!(result, Err(EncryptionError::KeyDerivation(_))));
    }

    // ---- decrypt_indexed (rotation drain observability, LAB-1645) ----

    #[test]
    fn test_decrypt_indexed_reports_winning_entry() {
        // AC: index 0 for a current-key hit, 1 for the first decrypt-only key,
        // plaintext identical to plain decrypt in both cases.
        let ciphertext_current = encrypt_under(&K2, b"fresh");
        let ciphertext_previous = encrypt_under(&K1, b"old");
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let keyring = Keyring::new(&K2, &[&K1]).unwrap();

        let (plaintext, index) = keyring
            .decrypt_indexed(&encryptor, &ciphertext_current, TENANT, AAD)
            .unwrap();
        assert_eq!((plaintext.as_slice(), index), (b"fresh".as_slice(), 0));

        let (plaintext, index) = keyring
            .decrypt_indexed(&encryptor, &ciphertext_previous, TENANT, AAD)
            .unwrap();
        assert_eq!((plaintext.as_slice(), index), (b"old".as_slice(), 1));
    }

    #[test]
    fn test_decrypt_indexed_exhaustion_and_terminal_errors_match_decrypt() {
        // AC: exhaustion still yields plain AuthenticationFailed; structural
        // and configuration errors stay terminal — identical to decrypt.
        let ciphertext = encrypt_under(&K1, b"secret");
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();

        let cut_over = Keyring::new(&K2, &[]).unwrap();
        assert!(matches!(
            cut_over.decrypt_indexed(&encryptor, &ciphertext, TENANT, AAD),
            Err(EncryptionError::AuthenticationFailed)
        ));

        let keyring = Keyring::new(&K2, &[&K1]).unwrap();
        assert!(matches!(
            keyring.decrypt_indexed(&encryptor, b"too short", TENANT, AAD),
            Err(EncryptionError::InvalidCiphertext(_))
        ));
        assert!(matches!(
            keyring.decrypt_indexed(&encryptor, &ciphertext, "", AAD),
            Err(EncryptionError::KeyDerivation(_))
        ));
    }

    #[test]
    fn test_tenant_keyring_decrypt_indexed_matches_unbound() {
        // AC: same contract on the tenant-bound (SDK steady-state) path.
        let ciphertext_current = encrypt_under(&K2, b"fresh");
        let ciphertext_previous = encrypt_under(&K1, b"old");
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let ring = Keyring::new(&K2, &[&K1])
            .unwrap()
            .for_tenant(TENANT)
            .unwrap();

        let (plaintext, index) = ring
            .decrypt_indexed(&encryptor, &ciphertext_current, AAD)
            .unwrap();
        assert_eq!((plaintext.as_slice(), index), (b"fresh".as_slice(), 0));

        let (plaintext, index) = ring
            .decrypt_indexed(&encryptor, &ciphertext_previous, AAD)
            .unwrap();
        assert_eq!((plaintext.as_slice(), index), (b"old".as_slice(), 1));

        // Exhaustion: plain AuthenticationFailed, structural errors terminal.
        let cut_over = Keyring::new(&K2, &[]).unwrap().for_tenant(TENANT).unwrap();
        assert!(matches!(
            cut_over.decrypt_indexed(&encryptor, &ciphertext_previous, AAD),
            Err(EncryptionError::AuthenticationFailed)
        ));
        assert!(matches!(
            ring.decrypt_indexed(&encryptor, b"too short", AAD),
            Err(EncryptionError::InvalidCiphertext(_))
        ));
    }

    // ---- TenantKeyring (tenant-bound, derivation cached at construction) ----

    #[test]
    fn test_tenant_keyring_derives_exactly_once() {
        // AC: derivation happens once per entry at construction; steady-state
        // decrypts perform NO HKDF. Counter is thread-local, so parallel tests
        // can't pollute this count.
        let ciphertext_current = encrypt_under(&K2, b"fresh");
        let ciphertext_previous = encrypt_under(&K1, b"old");
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();

        let before = hkdf_derivations();
        let ring = Keyring::new(&K2, &[&K1])
            .unwrap()
            .for_tenant(TENANT)
            .unwrap();
        assert_eq!(
            hkdf_derivations() - before,
            2,
            "construction derives exactly one key per keyring entry"
        );

        let at_steady_state = hkdf_derivations();
        for _ in 0..10 {
            ring.decrypt(&encryptor, &ciphertext_current, AAD).unwrap();
            ring.decrypt(&encryptor, &ciphertext_previous, AAD).unwrap();
            ring.decrypt_at(0, &encryptor, &ciphertext_current, AAD)
                .unwrap();
            ring.encryption_fingerprints();
        }
        assert_eq!(
            hkdf_derivations(),
            at_steady_state,
            "steady-state decrypts and fingerprints perform zero HKDF derivations"
        );
    }

    #[test]
    fn test_tenant_keyring_sequential_semantics_match_keyring() {
        // Same contract as Keyring::decrypt: current first, previous-key entry
        // decrypts after rotation, hard cut-over fails plain AuthenticationFailed.
        let ciphertext = encrypt_under(&K1, b"secret");
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();

        let ring = Keyring::new(&K2, &[&K1])
            .unwrap()
            .for_tenant(TENANT)
            .unwrap();
        assert_eq!(
            ring.decrypt(&encryptor, &ciphertext, AAD).unwrap(),
            b"secret"
        );

        let cut_over = Keyring::new(&K2, &[]).unwrap().for_tenant(TENANT).unwrap();
        assert!(matches!(
            cut_over.decrypt(&encryptor, &ciphertext, AAD),
            Err(EncryptionError::AuthenticationFailed)
        ));

        // Identical AAD required across attempts, exactly like the unbound path.
        assert!(matches!(
            ring.decrypt(&encryptor, &ciphertext, b"different_aad"),
            Err(EncryptionError::AuthenticationFailed)
        ));
    }

    #[test]
    fn test_tenant_keyring_structural_error_is_terminal() {
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let ring = Keyring::new(&K2, &[&K1])
            .unwrap()
            .for_tenant(TENANT)
            .unwrap();

        let result = ring.decrypt(&encryptor, b"too short", AAD);
        assert!(matches!(result, Err(EncryptionError::InvalidCiphertext(_))));
    }

    #[test]
    fn test_tenant_keyring_decrypt_at_out_of_range() {
        // KeyringIndexOutOfRange stays config-class on the bound path — never
        // folded into AuthenticationFailed (LAB-683 no-collapse rule).
        let encryptor = ZeroKnowledgeEncryptor::new().unwrap();
        let ring = Keyring::new(&K2, &[]).unwrap().for_tenant(TENANT).unwrap();
        let ciphertext = encrypt_under(&K2, b"x");

        let result = ring.decrypt_at(1, &encryptor, &ciphertext, AAD);
        assert!(matches!(
            result,
            Err(EncryptionError::KeyringIndexOutOfRange { index: 1, count: 1 })
        ));
    }

    #[test]
    fn test_tenant_keyring_bad_tenant_id_is_config_error_at_construction() {
        // On the bound path a bad tenant_id surfaces at for_tenant — same
        // KeyDerivation class as the unbound path, moved to construction time.
        let result = Keyring::new(&K2, &[&K1]).unwrap().for_tenant("");
        assert!(matches!(result, Err(EncryptionError::KeyDerivation(_))));
    }

    #[test]
    fn test_tenant_keyring_fingerprints_match_unbound_keyring() {
        // AC: fingerprints from the cached derivation are byte-identical to
        // Keyring::encryption_fingerprints (and thus to derive_tenant_keys).
        let keyring = Keyring::new(&K2, &[&K1]).unwrap();
        let unbound = keyring.encryption_fingerprints(TENANT).unwrap();
        let bound = keyring
            .for_tenant(TENANT)
            .unwrap()
            .encryption_fingerprints();

        assert_eq!(bound, unbound);
        assert_eq!(bound.len(), 2);
        assert_eq!(
            bound[0],
            derive_tenant_keys(&K2, TENANT)
                .unwrap()
                .encryption_fingerprint()
        );
        assert_eq!(
            bound[1],
            derive_tenant_keys(&K1, TENANT)
                .unwrap()
                .encryption_fingerprint()
        );
    }

    #[test]
    fn test_tenant_keyring_derived_keys_zeroize() {
        // AC: the derived ring is ZeroizeOnDrop. Vec::zeroize wipes every
        // element then clears the vec, so the observable post-condition of the
        // explicit zeroize() covering the field is an emptied ring; the
        // compile-time bound below proves the drop guarantee itself.
        let mut ring = Keyring::new(&K2, &[&K1])
            .unwrap()
            .for_tenant(TENANT)
            .unwrap();
        ring.zeroize();
        assert!(ring.keys.is_empty());

        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<TenantKeyring>();
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
}
