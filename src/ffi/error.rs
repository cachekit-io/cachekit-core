//! FFI error types for C-compatible error handling across the FFI boundary.

#[cfg(feature = "encryption")]
use crate::encryption::{EncryptionError, KeyDerivationError};

/// C-compatible error codes for FFI boundary
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachekitError {
    /// Operation succeeded
    Ok = 0,
    /// Invalid input provided
    InvalidInput = 1,
    /// Checksum verification failed
    ChecksumMismatch = 2,
    /// Decompression failed
    DecompressionFailed = 3,
    /// Decryption failed (authentication error)
    DecryptionFailed = 4,
    /// Key rotation needed (counter approaching limit)
    RotationNeeded = 5,
    /// Nonce counter exhausted
    CounterExhausted = 6,
    /// Invalid key length
    InvalidKeyLength = 7,
    /// Output buffer too small
    BufferTooSmall = 8,
    /// Null pointer provided
    NullPointer = 9,
    /// Input data exceeds size limits
    InputTooLarge = 10,
    /// Decompression bomb detected
    DecompressionBomb = 11,
    /// Size validation failed
    SizeValidationFailed = 12,
    /// Random number generator failure
    RngFailure = 13,
    /// Domain name exceeds maximum length
    DomainTooLong = 14,
    /// Tenant salt exceeds maximum length
    SaltTooLong = 15,
    /// Invalid or already-freed handle
    InvalidHandle = 16,
}

#[cfg(feature = "encryption")]
impl From<EncryptionError> for CachekitError {
    fn from(e: EncryptionError) -> Self {
        match e {
            EncryptionError::InvalidKeyLength(_) => CachekitError::InvalidKeyLength,
            EncryptionError::InvalidNonceLength(_) => CachekitError::InvalidInput,
            EncryptionError::EncryptionFailed(_) => CachekitError::InvalidInput,
            EncryptionError::DecryptionFailed(_) => CachekitError::DecryptionFailed,
            EncryptionError::RngFailure => CachekitError::RngFailure,
            EncryptionError::InvalidCiphertext(_) => CachekitError::InvalidInput,
            EncryptionError::InvalidHeader(_) => CachekitError::InvalidInput,
            EncryptionError::UnsupportedVersion(_) => CachekitError::InvalidInput,
            EncryptionError::UnsupportedAlgorithm(_) => CachekitError::InvalidInput,
            EncryptionError::AuthenticationFailed => CachekitError::DecryptionFailed,
            EncryptionError::NonceCounterExhausted => CachekitError::CounterExhausted,
            EncryptionError::NotImplemented(_) => CachekitError::InvalidInput,
        }
    }
}

#[cfg(feature = "encryption")]
impl From<KeyDerivationError> for CachekitError {
    fn from(e: KeyDerivationError) -> Self {
        match e {
            KeyDerivationError::InvalidMasterKeyLength(_) => CachekitError::InvalidKeyLength,
            KeyDerivationError::InvalidDomain(_) => CachekitError::InvalidInput,
            KeyDerivationError::InvalidSaltLength(_) => CachekitError::InvalidInput,
            KeyDerivationError::DerivationFailed(_) => CachekitError::InvalidInput,
            KeyDerivationError::DomainTooLong => CachekitError::DomainTooLong,
            KeyDerivationError::TenantSaltTooLong => CachekitError::SaltTooLong,
        }
    }
}

impl From<crate::byte_storage::ByteStorageError> for CachekitError {
    fn from(e: crate::byte_storage::ByteStorageError) -> Self {
        use crate::byte_storage::ByteStorageError;
        match e {
            ByteStorageError::InputTooLarge => CachekitError::InputTooLarge,
            ByteStorageError::DecompressionBomb => CachekitError::DecompressionBomb,
            ByteStorageError::ChecksumMismatch => CachekitError::ChecksumMismatch,
            ByteStorageError::DecompressionFailed => CachekitError::DecompressionFailed,
            ByteStorageError::SizeValidationFailed => CachekitError::SizeValidationFailed,
            ByteStorageError::CompressionFailed => CachekitError::InvalidInput,
            ByteStorageError::SerializationFailed(_) => CachekitError::InvalidInput,
            ByteStorageError::DeserializationFailed(_) => CachekitError::InvalidInput,
        }
    }
}
