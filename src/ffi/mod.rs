//! C FFI layer for cachekit-core
//!
//! Provides C-compatible interfaces for ByteStorage and encryption operations.
//! All functions use #[repr(C)] types and panic-safe wrappers.

pub mod byte_storage;
pub mod error;
pub mod handles; // Task 5 // Task 6

#[cfg(feature = "encryption")]
pub mod encryption; // Task 7

pub use error::CachekitError;
pub use handles::*;

// Re-export FFI functions for C clients
pub use byte_storage::{cachekit_compress, cachekit_compressed_bound, cachekit_decompress};

#[cfg(feature = "encryption")]
pub use encryption::{
    cachekit_decrypt, cachekit_derive_key, cachekit_encrypt, cachekit_encryptor_free,
    cachekit_encryptor_get_counter, cachekit_encryptor_new,
};
