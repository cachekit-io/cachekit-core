//! Opaque FFI handle types for cachekit-core
//!
//! Provides type-safe opaque pointers for passing Rust structs across FFI boundaries.
//! Handles must be created with constructor functions and freed with destructor functions.
//!
//! # Handle Validity Tracking
//!
//! All handles are tracked in a global registry to detect:
//! - Double-free attempts (calling free on already-freed handle)
//! - Use-after-free attempts (using a handle after it was freed)
//!
//! Invalid handle operations return `CachekitError::InvalidHandle` instead of causing
//! undefined behavior.

use crate::ByteStorage;
use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

/// Global registry of live ByteStorage handles
static BYTE_STORAGE_HANDLES: LazyLock<Mutex<HashSet<usize>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Global registry of live Encryptor handles (encryption feature only)
#[cfg(feature = "encryption")]
static ENCRYPTOR_HANDLES: LazyLock<Mutex<HashSet<usize>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Generates an opaque FFI handle type with validity tracking.
///
/// This macro creates:
/// - A `#[repr(C)]` struct with zero-sized private field
/// - `into_opaque_ptr`: Convert inner type to handle, registering in global registry
/// - `from_opaque_ptr`: Convert handle back to inner type, unregistering (returns `Option`)
/// - `is_valid`: Check if handle is registered
/// - `as_ref`: Borrow inner type (returns `Option`)
/// - `as_mut`: Mutably borrow inner type (returns `Option`)
macro_rules! opaque_handle {
    (
        $(#[$meta:meta])*
        $handle:ident,
        $inner:ty,
        $registry:ident
    ) => {
        $(#[$meta])*
        #[repr(C)]
        pub struct $handle {
            _private: [u8; 0],
        }

        #[allow(dead_code)]
        impl $handle {
            /// Convert from inner type to opaque FFI handle.
            ///
            /// The handle is registered in the global registry for validity tracking.
            ///
            /// # Safety
            /// Caller must ensure the returned pointer is eventually freed with
            /// `from_opaque_ptr` or memory will leak.
            pub(crate) fn into_opaque_ptr(inner: $inner) -> *mut Self {
                let ptr = Box::into_raw(Box::new(inner)) as *mut Self;
                if let Ok(mut handles) = $registry.lock() {
                    handles.insert(ptr as usize);
                }
                ptr
            }

            /// Convert from opaque FFI handle back to inner type.
            ///
            /// Returns `None` if the handle is invalid (null, already freed, or never created).
            /// On success, the handle is unregistered and cannot be used again.
            ///
            /// # Safety
            /// - If `Some` is returned, the pointer is consumed and must not be used again
            pub(crate) unsafe fn from_opaque_ptr(ptr: *mut Self) -> Option<$inner> {
                if ptr.is_null() {
                    return None;
                }
                let addr = ptr as usize;
                let registered = $registry
                    .lock()
                    .map(|mut handles| handles.remove(&addr))
                    .unwrap_or(false);
                if !registered {
                    return None; // Handle was never created or already freed
                }
                // SAFETY: Handle was registered, so it came from into_opaque_ptr
                Some(unsafe { *Box::from_raw(ptr as *mut $inner) })
            }

            /// Check if a handle is valid (registered and not freed).
            pub(crate) fn is_valid(ptr: *const Self) -> bool {
                if ptr.is_null() {
                    return false;
                }
                $registry
                    .lock()
                    .map(|handles| handles.contains(&(ptr as usize)))
                    .unwrap_or(false)
            }

            /// Borrow the inner type from an opaque pointer.
            ///
            /// Returns `None` if the handle is invalid.
            ///
            /// # Safety
            /// - Pointer must remain valid for the lifetime of the returned reference
            pub(crate) unsafe fn as_ref<'a>(ptr: *const Self) -> Option<&'a $inner> {
                if !Self::is_valid(ptr) {
                    return None;
                }
                // SAFETY: Handle is registered, so pointer is valid and aligned
                Some(unsafe { &*(ptr as *const $inner) })
            }

            /// Mutably borrow the inner type from an opaque pointer.
            ///
            /// Returns `None` if the handle is invalid.
            ///
            /// # Safety
            /// - Pointer must remain valid for the lifetime of the returned reference
            /// - No other references (mutable or immutable) may exist
            pub(crate) unsafe fn as_mut<'a>(ptr: *mut Self) -> Option<&'a mut $inner> {
                if !Self::is_valid(ptr) {
                    return None;
                }
                // SAFETY: Handle is registered, so pointer is valid, aligned, and exclusively accessed
                Some(unsafe { &mut *(ptr as *mut $inner) })
            }
        }
    };
}

// Generate ByteStorage handle
opaque_handle!(
    /// Opaque handle for ByteStorage instances
    ///
    /// This is an opaque pointer type for FFI. The actual ByteStorage struct
    /// is never exposed across the FFI boundary - only this pointer.
    ///
    /// # Safety
    /// - Create with `cachekit_byte_storage_new`
    /// - Free with `cachekit_byte_storage_free`
    /// - Never dereference from C code
    CachekitByteStorage,
    ByteStorage,
    BYTE_STORAGE_HANDLES
);

// Generate Encryptor handle (encryption feature only)
#[cfg(feature = "encryption")]
opaque_handle!(
    /// Opaque handle for ZeroKnowledgeEncryptor instances (encryption feature only)
    ///
    /// This is an opaque pointer type for FFI. The actual ZeroKnowledgeEncryptor
    /// struct is never exposed across the FFI boundary.
    ///
    /// # Safety
    /// - Create with `cachekit_encryptor_new`
    /// - Free with `cachekit_encryptor_free`
    /// - Never dereference from C code
    CachekitEncryptor,
    crate::encryption::ZeroKnowledgeEncryptor,
    ENCRYPTOR_HANDLES
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_storage_opaque_roundtrip() {
        let storage = ByteStorage::new(None);
        let ptr = CachekitByteStorage::into_opaque_ptr(storage);
        assert!(!ptr.is_null());
        assert!(CachekitByteStorage::is_valid(ptr));

        unsafe {
            let restored = CachekitByteStorage::from_opaque_ptr(ptr);
            assert!(restored.is_some());
            // Storage is now owned by restored and will be dropped
        }

        // After free, handle should be invalid
        assert!(!CachekitByteStorage::is_valid(ptr));
    }

    #[test]
    fn test_byte_storage_double_free_detection() {
        let storage = ByteStorage::new(None);
        let ptr = CachekitByteStorage::into_opaque_ptr(storage);

        // First free succeeds
        unsafe {
            let first = CachekitByteStorage::from_opaque_ptr(ptr);
            assert!(first.is_some());
        }

        // Second free returns None (detected as invalid)
        unsafe {
            let second = CachekitByteStorage::from_opaque_ptr(ptr);
            assert!(second.is_none());
        }
    }

    #[test]
    fn test_byte_storage_null_handle() {
        let null_ptr: *mut CachekitByteStorage = std::ptr::null_mut();
        assert!(!CachekitByteStorage::is_valid(null_ptr));

        unsafe {
            assert!(CachekitByteStorage::from_opaque_ptr(null_ptr).is_none());
            assert!(CachekitByteStorage::as_ref(null_ptr).is_none());
            assert!(CachekitByteStorage::as_mut(null_ptr).is_none());
        }
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_encryptor_opaque_roundtrip() {
        let encryptor = crate::encryption::ZeroKnowledgeEncryptor::new().unwrap();
        let ptr = CachekitEncryptor::into_opaque_ptr(encryptor);
        assert!(!ptr.is_null());
        assert!(CachekitEncryptor::is_valid(ptr));

        unsafe {
            let restored = CachekitEncryptor::from_opaque_ptr(ptr);
            assert!(restored.is_some());
            // Encryptor is now owned by restored and will be dropped
        }

        // After free, handle should be invalid
        assert!(!CachekitEncryptor::is_valid(ptr));
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn test_encryptor_double_free_detection() {
        let encryptor = crate::encryption::ZeroKnowledgeEncryptor::new().unwrap();
        let ptr = CachekitEncryptor::into_opaque_ptr(encryptor);

        // First free succeeds
        unsafe {
            let first = CachekitEncryptor::from_opaque_ptr(ptr);
            assert!(first.is_some());
        }

        // Second free returns None (detected as invalid)
        unsafe {
            let second = CachekitEncryptor::from_opaque_ptr(ptr);
            assert!(second.is_none());
        }
    }
}
