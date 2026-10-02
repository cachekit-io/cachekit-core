//! Allocation bound for the size-cap and ratio reject vectors.
//!
//! An error assertion cannot show check order: a reader could allocate an
//! `original_size` output buffer right after decoding the envelope, free it,
//! then run the size and ratio checks and still raise the expected error. So
//! `spec/wire-format.md` → Reject vectors requires the conformance test for
//! `reject_original_size_over_cap` and `reject_ratio_bomb` to count the bytes
//! the read requests from the Rust global allocator, and to fail if the count
//! reaches the vector's `original_size`, with a positive control that the same
//! probe catches such a buffer allocated inside the read path.
//!
//! The probe is a counting `#[global_allocator]` that adds every requested
//! size (alloc, alloc_zeroed, and the new size on realloc) to a per-thread
//! total. That is the cumulative count the spec allows: a buffer allocated and
//! freed inside the read still counts, and libtest runs each test on its own
//! thread, so the count is this read's alone.
//!
//! This lives in the crate's unit tests, compiled only under `cfg(test)`,
//! because the positive control needs a hook inside `StorageEnvelope::extract`
//! ([`reserve_first_control`]), and only `cfg(test)` code can reach it. No
//! published build compiles any of this, the hook included.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    /// Cumulative bytes requested from the global allocator on this thread.
    static REQUESTED: Cell<usize> = const { Cell::new(0) };
    /// Arms [`reserve_first_control`] on this thread.
    static RESERVE_FIRST: Cell<bool> = const { Cell::new(false) };
}

struct CountingAllocator;

fn record(bytes: usize) {
    // try_with: thread-locals can be gone during thread teardown, and an
    // allocation there belongs to no read.
    let _ = REQUESTED.try_with(|c| c.set(c.get().saturating_add(bytes)));
}

// SAFETY: every method forwards to `System` unchanged; counting allocates nothing.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Positive-control hook, called by `StorageEnvelope::extract` after the
/// envelope is decoded and before the size and ratio checks. When armed on
/// this thread it allocates and frees an `original_size` buffer there, as a
/// reserve-first reader would.
pub(crate) fn reserve_first_control(original_size: u32) {
    if RESERVE_FIRST.with(Cell::get) {
        // black_box: LLVM may otherwise delete an allocation nothing reads.
        drop(std::hint::black_box(Vec::<u8>::with_capacity(
            original_size as usize,
        )));
    }
}

#[cfg(feature = "messagepack")]
mod tests {
    use super::*;
    use crate::byte_storage::{ByteStorage, ByteStorageError};

    const FIXTURE: &str = include_str!("../tests/vectors/wire-format.json");

    /// Bytes requested on this thread while `f` runs, with its result.
    fn bytes_requested<R>(f: impl FnOnce() -> R) -> (R, usize) {
        let before = REQUESTED.with(Cell::get);
        let result = f();
        (result, REQUESTED.with(Cell::get) - before)
    }

    /// Disarms the control on drop, so a failing assert cannot leave it armed.
    struct ArmedControl;

    impl ArmedControl {
        fn arm() -> Self {
            RESERVE_FIRST.with(|c| c.set(true));
            ArmedControl
        }
    }

    impl Drop for ArmedControl {
        fn drop(&mut self) {
            RESERVE_FIRST.with(|c| c.set(false));
        }
    }

    /// `(envelope bytes, original_size)` of a reject vector, by name.
    fn reject_vector(name: &str) -> (Vec<u8>, usize) {
        let fixture: serde_json::Value =
            serde_json::from_str(FIXTURE).expect("wire-format.json fixture must parse");
        let vector = fixture["reject_vectors"]
            .as_array()
            .expect("wire-format.json has no reject_vectors group")
            .iter()
            .find(|v| v["name"] == name)
            .unwrap_or_else(|| panic!("reject_vectors has no {name:?} vector"));
        let envelope = hex::decode(vector["envelope_hex"].as_str().expect("envelope_hex"))
            .expect("envelope_hex must decode");
        let original_size = vector["original_size"].as_u64().expect("original_size");
        (envelope, original_size as usize)
    }

    fn retrieve_counted(envelope: &[u8]) -> (Result<(Vec<u8>, String), ByteStorageError>, usize) {
        let storage = ByteStorage::new(None);
        bytes_requested(|| storage.retrieve(envelope))
    }

    #[test]
    fn size_cap_and_ratio_reads_allocate_less_than_original_size() {
        for (name, expected) in [
            (
                "reject_original_size_over_cap",
                ByteStorageError::InputTooLarge,
            ),
            ("reject_ratio_bomb", ByteStorageError::DecompressionBomb),
        ] {
            let (envelope, original_size) = reject_vector(name);
            let (result, requested) = retrieve_counted(&envelope);
            assert_eq!(result.err(), Some(expected), "[{name}] wrong rejection");
            // Decoding the envelope allocates compressed_data, so a probe that
            // sees nothing is not counting this thread's allocations.
            assert!(requested > 0, "[{name}] probe saw no allocation at all");
            assert!(
                requested < original_size,
                "[{name}] the read requested {requested} B from the allocator, \
                 reaching original_size {original_size} B"
            );
        }
    }

    /// The same probe catches an `original_size` buffer allocated and freed
    /// inside the read path, after the envelope decode. One control at the
    /// ratio vector's 1,000,001 B covers both vectors, as the spec allows.
    #[test]
    fn probe_catches_a_reserve_first_reader() {
        let (envelope, original_size) = reject_vector("reject_ratio_bomb");
        let (result, requested) = {
            let _armed = ArmedControl::arm();
            retrieve_counted(&envelope)
        };
        // The reserve-first reader still raises the expected error, which is
        // why the error assertion alone is not enough.
        assert_eq!(result.err(), Some(ByteStorageError::DecompressionBomb));
        assert!(
            requested >= original_size,
            "probe missed the {original_size} B reserve-first buffer: counted {requested} B"
        );
    }
}
