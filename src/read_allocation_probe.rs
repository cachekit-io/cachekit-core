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
//! freed inside the read still counts. The read runs on the test's own thread,
//! and the test takes the thread's total before and after it, so the delta is
//! this read's alone.
//!
//! The same probe pins what an accepted msgpack-`bin` read below
//! `LARGE_PAYLOAD` allocates: `retrieve_data` requests only what the pre-scan
//! and the LZ4 decoder do, and `retrieve` adds the format `String` and nothing
//! else. A legacy int-array payload, and a payload from `LARGE_PAYLOAD` up,
//! are copied out of the input by design.
//!
//! The same count, [`bytes_requested`], also pins the write side: the
//! `byte_storage` unit test `store_allocates_only_its_output_and_block` checks
//! that `ByteStorage::store` requests only its output and its LZ4 block.
//!
//! This lives in the crate's unit tests, compiled only under `cfg(test)`,
//! because the positive control needs a hook inside `extract_payload`
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

/// Positive-control hook, called by `extract_payload` after the
/// envelope is decoded and before the size and ratio checks. When armed on
/// this thread it runs the reader's own decoder at `original_size` there and
/// discards the result: a reserve-first build of this reader. The decoder
/// sizes its output from `original_size` before it reads the block, so the
/// control allocates through the same allocator call the real decode uses.
pub(crate) fn reserve_first_control(compressed_data: &[u8], original_size: u32) {
    if RESERVE_FIRST.with(Cell::get) {
        let _ = lz4_flex::decompress(compressed_data, original_size as usize);
    }
}

/// Bytes requested on this thread while `f` runs, with its result.
#[cfg(feature = "messagepack")]
pub(crate) fn bytes_requested<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let before = REQUESTED.with(Cell::get);
    let result = f();
    (result, REQUESTED.with(Cell::get) - before)
}

#[cfg(feature = "messagepack")]
mod tests {
    use super::*;
    use crate::byte_storage::{ByteStorage, ByteStorageError, StorageEnvelope};

    const FIXTURE: &str = include_str!("../tests/vectors/wire-format.json");

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
            // The read allocates (the pre-scan's nesting stack; these
            // vectors' bin payload is borrowed), so a probe that sees
            // nothing is not counting this thread's allocations.
            assert!(requested > 0, "[{name}] probe saw no allocation at all");
            assert!(
                requested < original_size,
                "[{name}] the read requested {requested} B from the allocator, \
                 reaching original_size {original_size} B"
            );
        }
    }

    /// On every `msgpack bin` vector, `retrieve_data` allocates what the
    /// pre-scan and the LZ4 decoder do on their own and nothing else, and
    /// `retrieve` adds only the format `String`. A legacy int-array payload is
    /// copied out by design, so those vectors are skipped.
    #[test]
    fn retrieve_data_allocates_only_prescan_and_output() {
        let fixture: serde_json::Value =
            serde_json::from_str(FIXTURE).expect("wire-format.json fixture must parse");
        let storage = ByteStorage::new(None);
        let mut seen = 0;
        for vector in fixture["vectors"].as_array().expect("vectors group") {
            let name = vector["name"].as_str().expect("name");
            if !name.ends_with("_bin") {
                continue;
            }
            seen += 1;
            let envelope = hex::decode(vector["envelope_hex"].as_str().expect("envelope_hex"))
                .expect("envelope_hex must decode");
            let decoded: StorageEnvelope =
                rmp_serde::from_slice(&envelope).expect("vector must decode");
            // The pre-scan's allocation depends on the nesting, not the bound.
            let (_, prescan) = bytes_requested(|| crate::check_msgpack_structure(&envelope, 100));
            let (_, output) = bytes_requested(|| {
                lz4_flex::decompress(&decoded.compressed_data, decoded.original_size as usize)
            });
            let (data, requested) = bytes_requested(|| storage.retrieve_data(&envelope));
            data.unwrap_or_else(|e| panic!("[{name}] {e}"));
            assert_eq!(requested, prescan + output, "[{name}] retrieve_data");
            let (full, requested) = bytes_requested(|| storage.retrieve(&envelope));
            full.unwrap_or_else(|e| panic!("[{name}] {e}"));
            let format = decoded.format.len();
            assert_eq!(requested, prescan + output + format, "[{name}] retrieve");
        }
        assert!(seen > 0, "fixture has msgpack bin vectors");
    }

    /// The same probe catches an `original_size` buffer allocated and freed
    /// inside the read path, after the envelope decode. One control at the
    /// ratio vector's 1,000,001 B covers both vectors, as the spec allows.
    #[test]
    fn probe_catches_a_reserve_first_reader() {
        let (envelope, original_size) = reject_vector("reject_ratio_bomb");
        RESERVE_FIRST.with(|c| c.set(true));
        let (result, requested) = retrieve_counted(&envelope);
        RESERVE_FIRST.with(|c| c.set(false));
        // The reserve-first reader still raises the expected error, which is
        // why the error assertion alone is not enough.
        assert_eq!(result.err(), Some(ByteStorageError::DecompressionBomb));
        assert!(
            requested >= original_size,
            "probe missed the {original_size} B reserve-first buffer: counted {requested} B"
        );
    }
}
