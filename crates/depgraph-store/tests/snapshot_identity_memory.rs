use std::{
    alloc::{GlobalAlloc, Layout, System},
    path::Path,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use depgraph_store::Store;
use serde_json::json;

struct CountingAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static MEASURING: AtomicBool = AtomicBool::new(false);

fn allocated(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    if MEASURING.load(Ordering::Relaxed) {
        PEAK.fetch_max(live, Ordering::Relaxed);
    }
}

// SAFETY: Every operation delegates to System with the original pointer/layout;
// the counters observe sizes and never access or change allocated memory.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(pointer, layout, size) };
        if !result.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            allocated(size);
        }
        result
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

// This integration binary has one test, so other tests cannot add allocations
// inside the measured interval. Measure live Rust heap rather than process RSS
// to avoid allocator retention, SQLite's C heap, and platform sampling noise.
#[test]
fn snapshot_identity_does_not_copy_the_whole_graph_into_json() -> anyhow::Result<()> {
    const NODES: usize = 2_048;
    const PAYLOAD_BYTES: usize = 8_192;
    let mut store = Store::open_in_memory()?;
    store.start_scan("identity-memory", Path::new("/fixture"), false)?;
    let payload = "x".repeat(PAYLOAD_BYTES);
    for index in 0..NODES {
        store.ingest_event(&json!({
            "event": "node_upsert",
            "protocol_version": "1.0",
            "scan_id": "identity-memory",
            "adapter": "web",
            "adapter_version": "0.1.0",
            "seq": index + 1,
            "node": {
                "id": format!("file:{index:05}"),
                "kind": "file",
                "locator": format!("file://src/{index:05}.ts"),
                "display_name": format!("{index:05}.ts"),
                "properties": {"payload": payload},
            },
        }))?;
    }
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    MEASURING.store(true, Ordering::Relaxed);
    let identity = store.prospective_scan_snapshot_id("identity-memory");
    MEASURING.store(false, Ordering::Relaxed);
    let additional_peak = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
    assert!(identity?.starts_with("snapshot:sha256:"));
    // Allow the loaded graph, record metadata, and an entire extra payload's
    // worth of headroom; simultaneous full JSON copies exceed this bound.
    let limit = 2 * NODES * PAYLOAD_BYTES;
    eprintln!(
        "snapshot identity peak additional Rust heap: {additional_peak} bytes (limit {limit})"
    );
    assert!(
        additional_peak < limit,
        "snapshot identity allocated {additional_peak} bytes above baseline; limit {limit}"
    );
    Ok(())
}
