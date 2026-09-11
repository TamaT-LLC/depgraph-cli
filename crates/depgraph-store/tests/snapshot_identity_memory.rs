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
fn scan_validation_and_identity_stream_records_without_holding_the_whole_graph()
-> anyhow::Result<()> {
    const NODES: usize = 2_048;
    const PAYLOAD_BYTES: usize = 8_192;
    let mut store = Store::open_in_memory()?;
    store.start_scan("identity-memory", Path::new("/fixture"), false)?;
    let fixture = include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson")
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<serde_json::Result<Vec<_>>>()?;
    let event = |kind: &str| {
        let mut event = fixture
            .iter()
            .find(|event| event["event"] == kind)
            .unwrap()
            .clone();
        event["scan_id"] = json!("identity-memory");
        event
    };
    store.ingest_event(&event("profile_declared"))?;
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
        let node_id = format!("file:{index:05}");
        let site_id = format!("site:{index:05}");
        let condition = json!({"op":"eq","key":"fixture","value":payload});
        let mut site = event("dependency_site");
        site["site"]["id"] = json!(site_id);
        site["site"]["source"] = json!(node_id);
        site["site"]["target_ids"] = json!([node_id]);
        site["site"]["condition"] = condition.clone();
        site["site"]["evidence"][0]["properties"] = json!({"payload":payload});
        store.ingest_event(&site)?;
        let mut edge = event("edge_upsert");
        edge["edge"]["id"] = json!(format!("edge:{index:05}"));
        edge["edge"]["site_id"] = json!(site_id);
        edge["edge"]["source"] = json!(node_id);
        edge["edge"]["target"] = json!(node_id);
        edge["edge"]["condition"] = condition;
        edge["edge"]["evidence"][0]["properties"] = json!({"payload":payload});
        store.ingest_event(&edge)?;
    }
    let mut completed = event("scan_completed");
    completed["coverage"]["dependency_sites"] = json!(NODES);
    completed["coverage"]["resolved"] = json!(NODES);
    completed["coverage"]["files_discovered"] = json!(0);
    completed["coverage"]["files_analyzed"] = json!(0);
    let mut profile_completed = event("profile_completed");
    profile_completed["coverage"] = completed["coverage"].clone();
    store.ingest_event(&profile_completed)?;
    store.ingest_event(&completed)?;
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    MEASURING.store(true, Ordering::Relaxed);
    let validated = store.validate_scan_for_completion("identity-memory");
    MEASURING.store(false, Ordering::Relaxed);
    let validation_peak = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
    let validated = validated?;
    eprintln!("scan validation peak additional Rust heap: {validation_peak} bytes");
    assert!(
        validation_peak < 256 * 1024,
        "validation allocated {validation_peak} bytes"
    );
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    MEASURING.store(true, Ordering::Relaxed);
    let identity = store.prospective_scan_snapshot_id("identity-memory");
    let completion = store.finish_validated_scan(validated, true);
    MEASURING.store(false, Ordering::Relaxed);
    let additional_peak = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
    let identity = identity?;
    completion?;
    assert_eq!(
        store.current_snapshot_id()?.as_deref(),
        Some(identity.as_str())
    );
    // Each node/site/edge/evidence payload domain contains at least 16 MiB. Identity and
    // completion may retain one decoded record and its canonical JSON, but
    // must not materialize those payloads together. Validation has a separate
    // budget so its site and edge working set cannot hide in this baseline.
    let limit = 1024 * 1024;
    eprintln!(
        "snapshot identity peak additional Rust heap: {additional_peak} bytes (limit {limit})"
    );
    assert!(
        additional_peak < limit,
        "snapshot identity allocated {additional_peak} bytes above baseline; limit {limit}"
    );
    Ok(())
}
