use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use depgraph_store::{
    CoverageRecord, EdgeRecord, EvidenceRecord, GraphSnapshot, ProfileMatrixRecord, ProfileRecord,
    SiteRecord, Store, refresh_profile_matrix_view,
};
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

// Keep this as the only test in its process: the global allocator must not
// include allocations from unrelated concurrent tests in the measured peak.
#[test]
fn profile_matrix_keeps_working_copies_below_the_graph_budget() -> anyhow::Result<()> {
    const SITES: usize = 1_024;
    let mut snapshot: GraphSnapshot = serde_json::from_value(json!({
        "scan": {"id":"scan", "root":"/fixture", "status":"completed", "strict":false,
            "started_at":"now", "completed_at":null, "project_code_executed":false, "error":null},
        "profiles":[], "nodes":[], "sites":[], "edges":[], "evidence":[],
        "diagnostics":[], "file_coverage":[], "adapter_logs":[],
        "coverage":CoverageRecord::default(), "profile_matrix":ProfileMatrixRecord::default(),
    }))?;
    snapshot.profiles.push(ProfileRecord {
        id: "profile".into(),
        language: "go".into(),
        toolchain: None,
        command: None,
        target: None,
        features: vec![],
        environment: json!({}),
        source_revision: None,
        properties: json!({}),
        coverage: None,
    });
    for index in 0..SITES {
        let site_id = format!("site:{index:08}");
        let source = format!("node:{index:08}:{}", "source".repeat(32));
        let target = format!("node:{index:08}:{}", "target".repeat(32));
        let condition = json!({"op":"all","conditions":[]});
        snapshot.sites.push(SiteRecord {
            id: site_id.clone(),
            source: source.clone(),
            kind: "call".into(),
            specifier: Some(format!("function{index}")),
            profile_id: "profile".into(),
            resolution_status: "resolved".into(),
            precision: "exact".into(),
            condition: condition.clone(),
            target_ids: vec![target.clone()],
            reason: None,
        });
        snapshot.edges.push(EdgeRecord {
            id: format!("edge:{index:08}"),
            site_id: Some(site_id.clone()),
            source,
            target,
            kind: "calls".into(),
            phase: "semantic".into(),
            environment: "any".into(),
            profile_id: "profile".into(),
            resolution_status: "resolved".into(),
            precision: "exact".into(),
            condition,
            generated: false,
        });
        snapshot.evidence.push(EvidenceRecord {
            owner_type: "site".into(),
            owner_id: site_id,
            ordinal: 0,
            kind: "semantic".into(),
            extractor: "fixture".into(),
            extractor_version: "1".into(),
            path: format!("f{index}.go"),
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 2,
            detail: None,
            properties: json!({}),
        });
    }
    let mut expected = None;
    for pass in 0..2 {
        let baseline = LIVE.load(Ordering::Relaxed);
        PEAK.store(baseline, Ordering::Relaxed);
        MEASURING.store(true, Ordering::Relaxed);
        refresh_profile_matrix_view(&mut snapshot);
        MEASURING.store(false, Ordering::Relaxed);
        let additional_peak = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
        // Budget includes the complete public result plus temporary indexes.
        // The previous owned builders and retained old matrix exceed it.
        let limit = SITES * 6_000;
        eprintln!(
            "profile matrix pass {pass}: additional Rust heap {additional_peak} bytes (limit {limit})"
        );
        assert!(
            additional_peak < limit,
            "profile matrix exceeded its working-memory budget"
        );
        assert_eq!(snapshot.profile_matrix.correlations.len(), SITES);
        let serialized = serde_json::to_vec(&snapshot.profile_matrix)?;
        if let Some(expected) = &expected {
            assert_eq!(
                &serialized, expected,
                "refresh must preserve the exact output"
            );
        } else {
            expected = Some(serialized);
        }
    }
    // Exercise the actual completion-ID read path as well as the public view.
    // All graph rows fit in the budget; constructing an unused matrix as well
    // would exceed it even if the old view were discarded before returning.
    let mut store = Store::open_in_memory()?;
    store.start_scan("matrix-identity", std::path::Path::new("/fixture"), false)?;
    {
        let mut sequence = 0;
        let mut ingest =
            |event: &str, key: &str, payload: serde_json::Value| -> anyhow::Result<()> {
                sequence += 1;
                let mut value = json!({
                    "event":event, "protocol_version":"1.0", "scan_id":"matrix-identity",
                    "adapter":"fixture", "adapter_version":"1", "seq":sequence,
                });
                value[key] = payload;
                store.ingest_event(&value)
            };
        ingest(
            "profile_declared",
            "profile",
            serde_json::to_value(&snapshot.profiles[0])?,
        )?;
        for (index, site) in snapshot.sites.iter().enumerate() {
            for (label, id) in [("source", &site.source), ("target", &site.target_ids[0])] {
                ingest(
                    "node_upsert",
                    "node",
                    json!({
                        "id":id, "kind":"file", "locator":format!("{label}/{index}.go"),
                        "display_name":format!("{index}.go"), "properties":{},
                    }),
                )?;
            }
            let mut payload = serde_json::to_value(site)?;
            payload["evidence"] = json!([snapshot.evidence[index]]);
            ingest("dependency_site", "site", payload)?;
            ingest(
                "edge_upsert",
                "edge",
                serde_json::to_value(&snapshot.edges[index])?,
            )?;
        }
    }
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    MEASURING.store(true, Ordering::Relaxed);
    let identity = store.prospective_scan_snapshot_id("matrix-identity");
    MEASURING.store(false, Ordering::Relaxed);
    let additional_peak = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
    let limit = SITES * 6_000;
    eprintln!("completion identity: additional Rust heap {additional_peak} bytes (limit {limit})");
    assert!(identity?.starts_with("snapshot:sha256:"));
    assert!(
        additional_peak < limit,
        "completion allocated an unused matrix view"
    );
    Ok(())
}
