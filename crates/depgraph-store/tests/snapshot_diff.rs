use std::path::Path;

use anyhow::{Context, Result};
use depgraph_store::Store;
use serde_json::json;

fn persist_snapshot(store: &mut Store, scan_id: &str, version: u64) -> Result<String> {
    store.start_scan_with_revision(
        scan_id,
        Path::new("/portable/project"),
        false,
        Some(&format!("revision-{version}")),
    )?;
    let common = |event: &str, seq: u64| {
        json!({
            "event": event,
            "protocol_version": "1.0",
            "scan_id": scan_id,
            "adapter": "fixture",
            "adapter_version": "1.0",
            "seq": seq
        })
    };
    let coverage = json!({
        "profiles": 1,
        "files_discovered": 0,
        "files_analyzed": 0,
        "files_skipped": 0,
        "dependency_sites": 0,
        "resolved": 0,
        "candidates": 0,
        "external": 0,
        "unresolved": 0,
        "unsupported_syntax": 0,
        "project_code_executed": false,
        "completeness": ["syntax-complete"],
        "reasons": []
    });
    let mut started = common("scan_started", 1);
    started["root"] = json!("/portable/project");
    started["safe_mode"] = json!(true);
    started["project_code_executed"] = json!(false);
    let mut profile = common("profile_declared", 2);
    profile["profile"] = json!({
        "id": "fixture:safe",
        "language": "typescript",
        "features": [],
        "environment": {},
        "properties": {}
    });
    let mut node = common("node_upsert", 3);
    node["node"] = json!({
        "id": "node:shared",
        "kind": "file",
        "locator": "src/shared.ts",
        "display_name": "shared",
        "properties": {"version": version}
    });
    let mut profile_completed = common("profile_completed", 4);
    profile_completed["profile_id"] = json!("fixture:safe");
    profile_completed["coverage"] = coverage.clone();
    let mut completed = common("scan_completed", 5);
    completed["coverage"] = coverage;
    for event in [started, profile, node, profile_completed, completed] {
        store.ingest_event(&event)?;
    }
    store.finish_scan(scan_id, "completed", None, true)?;
    store
        .snapshot_id_for_source("scan", scan_id)?
        .context("completed fixture snapshot")
}

#[test]
fn sqlite_completed_snapshot_diff_is_deterministic_and_rejects_failed_attempt_ids() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let store_path = temp.path().join("graph.db");
    let mut store = Store::open(&store_path)?;
    let first_id = persist_snapshot(&mut store, "first-attempt", 1)?;
    let second_id = persist_snapshot(&mut store, "second-attempt", 2)?;

    let first = serde_json::to_vec(&store.diff_completed_snapshots(&first_id, &second_id)?)?;
    let second = serde_json::to_vec(&store.diff_completed_snapshots(&first_id, &second_id)?)?;
    assert_eq!(first, second);
    let diff: serde_json::Value = serde_json::from_slice(&first)?;
    assert_eq!(diff["nodes"]["changed"][0]["id"], "node:shared");
    assert_eq!(
        diff["nodes"]["changed"][0]["changed_fields"],
        json!(["properties"])
    );

    store.start_scan("failed-attempt", Path::new("/portable/project"), false)?;
    store.finish_scan("failed-attempt", "failed", Some("worker failed"), false)?;
    assert!(
        store
            .diff_completed_snapshots("failed-attempt", &second_id)
            .unwrap_err()
            .to_string()
            .contains("completed snapshot failed-attempt was not found")
    );
    Ok(())
}
