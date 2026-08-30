//! The three NDJSON inputs are compact worker-golden extracts: their event
//! envelopes and semantic fields follow the Rust, Go, and Web worker fixtures
//! under `crates/depgraph-protocol/tests/fixtures/`. They intentionally keep
//! only the small subgraph needed to prove that worker file, symbol, and type
//! records reach the health analyzer.

use std::fs;

use anyhow::Result;
use depgraph_core::health::{FindingKind, analyze_unused};
use depgraph_store::{GraphSnapshot, Store};
use serde_json::{Value, json};

const RUST_FIXTURE: &str = include_str!("fixtures/health/issue437-rust.ndjson");
const GO_FIXTURE: &str = include_str!("fixtures/health/issue437-go.ndjson");
const WEB_FIXTURE: &str = include_str!("fixtures/health/issue437-web.ndjson");

fn load_protocol_fixture(
    temporary: &tempfile::TempDir,
    scan_id: &str,
    fixture: &str,
) -> Result<GraphSnapshot> {
    let root = temporary.path().join(scan_id);
    fs::create_dir_all(&root)?;
    let store_path = temporary.path().join(format!("{scan_id}.sqlite"));
    let mut store = Store::open(&store_path)?;
    store.start_scan_with_revision(scan_id, &root, false, Some("issue-437-fixture"))?;

    for line in fixture.lines().filter(|line| !line.trim().is_empty()) {
        let mut event: Value = serde_json::from_str(line)?;
        event["scan_id"] = json!(scan_id);
        if event.get("event").and_then(Value::as_str) == Some("scan_started") {
            event["root"] = json!(root);
        }
        store.ingest_event(&event)?;
    }
    store.finish_scan(scan_id, "completed", None, true)?;
    let snapshot_id = store
        .current_snapshot_id()?
        .expect("protocol fixture should promote a completed snapshot");
    store.load_completed_snapshot(&snapshot_id)
}

fn location_path(finding: &depgraph_core::HealthFinding) -> Option<&str> {
    finding
        .location
        .as_ref()
        .map(|location| location.path.as_str())
}

#[test]
fn issue_437_worker_protocol_fixtures_detect_unused_subjects_for_rust_go_and_web() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let cases = [
        (
            "rust",
            RUST_FIXTURE,
            "src/unused.rs",
            "src/public.rs",
            "src/public.rs",
        ),
        (
            "go",
            GO_FIXTURE,
            "pkg/unused.go",
            "pkg/public.go",
            "pkg/public.go",
        ),
        (
            "web",
            WEB_FIXTURE,
            "src/unused.ts",
            "src/public.ts",
            "src/public.ts",
        ),
    ];

    for (language, fixture, unused_file, unused_export, unused_type) in cases {
        let snapshot = load_protocol_fixture(&temporary, &format!("issue437-{language}"), fixture)?;
        let findings = analyze_unused(&snapshot);

        for (kind, path) in [
            (FindingKind::UnusedFile, unused_file),
            (FindingKind::UnusedExport, unused_export),
            (FindingKind::UnusedType, unused_type),
        ] {
            let finding = findings
                .iter()
                .find(|finding| finding.kind == kind && location_path(finding) == Some(path))
                .unwrap_or_else(|| {
                    panic!("{language} fixture did not produce {kind:?} at {path}: {findings:?}")
                });
            let expected_confidence = if kind == FindingKind::UnusedFile {
                depgraph_core::Confidence::Confirmed
            } else {
                // Worker metadata marks exports/types as public surfaces; the
                // analyzer reports them for review but correctly keeps them
                // indeterminate until that public API decision is made.
                depgraph_core::Confidence::Indeterminate
            };
            assert_eq!(finding.confidence, expected_confidence);
        }

        assert_eq!(
            findings.len(),
            3,
            "fixture should contain only the three intended findings"
        );
    }
    Ok(())
}
