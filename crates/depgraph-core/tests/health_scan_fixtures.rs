//! The three NDJSON inputs are worker-golden extracts: their event envelopes
//! and semantic fields follow the Rust, Go, and Web worker output contracts.
//! The Go input is captured from the real safe worker, including its package,
//! file, semantic-site, semantic-edge, diagnostic, and coverage records, so
//! this test does not invent source-path or visibility fields that the worker
//! does not emit.

use std::fs;

use anyhow::Result;
use depgraph_core::health::{BlockerKind, FindingKind, analyze_unused};
use depgraph_protocol::validate_safe_semantic_ndjson;
use depgraph_store::{GraphSnapshot, Store};
use serde_json::{Value, json};
use std::io::Cursor;

const RUST_FIXTURE: &str = include_str!("fixtures/health/issue437-rust.ndjson");
const GO_FIXTURE: &str = include_str!("fixtures/health/issue437-go.ndjson");
const WEB_FIXTURE: &str = include_str!("fixtures/health/issue437-web.ndjson");

fn load_protocol_fixture(
    temporary: &tempfile::TempDir,
    scan_id: &str,
    fixture: &str,
) -> Result<GraphSnapshot> {
    // Keep these compact worker extracts on the same strict path as production
    // worker output. Store ingestion intentionally accepts already validated
    // event values, so validating here catches stale IDs, site/edge mismatches,
    // and coverage ledger drift before the health analyzer sees the snapshot.
    validate_safe_semantic_ndjson(Cursor::new(fixture.as_bytes()))?;

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

struct ExpectedFinding<'a> {
    kind: FindingKind,
    path: Option<&'a str>,
    locator: Option<&'a str>,
}

fn fixture_node_id(fixture: &str, locator: &str) -> Option<String> {
    fixture.lines().find_map(|line| {
        let event: Value = serde_json::from_str(line).ok()?;
        if event.get("event").and_then(Value::as_str) != Some("node_upsert")
            || event
                .get("node")
                .and_then(|node| node.get("locator"))
                .and_then(Value::as_str)
                != Some(locator)
        {
            return None;
        }
        event
            .get("node")
            .and_then(|node| node.get("id"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
}

#[test]
fn issue_437_worker_protocol_fixtures_detect_unused_subjects_for_rust_go_and_web() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let cases = [
        (
            "rust",
            RUST_FIXTURE,
            3,
            [
                ExpectedFinding {
                    kind: FindingKind::UnusedFile,
                    path: Some("src/unused.rs"),
                    locator: None,
                },
                ExpectedFinding {
                    kind: FindingKind::UnusedExport,
                    path: Some("src/public.rs"),
                    locator: None,
                },
                ExpectedFinding {
                    kind: FindingKind::UnusedType,
                    path: Some("src/public.rs"),
                    locator: None,
                },
            ],
        ),
        (
            "go",
            GO_FIXTURE,
            6,
            [
                ExpectedFinding {
                    kind: FindingKind::UnusedFile,
                    path: None,
                    locator: Some("file:pkg/unused.go"),
                },
                ExpectedFinding {
                    kind: FindingKind::UnusedExport,
                    path: None,
                    locator: Some("go-symbol:example.com/issue437/pkg.UnusedExport"),
                },
                ExpectedFinding {
                    kind: FindingKind::UnusedType,
                    path: None,
                    locator: Some("go-type:example.com/issue437/pkg.UnusedType"),
                },
            ],
        ),
        (
            "web",
            WEB_FIXTURE,
            3,
            [
                ExpectedFinding {
                    kind: FindingKind::UnusedFile,
                    path: Some("src/unused.ts"),
                    locator: None,
                },
                ExpectedFinding {
                    kind: FindingKind::UnusedExport,
                    path: Some("src/public.ts"),
                    locator: None,
                },
                ExpectedFinding {
                    kind: FindingKind::UnusedType,
                    path: Some("src/public.ts"),
                    locator: None,
                },
            ],
        ),
    ];

    for (language, fixture, expected_count, expected_findings) in cases {
        let snapshot = load_protocol_fixture(&temporary, &format!("issue437-{language}"), fixture)?;
        let findings = analyze_unused(&snapshot);

        for expected in expected_findings {
            let subject_id = expected.locator.map(|locator| {
                fixture_node_id(fixture, locator).unwrap_or_else(|| {
                    panic!("{language} fixture has no node with locator {locator:?}")
                })
            });
            let finding = findings
                .iter()
                .find(|finding| {
                    if finding.kind != expected.kind {
                        return false;
                    }
                    if let Some(path) = expected.path {
                        return location_path(finding) == Some(path);
                    }
                    subject_id.as_deref() == Some(finding.subject_id.as_str())
                        && location_path(finding).is_none()
                })
                .unwrap_or_else(|| {
                    panic!(
                        "{language} fixture did not produce {:?} for path={:?}, locator={:?}: {findings:?}",
                        expected.kind, expected.path, expected.locator
                    )
                });
            let expected_confidence = if expected.kind == FindingKind::UnusedFile {
                depgraph_core::Confidence::Confirmed
            } else {
                // Rust/Web worker metadata and Go's exported-identifier rule
                // mark exports/types as public surfaces; the analyzer reports
                // them for review but keeps them indeterminate until that API
                // decision is made.
                depgraph_core::Confidence::Indeterminate
            };
            assert_eq!(finding.confidence, expected_confidence);
            if matches!(
                expected.kind,
                FindingKind::UnusedExport | FindingKind::UnusedType
            ) {
                assert!(
                    finding
                        .blockers
                        .iter()
                        .any(|blocker| blocker.kind == BlockerKind::PublicSurface),
                    "{language} fixture public subject lacks a public-surface blocker: {finding:?}"
                );
            }
        }

        assert_eq!(
            findings.len(),
            expected_count,
            "unexpected findings for {language} fixture: {findings:?}"
        );
    }
    Ok(())
}
