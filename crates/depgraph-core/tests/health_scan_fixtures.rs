//! The three NDJSON inputs are worker-golden extracts: their event envelopes
//! and semantic fields follow the Rust, Go, and Web worker output contracts.
//! The Go input is captured from the real safe worker, including its package,
//! file, semantic-site, semantic-edge, diagnostic, and coverage records, so
//! this test does not invent source-path or visibility fields that the worker
//! does not emit.
//! Web file nodes additionally pin the production ownership and source-hash
//! property shape so a hand-authored fixture cannot silently drift from the
//! worker's final protocol stream.

use std::collections::BTreeSet;
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

#[test]
fn incomplete_analysis_units_cannot_confirm_unused_files_in_otherwise_complete_profiles()
-> Result<()> {
    let temporary = tempfile::tempdir()?;
    for (language, fixture) in [
        ("rust", RUST_FIXTURE),
        ("go", GO_FIXTURE),
        ("web", WEB_FIXTURE),
    ] {
        let snapshot =
            load_protocol_fixture(&temporary, &format!("incomplete-{language}"), fixture)?;
        let confirmed = analyze_unused(&snapshot)
            .into_iter()
            .filter(|finding| finding.confidence == depgraph_core::Confidence::Confirmed)
            .map(|finding| finding.subject_id)
            .collect::<BTreeSet<_>>();
        assert!(
            !confirmed.is_empty(),
            "fixture must have a confirmed unused subject"
        );
        for reason in [
            "status:partial",
            "status:failed",
            "status:cancelled",
            "analysis-unit-unanalysed",
            "analysis-unit-failed",
            "analysis-unit-cancelled",
            "analysis-unit-context-mismatch",
            "analysis-unit-unknown-dependency",
            "analysis-input-changed-during-scan",
        ] {
            let mut incomplete = snapshot.clone();
            if let Some(status) = reason.strip_prefix("status:") {
                incomplete.scan.status = status.to_owned();
            } else {
                incomplete.coverage.reasons.push(reason.to_owned());
            }
            let findings = analyze_unused(&incomplete);
            for subject in &confirmed {
                let finding = findings
                    .iter()
                    .find(|finding| &finding.subject_id == subject)
                    .expect("an incomplete result must retain the finding for review");
                assert_ne!(
                    finding.confidence,
                    depgraph_core::Confidence::Confirmed,
                    "{language}: {reason}"
                );
                assert!(
                    finding
                        .blockers
                        .iter()
                        .any(|blocker| blocker.kind == BlockerKind::IncompleteCoverage)
                );
            }
        }
    }
    Ok(())
}

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
    /// The surface blocker an export / type finding must carry.
    blocker: Option<BlockerKind>,
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

fn assert_web_file_node_shape(fixture: &str) -> Result<()> {
    let expected_keys = [
        "analysis_hash",
        "content_hash",
        "extension",
        "generated",
        "language",
        "package_id",
        "package_locator",
        "path",
        "profile_id",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    let mut file_count = 0;

    for line in fixture.lines().filter(|line| !line.trim().is_empty()) {
        let event: Value = serde_json::from_str(line)?;
        let Some(node) = event.get("node") else {
            continue;
        };
        if node.get("kind").and_then(Value::as_str) != Some("file")
            || node
                .get("properties")
                .and_then(|properties| properties.get("language"))
                .and_then(Value::as_str)
                != Some("typescript")
        {
            continue;
        }

        let properties = node
            .get("properties")
            .and_then(Value::as_object)
            .expect("Web file node must have object properties");
        let actual_keys = properties.keys().cloned().collect::<BTreeSet<_>>();
        assert_eq!(actual_keys, expected_keys, "Web file node property drift");
        assert_eq!(
            properties.get("package_locator").and_then(Value::as_str),
            Some("npm:issue437@workspace#.")
        );
        assert!(
            properties
                .get("package_id")
                .and_then(Value::as_str)
                .is_some_and(|value| value.starts_with("package:sha256:")),
            "Web file node must retain its package owner"
        );
        for field in ["content_hash", "analysis_hash"] {
            assert!(
                properties
                    .get(field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.starts_with("sha256:")),
                "Web file node must retain its {field}"
            );
        }
        file_count += 1;
    }

    assert_eq!(file_count, 4, "Web fixture file-node count drift");
    Ok(())
}

#[test]
fn issue_437_worker_protocol_fixtures_detect_unused_subjects_for_rust_go_and_web() -> Result<()> {
    assert_web_file_node_shape(WEB_FIXTURE)?;
    let temporary = tempfile::tempdir()?;
    let cases = [
        (
            "rust",
            RUST_FIXTURE,
            3,
            vec![
                ExpectedFinding {
                    kind: FindingKind::UnusedFile,
                    path: Some("src/unused.rs"),
                    locator: None,
                    blocker: None,
                },
                ExpectedFinding {
                    kind: FindingKind::UnusedExport,
                    path: Some("src/public.rs"),
                    locator: None,
                    blocker: Some(BlockerKind::PublicSurface),
                },
                ExpectedFinding {
                    kind: FindingKind::UnusedType,
                    path: Some("src/public.rs"),
                    locator: None,
                    blocker: Some(BlockerKind::PublicSurface),
                },
            ],
        ),
        (
            "go",
            GO_FIXTURE,
            4,
            vec![
                // Go file nodes record their repository-relative `path`
                // (Issue #591), so the unused file carries a location.
                ExpectedFinding {
                    kind: FindingKind::UnusedFile,
                    path: Some("pkg/unused/unused.go"),
                    locator: None,
                    blocker: None,
                },
                // Go symbol / type nodes record their declaration site as
                // `source_path` and `source_span` (Issue #596).
                ExpectedFinding {
                    kind: FindingKind::UnusedExport,
                    path: Some("pkg/public.go"),
                    locator: None,
                    blocker: Some(BlockerKind::PublicSurface),
                },
                ExpectedFinding {
                    kind: FindingKind::UnusedType,
                    path: Some("pkg/public.go"),
                    locator: None,
                    blocker: Some(BlockerKind::PublicSurface),
                },
                // With its path, the unexported `main` in cmd/main.go is an
                // entry point rather than an internal symbol, so it is
                // reported for review, as Rust's src/main.rs would be.
                ExpectedFinding {
                    kind: FindingKind::UnusedExport,
                    path: Some("cmd/main.go"),
                    locator: None,
                    blocker: Some(BlockerKind::EntryPoint),
                },
            ],
        ),
        (
            "web",
            WEB_FIXTURE,
            3,
            vec![
                ExpectedFinding {
                    kind: FindingKind::UnusedFile,
                    path: Some("src/unused.ts"),
                    locator: None,
                    blocker: None,
                },
                ExpectedFinding {
                    kind: FindingKind::UnusedExport,
                    path: Some("src/public.ts"),
                    locator: None,
                    blocker: Some(BlockerKind::PublicSurface),
                },
                ExpectedFinding {
                    kind: FindingKind::UnusedType,
                    path: Some("src/public.ts"),
                    locator: None,
                    blocker: Some(BlockerKind::PublicSurface),
                },
            ],
        ),
    ];

    for (language, fixture, expected_count, expected_findings) in cases {
        let snapshot = load_protocol_fixture(&temporary, &format!("issue437-{language}"), fixture)?;
        let findings = analyze_unused(&snapshot);

        let expected_keys = expected_findings
            .iter()
            .map(|expected| {
                let subject = expected
                    .locator
                    .map(|locator| {
                        format!(
                            "subject:{}",
                            fixture_node_id(fixture, locator).unwrap_or_else(|| {
                                panic!("{language} fixture has no node with locator {locator:?}")
                            })
                        )
                    })
                    .or_else(|| expected.path.map(|path| format!("path:{path}")))
                    .expect("expected finding must identify a subject");
                (expected.kind, subject)
            })
            .collect::<BTreeSet<_>>();
        let actual_keys = findings
            .iter()
            .map(|finding| {
                let subject = location_path(finding).map_or_else(
                    || format!("subject:{}", finding.subject_id),
                    |path| format!("path:{path}"),
                );
                (finding.kind, subject)
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            findings.len(),
            actual_keys.len(),
            "duplicate findings for {language}: {findings:?}"
        );
        assert_eq!(
            actual_keys, expected_keys,
            "unexpected findings for {language}: {findings:?}"
        );

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
                let blocker = expected
                    .blocker
                    .expect("export / type expectations name a blocker");
                assert!(
                    finding.blockers.iter().any(|found| found.kind == blocker),
                    "{language} fixture subject lacks a {blocker:?} blocker: {finding:?}"
                );
                // The nested `source_span` gives the declaration line (#596).
                assert!(
                    finding
                        .location
                        .as_ref()
                        .is_some_and(|location| location.start_line.is_some()),
                    "{language} fixture symbol / type finding lacks a declaration line: {finding:?}"
                );
            }
        }

        assert_eq!(
            findings.len(),
            expected_count,
            "finding count drift for {language}: {findings:?}"
        );
    }
    Ok(())
}
