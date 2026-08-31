use std::{fs, path::Path, process::Command};

use anyhow::Result;
use depgraph_core::service::{
    DepgraphCapabilitySet, DepgraphService, DepgraphServiceConfig, DepgraphServiceError,
    DepgraphServiceLimits, HealthAuditRequest, HealthFindingGetRequest, HealthFindingsRequest,
    HealthHotspotsRequest, HealthSummaryRequest, MAX_HEALTH_BLOCKERS_PER_FINDING,
    MAX_HEALTH_FINDINGS, PolicyEvaluateRequest, SnapshotLocator,
};
use depgraph_core::{
    CancellationToken, Confidence, DEFAULT_HOTSPOT_WEIGHTS, FindingKind, HotspotWeights,
};
use depgraph_store::Store;
use serde_json::json;

fn service(root: &Path, store_path: &Path) -> Result<DepgraphService> {
    Ok(DepgraphService::new(DepgraphServiceConfig::new(
        root,
        store_path,
        DepgraphCapabilitySet::read_only(),
        DepgraphServiceLimits::default(),
    )?))
}

fn seed_health_snapshot(
    store: &mut Store,
    root: &Path,
    scan_id: &str,
    revision: &str,
    add_changed_usage: bool,
    heuristic_unused_edges: usize,
) -> Result<String> {
    store.start_scan_with_revision(scan_id, root, false, Some(revision))?;
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
        "completeness": ["semantic-complete"],
        "reasons": []
    });
    let common = |event: &str, seq: u64| {
        json!({
            "event": event,
            "protocol_version": "1.0",
            "scan_id": scan_id,
            "adapter": "health-fixture",
            "adapter_version": "1.0",
            "seq": seq
        })
    };
    let mut started = common("scan_started", 1);
    started["root"] = json!(root);
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    store.ingest_event(&started)?;
    let mut profile = common("profile_declared", 2);
    profile["profile"] = json!({
        "id": "fixture:rust",
        "language": "rust",
        "features": [],
        "environment": {},
        "properties": {}
    });
    store.ingest_event(&profile)?;
    let mut unused = common("node_upsert", 3);
    unused["node"] = json!({
        "id": "file:src/unused.rs",
        "kind": "file",
        "locator": "repo://src/unused.rs",
        "display_name": "unused.rs",
        "properties": {
            "path": "src/unused.rs",
            "language": "rust"
        }
    });
    store.ingest_event(&unused)?;
    let mut used = common("node_upsert", 4);
    used["node"] = json!({
        "id": "file:src/used.rs",
        "kind": "file",
        "locator": "repo://src/used.rs",
        "display_name": "used.rs",
        "properties": {
            "path": "src/used.rs",
            "language": "rust"
        }
    });
    store.ingest_event(&used)?;
    let mut importer = common("node_upsert", 5);
    importer["node"] = json!({
        "id": "file:src/lib.rs",
        "kind": "file",
        "locator": "repo://src/lib.rs",
        "display_name": "lib.rs",
        "properties": {
            "path": "src/lib.rs",
            "language": "rust"
        }
    });
    store.ingest_event(&importer)?;
    let mut edge = common("edge_upsert", 6);
    edge["edge"] = json!({
        "id": "edge:lib-used",
        "source": "file:src/lib.rs",
        "target": "file:src/used.rs",
        "kind": "imports",
        "phase": "source",
        "environment": "host",
        "profile_id": "fixture:rust",
        "resolution_status": "resolved",
        "precision": "exact",
        "condition": {"op": "all", "conditions": []},
        "generated": false
    });
    store.ingest_event(&edge)?;
    let mut next_seq = 7;
    for index in 0..heuristic_unused_edges {
        let mut heuristic = common("edge_upsert", next_seq);
        heuristic["edge"] = json!({
            "id": format!("edge:heuristic-unused:{index:02}"),
            "source": "file:src/lib.rs",
            "target": "file:src/unused.rs",
            "kind": "references",
            "phase": "source",
            "environment": "host",
            "profile_id": "fixture:rust",
            "resolution_status": "resolved",
            "precision": "heuristic",
            "condition": {"op": "all", "conditions": []},
            "generated": false
        });
        store.ingest_event(&heuristic)?;
        next_seq += 1;
    }
    if add_changed_usage {
        let mut changed_edge = common("edge_upsert", next_seq);
        changed_edge["edge"] = json!({
            "id": "edge:used-unused",
            "source": "file:src/used.rs",
            "target": "file:src/unused.rs",
            "kind": "imports",
            "phase": "source",
            "environment": "host",
            "profile_id": "fixture:rust",
            "resolution_status": "resolved",
            "precision": "exact",
            "condition": {"op": "all", "conditions": []},
            "generated": false,
            "evidence": [{
                "kind": "source",
                "extractor": "health-fixture",
                "extractor_version": "1.0",
                "path": "src/used.rs",
                "start_line": 1,
                "start_column": 1,
                "end_line": 1,
                "end_column": 2,
                "properties": {}
            }]
        });
        store.ingest_event(&changed_edge)?;
        next_seq += 1;
    }
    let mut profile_completed = common("profile_completed", next_seq);
    profile_completed["profile_id"] = json!("fixture:rust");
    profile_completed["coverage"] = coverage.clone();
    store.ingest_event(&profile_completed)?;
    let mut completed = common("scan_completed", next_seq + 1);
    completed["coverage"] = coverage;
    store.ingest_event(&completed)?;
    store.finish_scan(scan_id, "completed", None, true)?;
    Ok(store
        .current_snapshot_id()?
        .expect("completed health snapshot is promoted"))
}

fn run_git(root: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "health")
        .env("GIT_AUTHOR_EMAIL", "health@example.test")
        .env("GIT_COMMITTER_NAME", "health")
        .env("GIT_COMMITTER_EMAIL", "health@example.test")
        .output()
        .expect("git");
    assert!(
        output.status.success(),
        "git {:?}: {}",
        arguments,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn init_git(root: &Path) -> String {
    run_git(root, &["init"]);
    run_git(root, &["config", "user.name", "health"]);
    run_git(root, &["config", "user.email", "health@example.test"]);
    fs::write(root.join("src/unused.rs"), "pub fn unused() {}\n").unwrap();
    fs::write(root.join("src/used.rs"), "pub fn used() {}\n").unwrap();
    fs::write(root.join("src/lib.rs"), "mod used;\n").unwrap();
    run_git(root, &["add", "."]);
    run_git(root, &["commit", "-m", "seed"]);
    run_git(root, &["rev-parse", "HEAD"])
}

#[test]
fn issue_423_health_service_pins_snapshot_and_rejects_invalid_requests() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repo");
    fs::create_dir_all(root.join("src"))?;
    let revision = init_git(&root);
    let store_path = temporary.path().join("graph.sqlite");
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_health_snapshot(&mut store, &root, "health-scan", &revision, false, 0)?;
    drop(store);

    let service = service(&root, &store_path)?;
    let cancellation = CancellationToken::new();
    let mut request =
        service.start_snapshot_request_at_cancellable(&SnapshotLocator::Current, &cancellation)?;
    assert_eq!(request.snapshot_id().as_str(), snapshot_id);

    assert!(matches!(
        HealthSummaryRequest::try_new(Some(vec![FindingKind::Hotspot])),
        Err(DepgraphServiceError::InvalidInput)
    ));
    assert!(matches!(
        HealthFindingsRequest::try_new(vec![FindingKind::NewCycle], Vec::new(), Vec::new(), 8),
        Err(DepgraphServiceError::InvalidInput)
    ));
    assert!(matches!(
        HealthFindingsRequest::try_new(Vec::new(), Vec::new(), Vec::new(), 0),
        Err(DepgraphServiceError::InvalidInput)
    ));
    assert!(matches!(
        HealthFindingGetRequest::try_new("not-a-finding"),
        Err(DepgraphServiceError::InvalidInput)
    ));
    assert!(matches!(
        HealthHotspotsRequest::try_new(0, Vec::new(), DEFAULT_HOTSPOT_WEIGHTS),
        Err(DepgraphServiceError::InvalidInput)
    ));
    assert!(HotspotWeights::try_new(10_001, 0, 0, 0, 0).is_err());

    let summary = service.health_summary(
        &mut request,
        &HealthSummaryRequest::try_new(Some(vec![FindingKind::UnusedFile]))?,
        &cancellation,
    )?;
    assert_eq!(summary.snapshot_id().as_str(), snapshot_id);
    assert!(summary.counts_by_kind().contains_key("unused-file"));
    assert!(
        summary
            .collection_digest()
            .starts_with("collection:sha256:")
    );

    let findings = service.health_findings(
        &mut request,
        &HealthFindingsRequest::try_new(
            vec![FindingKind::UnusedFile],
            Vec::new(),
            Vec::new(),
            MAX_HEALTH_FINDINGS,
        )?,
        &cancellation,
    )?;
    assert_eq!(findings.collection_digest(), summary.collection_digest());
    let unused = findings
        .findings()
        .iter()
        .find(|finding| finding.subject_id == "file:src/unused.rs")
        .expect("unused file finding");
    assert_eq!(unused.kind, FindingKind::UnusedFile);
    assert!(
        unused.confidence == Confidence::Confirmed || unused.confidence == Confidence::Probable
    );

    let detail = service.health_finding_get(
        &mut request,
        &HealthFindingGetRequest::try_new(unused.id.clone())?,
        &cancellation,
    )?;
    assert_eq!(detail.finding.id, unused.id);

    let missing = service.health_finding_get(
        &mut request,
        &HealthFindingGetRequest::try_new(
            "finding:sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )?,
        &cancellation,
    );
    assert!(matches!(missing, Err(DepgraphServiceError::InvalidInput)));

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(matches!(
        service.health_summary(
            &mut request,
            &HealthSummaryRequest::try_new(None)?,
            &cancelled
        ),
        Err(DepgraphServiceError::Cancelled)
    ));
    Ok(())
}

#[test]
fn issue_436_health_endpoints_compact_oversized_blocker_sets() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repo");
    fs::create_dir_all(root.join("src"))?;
    let revision = init_git(&root);
    let store_path = temporary.path().join("graph.sqlite");
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_health_snapshot(
        &mut store,
        &root,
        "health-many-blockers",
        &revision,
        false,
        MAX_HEALTH_BLOCKERS_PER_FINDING + 1,
    )?;
    drop(store);

    let service = service(&root, &store_path)?;
    let cancellation = CancellationToken::new();
    let mut request =
        service.start_snapshot_request_at_cancellable(&SnapshotLocator::Current, &cancellation)?;
    let summary = service.health_summary(
        &mut request,
        &HealthSummaryRequest::try_new(None)?,
        &cancellation,
    )?;
    let findings_request =
        HealthFindingsRequest::try_new(Vec::new(), Vec::new(), Vec::new(), MAX_HEALTH_FINDINGS)?;
    let findings = service.health_findings(&mut request, &findings_request, &cancellation)?;
    assert_eq!(summary.snapshot_id().as_str(), snapshot_id);
    assert_eq!(summary.collection_digest(), findings.collection_digest());

    let unused = findings
        .findings()
        .iter()
        .find(|finding| finding.subject_id == "file:src/unused.rs")
        .expect("heuristic references do not prove usage");
    assert_eq!(unused.confidence, Confidence::Indeterminate);
    assert_eq!(unused.blockers.len(), 1);
    assert_eq!(
        unused.blockers[0].kind,
        depgraph_core::BlockerKind::HeuristicPrecision
    );
    assert!(
        unused.blockers[0]
            .detail
            .starts_with("33 blockers of kind heuristic-precision;")
    );
    assert_eq!(
        unused.fingerprint,
        depgraph_core::finding_fingerprint(unused)
    );

    let detail = service.health_finding_get(
        &mut request,
        &HealthFindingGetRequest::try_new(unused.id.clone())?,
        &cancellation,
    )?;
    assert_eq!(&detail.finding, unused);
    let repeated = service.health_findings(&mut request, &findings_request, &cancellation)?;
    assert_eq!(repeated.collection_digest(), findings.collection_digest());
    assert_eq!(repeated.findings(), findings.findings());
    Ok(())
}

#[cfg(unix)]
#[test]
fn issue_423_unreadable_manifest_degrades_health_instead_of_failing() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repo");
    fs::create_dir_all(root.join("src"))?;
    let revision = init_git(&root);
    let outside_manifest = temporary.path().join("outside-Cargo.toml");
    fs::write(&outside_manifest, "[dependencies]\nserde = \"1\"\n")?;
    symlink(&outside_manifest, root.join("Cargo.toml"))?;
    let store_path = temporary.path().join("graph.sqlite");
    let mut store = Store::open(&store_path)?;
    seed_health_snapshot(&mut store, &root, "health-symlink", &revision, false, 0)?;
    drop(store);

    let service = service(&root, &store_path)?;
    let cancellation = CancellationToken::new();
    let mut request =
        service.start_snapshot_request_at_cancellable(&SnapshotLocator::Current, &cancellation)?;
    let summary = service.health_summary(
        &mut request,
        &HealthSummaryRequest::try_new(None)?,
        &cancellation,
    )?;
    assert!(summary.manifest_digest().is_some());
    Ok(())
}

#[test]
fn issue_423_health_audit_pins_a_snapshot_pair_and_binds_identity() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repo");
    fs::create_dir_all(root.join("src"))?;
    let base_revision = init_git(&root);
    let store_path = temporary.path().join("graph.sqlite");
    let mut store = Store::open(&store_path)?;
    let base_id = seed_health_snapshot(&mut store, &root, "health-base", &base_revision, false, 0)?;
    fs::write(
        root.join("src/unused.rs"),
        "pub fn unused() { println!(\"changed\"); }\n",
    )?;
    run_git(&root, &["add", "."]);
    run_git(&root, &["commit", "-m", "change unused"]);
    let head_revision = run_git(&root, &["rev-parse", "HEAD"]);
    let after_id =
        seed_health_snapshot(&mut store, &root, "health-after", &head_revision, true, 0)?;
    drop(store);

    let service = service(&root, &store_path)?;
    let cancellation = CancellationToken::new();
    let mut after =
        service.start_snapshot_request_at_cancellable(&SnapshotLocator::Current, &cancellation)?;
    let scope = service.start_health_audit_scope(
        &mut after,
        &HealthAuditRequest::try_new(&base_revision, None)?,
        &cancellation,
    )?;
    assert_eq!(scope.after().id().as_str(), after_id);
    let (before, _) = scope.comparable_pair().expect("base snapshot pair");
    assert_eq!(before.id().as_str(), base_id);
    let first = service.health_audit(&scope, &cancellation)?;
    assert_eq!(first.after_snapshot_id().as_str(), after_id);
    assert_eq!(
        first.before_snapshot_id().map(|id| id.as_str()),
        Some(base_id.as_str())
    );
    assert_eq!(first.changed_oid(), head_revision);
    assert!(first.collection_digest().starts_with("collection:sha256:"));
    assert!(first.findings().iter().all(|finding| {
        finding
            .blockers
            .iter()
            .all(|blocker| blocker.kind != depgraph_core::BlockerKind::IncomparableProfileMatrix)
    }));

    fs::write(root.join("src/late-change.rs"), "pub fn late() {}\n")?;
    let second = service.health_audit(&scope, &cancellation)?;
    assert_eq!(first.collection_digest(), second.collection_digest());
    assert_eq!(first.findings(), second.findings());
    Ok(())
}

#[test]
fn issue_438_health_audit_missing_base_keeps_placeholders_blast_and_digest_stable() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repo");
    fs::create_dir_all(root.join("src"))?;
    let base_revision = init_git(&root);
    let store_path = temporary.path().join("graph.sqlite");

    // Keep only a snapshot after the merge base. Its graph has two reverse
    // dependents so the missing-base path can still prove blast-radius work.
    fs::write(
        root.join("src/unused.rs"),
        "pub fn unused() { println!(\"after\"); }\n",
    )?;
    run_git(&root, &["add", "."]);
    run_git(&root, &["commit", "-m", "snapshot after base"]);
    let after_revision = run_git(&root, &["rev-parse", "HEAD"]);
    let mut store = Store::open(&store_path)?;
    let after_id = seed_health_snapshot(
        &mut store,
        &root,
        "health-after-missing-base",
        &after_revision,
        true,
        0,
    )?;
    drop(store);

    // The merge base remains the original commit, for which no snapshot was
    // stored. The unrelated change keeps the after snapshot stale while the
    // changed set still contains the changed subject above.
    fs::write(root.join("notes.txt"), "later change\n")?;
    run_git(&root, &["add", "."]);
    run_git(&root, &["commit", "-m", "change after snapshot"]);

    let service = service(&root, &store_path)?;
    let cancellation = CancellationToken::new();
    let mut after =
        service.start_snapshot_request_at_cancellable(&SnapshotLocator::Current, &cancellation)?;
    assert_eq!(after.snapshot_id().as_str(), after_id);
    let scope = service.start_health_audit_scope(
        &mut after,
        &HealthAuditRequest::try_new(&base_revision, None)?,
        &cancellation,
    )?;
    assert!(scope.before().is_none());
    assert!(
        scope
            .policy_config_digest()
            .starts_with("policy-config:sha256:")
    );

    let first = service.health_audit(&scope, &cancellation)?;
    let second = service.health_audit(&scope, &cancellation)?;
    assert_eq!(first.before_snapshot_id(), None);
    assert_eq!(first.collection_digest(), second.collection_digest());
    assert_eq!(first.findings(), second.findings());
    let degraded = first
        .findings()
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind,
                FindingKind::NewCycle
                    | FindingKind::NewBoundaryViolation
                    | FindingKind::PublicApiChange
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(degraded.len(), 3);
    assert!(degraded.iter().all(|finding| {
        finding.confidence == Confidence::Indeterminate
            && finding.subject_id == format!("degraded:{}", finding.kind.as_str())
            && finding
                .blockers
                .iter()
                .any(|blocker| blocker.kind == depgraph_core::BlockerKind::MissingBaseSnapshot)
    }));
    assert!(
        first
            .findings()
            .iter()
            .any(|finding| finding.kind == FindingKind::WideBlastRadius)
    );
    Ok(())
}

#[test]
fn issue_438_health_audit_uses_evaluated_policy_violation_identity() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repo");
    fs::create_dir_all(root.join("src"))?;
    let base_revision = init_git(&root);
    let store_path = temporary.path().join("graph.sqlite");
    let mut store = Store::open(&store_path)?;
    let base_id = seed_health_snapshot(
        &mut store,
        &root,
        "health-policy-base",
        &base_revision,
        false,
        0,
    )?;

    fs::write(
        root.join("src/unused.rs"),
        "pub fn unused() { println!(\"after\"); }\n",
    )?;
    run_git(&root, &["add", "."]);
    run_git(&root, &["commit", "-m", "introduce boundary edge"]);
    let after_revision = run_git(&root, &["rev-parse", "HEAD"]);
    let after_id = seed_health_snapshot(
        &mut store,
        &root,
        "health-policy-after",
        &after_revision,
        true,
        0,
    )?;
    drop(store);

    fs::write(
        root.join(".depgraph.toml"),
        r#"schema_version = 1
[policy]
schema_version = "1.0"

[[policy.rules]]
id = "audit-boundary"
kind = "forbidden_dependency"
severity = "error"
source = { kind = "file", field = "id", match = "exact", value = "file:src/used.rs", cardinality = "one", exclude = [], scope = { paths = [], packages = [] } }
target = { kind = "file", field = "id", match = "exact", value = "file:src/unused.rs", cardinality = "one", exclude = [], scope = { paths = [], packages = [] } }
profiles = { include = [{ match = "exact", value = "fixture:rust" }], exclude = [] }
condition = { op = "all", conditions = [] }
precisions = ["exact"]
resolution_statuses = ["resolved"]
evidence = { kinds = ["source"], minimum_spans = 1, primary_only = true }
"#,
    )?;

    let service = service(&root, &store_path)?;
    let cancellation = CancellationToken::new();
    let policy_pair = service.policy_evaluate(
        &PolicyEvaluateRequest::new(
            SnapshotLocator::parse(&base_id)?,
            SnapshotLocator::parse(&after_id)?,
        ),
        &cancellation,
    )?;
    let expected_policy_id = policy_pair
        .result
        .violations
        .first()
        .map(|violation| violation.id.clone())
        .expect("after snapshot has a policy violation");
    let mut after =
        service.start_snapshot_request_at_cancellable(&SnapshotLocator::Current, &cancellation)?;
    let scope = service.start_health_audit_scope(
        &mut after,
        &HealthAuditRequest::try_new(&base_revision, None)?,
        &cancellation,
    )?;
    assert_eq!(
        scope.policy_config_digest(),
        policy_pair.result.policy_config_digest
    );
    let result = service.health_audit(&scope, &cancellation)?;
    let boundary = result
        .findings()
        .iter()
        .find(|finding| finding.kind == FindingKind::NewBoundaryViolation)
        .expect("evaluated boundary violation becomes an audit finding");
    assert_eq!(boundary.subject_id, expected_policy_id);
    assert_eq!(boundary.subject_id, policy_pair.result.violations[0].id);
    Ok(())
}

#[test]
fn issue_423_health_hotspots_degrade_missing_layers_deterministically() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repo");
    fs::create_dir_all(root.join("src"))?;
    let revision = init_git(&root);
    let store_path = temporary.path().join("graph.sqlite");
    let mut store = Store::open(&store_path)?;
    seed_health_snapshot(&mut store, &root, "health-hotspots", &revision, false, 0)?;
    drop(store);

    let service = service(&root, &store_path)?;
    let cancellation = CancellationToken::new();
    let mut request =
        service.start_snapshot_request_at_cancellable(&SnapshotLocator::Current, &cancellation)?;
    let first = service.health_hotspots(
        &mut request,
        &HealthHotspotsRequest::try_new(8, Vec::new(), DEFAULT_HOTSPOT_WEIGHTS)?,
        &cancellation,
    )?;
    let second = service.health_hotspots(
        &mut request,
        &HealthHotspotsRequest::try_new(8, Vec::new(), DEFAULT_HOTSPOT_WEIGHTS)?,
        &cancellation,
    )?;
    assert_eq!(first.collection_digest(), second.collection_digest());
    let ids = first
        .findings()
        .iter()
        .map(|finding| finding.id.as_str())
        .collect::<Vec<_>>();
    let repeated_ids = second
        .findings()
        .iter()
        .map(|finding| finding.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, repeated_ids);
    assert_eq!(first.findings()[0].subject_id, "file:src/used.rs");
    let scores = first.findings()[0]
        .hotspot_scores
        .as_ref()
        .expect("hotspot findings expose structured scores");
    assert_eq!(scores.reverse_impact.normalized_basis_points, 10_000);
    assert_eq!(scores.git_churn.raw, 1);
    assert!(scores.git_churn.available);
    assert_eq!(scores.runtime.raw, 0);
    assert!(!scores.runtime.available);
    assert_eq!(
        scores.runtime.weight_basis_points,
        DEFAULT_HOTSPOT_WEIGHTS.runtime
    );
    assert_eq!(first.findings()[0].confidence, Confidence::Probable);
    assert!(first.findings().iter().all(|finding| {
        finding
            .blockers
            .iter()
            .all(|blocker| blocker.kind != depgraph_core::BlockerKind::ChurnUnavailable)
    }));
    Ok(())
}
