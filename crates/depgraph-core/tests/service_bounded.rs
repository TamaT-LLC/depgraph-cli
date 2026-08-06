use std::{fs, path::Path};

use anyhow::Result;
use depgraph_core::service::{
    BoundedQueryMode, BoundedQueryRequest, DEPGRAPH_SERVICE_LIMITS_VERSION, DepgraphCapabilitySet,
    DepgraphService, DepgraphServiceConfig, DepgraphServiceError, DepgraphServiceLimits,
    RepositoryRelativePath, RuntimeValidateRequest, ServiceSnapshotSelector,
};
use depgraph_core::{CancellationToken, MAX_QUERY_BYTES, RUNTIME_TRACE_MAX_BYTES};
use depgraph_store::Store;
use serde_json::json;
use sha2::{Digest as _, Sha256};

const QUERY: &str = r#"MATCH p = (source:"file")-["imports"*1..1]->(target:"file")
RETURN source.id, target.id LIMIT 10"#;

fn service(root: &Path, store_path: &Path) -> Result<DepgraphService> {
    service_with_limits(root, store_path, DepgraphServiceLimits::default())
}

fn service_with_limits(
    root: &Path,
    store_path: &Path,
    limits: DepgraphServiceLimits,
) -> Result<DepgraphService> {
    Ok(DepgraphService::new(DepgraphServiceConfig::new(
        root,
        store_path,
        DepgraphCapabilitySet::read_only(),
        limits,
    )?))
}

fn query_request(query: Option<&str>, file: Option<&str>) -> BoundedQueryRequest {
    BoundedQueryRequest {
        query: query.map(str::to_owned),
        query_file: file.map(|path| RepositoryRelativePath::parse(path).unwrap()),
        snapshot: ServiceSnapshotSelector::current(),
        mode: BoundedQueryMode::Execute,
    }
}

fn runtime_request(trace: Option<String>, file: Option<&str>) -> RuntimeValidateRequest {
    RuntimeValidateRequest {
        trace,
        trace_file: file.map(|path| RepositoryRelativePath::parse(path).unwrap()),
        snapshot: ServiceSnapshotSelector::current(),
    }
}

fn seed_snapshot(store_path: &Path, root: &Path) -> Result<String> {
    let mut store = Store::open(store_path)?;
    store.start_scan_with_revision("bounded-service", root, false, Some("revision-304"))?;
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
    let common = |event: &str, seq: u64| {
        json!({
            "event": event,
            "protocol_version": "1.0",
            "scan_id": "bounded-service",
            "adapter": "fixture",
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
        "id": "profile:web",
        "language": "web",
        "features": [],
        "environment": {},
        "properties": {}
    });
    store.ingest_event(&profile)?;
    for (seq, (id, kind, locator, path)) in [
        (
            "workspace:fixture",
            "workspace",
            "repo://workspace",
            "workspace",
        ),
        ("file:a", "file", "repo://src/a.rs", "src/a.rs"),
        ("file:b", "file", "repo://src/b.rs", "src/b.rs"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut node = common("node_upsert", seq as u64 + 3);
        node["node"] = json!({
            "id": id,
            "kind": kind,
            "locator": locator,
            "display_name": id,
            "properties": {
                "path": path,
                "repository_identity": if kind == "workspace" { Some("workspace:fixture") } else { None }
            }
        });
        store.ingest_event(&node)?;
    }
    let mut edge = common("edge_upsert", 6);
    edge["edge"] = json!({
        "id": "edge:a-b",
        "source": "file:a",
        "target": "file:b",
        "kind": "imports",
        "phase": "semantic",
        "environment": "host",
        "profile_id": "profile:web",
        "resolution_status": "resolved",
        "precision": "exact",
        "condition": {"op": "all", "conditions": []},
        "generated": false
    });
    store.ingest_event(&edge)?;
    let mut profile_completed = common("profile_completed", 7);
    profile_completed["profile_id"] = json!("profile:web");
    profile_completed["coverage"] = coverage.clone();
    store.ingest_event(&profile_completed)?;
    let mut completed = common("scan_completed", 8);
    completed["coverage"] = coverage;
    store.ingest_event(&completed)?;
    store.finish_scan("bounded-service", "completed", None, true)?;
    Ok(store.current_snapshot_id()?.unwrap())
}

fn trace() -> String {
    json!({
        "schema_version": "1.0",
        "repository": {"identity": "workspace:fixture", "revision": "revision-304"},
        "session": {
            "id": "session-304",
            "started_at": "2026-08-07T00:00:00Z",
            "ended_at": "2026-08-07T00:00:01Z",
            "profile": {"language": "web", "features": []},
            "environment": {"name": "test"},
            "redaction": {"redacted_value_count": 1}
        },
        "events": [{
            "sequence": 1,
            "timestamp": "2026-08-07T00:00:00Z",
            "dependency_kind": "imports",
            "source": {"kind": "node", "node_id": "file:a"},
            "target": {"kind": "node", "node_id": "file:b"},
            "count": 1,
            "redaction": {"redacted_value_count": 1}
        }]
    })
    .to_string()
}

fn digest(path: &Path) -> String {
    format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
}

#[test]
fn invalid_credential_and_ambiguous_queries_fail_before_store_access_without_echo() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    fs::create_dir(&root)?;
    let missing_store = temporary.path().join("missing.sqlite");
    let service = service(&root, &missing_store)?;

    for request in [
        query_request(None, None),
        query_request(Some(QUERY), Some("query.depgraph")),
    ] {
        assert!(matches!(
            service.bounded_query(&request, &CancellationToken::new()),
            Err(DepgraphServiceError::InvalidInput)
        ));
        assert!(!missing_store.exists());
    }

    let secret = "fixture-secret-value";
    let credential = QUERY.replace(
        "RETURN",
        &format!("WHERE source.id = \"token={secret}\" RETURN"),
    );
    let error = service
        .bounded_query(
            &query_request(Some(&credential), None),
            &CancellationToken::new(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        DepgraphServiceError::BoundedQueryInput { .. }
    ));
    let rendered = error.to_string();
    assert!(rendered.contains("query_literal_credential_shape"));
    assert!(!rendered.contains(secret));
    assert!(!missing_store.exists());
    Ok(())
}

#[test]
fn service_output_admission_rejects_before_opening_a_missing_store() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    fs::create_dir(&root)?;
    let missing_store = temporary.path().join("missing.sqlite");
    let limits = DepgraphServiceLimits::try_new(
        DEPGRAPH_SERVICE_LIMITS_VERSION,
        1024 * 1024,
        1024 * 1024,
        100,
        1_000,
    )?;
    let service = service_with_limits(&root, &missing_store, limits)?;
    assert!(matches!(
        service.bounded_query(&query_request(Some(QUERY), None), &CancellationToken::new()),
        Err(DepgraphServiceError::QueryRejected)
    ));
    assert!(!missing_store.exists());
    Ok(())
}

#[test]
fn inline_and_confined_file_queries_are_canonical_and_read_only() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    fs::create_dir(&root)?;
    fs::write(root.join("query.depgraph"), QUERY)?;
    let store_path = temporary.path().join("store.sqlite");
    seed_snapshot(&store_path, &root)?;
    let before = digest(&store_path);
    let service = service(&root, &store_path)?;

    let inline =
        service.bounded_query(&query_request(Some(QUERY), None), &CancellationToken::new())?;
    let file = service.bounded_query(
        &query_request(None, Some("query.depgraph")),
        &CancellationToken::new(),
    )?;
    assert_eq!(inline.input_digest(), file.input_digest());
    assert_eq!(inline.result(), file.result());
    assert_eq!(inline.result().unwrap().rows.len(), 1);
    assert_eq!(before, digest(&store_path));

    assert!(RepositoryRelativePath::parse(root.join("query.depgraph").to_string_lossy()).is_err());
    assert!(RepositoryRelativePath::parse("../query.depgraph").is_err());

    fs::write(root.join("oversize.query"), vec![b'x'; MAX_QUERY_BYTES + 1])?;
    assert!(matches!(
        service.bounded_query(
            &query_request(None, Some("oversize.query")),
            &CancellationToken::new()
        ),
        Err(DepgraphServiceError::BoundedQueryInput { .. })
    ));
    fs::create_dir(root.join("directory.query"))?;
    assert!(matches!(
        service.bounded_query(
            &query_request(None, Some("directory.query")),
            &CancellationToken::new()
        ),
        Err(DepgraphServiceError::BoundedQueryInput { .. })
    ));

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(root.join("query.depgraph"), root.join("linked.query"))?;
        assert!(matches!(
            service.bounded_query(
                &query_request(None, Some("linked.query")),
                &CancellationToken::new()
            ),
            Err(DepgraphServiceError::BoundedQueryInput { .. })
        ));
    }
    assert_eq!(before, digest(&store_path));
    Ok(())
}

#[test]
fn runtime_validate_accepts_only_one_bounded_source_and_mutates_nothing() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    fs::create_dir(&root)?;
    fs::write(root.join("trace.json"), trace())?;
    let store_path = temporary.path().join("store.sqlite");
    seed_snapshot(&store_path, &root)?;
    let store_before = digest(&store_path);
    let trace_before = digest(&root.join("trace.json"));
    let service = service(&root, &store_path)?;

    for request in [
        runtime_request(None, None),
        runtime_request(Some(trace()), Some("trace.json")),
    ] {
        assert!(matches!(
            service.runtime_validate(&request, &CancellationToken::new()),
            Err(DepgraphServiceError::InvalidInput)
        ));
    }

    let inline = service.runtime_validate(
        &runtime_request(Some(trace()), None),
        &CancellationToken::new(),
    )?;
    let file = service.runtime_validate(
        &runtime_request(None, Some("trace.json")),
        &CancellationToken::new(),
    )?;
    assert_eq!(inline.input_digest(), file.input_digest());
    assert_eq!(inline.trace(), file.trace());
    assert_eq!(inline.trace().summary.events, 1);
    assert_eq!(
        inline.trace().events[0].source.node_id.as_deref(),
        Some("file:a")
    );
    assert_eq!(store_before, digest(&store_path));
    assert_eq!(trace_before, digest(&root.join("trace.json")));

    fs::write(
        root.join("oversize.trace"),
        vec![b' '; RUNTIME_TRACE_MAX_BYTES + 1],
    )?;
    assert!(matches!(
        service.runtime_validate(
            &runtime_request(None, Some("oversize.trace")),
            &CancellationToken::new()
        ),
        Err(DepgraphServiceError::ResourceExhausted)
    ));
    fs::create_dir(root.join("directory.trace"))?;
    assert!(
        service
            .runtime_validate(
                &runtime_request(None, Some("directory.trace")),
                &CancellationToken::new()
            )
            .is_err()
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(root.join("trace.json"), root.join("linked.trace"))?;
        assert!(
            service
                .runtime_validate(
                    &runtime_request(None, Some("linked.trace")),
                    &CancellationToken::new()
                )
                .is_err()
        );
    }
    assert_eq!(store_before, digest(&store_path));
    Ok(())
}

#[test]
fn runtime_secret_rejection_and_cancellation_have_pre_store_priority() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    fs::create_dir(&root)?;
    let missing_store = temporary.path().join("missing.sqlite");
    let service = service(&root, &missing_store)?;
    let secret = "fixture-secret-value";
    let hostile = json!({"authorization": secret}).to_string();
    let error = service
        .runtime_validate(
            &runtime_request(Some(hostile), None),
            &CancellationToken::new(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        DepgraphServiceError::RuntimeTraceInput { .. }
    ));
    assert!(!error.to_string().contains(secret));
    assert!(!missing_store.exists());

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert!(matches!(
        service.bounded_query(&query_request(None, None), &cancellation),
        Err(DepgraphServiceError::Cancelled)
    ));
    assert!(matches!(
        service.runtime_validate(&runtime_request(None, None), &cancellation),
        Err(DepgraphServiceError::Cancelled)
    ));
    assert!(!missing_store.exists());
    Ok(())
}
