use std::path::Path;

use anyhow::Result;
use depgraph_core::service::{
    DeferredRuntimeImportRecovery, DeferredRuntimeImportServiceOutcome, DeferredScanRecovery,
    DeferredScanServiceOutcome, DepgraphCapability, DepgraphCapabilitySet, DepgraphService,
    DepgraphServiceConfig, DepgraphServiceError, DepgraphServiceLimits, RepositoryRelativePath,
    RuntimeValidateRequest, ScanRequest, ServiceSnapshotSelector, SnapshotLocator,
    SnapshotNameCreateRequest,
};
use depgraph_core::{CancellationToken, ScanCacheMode, acquire_store_writer_lock};
use depgraph_store::Store;
use serde_json::json;

fn service(
    root: &Path,
    store_path: &Path,
    capabilities: impl IntoIterator<Item = DepgraphCapability>,
) -> DepgraphService {
    DepgraphService::new(
        DepgraphServiceConfig::new(
            root,
            store_path,
            DepgraphCapabilitySet::try_new(capabilities).unwrap(),
            DepgraphServiceLimits::default(),
        )
        .unwrap(),
    )
}

fn seed_completed_snapshot(store: &mut Store, root: &Path, scan_id: &str) -> Result<String> {
    let coverage = json!({
        "profiles": 0,
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
    store.start_scan_with_revision(scan_id, root, false, Some("revision"))?;
    for event in [
        json!({"event":"scan_started","protocol_version":"1.0","scan_id":scan_id,"adapter":"rust","adapter_version":"0.1.0","seq":1,"root":root,"project_code_executed":false,"safe_mode":true}),
        json!({"event":"scan_completed","protocol_version":"1.0","scan_id":scan_id,"adapter":"rust","adapter_version":"0.1.0","seq":2,"coverage":coverage}),
    ] {
        store.ingest_event(&event)?;
    }
    store.finish_scan(scan_id, "completed", None, true)?;
    Ok(store.current_snapshot_id()?.unwrap())
}

fn seed_runtime_snapshot(store: &mut Store, root: &Path) -> Result<String> {
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
            "scan_id": "runtime-service",
            "adapter": "fixture",
            "adapter_version": "1.0",
            "seq": seq
        })
    };
    store.start_scan_with_revision("runtime-service", root, false, Some("revision-313"))?;
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
    for (offset, (id, kind, locator, path)) in [
        (
            "workspace:fixture",
            "workspace",
            "repo://workspace",
            "workspace",
        ),
        ("file:a", "file", "repo://src/a.ts", "src/a.ts"),
        ("file:b", "file", "repo://src/b.ts", "src/b.ts"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut node = common("node_upsert", offset as u64 + 3);
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
    let mut profile_completed = common("profile_completed", 6);
    profile_completed["profile_id"] = json!("profile:web");
    profile_completed["coverage"] = coverage.clone();
    store.ingest_event(&profile_completed)?;
    let mut completed = common("scan_completed", 7);
    completed["coverage"] = coverage;
    store.ingest_event(&completed)?;
    store.finish_scan("runtime-service", "completed", None, true)?;
    Ok(store.current_snapshot_id()?.unwrap())
}

fn runtime_trace() -> String {
    json!({
        "schema_version": "1.0",
        "repository": {"identity": "workspace:fixture", "revision": "revision-313"},
        "session": {
            "id": "session-313",
            "started_at": "2026-08-08T00:00:00Z",
            "ended_at": "2026-08-08T00:00:01Z",
            "profile": {"language": "web", "features": []},
            "environment": {"name": "test"},
            "redaction": {"redacted_value_count": 0}
        },
        "events": [{
            "sequence": 1,
            "timestamp": "2026-08-08T00:00:00Z",
            "dependency_kind": "imports",
            "source": {"kind": "node", "node_id": "file:a"},
            "target": {"kind": "node", "node_id": "file:b"},
            "count": 1
        }]
    })
    .to_string()
}

fn runtime_request(trace: Option<String>, file: Option<&str>) -> RuntimeValidateRequest {
    RuntimeValidateRequest {
        trace,
        trace_file: file.map(|path| RepositoryRelativePath::parse(path).unwrap()),
        snapshot: ServiceSnapshotSelector::current(),
    }
}

#[tokio::test]
async fn store_write_service_denies_scan_and_snapshot_naming_before_store_access() {
    let temporary = tempfile::tempdir().unwrap();
    let repository = temporary.path().join("repository");
    let store_path = temporary.path().join("missing-store.sqlite");
    std::fs::create_dir(&repository).unwrap();
    let service = service(&repository, &store_path, [DepgraphCapability::Read]);

    let scan = service
        .scan_cancellable(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            CancellationToken::new(),
        )
        .await;
    assert!(matches!(
        scan,
        Err(DepgraphServiceError::CapabilityDenied {
            required: DepgraphCapability::StoreWrite
        })
    ));
    let naming = service.snapshot_name_create(
        &SnapshotNameCreateRequest::new("baseline", SnapshotLocator::Current),
        &CancellationToken::new(),
    );
    assert!(matches!(
        naming,
        Err(DepgraphServiceError::CapabilityDenied {
            required: DepgraphCapability::StoreWrite
        })
    ));
    assert!(!store_path.exists());
}

#[test]
fn runtime_import_rejects_invalid_input_before_store_creation() {
    let temporary = tempfile::tempdir().unwrap();
    let repository = temporary.path().join("repository");
    let store_path = temporary.path().join("missing-store.sqlite");
    std::fs::create_dir(&repository).unwrap();
    let service = service(
        &repository,
        &store_path,
        [DepgraphCapability::Read, DepgraphCapability::StoreWrite],
    );

    assert!(matches!(
        service.runtime_import(&runtime_request(None, None), &CancellationToken::new()),
        Err(DepgraphServiceError::InvalidInput)
    ));
    assert!(!store_path.exists());
}

fn downgrade_store_to_v15(path: &Path) -> Result<()> {
    let connection = rusqlite::Connection::open(path)?;
    connection.execute_batch(
        "PRAGMA wal_checkpoint(TRUNCATE);
         DROP TABLE scan_operation_staging;
         DROP TABLE runtime_import_operation_owners;
         PRAGMA user_version=15;
         PRAGMA journal_mode=DELETE;",
    )?;
    Ok(())
}

#[test]
fn v15_runtime_semantic_mismatches_do_not_migrate_or_mutate_the_store() -> Result<()> {
    for (field, mismatched) in [
        ("repository", "workspace:foreign"),
        ("revision", "revision-foreign"),
    ] {
        let temporary = tempfile::tempdir()?;
        let repository = temporary.path().join("repository");
        let store_path = temporary.path().join("graph.sqlite");
        std::fs::create_dir(&repository)?;
        seed_runtime_snapshot(&mut Store::open(&store_path)?, &repository)?;
        downgrade_store_to_v15(&store_path)?;
        let bytes_before = std::fs::read(&store_path)?;
        let mut trace = serde_json::from_str::<serde_json::Value>(&runtime_trace())?;
        match field {
            "repository" => trace["repository"]["identity"] = json!(mismatched),
            "revision" => trace["repository"]["revision"] = json!(mismatched),
            _ => unreachable!(),
        }
        let service = service(
            &repository,
            &store_path,
            [DepgraphCapability::Read, DepgraphCapability::StoreWrite],
        );

        assert!(matches!(
            service.prepare_runtime_import(
                &runtime_request(Some(trace.to_string()), None),
                &CancellationToken::new(),
            ),
            Err(DepgraphServiceError::RuntimeTraceInput { .. })
        ));
        assert_eq!(std::fs::read(&store_path)?, bytes_before, "{field}");
        let read = rusqlite::Connection::open_with_flags(
            &store_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        assert_eq!(
            read.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?,
            15,
            "{field}"
        );
    }
    Ok(())
}

#[test]
fn runtime_import_service_promotes_atomically_and_deferred_cancel_stays_unpublished() -> Result<()>
{
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let store_path = temporary.path().join("graph.sqlite");
    std::fs::create_dir(&repository)?;
    let base_snapshot_id = seed_runtime_snapshot(&mut Store::open(&store_path)?, &repository)?;
    let service = service(
        &repository,
        &store_path,
        [DepgraphCapability::Read, DepgraphCapability::StoreWrite],
    );

    let cancelled_trace = runtime_trace().replace("session-313", "session-313-cancelled");
    let prepared = service.prepare_runtime_import(
        &runtime_request(Some(cancelled_trace), None),
        &CancellationToken::new(),
    )?;
    let completion = match service.runtime_import_deferred_prepared(
        prepared,
        "op_service_cancelled",
        &CancellationToken::new(),
    )? {
        DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
        DeferredRuntimeImportServiceOutcome::Finished(_) => {
            anyhow::bail!("new runtime import did not defer promotion")
        }
    };
    let cancelled_snapshot_id = completion
        .outcome()
        .completed_snapshot_id()
        .as_str()
        .to_owned();
    assert_eq!(
        Store::open_read_only(&store_path)?
            .current_snapshot_id()?
            .as_deref(),
        Some(base_snapshot_id.as_str())
    );
    assert!(
        Store::open_read_only(&store_path)?
            .completed_snapshot(&cancelled_snapshot_id)?
            .is_none()
    );
    completion.cancel()?;
    assert_eq!(
        Store::open_read_only(&store_path)?
            .current_snapshot_id()?
            .as_deref(),
        Some(base_snapshot_id.as_str())
    );

    let imported = service.runtime_import(
        &runtime_request(Some(runtime_trace()), None),
        &CancellationToken::new(),
    )?;
    assert_ne!(imported.completed_snapshot_id().as_str(), base_snapshot_id);
    assert_eq!(
        Store::open_read_only(&store_path)?
            .current_snapshot_id()?
            .as_deref(),
        Some(imported.completed_snapshot_id().as_str())
    );
    assert_eq!(imported.result().status, "completed");
    Ok(())
}

#[test]
fn prepared_immediate_runtime_import_does_not_replace_newer_current_snapshot() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let store_path = temporary.path().join("graph.sqlite");
    std::fs::create_dir(&repository)?;
    let base_snapshot_id = seed_runtime_snapshot(&mut Store::open(&store_path)?, &repository)?;
    let service = service(
        &repository,
        &store_path,
        [DepgraphCapability::Read, DepgraphCapability::StoreWrite],
    );
    let prepared = service.prepare_runtime_import(
        &runtime_request(Some(runtime_trace()), None),
        &CancellationToken::new(),
    )?;
    assert_eq!(prepared.base_snapshot_id().as_str(), base_snapshot_id);

    let newer_snapshot_id =
        seed_completed_snapshot(&mut Store::open(&store_path)?, &repository, "newer-current")?;
    assert_ne!(newer_snapshot_id, base_snapshot_id);

    let imported = service.runtime_import_prepared(prepared, &CancellationToken::new())?;
    assert_ne!(imported.completed_snapshot_id().as_str(), newer_snapshot_id);
    let read = Store::open_read_only(&store_path)?;
    assert_eq!(
        read.current_snapshot_id()?.as_deref(),
        Some(newer_snapshot_id.as_str())
    );
    let completed = read
        .completed_snapshot(imported.completed_snapshot_id().as_str())?
        .ok_or_else(|| anyhow::anyhow!("runtime completion evidence was not created"))?;
    assert_eq!(
        completed.parent_snapshot_id.as_deref(),
        Some(base_snapshot_id.as_str())
    );
    Ok(())
}

#[test]
fn deferred_runtime_import_recovers_promotion_idempotently_after_restart() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let store_path = temporary.path().join("graph.sqlite");
    std::fs::create_dir(&repository)?;
    seed_runtime_snapshot(&mut Store::open(&store_path)?, &repository)?;
    let service = service(
        &repository,
        &store_path,
        [DepgraphCapability::Read, DepgraphCapability::StoreWrite],
    );
    let prepared = service.prepare_runtime_import(
        &runtime_request(Some(runtime_trace()), None),
        &CancellationToken::new(),
    )?;
    let base_snapshot_id = prepared.base_snapshot_id().as_str().to_owned();
    let runtime_trace_digest = prepared.runtime_trace_digest().to_owned();
    let completion = match service.runtime_import_deferred_prepared(
        prepared,
        "op_service_recovery",
        &CancellationToken::new(),
    )? {
        DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
        DeferredRuntimeImportServiceOutcome::Finished(_) => {
            anyhow::bail!("new runtime import did not defer promotion")
        }
    };
    let import_id = completion.outcome().result().import_id.clone();
    let session_id = completion.outcome().result().session_id.clone();
    let status = completion.outcome().result().status.clone();
    let snapshot_id = completion
        .outcome()
        .completed_snapshot_id()
        .as_str()
        .to_owned();
    drop(completion);

    // A runner lost before committing its completion intent can claim the
    // operation again and attach to the deterministic staged import.
    let replay_prepared = service.prepare_runtime_import(
        &runtime_request(Some(runtime_trace()), None),
        &CancellationToken::new(),
    )?;
    let replay_completion = match service.runtime_import_deferred_prepared(
        replay_prepared,
        "op_service_recovery",
        &CancellationToken::new(),
    )? {
        DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
        DeferredRuntimeImportServiceOutcome::Finished(_) => {
            anyhow::bail!("staged runtime import replay was not recoverable")
        }
    };
    assert_eq!(replay_completion.outcome().result().import_id, import_id);
    assert_eq!(replay_completion.outcome().result().session_id, session_id);
    assert_eq!(
        replay_completion.outcome().completed_snapshot_id().as_str(),
        snapshot_id
    );
    drop(replay_completion);

    let recovery = DeferredRuntimeImportRecovery {
        operation_id: "op_service_recovery",
        base_snapshot_id: &base_snapshot_id,
        runtime_trace_digest: Some(&runtime_trace_digest),
        import_id: &import_id,
        session_id: &session_id,
        snapshot_id: &snapshot_id,
        status: &status,
        deduplicated: false,
    };
    service.recover_deferred_runtime_import_completion(&recovery)?;
    service.recover_deferred_runtime_import_completion(&recovery)?;
    assert_eq!(
        Store::open_read_only(&store_path)?
            .current_snapshot_id()?
            .as_deref(),
        Some(snapshot_id.as_str())
    );
    Ok(())
}

#[test]
fn snapshot_name_create_is_completed_only_immutable_and_writer_locked() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let store_path = temporary.path().join("graph.sqlite");
    std::fs::create_dir(&repository)?;
    let snapshot_id = seed_completed_snapshot(&mut Store::open(&store_path)?, &repository, "one")?;
    let service = service(
        &repository,
        &store_path,
        [DepgraphCapability::Read, DepgraphCapability::StoreWrite],
    );

    let named = service.snapshot_name_create(
        &SnapshotNameCreateRequest::new("baseline", SnapshotLocator::Current),
        &CancellationToken::new(),
    )?;
    assert_eq!(named.name(), "baseline");
    assert_eq!(named.snapshot().id(), snapshot_id);
    assert!(matches!(
        service.snapshot_name_create(
            &SnapshotNameCreateRequest::new("BASELINE", SnapshotLocator::Current),
            &CancellationToken::new(),
        ),
        Err(DepgraphServiceError::Conflict)
    ));
    assert_eq!(
        Store::open_read_only(&store_path)?
            .snapshot_id_for_name("baseline")?
            .as_deref(),
        Some(snapshot_id.as_str())
    );

    let missing = SnapshotLocator::parse(format!("snapshot:sha256:{}", "f".repeat(64)))?;
    assert!(matches!(
        service.snapshot_name_create(
            &SnapshotNameCreateRequest::new("missing", missing),
            &CancellationToken::new(),
        ),
        Err(DepgraphServiceError::NotFound)
    ));

    let _lock = acquire_store_writer_lock(&store_path)?;
    assert!(matches!(
        service.snapshot_name_create(
            &SnapshotNameCreateRequest::new("locked", SnapshotLocator::Current),
            &CancellationToken::new(),
        ),
        Err(DepgraphServiceError::StoreWriterConflict)
    ));
    Ok(())
}

#[tokio::test]
async fn safe_scan_preserves_source_tree_and_cancel_does_not_replace_current_snapshot() -> Result<()>
{
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let store_path = temporary.path().join("graph.sqlite");
    std::fs::create_dir(&repository)?;
    std::fs::write(repository.join("README.md"), "source remains immutable\n")?;
    let before_source = std::fs::read(repository.join("README.md"))?;
    let service = service(
        &repository,
        &store_path,
        [DepgraphCapability::Read, DepgraphCapability::StoreWrite],
    );

    let completed = service
        .scan_cancellable(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            CancellationToken::new(),
        )
        .await?;
    let snapshot_id = completed
        .completed_snapshot_id()
        .unwrap()
        .as_str()
        .to_owned();
    assert_eq!(completed.outcome().status, "completed");
    assert!(!completed.outcome().coverage.project_code_executed);
    assert_eq!(std::fs::read(repository.join("README.md"))?, before_source);

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(matches!(
        service
            .scan_cancellable(&ScanRequest::new(false, ScanCacheMode::Disabled), cancelled,)
            .await,
        Err(DepgraphServiceError::Cancelled)
    ));
    assert_eq!(
        Store::open_read_only(&store_path)?
            .current_snapshot_id()?
            .as_deref(),
        Some(snapshot_id.as_str())
    );
    assert_eq!(std::fs::read(repository.join("README.md"))?, before_source);
    Ok(())
}

#[tokio::test]
async fn cached_safe_scan_completes_and_reports_cold_then_warm_cache_events() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let store_path = temporary.path().join("graph.sqlite");
    std::fs::create_dir(&repository)?;
    std::fs::write(repository.join("README.md"), "cache fixture\n")?;
    let service = service(
        &repository,
        &store_path,
        [DepgraphCapability::Read, DepgraphCapability::StoreWrite],
    );

    let cold = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        service.scan_cancellable(
            &ScanRequest::new(false, ScanCacheMode::Enabled),
            CancellationToken::new(),
        ),
    )
    .await
    .expect("cold cached scan timed out")?;
    assert!(
        cold.outcome()
            .cache_events
            .iter()
            .any(|event| event.outcome == "miss")
    );

    let warm = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        service.scan_cancellable(
            &ScanRequest::new(false, ScanCacheMode::Enabled),
            CancellationToken::new(),
        ),
    )
    .await
    .expect("warm cached scan timed out")?;
    assert!(
        warm.outcome()
            .cache_events
            .iter()
            .any(|event| event.outcome == "hit")
    );
    Ok(())
}

#[tokio::test]
async fn completed_deferred_recovery_does_not_replace_a_newer_current_snapshot() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let store_path = temporary.path().join("graph.sqlite");
    std::fs::create_dir(&repository)?;
    std::fs::write(repository.join("one.rs"), "pub fn one() {}\n")?;
    let service = service(
        &repository,
        &store_path,
        [DepgraphCapability::Read, DepgraphCapability::StoreWrite],
    );

    let operation_id = "operation-newer-current";
    let result_digest = [7_u8; 32];
    let mut completion = match service
        .scan_deferred_cancellable_for_operation(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            operation_id,
            CancellationToken::new(),
        )
        .await?
    {
        DeferredScanServiceOutcome::Pending(completion) => completion,
        DeferredScanServiceOutcome::Finished(_) => anyhow::bail!("scan did not defer completion"),
    };
    let scan_id = completion.outcome().outcome().scan_id.clone();
    let completed_snapshot_id = completion
        .outcome()
        .completed_snapshot_id()
        .unwrap()
        .as_str()
        .to_owned();
    completion.bind_recovery_result_digest(&result_digest)?;
    completion.promote()?;

    std::fs::write(repository.join("two.rs"), "pub fn two() {}\n")?;
    let newer = service
        .scan_cancellable(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            CancellationToken::new(),
        )
        .await?;
    let newer_snapshot_id = newer.completed_snapshot_id().unwrap().as_str().to_owned();
    assert_ne!(newer_snapshot_id, completed_snapshot_id);

    service.recover_deferred_scan_completion(&DeferredScanRecovery {
        operation_id,
        scan_id: &scan_id,
        snapshot_id: &completed_snapshot_id,
        strict: false,
        cache_enabled: false,
        result_digest: &result_digest,
    })?;
    assert_eq!(
        Store::open_read_only(&store_path)?
            .current_snapshot_id()?
            .as_deref(),
        Some(newer_snapshot_id.as_str())
    );
    Ok(())
}
