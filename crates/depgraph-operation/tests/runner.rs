use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use depgraph_core::{
    CancellationToken, DepgraphCapability, DepgraphCapabilitySet, DepgraphService,
    DepgraphServiceConfig, DepgraphServiceLimits, GraphQueryFilter, SnapshotLocator,
    service::{
        ExportFileRequest, GraphExportFormat, GraphExportRequest, RepositoryOverwritePolicy,
        RepositoryRelativePath,
    },
};
use depgraph_mcp_tools::{AgentExportOutcome, LogicalRepositoryId, SnapshotId, SuccessEnvelope};
use depgraph_operation::{
    CanonicalJson, DispatchOutcome, EXECUTION_STATE_UNKNOWN_ERROR_JSON, ExecutionControl,
    JournalDigest, LeaseOwner, OperationDispatcher, OperationJournal, OperationKind,
    OperationManager, OperationOutcome, OperationRunner, OperationStatus, RunnerStartupConfig,
    RunnerWork, ScanOperationDispatcher, SubmitRequest, UNSUPPORTED_OPERATION_ERROR_JSON,
    UnsupportedOperationDispatcher,
};
use serde_json::json;

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn config(root: &Path) -> DepgraphServiceConfig {
    let repository = root.join("repository");
    std::fs::create_dir_all(&repository).unwrap();
    DepgraphServiceConfig::new(
        repository,
        root.join("graph.sqlite"),
        DepgraphCapabilitySet::try_new([
            DepgraphCapability::Read,
            DepgraphCapability::StoreWrite,
            DepgraphCapability::RepositoryWrite,
            DepgraphCapability::DaemonControl,
            DepgraphCapability::ProjectExec,
        ])
        .unwrap(),
        DepgraphServiceLimits::default(),
    )
    .unwrap()
}

fn repository(config: &DepgraphServiceConfig) -> LogicalRepositoryId {
    LogicalRepositoryId::parse(config.logical_repository_id()).unwrap()
}

#[derive(Clone)]
struct CountingDispatcher {
    calls: Arc<AtomicUsize>,
}

impl OperationDispatcher for CountingDispatcher {
    fn dispatch(
        &mut self,
        work: &RunnerWork,
        control: &mut ExecutionControl<'_>,
    ) -> DispatchOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(control.checkpoint().unwrap().may_continue());
        DispatchOutcome::Completed(
            CanonicalJson::new(json!({"kind": work.kind().as_str()})).unwrap(),
        )
    }
}

#[test]
fn safe_released_work_is_recovered_by_a_restarted_runner() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = repository(&config);
    let now = now_ms() - 1_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"safe": true}),
                b"safe-runner-recovery",
                now + 60_000,
            )
            .unwrap(),
            now,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &depgraph_operation::LeaseOwner::parse("crashed-runner").unwrap(),
            b"crashed-runner-token",
            now + 1,
            now + 1_000,
        )
        .unwrap();
    journal
        .release_lease(&repository, &operation_id, b"crashed-runner-token", now + 2)
        .unwrap();
    drop(journal);

    let calls = Arc::new(AtomicUsize::new(0));
    let startup = RunnerStartupConfig::new(config.clone()).unwrap();
    OperationRunner::new(
        startup,
        CountingDispatcher {
            calls: Arc::clone(&calls),
        },
    )
    .run_until_idle()
    .unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let journal = OperationJournal::open(&config).unwrap();
    assert_eq!(
        journal
            .get(&repository, &operation_id, now_ms())
            .unwrap()
            .status(),
        OperationStatus::Completed
    );
}

#[test]
fn project_exec_lease_loss_is_terminal_and_dispatch_count_stays_zero() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = repository(&config);
    let now = now_ms() - 1_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ResolveBuildSubmit,
                &json!({"unsafe": true}),
                b"unsafe-runner-recovery",
                now + 60_000,
            )
            .unwrap(),
            now,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &depgraph_operation::LeaseOwner::parse("lost-project-runner").unwrap(),
            b"lost-project-token",
            now + 1,
            now + 1_000,
        )
        .unwrap();
    journal
        .release_lease(&repository, &operation_id, b"lost-project-token", now + 2)
        .unwrap();
    drop(journal);

    let calls = Arc::new(AtomicUsize::new(0));
    OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        CountingDispatcher {
            calls: Arc::clone(&calls),
        },
    )
    .run_until_idle()
    .unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let journal = OperationJournal::open(&config).unwrap();
    match journal
        .result(&repository, &operation_id, now_ms())
        .unwrap()
    {
        OperationOutcome::Failed(error) => {
            assert_eq!(error.as_str(), EXECUTION_STATE_UNKNOWN_ERROR_JSON);
        }
        other => panic!("unexpected project-exec recovery outcome: {other:?}"),
    }
}

#[test]
fn production_dispatcher_fails_unwired_operations_with_a_closed_error() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = repository(&config);
    let now = now_ms() - 1_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"must_not_be_fabricated": true}),
                b"unsupported-production-dispatch",
                now + 60_000,
            )
            .unwrap(),
            now,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        UnsupportedOperationDispatcher,
    )
    .run_until_idle()
    .unwrap();

    let journal = OperationJournal::open(&config).unwrap();
    match journal
        .result(&repository, &operation_id, now_ms())
        .unwrap()
    {
        OperationOutcome::Failed(error) => {
            assert_eq!(error.as_str(), UNSUPPORTED_OPERATION_ERROR_JSON);
        }
        other => panic!("unwired operation fabricated an outcome: {other:?}"),
    }
}

#[test]
fn production_scan_dispatcher_executes_safe_scan_and_persists_closed_terminal_output() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = repository(&config);
    let now = now_ms() - 1_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"real-production-scan",
                now + 60_000,
            )
            .unwrap(),
            now,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();

    let journal = OperationJournal::open(&config).unwrap();
    match journal
        .result(&repository, &operation_id, now_ms())
        .unwrap()
    {
        OperationOutcome::Completed(output) => {
            let value: serde_json::Value = serde_json::from_str(output.as_str()).unwrap();
            assert_eq!(value["result"]["status"], "completed");
            assert_eq!(value["result"]["project_code_executed"], false);
            assert!(
                value["snapshot_id"]
                    .as_str()
                    .unwrap()
                    .starts_with("snapshot:sha256:")
            );
            assert!(value.get("raw_journal_payload").is_none());
            assert_eq!(
                DepgraphService::new(config)
                    .start_snapshot_request("current")
                    .unwrap()
                    .snapshot_id()
                    .as_str(),
                value["snapshot_id"].as_str().unwrap()
            );
        }
        other => panic!("unexpected scan outcome: {other:?}"),
    }
}

#[test]
fn production_dispatcher_completes_idempotent_daemon_stop_with_closed_outcome() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = repository(&config);
    let status_path = root.path().join("graph.sqlite.daemon-status.json");
    std::fs::write(
        status_path,
        serde_json::to_vec(&json!({
            "schema_version": "daemon-status-v1",
            "root": config.canonical_root(),
            "phase": "stopped",
            "started_at": "2026-08-11T00:00:00Z",
            "stopped_at": "2026-08-11T00:00:01Z",
            "debounce_milliseconds": 100,
            "pending_change_count": 0,
            "active_attempt_id": null,
            "last_completed_attempt": null,
            "last_failed_attempt": null,
            "last_cancelled_attempt": null,
            "last_watcher_error": null,
            "recovered_attempts": {"scan_attempt_ids": [], "build_attempt_ids": []}
        }))
        .unwrap(),
    )
    .unwrap();
    let now = now_ms() - 1_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::DaemonStop,
                &json!({}),
                b"daemon-stop-already-stopped",
                now + 60_000,
            )
            .unwrap(),
            now,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();

    match OperationJournal::open(&config)
        .unwrap()
        .result(&repository, &operation_id, now_ms())
        .unwrap()
    {
        OperationOutcome::Completed(output) => {
            let value: serde_json::Value = serde_json::from_str(output.as_str()).unwrap();
            assert_eq!(value["result"], json!({"action":"stop", "phase":"stopped"}));
            assert!(value["snapshot_id"].is_null());
            assert!(
                !value
                    .to_string()
                    .contains(config.canonical_root().to_str().unwrap())
            );
        }
        other => panic!("unexpected daemon stop outcome: {other:?}"),
    }
}

#[test]
fn production_dispatcher_launches_one_verified_daemon_and_then_stops_it() {
    struct StopMarker {
        path: std::path::PathBuf,
        armed: bool,
    }
    impl Drop for StopMarker {
        fn drop(&mut self) {
            if self.armed {
                let _ = std::fs::write(&self.path, b"stop\n");
            }
        }
    }
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let mut stop_marker = StopMarker {
        path: std::path::PathBuf::from(format!("{}.daemon-stop", config.store_path().display())),
        armed: false,
    };
    let repository = repository(&config);
    let now = now_ms() - 1_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let start_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::DaemonStartSubmit,
                &json!({"strict":false}),
                b"daemon-start-real",
                now + 60_000,
            )
            .unwrap(),
            now,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    stop_marker.armed = true;

    let mut journal = OperationJournal::open(&config).unwrap();
    match journal.result(&repository, &start_id, now_ms()).unwrap() {
        OperationOutcome::Completed(output) => {
            let value: serde_json::Value = serde_json::from_str(output.as_str()).unwrap();
            assert_eq!(
                value["result"],
                json!({"action":"start", "phase":"running"})
            );
        }
        other => panic!("unexpected daemon start outcome: {other:?}"),
    }
    let stop_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::DaemonStop,
                &json!({}),
                b"daemon-stop-real",
                now_ms() + 60_000,
            )
            .unwrap(),
            now_ms(),
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);
    OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    assert!(matches!(
        OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &stop_id, now_ms())
            .unwrap(),
        OperationOutcome::Completed(_)
    ));
    stop_marker.armed = false;
}

#[test]
fn production_dispatcher_completes_durable_export_file_with_closed_digest_outcome() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = repository(&config);
    let now = now_ms() - 2_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"export-fixture-scan",
                now + 60_000,
            )
            .unwrap(),
            now,
        )
        .unwrap();
    drop(journal);
    OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    let snapshot_id = DepgraphService::new(config.clone())
        .start_snapshot_request("current")
        .unwrap()
        .snapshot_id()
        .as_str()
        .to_owned();
    std::fs::create_dir(config.canonical_root().join("artifacts")).unwrap();
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ExportFile,
                &json!({
                    "format": "json",
                    "max_edges": 100_000,
                    "max_nodes": 50_000,
                    "output_path": "artifacts/graph.json",
                    "overwrite": false,
                    "snapshot_id": snapshot_id,
                }),
                b"durable-export-file",
                now + 60_000,
            )
            .unwrap(),
            now + 1_000,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();

    let content = std::fs::read(config.canonical_root().join("artifacts/graph.json")).unwrap();
    let journal = OperationJournal::open(&config).unwrap();
    match journal
        .result(&repository, &operation_id, now_ms())
        .unwrap()
    {
        OperationOutcome::Completed(output) => {
            let value: serde_json::Value = serde_json::from_str(output.as_str()).unwrap();
            assert_eq!(value["snapshot_id"], snapshot_id);
            assert_eq!(value["result"]["output_path"], "artifacts/graph.json");
            assert_eq!(value["result"]["format"], "json");
            assert_eq!(value["result"]["output_bytes"], content.len() as u64);
            assert_eq!(
                value["result"]["content_sha256"],
                JournalDigest::sha256(&content).to_hex()
            );
            assert!(value["result"].get("content").is_none());
        }
        other => panic!("unexpected export outcome: {other:?}"),
    }
    assert_eq!(
        std::fs::read_dir(config.canonical_root().join("artifacts"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn restarted_runner_finalizes_a_committed_overwrite_against_its_bound_destination() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = repository(&config);
    let now = now_ms() - 2_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"overwrite-recovery-fixture-scan",
                now + 60_000,
            )
            .unwrap(),
            now,
        )
        .unwrap();
    drop(journal);
    OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    let service = DepgraphService::new(config.clone());
    let snapshot_id = service
        .start_snapshot_request("current")
        .unwrap()
        .snapshot_id()
        .as_str()
        .to_owned();
    let artifacts = config.canonical_root().join("artifacts");
    std::fs::create_dir(&artifacts).unwrap();
    let output = artifacts.join("graph.json");
    std::fs::write(&output, b"original-destination").unwrap();
    let output_path = RepositoryRelativePath::parse("artifacts/graph.json").unwrap();
    let destination_precondition = service
        .repository_output_precondition(&output_path, &CancellationToken::new())
        .unwrap();
    let normalized_input = json!({
        "destination_precondition": destination_precondition,
        "format": "json",
        "max_edges": 100_000,
        "max_nodes": 50_000,
        "output_path": output_path.as_str(),
        "overwrite": true,
        "snapshot_id": snapshot_id,
    });
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ExportFile,
                &normalized_input,
                b"committed-overwrite-recovery",
                now + 60_000,
            )
            .unwrap(),
            now + 1_000,
        )
        .unwrap()
        .operation_id()
        .clone();
    let lease = b"committed-overwrite-recovery-lease";
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("overwrite-recovery-runner").unwrap(),
            lease,
            now + 1_001,
            now + 30_000,
        )
        .unwrap();
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id).unwrap(),
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            50_000,
            100_000,
        )
        .unwrap(),
        output_path,
        RepositoryOverwritePolicy::Overwrite,
    )
    .with_destination_precondition(destination_precondition);
    let completion = service
        .export_file_deferred_for_operation(
            &request,
            operation_id.as_str(),
            &CancellationToken::new(),
        )
        .unwrap();
    let expected = completion.result().clone();
    let result = CanonicalJson::new(
        serde_json::to_value(SuccessEnvelope::new(
            repository.clone(),
            Some(SnapshotId::parse(&snapshot_id).unwrap()),
            AgentExportOutcome::try_from(completion.result()).unwrap(),
        ))
        .unwrap(),
    )
    .unwrap();
    journal
        .commit_completion_intent(&repository, &operation_id, lease, result, now + 1_002)
        .unwrap();
    drop(completion);
    drop(journal);

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();

    assert_eq!(report.completed(), 1);
    let content = std::fs::read(&output).unwrap();
    assert_eq!(content.len() as u64, expected.output_bytes());
    assert_eq!(
        JournalDigest::sha256(&content).to_hex(),
        expected.content_sha256()
    );
    assert!(matches!(
        OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &operation_id, now_ms()),
        Ok(OperationOutcome::Completed(_))
    ));
    assert_eq!(std::fs::read_dir(&artifacts).unwrap().count(), 1);
}

#[test]
fn expired_export_cleans_only_its_owned_stage_without_publishing() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let now = now_ms();
    let mut journal = OperationJournal::open(&config).unwrap();
    journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"expired-export-fixture-scan",
                now + 60_000,
            )
            .unwrap(),
            now,
        )
        .unwrap();
    drop(journal);
    OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    let service = DepgraphService::new(config.clone());
    let snapshot_id = service
        .start_snapshot_request("current")
        .unwrap()
        .snapshot_id()
        .as_str()
        .to_owned();
    let artifacts = config.canonical_root().join("artifacts");
    std::fs::create_dir(&artifacts).unwrap();
    let normalized_input = json!({
        "format": "json",
        "max_edges": 100_000,
        "max_nodes": 50_000,
        "output_path": "artifacts/expired.json",
        "overwrite": false,
        "snapshot_id": snapshot_id,
    });
    let submitted_at = now - 2_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ExportFile,
                &normalized_input,
                b"expired-export-cleanup",
                now - 1_000,
            )
            .unwrap(),
            submitted_at,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id).unwrap(),
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            50_000,
            100_000,
        )
        .unwrap(),
        RepositoryRelativePath::parse("artifacts/expired.json").unwrap(),
        RepositoryOverwritePolicy::NoReplace,
    );
    let _staged = service
        .export_file_deferred_for_operation(
            &request,
            operation_id.as_str(),
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(std::fs::read_dir(&artifacts).unwrap().count(), 1);

    OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();

    assert!(!artifacts.join("expired.json").exists());
    assert_eq!(std::fs::read_dir(&artifacts).unwrap().count(), 0);
}

#[test]
fn cancelled_export_cleans_only_its_owned_stage_without_publishing() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = repository(&config);
    let now = now_ms();
    let mut journal = OperationJournal::open(&config).unwrap();
    journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"cancelled-export-fixture-scan",
                now + 60_000,
            )
            .unwrap(),
            now,
        )
        .unwrap();
    drop(journal);
    OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    let service = DepgraphService::new(config.clone());
    let snapshot_id = service
        .start_snapshot_request("current")
        .unwrap()
        .snapshot_id()
        .as_str()
        .to_owned();
    let artifacts = config.canonical_root().join("artifacts");
    std::fs::create_dir(&artifacts).unwrap();
    let normalized_input = json!({
        "format": "json",
        "max_edges": 100_000,
        "max_nodes": 50_000,
        "output_path": "artifacts/cancelled.json",
        "overwrite": false,
        "snapshot_id": snapshot_id,
    });
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ExportFile,
                &normalized_input,
                b"cancelled-export-cleanup",
                now + 60_000,
            )
            .unwrap(),
            now + 1,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id).unwrap(),
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            50_000,
            100_000,
        )
        .unwrap(),
        RepositoryRelativePath::parse("artifacts/cancelled.json").unwrap(),
        RepositoryOverwritePolicy::NoReplace,
    );
    let _staged = service
        .export_file_deferred_for_operation(
            &request,
            operation_id.as_str(),
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(std::fs::read_dir(&artifacts).unwrap().count(), 1);
    OperationManager::open(&config)
        .unwrap()
        .cancel(&operation_id, now + 2)
        .unwrap();

    OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();

    assert!(!artifacts.join("cancelled.json").exists());
    assert_eq!(std::fs::read_dir(&artifacts).unwrap().count(), 0);
    assert!(matches!(
        OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &operation_id, now_ms()),
        Ok(OperationOutcome::Cancelled)
    ));
}

#[test]
fn cancelled_export_preserves_foreign_stage_and_still_terminalizes() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = repository(&config);
    let now = now_ms();
    let mut journal = OperationJournal::open(&config).unwrap();
    journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"foreign-export-fixture-scan",
                now + 60_000,
            )
            .unwrap(),
            now,
        )
        .unwrap();
    drop(journal);
    OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    let service = DepgraphService::new(config.clone());
    let snapshot_id = service
        .start_snapshot_request("current")
        .unwrap()
        .snapshot_id()
        .as_str()
        .to_owned();
    let artifacts = config.canonical_root().join("artifacts");
    std::fs::create_dir(&artifacts).unwrap();
    let normalized_input = json!({
        "format": "json",
        "max_edges": 100_000,
        "max_nodes": 50_000,
        "output_path": "artifacts/cancelled.json",
        "overwrite": false,
        "snapshot_id": snapshot_id,
    });
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ExportFile,
                &normalized_input,
                b"foreign-export-cleanup",
                now + 60_000,
            )
            .unwrap(),
            now + 1,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id).unwrap(),
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            50_000,
            100_000,
        )
        .unwrap(),
        RepositoryRelativePath::parse("artifacts/cancelled.json").unwrap(),
        RepositoryOverwritePolicy::NoReplace,
    );
    let _staged = service
        .export_file_deferred_for_operation(
            &request,
            operation_id.as_str(),
            &CancellationToken::new(),
        )
        .unwrap();
    let stage = std::fs::read_dir(&artifacts)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::write(&stage, b"foreign-canary").unwrap();
    OperationManager::open(&config)
        .unwrap()
        .cancel(&operation_id, now + 2)
        .unwrap();

    OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();

    assert_eq!(std::fs::read(&stage).unwrap(), b"foreign-canary");
    assert!(!artifacts.join("cancelled.json").exists());
    assert!(matches!(
        OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &operation_id, now_ms()),
        Ok(OperationOutcome::Cancelled)
    ));
}
