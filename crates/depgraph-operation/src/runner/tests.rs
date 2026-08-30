use std::{
    cell::Cell,
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

use depgraph_core::{
    DepgraphCapability, DepgraphCapabilitySet, DepgraphServiceConfig, DepgraphServiceLimits,
};
use serde_json::json;

use super::*;
use crate::{
    CapabilitySet, OperationManager, OperationOutcome, SubmitRequest, TERMINAL_RETENTION_MS,
    try_acquire_operation_runner_exclusion,
};

const NOW: i64 = 1_800_000_000_000;

fn config(root: &Path) -> DepgraphServiceConfig {
    let repository = root.join("repository");
    std::fs::create_dir_all(&repository).unwrap();
    DepgraphServiceConfig::new(
        repository,
        root.join("graph.sqlite"),
        DepgraphCapabilitySet::try_new([DepgraphCapability::Read, DepgraphCapability::StoreWrite])
            .unwrap(),
        DepgraphServiceLimits::default(),
    )
    .unwrap()
}

#[test]
fn runner_defers_the_first_journal_open_until_after_exclusion() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let journal_path = operation_journal_path(&config);
    std::fs::write(journal_path.as_path(), b"not a sqlite journal").unwrap();
    let cleanup = try_acquire_operation_runner_exclusion(&journal_path)
        .unwrap()
        .unwrap();

    let startup = RunnerStartupConfig::new(config.clone()).unwrap();
    let report = OperationRunner::new(startup, ScanOperationDispatcher::new(config.clone()))
        .run_until_idle()
        .unwrap();
    assert_eq!(report.completed(), 0);
    assert_eq!(report.failed(), 0);
    assert_eq!(report.cancelled(), 0);
    assert_eq!(report.lease_lost(), 0);

    drop(cleanup);
    let error = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config),
    )
    .run_until_idle()
    .unwrap_err();
    assert!(matches!(error, RunnerError::Journal(_)));
}

fn daemon_config(root: &Path) -> DepgraphServiceConfig {
    let repository = root.join("repository");
    std::fs::create_dir_all(&repository).unwrap();
    DepgraphServiceConfig::new(
        repository,
        root.join("graph.sqlite"),
        DepgraphCapabilitySet::try_new([
            DepgraphCapability::Read,
            DepgraphCapability::StoreWrite,
            DepgraphCapability::DaemonControl,
        ])
        .unwrap(),
        DepgraphServiceLimits::default(),
    )
    .unwrap()
}

fn write_stale_running_daemon_status(config: &DepgraphServiceConfig) {
    let mut status_path = config.store_path().as_os_str().to_os_string();
    status_path.push(".daemon-status.json");
    std::fs::write(
        PathBuf::from(status_path),
        serde_json::to_vec(&json!({
            "schema_version": depgraph_core::DAEMON_STATUS_SCHEMA_VERSION,
            "root": config.canonical_root(),
            "phase": "idle",
            "started_at": "2026-08-11T00:00:00.000Z",
            "stopped_at": null,
            "debounce_milliseconds": 250,
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
}

fn daemon_start_result(config: &DepgraphServiceConfig) -> CanonicalJson {
    let repository_id = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    CanonicalJson::new(
        serde_json::to_value(SuccessEnvelope::new(
            repository_id,
            None,
            AgentDaemonControlOutcome::running(),
        ))
        .unwrap(),
    )
    .unwrap()
}

fn daemon_stop_result(config: &DepgraphServiceConfig) -> CanonicalJson {
    let repository_id = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    CanonicalJson::new(
        serde_json::to_value(SuccessEnvelope::new(
            repository_id,
            None,
            AgentDaemonControlOutcome::stopped(),
        ))
        .unwrap(),
    )
    .unwrap()
}

#[cfg(unix)]
#[test]
fn issue_315_daemon_start_fails_closed_when_child_exits_before_publication() {
    let root = tempfile::tempdir().unwrap();
    let config = daemon_config(root.path());
    let launcher =
        DaemonExecutableLauncher::for_test_executable(Path::new("/usr/bin/false")).unwrap();
    let started = std::time::Instant::now();

    assert!(matches!(
        promote_daemon_start(&config, false, Some(launcher)),
        Err(RunnerError::Service(DepgraphServiceError::Internal))
    ));
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "early daemon exit took {elapsed:?} and approached the 30-second publication timeout"
    );
}

#[test]
fn cleanup_guard_is_unlocked_before_acknowledgement_without_masking_terminal_errors() {
    struct ReacquiringCleanupDispatcher {
        store_path: PathBuf,
        acknowledgements: usize,
    }

    impl OperationDispatcher for ReacquiringCleanupDispatcher {
        fn dispatch(
            &mut self,
            _work: &RunnerWork,
            _control: &mut ExecutionControl<'_>,
        ) -> DispatchOutcome {
            unreachable!("terminal cleanup test does not dispatch work")
        }

        fn finalize_cleanup_acknowledgement(
            &mut self,
            _kind: OperationKind,
            _operation_id: &OperationId,
        ) -> Result<(), RunnerError> {
            let guard = depgraph_core::acquire_store_writer_lock(&self.store_path)
                .map_err(|_| RunnerError::Service(DepgraphServiceError::StoreWriterConflict))?;
            self.acknowledgements += 1;
            drop(guard);
            Ok(())
        }
    }

    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let mut runner = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ReacquiringCleanupDispatcher {
            store_path: config.store_path().to_path_buf(),
            acknowledgements: 0,
        },
    );
    let work = RunnerWork {
        operation_id: OperationId::parse(format!("op_{}", "a".repeat(32))).unwrap(),
        kind: OperationKind::ScanSubmit,
        input: CanonicalInput::new(&json!({})).unwrap(),
        execution_deadline_ms: NOW + 10_000,
    };
    let guard = depgraph_core::acquire_store_writer_lock(config.store_path()).unwrap();
    runner
        .terminalize_after_cleanup(&work, Some(guard), || Ok::<_, RunnerError>(()))
        .unwrap();
    assert_eq!(runner.dispatcher.acknowledgements, 1);

    let guard = depgraph_core::acquire_store_writer_lock(config.store_path()).unwrap();
    assert!(matches!(
        runner.terminalize_after_cleanup(&work, Some(guard), || {
            Err::<(), _>(RunnerError::ClockUnavailable)
        }),
        Err(RunnerError::ClockUnavailable)
    ));
    assert_eq!(runner.dispatcher.acknowledgements, 1);
}

fn counting_daemon_dispatcher(
    config: DepgraphServiceConfig,
    expected_strict: bool,
    launches: Arc<AtomicUsize>,
) -> ScanOperationDispatcher {
    let expected_root = config.canonical_root().to_path_buf();
    let expected_store = config.store_path().to_path_buf();
    ScanOperationDispatcher::new(config).with_daemon_start_promoter_for_test(Arc::new(
        move |observed, strict| {
            assert_eq!(observed.canonical_root(), expected_root);
            assert_eq!(observed.store_path(), expected_store);
            assert_eq!(strict, expected_strict);
            launches.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    ))
}

#[test]
fn repository_file_not_found_is_distinct_from_snapshot_not_found() {
    let root = tempfile::tempdir().unwrap();
    let dispatcher = ScanOperationDispatcher::new(config(root.path()));
    let error_code = |outcome| match outcome {
        DispatchOutcome::Failed(error) => error.value()["error"]["code"].clone(),
        _ => panic!("service error must produce a terminal failure"),
    };

    assert_eq!(
        error_code(
            dispatcher.failed_service(&DepgraphServiceError::RepositoryFile {
                reason: depgraph_core::service::RepositoryFileError::NotFound,
            })
        ),
        json!("NOT_FOUND")
    );
    assert_eq!(
        error_code(dispatcher.failed_service(&DepgraphServiceError::NotFound)),
        json!("SNAPSHOT_NOT_FOUND")
    );
}

#[test]
fn overwrite_export_input_requires_a_durable_destination_precondition() {
    let root = tempfile::tempdir().unwrap();
    let dispatcher = ScanOperationDispatcher::new(config(root.path()));
    let input = ExportFileInput {
        output_path: "artifacts/graph.json".to_owned(),
        overwrite: true,
        format: GraphExportFormat::Json,
        snapshot_id: SnapshotId::parse(
            "snapshot:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap(),
        selector: None,
        max_nodes: 100,
        max_edges: 100,
        destination_precondition: None,
    };

    let error = dispatcher.export_file_request(&input).unwrap_err();

    assert_eq!(
        error.category(),
        depgraph_core::service::DepgraphServiceErrorCategory::Input
    );
}

fn runtime_import_fixture(
    config: &DepgraphServiceConfig,
    source_session_id: &str,
) -> (String, String, serde_json::Value) {
    let coverage = json!({
        "profiles":1,
        "files_discovered":0,
        "files_analyzed":0,
        "files_skipped":0,
        "dependency_sites":0,
        "resolved":0,
        "candidates":0,
        "external":0,
        "unresolved":0,
        "unsupported_syntax":0,
        "project_code_executed":false,
        "completeness":["syntax-complete"],
        "reasons":[]
    });
    let common = |event: &str, seq: u64| {
        json!({
            "event":event,
            "protocol_version":"1.0",
            "scan_id":"runtime-runner-base",
            "adapter":"fixture",
            "adapter_version":"1.0",
            "seq":seq
        })
    };
    let mut store = depgraph_core::open_store(config.store_path()).unwrap();
    store
        .start_scan_with_revision(
            "runtime-runner-base",
            config.canonical_root(),
            false,
            Some("runtime-runner-revision"),
        )
        .unwrap();
    let mut started = common("scan_started", 1);
    started["root"] = json!(config.canonical_root());
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    store.ingest_event(&started).unwrap();
    let mut profile = common("profile_declared", 2);
    profile["profile"] = json!({
        "id":"profile:runtime-runner",
        "language":"runtime-fixture",
        "features":[],
        "environment":{},
        "properties":{}
    });
    store.ingest_event(&profile).unwrap();
    for (seq, (id, kind, locator, path)) in [
        (
            "workspace:runtime-runner",
            "workspace",
            "repo://runtime-runner",
            "workspace",
        ),
        (
            "file:runtime-source",
            "file",
            "repo://runtime-source.js",
            "runtime-source.js",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut node = common("node_upsert", seq as u64 + 3);
        node["node"] = json!({
            "id":id,
            "kind":kind,
            "locator":locator,
            "display_name":id,
            "properties":{
                "path":path,
                "repository_identity":if kind == "workspace" {
                    Some("workspace:runtime-runner")
                } else {
                    None
                }
            }
        });
        store.ingest_event(&node).unwrap();
    }
    let mut profile_completed = common("profile_completed", 5);
    profile_completed["profile_id"] = json!("profile:runtime-runner");
    profile_completed["coverage"] = coverage.clone();
    store.ingest_event(&profile_completed).unwrap();
    let mut completed = common("scan_completed", 6);
    completed["coverage"] = coverage;
    store.ingest_event(&completed).unwrap();
    store
        .finish_scan("runtime-runner-base", "completed", None, true)
        .unwrap();
    drop(store);

    let service = DepgraphService::new(config.clone());
    let store = depgraph_core::open_store_read_only(config.store_path()).unwrap();
    let base_snapshot_id = store.current_snapshot_id().unwrap().unwrap();
    let snapshot = store.load_completed_snapshot(&base_snapshot_id).unwrap();
    let workspace = snapshot
        .nodes
        .iter()
        .find(|node| node.kind == "workspace")
        .expect("safe scan creates the workspace node");
    let repository_identity = workspace
        .properties
        .get("repository_identity")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(workspace.id.as_str());
    let mut repository = json!({"identity": repository_identity});
    if let Some(revision) = snapshot.scan.source_revision.as_deref() {
        repository["revision"] = json!(revision);
    }
    let trace = json!({
        "schema_version":"1.0",
        "repository":repository,
        "session":{
            "id":source_session_id,
            "started_at":"2026-08-08T00:00:00Z",
            "ended_at":"2026-08-08T00:00:01Z",
            "profile":{"language":"runtime-fixture","features":[]},
            "environment":{"name":"test"},
            "redaction":{"redacted_value_count":0}
        },
        "events":[{
            "sequence":1,
            "timestamp":"2026-08-08T00:00:00Z",
            "dependency_kind":"imports",
            "source":{"kind":"node","node_id":workspace.id},
            "target":{"kind":"external","namespace":"fixture","name":"dependency"},
            "count":1
        }]
    })
    .to_string();
    let request = RuntimeValidateRequest {
        trace: Some(trace.clone()),
        trace_file: None,
        snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
            base_snapshot_id.clone(),
        )),
    };
    let durable_input = service
        .prepare_runtime_import(&request, &CancellationToken::new())
        .unwrap()
        .durable_input();
    (base_snapshot_id, trace, durable_input)
}

fn legacy_runtime_import_input(mut durable_input: serde_json::Value) -> serde_json::Value {
    let input = durable_input
        .as_object_mut()
        .expect("runtime durable input is an object");
    assert!(input.remove("session_id").is_some());
    assert!(input.remove("runtime_trace_digest").is_some());
    durable_input
}

fn cancellable_capabilities() -> CapabilitySet {
    CapabilitySet::new([
        depgraph_mcp_tools::AgentCapability::Read,
        depgraph_mcp_tools::AgentCapability::StoreWrite,
    ])
    .unwrap()
}

fn downgrade_store_to_v15(config: &DepgraphServiceConfig) -> Vec<u8> {
    let connection = rusqlite::Connection::open(config.store_path()).unwrap();
    connection
        .execute_batch(
            "PRAGMA wal_checkpoint(TRUNCATE);
                 DROP TABLE scan_operation_staging;
                 DROP TABLE runtime_import_operation_owners;
                 PRAGMA user_version=15;
                 PRAGMA journal_mode=DELETE;",
        )
        .unwrap();
    drop(connection);
    std::fs::read(config.store_path()).unwrap()
}

#[test]
fn cooperative_checkpoint_observes_without_owning_lease_renewal() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"lease": "renew"}),
                b"checkpoint-renewal",
                NOW + 1_000,
            )
            .unwrap(),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("renewing-runner").unwrap(),
            b"renewing-token",
            NOW + 1,
            NOW + 100,
        )
        .unwrap();
    let clock = Cell::new(NOW + 70);
    let now = || Ok(clock.get());
    {
        let mut control = ExecutionControl {
            journal: &mut journal,
            repository_id: &repository,
            operation_id: &operation_id,
            lease_token: b"renewing-token",
            execution_deadline_ms: NOW + 1_000,
            cancellation: &CancellationToken::new(),
            now: &now,
        };

        assert_eq!(control.checkpoint().unwrap(), ExecutionCheckpoint::Continue);
    }
    let observed = journal.get(&repository, &operation_id, NOW + 71).unwrap();
    assert_eq!(observed.lease().unwrap().expires_at_ms(), NOW + 100);
}

#[test]
fn cooperative_checkpoint_observes_cancel_and_deadline() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"cooperative": true}),
                b"checkpoint-cancel-deadline",
                NOW + 100,
            )
            .unwrap(),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("cooperative-runner").unwrap(),
            b"cooperative-token",
            NOW + 1,
            NOW + 90,
        )
        .unwrap();
    journal
        .cancel(
            &repository,
            &operation_id,
            &CapabilitySet::new([
                depgraph_mcp_tools::AgentCapability::Read,
                depgraph_mcp_tools::AgentCapability::StoreWrite,
            ])
            .unwrap(),
            NOW + 2,
        )
        .unwrap();
    let clock = Cell::new(NOW + 3);
    let now = || Ok(clock.get());
    let mut control = ExecutionControl {
        journal: &mut journal,
        repository_id: &repository,
        operation_id: &operation_id,
        lease_token: b"cooperative-token",
        execution_deadline_ms: NOW + 100,
        cancellation: &CancellationToken::new(),
        now: &now,
    };

    assert_eq!(
        control.checkpoint().unwrap(),
        ExecutionCheckpoint::CancellationRequested
    );
    clock.set(NOW + 100);
    assert_eq!(
        control.checkpoint().unwrap(),
        ExecutionCheckpoint::DeadlineExceeded
    );
}

#[test]
fn issue_315_restarted_runner_recovers_daemon_start_completion_intent_once() {
    let root = tempfile::tempdir().unwrap();
    let config = daemon_config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 60_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::DaemonStartSubmit,
                &json!({"strict": true}),
                b"issue-315-daemon-completion-recovery",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    let crashed_lease = b"issue-315-crashed-daemon-lease";
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("issue-315-crashed-daemon-owner").unwrap(),
            crashed_lease,
            submitted_at_ms + 1,
            deadline_ms,
        )
        .unwrap();
    let expected_result = daemon_start_result(&config);
    assert_eq!(
        journal
            .commit_completion_intent(
                &repository,
                &operation_id,
                crashed_lease,
                expected_result.clone(),
                submitted_at_ms + 2,
            )
            .unwrap(),
        CompletionDecision::Committed
    );
    drop(journal);
    write_stale_running_daemon_status(&config);

    let launches = Arc::new(AtomicUsize::new(0));
    let recovered = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        counting_daemon_dispatcher(config.clone(), true, Arc::clone(&launches)),
    )
    .run_until_idle()
    .unwrap();

    assert_eq!(recovered.claimed(), 0);
    assert_eq!(recovered.completed(), 1);
    assert_eq!(launches.load(Ordering::SeqCst), 1);
    let journal = OperationJournal::open(&config).unwrap();
    assert_eq!(
        journal
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Completed(expected_result)
    );
    assert!(
        journal
            .next_completion_intent(&repository, system_now_ms().unwrap())
            .unwrap()
            .is_none()
    );
    drop(journal);

    let settled_replay = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        counting_daemon_dispatcher(config, true, Arc::clone(&launches)),
    )
    .run_until_idle()
    .unwrap();
    assert_eq!(settled_replay, RunnerReport::default());
    assert_eq!(launches.load(Ordering::SeqCst), 1);
}

#[test]
fn issue_315_restarted_runner_repairs_and_finalizes_daemon_stop_intent_once() {
    let root = tempfile::tempdir().unwrap();
    let config = daemon_config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 60_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::DaemonStop,
                &json!({}),
                b"issue-315-daemon-stop-completion-recovery",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    let crashed_lease = b"issue-315-crashed-daemon-stop-lease";
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("issue-315-crashed-daemon-stop-owner").unwrap(),
            crashed_lease,
            submitted_at_ms + 1,
            deadline_ms,
        )
        .unwrap();
    let expected_result = daemon_stop_result(&config);
    assert_eq!(
        journal
            .commit_completion_intent(
                &repository,
                &operation_id,
                crashed_lease,
                expected_result.clone(),
                submitted_at_ms + 2,
            )
            .unwrap(),
        CompletionDecision::Committed
    );
    drop(journal);
    write_stale_running_daemon_status(&config);
    let mut stop_path = config.store_path().as_os_str().to_os_string();
    stop_path.push(".daemon-stop");
    std::fs::write(PathBuf::from(&stop_path), b"stop\n").unwrap();

    let launches = Arc::new(AtomicUsize::new(0));
    let recovered = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        counting_daemon_dispatcher(config.clone(), false, Arc::clone(&launches)),
    )
    .run_until_idle()
    .unwrap();

    assert_eq!(recovered.claimed(), 0);
    assert_eq!(recovered.completed(), 1);
    assert_eq!(launches.load(Ordering::SeqCst), 0);
    let journal = OperationJournal::open(&config).unwrap();
    assert_eq!(
        journal
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Completed(expected_result)
    );
    assert!(
        journal
            .next_completion_intent(&repository, system_now_ms().unwrap())
            .unwrap()
            .is_none()
    );
    drop(journal);
    assert!(!PathBuf::from(stop_path).exists());
    let mut status_path = config.store_path().as_os_str().to_os_string();
    status_path.push(".daemon-status.json");
    let status: serde_json::Value =
        serde_json::from_slice(&std::fs::read(PathBuf::from(status_path)).unwrap()).unwrap();
    assert_eq!(status["phase"], "stopped");

    let settled_replay = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        counting_daemon_dispatcher(config, false, Arc::clone(&launches)),
    )
    .run_until_idle()
    .unwrap();
    assert_eq!(settled_replay, RunnerReport::default());
    assert_eq!(launches.load(Ordering::SeqCst), 0);
}

#[test]
fn issue_315_daemon_stop_submission_repairs_stale_unlocked_status() {
    let root = tempfile::tempdir().unwrap();
    let config = daemon_config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let submitted_at_ms = system_now_ms().unwrap();
    let mut manager = OperationManager::open(&config).unwrap();
    let operation_id = manager
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::DaemonStop,
                &json!({}),
                b"issue-315-stale-daemon-stop-submission",
                submitted_at_ms + 60_000,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(manager);
    write_stale_running_daemon_status(&config);

    let launches = Arc::new(AtomicUsize::new(0));
    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        counting_daemon_dispatcher(config.clone(), false, Arc::clone(&launches)),
    )
    .run_until_idle()
    .unwrap();

    assert_eq!(report.completed(), 1);
    assert_eq!(report.failed(), 0);
    assert_eq!(launches.load(Ordering::SeqCst), 0);
    assert!(matches!(
        OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Completed(_)
    ));
    let status: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.path().join("graph.sqlite.daemon-status.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(status["phase"], "stopped");
}

#[test]
fn issue_315_daemon_cancellation_before_completion_decision_never_launches_and_settles() {
    let root = tempfile::tempdir().unwrap();
    let config = daemon_config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let submitted_at_ms = system_now_ms().unwrap();
    let mut manager = OperationManager::open(&config).unwrap();
    let operation_id = manager
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::DaemonStartSubmit,
                &json!({"strict": false}),
                b"issue-315-cancel-before-daemon-launch",
                submitted_at_ms + 60_000,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(manager);

    let launches = Arc::new(AtomicUsize::new(0));
    let (decision_ready, wait_for_decision) = mpsc::sync_channel(0);
    let (release_decision, decision_release) = mpsc::sync_channel(0);
    let runner = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        counting_daemon_dispatcher(config.clone(), false, Arc::clone(&launches)),
    )
    .with_completion_decision_barrier_for_test(decision_ready, decision_release);
    let runner_thread = std::thread::spawn(move || runner.run_until_idle());

    wait_for_decision
        .recv_timeout(Duration::from_secs(5))
        .expect("daemon completion reaches the durable decision boundary");
    let mut manager = OperationManager::open(&config).unwrap();
    manager
        .cancel(&operation_id, system_now_ms().unwrap())
        .unwrap();
    release_decision.send(()).unwrap();

    let report = runner_thread.join().unwrap().unwrap();
    assert_eq!(report.completed(), 0);
    assert_eq!(report.cancelled(), 1);
    assert_eq!(launches.load(Ordering::SeqCst), 0);
    assert_eq!(
        OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Cancelled
    );
    assert!(!root.path().join("graph.sqlite.daemon-status.json").exists());
    assert!(!root.path().join("graph.sqlite.daemon-lock").exists());
}

#[test]
fn issue_315_competing_start_exit_waits_for_winner_status() {
    let started = std::time::Instant::now();
    let deadline = started + Duration::from_secs(30);
    let mut exit_observed_at = None;

    assert!(matches!(
        classify_daemon_start_poll(Ok(false), true, &mut exit_observed_at, started, deadline,),
        DaemonStartPoll::Waiting
    ));
    assert_eq!(exit_observed_at, Some(started));
    assert!(matches!(
        classify_daemon_start_poll(
            Ok(true),
            true,
            &mut exit_observed_at,
            started + DAEMON_START_EXIT_GRACE,
            deadline,
        ),
        DaemonStartPoll::Running
    ));
    assert!(matches!(
        classify_daemon_start_poll(
            Ok(false),
            true,
            &mut exit_observed_at,
            started + DAEMON_START_EXIT_GRACE,
            deadline,
        ),
        DaemonStartPoll::ChildExited
    ));
}

#[test]
fn issue_315_concurrent_daemon_requests_have_one_owner_one_launch_and_closed_settlement() {
    let root = tempfile::tempdir().unwrap();
    let config = daemon_config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let submitted_at_ms = system_now_ms().unwrap();
    OperationJournal::open(&config).unwrap();
    let submit_barrier = Arc::new(Barrier::new(3));
    let mut submitters = Vec::new();
    for _ in 0..2 {
        let config = config.clone();
        let barrier = Arc::clone(&submit_barrier);
        submitters.push(std::thread::spawn(move || {
            barrier.wait();
            OperationManager::open(&config)
                .unwrap()
                .submit(
                    &SubmitRequest::new(
                        &config,
                        OperationKind::DaemonStartSubmit,
                        &json!({"strict": false}),
                        b"issue-315-simultaneous-daemon-start",
                        submitted_at_ms + 60_000,
                    )
                    .unwrap(),
                    submitted_at_ms,
                )
                .unwrap()
        }));
    }
    submit_barrier.wait();
    let handles = submitters
        .into_iter()
        .map(|submitter| submitter.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(handles.iter().filter(|handle| handle.created()).count(), 1);
    assert_eq!(handles[0].operation_id(), handles[1].operation_id());
    let operation_id = handles[0].operation_id().clone();

    let launches = Arc::new(AtomicUsize::new(0));
    let runner_barrier = Arc::new(Barrier::new(3));
    let mut runners = Vec::new();
    for _ in 0..2 {
        let config = config.clone();
        let launches = Arc::clone(&launches);
        let barrier = Arc::clone(&runner_barrier);
        runners.push(std::thread::spawn(move || {
            let runner = OperationRunner::new(
                RunnerStartupConfig::new(config.clone()).unwrap(),
                counting_daemon_dispatcher(config, false, launches),
            );
            barrier.wait();
            runner.run_until_idle().unwrap()
        }));
    }
    runner_barrier.wait();
    let reports = runners
        .into_iter()
        .map(|runner| runner.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        reports.iter().map(|report| report.claimed()).sum::<u64>(),
        1
    );
    assert_eq!(
        reports.iter().map(|report| report.completed()).sum::<u64>(),
        1
    );
    assert_eq!(launches.load(Ordering::SeqCst), 1);
    match OperationJournal::open(&config)
        .unwrap()
        .result(&repository, &operation_id, system_now_ms().unwrap())
        .unwrap()
    {
        OperationOutcome::Completed(result) => {
            assert_eq!(result, daemon_start_result(&config));
            assert_eq!(
                result.value()["result"],
                json!({"action":"start", "phase":"running"})
            );
        }
        other => panic!("concurrent daemon request did not settle closed: {other:?}"),
    }
}

struct BlockingDispatcher {
    calls: Arc<AtomicUsize>,
    started: mpsc::SyncSender<i64>,
    release: mpsc::Receiver<()>,
}

impl OperationDispatcher for BlockingDispatcher {
    fn dispatch(
        &mut self,
        _work: &RunnerWork,
        _control: &mut ExecutionControl<'_>,
    ) -> DispatchOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.send(system_now_ms().unwrap()).unwrap();
        self.release
            .recv_timeout(Duration::from_secs(5))
            .expect("test dispatcher release signal");
        DispatchOutcome::Completed(CanonicalJson::new(json!({"completed": true})).unwrap())
    }
}

#[test]
fn cancellation_requested_after_dispatch_wins_over_completed_outcome() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 10_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"cancel_race": true}),
                b"cancel-after-dispatch",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let calls = Arc::new(AtomicUsize::new(0));
    let (dispatch_started, wait_for_dispatch) = mpsc::sync_channel(0);
    let (release_dispatch, wait_for_release) = mpsc::sync_channel(0);
    let runner = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        BlockingDispatcher {
            calls: Arc::clone(&calls),
            started: dispatch_started,
            release: wait_for_release,
        },
    );
    let runner_thread = std::thread::spawn(move || runner.run_until_idle());

    wait_for_dispatch
        .recv_timeout(Duration::from_secs(5))
        .expect("dispatcher start signal");
    let mut journal = OperationJournal::open(&config).unwrap();
    journal
        .cancel(
            &repository,
            &operation_id,
            &CapabilitySet::new([
                depgraph_mcp_tools::AgentCapability::Read,
                depgraph_mcp_tools::AgentCapability::StoreWrite,
            ])
            .unwrap(),
            system_now_ms().unwrap(),
        )
        .unwrap();
    release_dispatch.send(()).unwrap();

    let report = runner_thread.join().unwrap().unwrap();
    assert_eq!(report.completed(), 0);
    assert_eq!(report.cancelled(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        journal
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Cancelled
    ));
}

#[test]
fn cancellation_in_scan_completion_window_keeps_previous_current_snapshot() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let service = DepgraphService::new(config.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(service.scan_cancellable(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            CancellationToken::new(),
        ))
        .unwrap();
    let previous_current = service
        .start_snapshot_request("current")
        .unwrap()
        .snapshot_id()
        .as_str()
        .to_owned();
    std::fs::write(
        config.canonical_root().join("changed.rs"),
        "pub fn changed() {}\n",
    )
    .unwrap();

    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 10_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"cancel-in-scan-completion-window",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let (dispatch_completed, wait_for_dispatch) = mpsc::sync_channel(0);
    let (release_completion, wait_for_release) = mpsc::sync_channel(0);
    let runner = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .with_completion_decision_barrier_for_test(dispatch_completed, wait_for_release);
    let runner_thread = std::thread::spawn(move || runner.run_until_idle());

    wait_for_dispatch
        .recv_timeout(Duration::from_secs(5))
        .expect("scan dispatch completion signal");
    let mut journal = OperationJournal::open(&config).unwrap();
    journal
        .cancel(
            &repository,
            &operation_id,
            &CapabilitySet::new([
                depgraph_mcp_tools::AgentCapability::Read,
                depgraph_mcp_tools::AgentCapability::StoreWrite,
            ])
            .unwrap(),
            system_now_ms().unwrap(),
        )
        .unwrap();
    assert_eq!(
        service
            .start_snapshot_request("current")
            .unwrap()
            .snapshot_id()
            .as_str(),
        previous_current
    );
    release_completion.send(()).unwrap();

    let report = runner_thread.join().unwrap().unwrap();
    assert_eq!(report.completed(), 0);
    assert_eq!(report.cancelled(), 1);
    assert!(matches!(
        journal
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Cancelled
    ));
    assert_eq!(
        service
            .start_snapshot_request("current")
            .unwrap()
            .snapshot_id()
            .as_str(),
        previous_current
    );
}

#[test]
fn scan_cancel_cleanup_failure_is_retried_before_terminalizing() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let service = DepgraphService::new(config.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(service.scan_cancellable(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            CancellationToken::new(),
        ))
        .unwrap();
    std::fs::write(
        config.canonical_root().join("scan-cancel-retry.rs"),
        "pub fn changed() {}\n",
    )
    .unwrap();
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 30_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"scan-cancel-cleanup-retry",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let (dispatch_completed, wait_for_dispatch) = mpsc::sync_channel(0);
    let (release_completion, wait_for_release) = mpsc::sync_channel(0);
    let runner = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .with_completion_decision_barrier_for_test(dispatch_completed, wait_for_release);
    let runner_thread = std::thread::spawn(move || runner.run_until_idle());
    wait_for_dispatch
        .recv_timeout(Duration::from_secs(5))
        .expect("scan completion signal");

    let store = rusqlite::Connection::open(config.store_path()).unwrap();
    let (scan_id, scan_status) = store
        .query_row(
            "SELECT owner.scan_id, scan.status
                   FROM scan_operation_staging AS owner
                   JOIN scans AS scan ON scan.id=owner.scan_id
                  WHERE owner.operation_id=?1",
            [operation_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .unwrap();
    assert_eq!(scan_status, "staging");
    store
        .execute_batch(
            "CREATE TRIGGER fail_first_scan_cancel
                 BEFORE UPDATE OF status ON scans
                 WHEN OLD.status='staging' AND NEW.status='cancelled'
                 BEGIN SELECT RAISE(ABORT, 'injected scan cancel failure'); END;",
        )
        .unwrap();
    drop(store);
    let mut journal = OperationJournal::open(&config).unwrap();
    journal
        .cancel(
            &repository,
            &operation_id,
            &CapabilitySet::new([
                depgraph_mcp_tools::AgentCapability::Read,
                depgraph_mcp_tools::AgentCapability::StoreWrite,
            ])
            .unwrap(),
            system_now_ms().unwrap(),
        )
        .unwrap();
    release_completion.send(()).unwrap();

    let first_error = runner_thread.join().unwrap().unwrap_err();
    assert!(matches!(first_error, RunnerError::Service(_)));
    let retryable = journal
        .get(&repository, &operation_id, system_now_ms().unwrap())
        .unwrap();
    assert_eq!(retryable.status(), OperationStatus::Cancelling);
    assert!(retryable.lease().is_some());
    assert_eq!(retryable.terminal_at_ms(), None);
    assert_eq!(
        journal
            .runner_handoff(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap()
            .completed_at_ms(),
        None
    );
    let store = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        store
            .query_row("SELECT status FROM scans WHERE id=?1", [&scan_id], |row| {
                row.get::<_, String>(0)
            },)
            .unwrap(),
        "staging"
    );
    store
        .execute_batch("DROP TRIGGER fail_first_scan_cancel")
        .unwrap();
    drop(store);

    std::thread::sleep(Duration::from_millis(2));
    let retry_at_ms = system_now_ms().unwrap();
    rusqlite::Connection::open(crate::operation_journal_path(&config))
        .unwrap()
        .execute(
            "UPDATE operations SET lease_expires_at_ms=?1 WHERE operation_id=?2",
            rusqlite::params![retry_at_ms - 1, operation_id.as_str()],
        )
        .unwrap();
    drop(journal);

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    assert_eq!(report.claimed(), 1);
    assert_eq!(report.cancelled(), 1);
    assert!(matches!(
        OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Cancelled
    ));
    assert_eq!(
        rusqlite::Connection::open(config.store_path())
            .unwrap()
            .query_row("SELECT status FROM scans WHERE id=?1", [&scan_id], |row| {
                row.get::<_, String>(0)
            },)
            .unwrap(),
        "cancelled"
    );
}

#[test]
fn cancellation_in_runtime_import_completion_window_keeps_base_snapshot_current() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let (base_snapshot_id, _, durable_input) =
        runtime_import_fixture(&config, "runtime-cancel-window");
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 10_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &durable_input,
                b"cancel-in-runtime-completion-window",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let (dispatch_completed, wait_for_dispatch) = mpsc::sync_channel(0);
    let (release_completion, wait_for_release) = mpsc::sync_channel(0);
    let runner = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .with_completion_decision_barrier_for_test(dispatch_completed, wait_for_release);
    let runner_thread = std::thread::spawn(move || runner.run_until_idle());

    wait_for_dispatch
        .recv_timeout(Duration::from_secs(5))
        .expect("runtime import dispatch completion signal");
    let mut journal = OperationJournal::open(&config).unwrap();
    journal
        .cancel(
            &repository,
            &operation_id,
            &CapabilitySet::new([
                depgraph_mcp_tools::AgentCapability::Read,
                depgraph_mcp_tools::AgentCapability::StoreWrite,
            ])
            .unwrap(),
            system_now_ms().unwrap(),
        )
        .unwrap();
    assert_eq!(
        depgraph_core::open_store_read_only(config.store_path())
            .unwrap()
            .current_snapshot_id()
            .unwrap()
            .as_deref(),
        Some(base_snapshot_id.as_str())
    );
    release_completion.send(()).unwrap();

    let report = runner_thread.join().unwrap().unwrap();
    assert_eq!(report.completed(), 0);
    assert_eq!(report.cancelled(), 1);
    assert!(matches!(
        journal
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Cancelled
    ));
    assert_eq!(
        depgraph_core::open_store_read_only(config.store_path())
            .unwrap()
            .current_snapshot_id()
            .unwrap()
            .as_deref(),
        Some(base_snapshot_id.as_str())
    );
}

#[test]
fn cancellation_winner_retries_runtime_cleanup_before_terminalizing() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let (_, _, durable_input) = runtime_import_fixture(&config, "runtime-cancel-cleanup-retry");
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 30_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &durable_input,
                b"runtime-cancel-cleanup-retry",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let (dispatch_completed, wait_for_dispatch) = mpsc::sync_channel(0);
    let (release_completion, wait_for_release) = mpsc::sync_channel(0);
    let runner = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .with_completion_decision_barrier_for_test(dispatch_completed, wait_for_release);
    let runner_thread = std::thread::spawn(move || runner.run_until_idle());

    wait_for_dispatch
        .recv_timeout(Duration::from_secs(5))
        .expect("runtime completion signal");
    let store = rusqlite::Connection::open(config.store_path()).unwrap();
    let import_id = store
        .query_row(
            "SELECT id FROM runtime_imports WHERE status='staging'",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    store
        .execute_batch(
            "CREATE TRIGGER fail_first_runtime_cancel
                 BEFORE DELETE ON runtime_import_operation_owners
                 BEGIN SELECT RAISE(ABORT, 'injected runtime cancel failure'); END;",
        )
        .unwrap();
    drop(store);
    let mut journal = OperationJournal::open(&config).unwrap();
    journal
        .cancel(
            &repository,
            &operation_id,
            &CapabilitySet::new([
                depgraph_mcp_tools::AgentCapability::Read,
                depgraph_mcp_tools::AgentCapability::StoreWrite,
            ])
            .unwrap(),
            system_now_ms().unwrap(),
        )
        .unwrap();
    release_completion.send(()).unwrap();

    let first_error = runner_thread.join().unwrap().unwrap_err();
    assert!(matches!(first_error, RunnerError::Service(_)));
    let retryable = journal
        .get(&repository, &operation_id, system_now_ms().unwrap())
        .unwrap();
    assert_eq!(retryable.status(), OperationStatus::Cancelling);
    assert!(retryable.lease().is_some());
    assert_eq!(retryable.terminal_at_ms(), None);
    assert_eq!(
        journal
            .runner_handoff(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap()
            .completed_at_ms(),
        None
    );
    let store = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        store
            .query_row(
                "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                [&import_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .query_row(
                "SELECT COUNT(*) FROM runtime_import_operation_owners
                     WHERE import_id=?1 AND operation_id=?2",
                rusqlite::params![import_id, operation_id.as_str()],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        1
    );
    store
        .execute_batch("DROP TRIGGER fail_first_runtime_cancel")
        .unwrap();
    drop(store);

    std::thread::sleep(Duration::from_millis(2));
    let retry_at_ms = system_now_ms().unwrap();
    rusqlite::Connection::open(crate::operation_journal_path(&config))
        .unwrap()
        .execute(
            "UPDATE operations SET lease_expires_at_ms=?1 WHERE operation_id=?2",
            rusqlite::params![retry_at_ms - 1, operation_id.as_str()],
        )
        .unwrap();
    drop(journal);

    let (cleanup_completed, wait_for_cleanup) = mpsc::sync_channel(0);
    let (release_terminal, wait_for_terminal) = mpsc::sync_channel(0);
    let retry_runner = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .with_cleanup_terminal_barrier_for_test(cleanup_completed, wait_for_terminal);
    let retry_thread = std::thread::spawn(move || retry_runner.run_until_idle());
    wait_for_cleanup
        .recv_timeout(Duration::from_secs(5))
        .expect("runtime cleanup completion");

    let journal = OperationJournal::open(&config).unwrap();
    let before_terminal = journal
        .get(&repository, &operation_id, system_now_ms().unwrap())
        .unwrap();
    assert_eq!(before_terminal.status(), OperationStatus::Cancelling);
    assert!(before_terminal.lease().is_some());
    assert_eq!(before_terminal.terminal_at_ms(), None);
    let store = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        store
            .query_row(
                "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                [&import_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .query_row(
                "SELECT COUNT(*) FROM runtime_import_operation_owners WHERE import_id=?1",
                [&import_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
    drop(store);
    release_terminal.send(()).unwrap();

    let report = retry_thread.join().unwrap().unwrap();
    assert_eq!(report.claimed(), 1);
    assert_eq!(report.cancelled(), 1);
    assert!(matches!(
        journal
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Cancelled
    ));
}

#[test]
fn dispatch_time_runtime_cancel_cleanup_error_is_retryable() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let (_, _, durable_input) = runtime_import_fixture(&config, "runtime-dispatch-cancel-failure");
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 30_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &durable_input,
                b"runtime-dispatch-cancel-failure",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let (staged, wait_for_stage) = mpsc::sync_channel(0);
    let (release_dispatch, wait_for_release) = mpsc::sync_channel(0);
    let dispatcher = ScanOperationDispatcher::new(config.clone())
        .with_runtime_dispatch_barrier_for_test(staged, wait_for_release);
    let runner = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        dispatcher,
    );
    let runner_thread = std::thread::spawn(move || runner.run_until_idle());
    wait_for_stage
        .recv_timeout(Duration::from_secs(5))
        .expect("runtime staging signal");

    let store = rusqlite::Connection::open(config.store_path()).unwrap();
    let import_id = store
        .query_row(
            "SELECT id FROM runtime_imports WHERE status='staging'",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    store
        .execute_batch(
            "CREATE TRIGGER fail_dispatch_runtime_cancel
                 BEFORE DELETE ON runtime_import_operation_owners
                 BEGIN SELECT RAISE(ABORT, 'injected dispatch cancel failure'); END;",
        )
        .unwrap();
    drop(store);
    let mut journal = OperationJournal::open(&config).unwrap();
    journal
        .cancel(
            &repository,
            &operation_id,
            &CapabilitySet::new([
                depgraph_mcp_tools::AgentCapability::Read,
                depgraph_mcp_tools::AgentCapability::StoreWrite,
            ])
            .unwrap(),
            system_now_ms().unwrap(),
        )
        .unwrap();
    release_dispatch.send(()).unwrap();

    let error = runner_thread.join().unwrap().unwrap_err();
    assert!(matches!(error, RunnerError::Service(_)));
    let retryable = journal
        .get(&repository, &operation_id, system_now_ms().unwrap())
        .unwrap();
    assert_eq!(retryable.status(), OperationStatus::Cancelling);
    assert!(retryable.lease().is_some());
    assert_eq!(retryable.terminal_at_ms(), None);
    assert_eq!(
        journal
            .runner_handoff(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap()
            .completed_at_ms(),
        None
    );
    let store = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        store
            .query_row(
                "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                [&import_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .query_row(
                "SELECT COUNT(*) FROM runtime_import_operation_owners
                     WHERE import_id=?1 AND operation_id=?2",
                rusqlite::params![import_id, operation_id.as_str()],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        1
    );
}

#[test]
fn cancellation_reclaim_after_runtime_stage_crash_removes_only_staging_evidence() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let (base_snapshot_id, trace, durable_input) =
        runtime_import_fixture(&config, "runtime-stage-crash-cancel");
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 10_000;
    let lease_token = b"runtime-stage-crash-cancel-token";
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &durable_input,
                b"runtime-stage-crash-cancel",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("crashing-runtime-stage-runner").unwrap(),
            lease_token,
            submitted_at_ms + 1,
            submitted_at_ms + 2,
        )
        .unwrap();

    let service = DepgraphService::new(config.clone());
    let prepared = service
        .prepare_runtime_import(
            &RuntimeValidateRequest {
                trace: Some(trace),
                trace_file: None,
                snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                    base_snapshot_id.clone(),
                )),
            },
            &CancellationToken::new(),
        )
        .unwrap();
    let completion = match service
        .runtime_import_deferred_prepared(
            prepared,
            operation_id.as_str(),
            &CancellationToken::new(),
        )
        .unwrap()
    {
        DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
        DeferredRuntimeImportServiceOutcome::Finished(_) => {
            panic!("runtime import did not leave staging evidence")
        }
    };
    let import_id = completion.outcome().result().import_id.clone();
    let session_id = completion.outcome().result().session_id.clone();
    drop(completion);

    let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        evidence
            .query_row(
                "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                [&import_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        evidence
            .query_row(
                "SELECT COUNT(*) FROM runtime_sessions WHERE id=?1",
                [&session_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        1
    );
    drop(evidence);
    journal
        .cancel(
            &repository,
            &operation_id,
            &CapabilitySet::new([
                depgraph_mcp_tools::AgentCapability::Read,
                depgraph_mcp_tools::AgentCapability::StoreWrite,
            ])
            .unwrap(),
            system_now_ms().unwrap(),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(5));

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();

    assert_eq!(report.cancelled(), 1);
    assert!(matches!(
        OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Cancelled
    ));
    let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        evidence
            .query_row(
                "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                [&import_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        evidence
            .query_row(
                "SELECT COUNT(*) FROM runtime_sessions WHERE id=?1",
                [&session_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        depgraph_core::open_store_read_only(config.store_path())
            .unwrap()
            .current_snapshot_id()
            .unwrap()
            .as_deref(),
        Some(base_snapshot_id.as_str())
    );
}

#[test]
fn legacy_runtime_input_cancellation_reclaims_v17_stage_by_operation_owner() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let (base_snapshot_id, trace, durable_input) =
        runtime_import_fixture(&config, "legacy-v17-cancel-cleanup");
    let durable_input = legacy_runtime_import_input(durable_input);
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 60_000;
    let expired_at_ms = submitted_at_ms + 50;
    let lease = b"legacy-v17-cancel-cleanup-token";
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &durable_input,
                b"legacy-v17-cancel-cleanup",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("legacy-v17-cancel-crash").unwrap(),
            lease,
            submitted_at_ms + 1,
            expired_at_ms,
        )
        .unwrap();
    let service = DepgraphService::new(config.clone());
    let prepared = service
        .prepare_runtime_import(
            &RuntimeValidateRequest {
                trace: Some(trace),
                trace_file: None,
                snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                    base_snapshot_id,
                )),
            },
            &CancellationToken::new(),
        )
        .unwrap();
    let completion = match service
        .runtime_import_deferred_prepared(
            prepared,
            operation_id.as_str(),
            &CancellationToken::new(),
        )
        .unwrap()
    {
        DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
        DeferredRuntimeImportServiceOutcome::Finished(_) => {
            panic!("legacy operation did not leave v17 staging")
        }
    };
    let import_id = completion.outcome().result().import_id.clone();
    let session_id = completion.outcome().result().session_id.clone();
    drop(completion);
    journal
        .cancel(
            &repository,
            &operation_id,
            &cancellable_capabilities(),
            submitted_at_ms + 2,
        )
        .unwrap();
    drop(journal);
    while system_now_ms().unwrap() <= expired_at_ms {
        std::thread::yield_now();
    }

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    assert_eq!(report.cancelled(), 1);
    let store = rusqlite::Connection::open(config.store_path()).unwrap();
    for (table, column, identity) in [
        ("runtime_imports", "id", import_id.as_str()),
        ("runtime_sessions", "id", session_id.as_str()),
        (
            "runtime_import_operation_owners",
            "operation_id",
            operation_id.as_str(),
        ),
    ] {
        assert_eq!(
            store
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE {column}=?1"),
                    [identity],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
    }
}

#[test]
fn legacy_runtime_file_failure_reclaims_v17_stage_by_operation_owner() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let (base_snapshot_id, trace, _) =
        runtime_import_fixture(&config, "legacy-v17-failure-cleanup");
    std::fs::create_dir_all(config.canonical_root().join("traces")).unwrap();
    let trace_path = config.canonical_root().join("traces/legacy-runtime.json");
    std::fs::write(&trace_path, &trace).unwrap();
    let trace_file = RepositoryRelativePath::parse("traces/legacy-runtime.json").unwrap();
    let service = DepgraphService::new(config.clone());
    let prepared = service
        .prepare_runtime_import(
            &RuntimeValidateRequest {
                trace: None,
                trace_file: Some(trace_file),
                snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                    base_snapshot_id,
                )),
            },
            &CancellationToken::new(),
        )
        .unwrap();
    let durable_input = legacy_runtime_import_input(prepared.durable_input());
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 60_000;
    let expired_at_ms = submitted_at_ms + 50;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &durable_input,
                b"legacy-v17-failure-cleanup",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("legacy-v17-failure-crash").unwrap(),
            b"legacy-v17-failure-cleanup-token",
            submitted_at_ms + 1,
            expired_at_ms,
        )
        .unwrap();
    let completion = match service
        .runtime_import_deferred_prepared(
            prepared,
            operation_id.as_str(),
            &CancellationToken::new(),
        )
        .unwrap()
    {
        DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
        DeferredRuntimeImportServiceOutcome::Finished(_) => {
            panic!("legacy operation did not leave v17 staging")
        }
    };
    let import_id = completion.outcome().result().import_id.clone();
    let session_id = completion.outcome().result().session_id.clone();
    drop(completion);
    std::fs::write(
        trace_path,
        trace.replace("legacy-v17-failure-cleanup", "legacy-v17-failure-drifted"),
    )
    .unwrap();
    drop(journal);
    while system_now_ms().unwrap() <= expired_at_ms {
        std::thread::yield_now();
    }

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    assert_eq!(report.failed(), 1);
    assert!(matches!(
        OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Failed(_)
    ));
    let store = rusqlite::Connection::open(config.store_path()).unwrap();
    for (table, column, identity) in [
        ("runtime_imports", "id", import_id.as_str()),
        ("runtime_sessions", "id", session_id.as_str()),
        (
            "runtime_import_operation_owners",
            "operation_id",
            operation_id.as_str(),
        ),
    ] {
        assert_eq!(
            store
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE {column}=?1"),
                    [identity],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
    }
}

#[test]
fn deadline_reclaim_after_runtime_stage_crash_removes_only_staging_evidence() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let (base_snapshot_id, trace, durable_input) =
        runtime_import_fixture(&config, "runtime-stage-crash-deadline");
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 200;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &durable_input,
                b"runtime-stage-crash-deadline",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("crashing-runtime-deadline-runner").unwrap(),
            b"runtime-stage-crash-deadline-token",
            submitted_at_ms + 1,
            deadline_ms,
        )
        .unwrap();

    let service = DepgraphService::new(config.clone());
    let prepared = service
        .prepare_runtime_import(
            &RuntimeValidateRequest {
                trace: Some(trace.clone()),
                trace_file: None,
                snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                    base_snapshot_id.clone(),
                )),
            },
            &CancellationToken::new(),
        )
        .unwrap();
    let completion = match service
        .runtime_import_deferred_prepared(
            prepared,
            operation_id.as_str(),
            &CancellationToken::new(),
        )
        .unwrap()
    {
        DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
        DeferredRuntimeImportServiceOutcome::Finished(_) => {
            panic!("runtime import did not leave staging evidence")
        }
    };
    let import_id = completion.outcome().result().import_id.clone();
    let session_id = completion.outcome().result().session_id.clone();
    drop(completion);
    let competing_prepared = service
        .prepare_runtime_import(
            &RuntimeValidateRequest {
                trace: Some(trace),
                trace_file: None,
                snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                    base_snapshot_id.clone(),
                )),
            },
            &CancellationToken::new(),
        )
        .unwrap();
    while system_now_ms().unwrap() < deadline_ms {
        std::thread::sleep(Duration::from_millis(5));
    }

    let (cleanup_finished, wait_for_cleanup) = mpsc::sync_channel(0);
    let (release_terminal, wait_for_terminal_release) = mpsc::sync_channel(0);
    let runner = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .with_cleanup_terminal_barrier_for_test(cleanup_finished, wait_for_terminal_release);
    let runner_thread = std::thread::spawn(move || runner.run_until_idle());

    wait_for_cleanup
        .recv_timeout(Duration::from_secs(5))
        .expect("runtime cleanup completion signal");
    // The runner is paused after store cleanup while the returned writer
    // guard is still held, but before its journal transition is terminal.
    assert_eq!(
        journal
            .get(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap()
            .status(),
        OperationStatus::Running
    );
    assert!(matches!(
        service.runtime_import_deferred_prepared(
            competing_prepared,
            operation_id.as_str(),
            &CancellationToken::new(),
        ),
        Err(DepgraphServiceError::StoreWriterConflict)
    ));
    let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        evidence
            .query_row(
                "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                [&import_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        evidence
            .query_row(
                "SELECT COUNT(*) FROM runtime_import_operation_owners WHERE import_id=?1",
                [&import_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
    drop(evidence);
    release_terminal.send(()).unwrap();
    let report = runner_thread.join().unwrap().unwrap();

    assert_eq!(report.failed(), 1);
    assert!(matches!(
        OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Failed(_)
    ));
    let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        evidence
            .query_row(
                "SELECT COUNT(*) FROM runtime_import_operation_owners WHERE import_id=?1",
                [&import_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        evidence
            .query_row(
                "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                [&import_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        evidence
            .query_row(
                "SELECT COUNT(*) FROM runtime_sessions WHERE id=?1",
                [&session_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        depgraph_core::open_store_read_only(config.store_path())
            .unwrap()
            .current_snapshot_id()
            .unwrap()
            .as_deref(),
        Some(base_snapshot_id.as_str())
    );
}

#[test]
fn runtime_deadline_cleanup_bypasses_elapsed_observability_and_unblocks_the_queue() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let (base_snapshot_id, trace, durable_input) =
        runtime_import_fixture(&config, "runtime-expired-after-retention");
    let reference_ms = system_now_ms().unwrap();
    let submitted_at_ms = reference_ms - TERMINAL_RETENTION_MS - 10_000;
    let deadline_ms = submitted_at_ms + 1_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &durable_input,
                b"runtime-expired-after-retention",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("expired-retention-runtime-runner").unwrap(),
            b"expired-retention-runtime-token",
            submitted_at_ms + 1,
            deadline_ms,
        )
        .unwrap();

    let service = DepgraphService::new(config.clone());
    let prepared = service
        .prepare_runtime_import(
            &RuntimeValidateRequest {
                trace: Some(trace),
                trace_file: None,
                snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                    base_snapshot_id,
                )),
            },
            &CancellationToken::new(),
        )
        .unwrap();
    let completion = match service
        .runtime_import_deferred_prepared(
            prepared,
            operation_id.as_str(),
            &CancellationToken::new(),
        )
        .unwrap()
    {
        DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
        DeferredRuntimeImportServiceOutcome::Finished(_) => {
            panic!("runtime import did not leave staging evidence")
        }
    };
    let import_id = completion.outcome().result().import_id.clone();
    drop(completion);
    assert!(matches!(
        journal.runner_handoff(&repository, &operation_id, reference_ms),
        Err(JournalError::Expired)
    ));

    let queued_at_ms = system_now_ms().unwrap();
    let queued_operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"queued-after-expired-retention-runtime",
                queued_at_ms + 60_000,
            )
            .unwrap(),
            queued_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    assert_eq!(report.failed(), 1);
    assert_eq!(report.completed(), 1);
    let journal = OperationJournal::open(&config).unwrap();
    assert!(matches!(
        journal
            .result(&repository, &queued_operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Completed(_)
    ));
    let journal_connection =
        rusqlite::Connection::open(crate::operation_journal_path(&config)).unwrap();
    assert_eq!(
        journal_connection
            .query_row(
                "SELECT COUNT(*) FROM operation_tombstones WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        rusqlite::Connection::open(config.store_path())
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM runtime_import_operation_owners WHERE import_id=?1",
                [&import_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn failed_first_attempt_file_runtime_import_cleans_staging_before_terminalization() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let (base_snapshot_id, trace, _) =
        runtime_import_fixture(&config, "runtime-stage-crash-file-drift");
    std::fs::create_dir_all(config.canonical_root().join("traces")).unwrap();
    std::fs::write(config.canonical_root().join("traces/runtime.json"), &trace).unwrap();
    let trace_file = RepositoryRelativePath::parse("traces/runtime.json").unwrap();
    let service = DepgraphService::new(config.clone());
    let prepared = service
        .prepare_runtime_import(
            &RuntimeValidateRequest {
                trace: None,
                trace_file: Some(trace_file.clone()),
                snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                    base_snapshot_id.clone(),
                )),
            },
            &CancellationToken::new(),
        )
        .unwrap();
    let durable_input = prepared.durable_input();
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 10_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &durable_input,
                b"runtime-stage-crash-file-drift",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    let completion = match service
        .runtime_import_deferred_prepared(
            prepared,
            operation_id.as_str(),
            &CancellationToken::new(),
        )
        .unwrap()
    {
        DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
        DeferredRuntimeImportServiceOutcome::Finished(_) => {
            panic!("runtime import did not leave staging evidence")
        }
    };
    let import_id = completion.outcome().result().import_id.clone();
    let session_id = completion.outcome().result().session_id.clone();
    drop(completion);
    let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
    for (query, identity) in [
        (
            "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
            import_id.as_str(),
        ),
        (
            "SELECT COUNT(*) FROM runtime_import_operation_owners WHERE import_id=?1",
            import_id.as_str(),
        ),
        (
            "SELECT COUNT(*) FROM runtime_sessions WHERE id=?1",
            session_id.as_str(),
        ),
    ] {
        assert_eq!(
            evidence
                .query_row(query, [identity], |row| row.get::<_, u64>(0))
                .unwrap(),
            1
        );
    }
    drop(evidence);
    let competing_prepared = service
        .prepare_runtime_import(
            &RuntimeValidateRequest {
                trace: Some(trace.clone()),
                trace_file: None,
                snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                    base_snapshot_id.clone(),
                )),
            },
            &CancellationToken::new(),
        )
        .unwrap();
    std::fs::write(
        config.canonical_root().join("traces/runtime.json"),
        trace.replace(
            "runtime-stage-crash-file-drift",
            "runtime-stage-crash-file-drifted",
        ),
    )
    .unwrap();
    let queued_operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"queued-after-first-runtime-failure",
                submitted_at_ms + 60_000,
            )
            .unwrap(),
            submitted_at_ms + 1,
        )
        .unwrap()
        .operation_id()
        .clone();

    let (cleanup_finished, wait_for_cleanup) = mpsc::sync_channel(0);
    let (release_terminal, wait_for_terminal_release) = mpsc::sync_channel(0);
    let runner = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .with_cleanup_terminal_barrier_for_test(cleanup_finished, wait_for_terminal_release);
    let runner_thread = std::thread::spawn(move || runner.run_until_idle());

    wait_for_cleanup
        .recv_timeout(Duration::from_secs(5))
        .expect("failed-dispatch cleanup completion signal");
    assert_eq!(
        journal
            .get(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap()
            .status(),
        OperationStatus::Running
    );
    assert!(matches!(
        service.runtime_import_deferred_prepared(
            competing_prepared,
            operation_id.as_str(),
            &CancellationToken::new(),
        ),
        Err(DepgraphServiceError::StoreWriterConflict)
    ));
    let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
    for (query, identity) in [
        (
            "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
            import_id.as_str(),
        ),
        (
            "SELECT COUNT(*) FROM runtime_import_operation_owners WHERE import_id=?1",
            import_id.as_str(),
        ),
        (
            "SELECT COUNT(*) FROM runtime_sessions WHERE id=?1",
            session_id.as_str(),
        ),
    ] {
        assert_eq!(
            evidence
                .query_row(query, [identity], |row| row.get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
    drop(evidence);

    release_terminal.send(()).unwrap();
    let report = runner_thread.join().unwrap().unwrap();
    assert_eq!(report.claimed(), 2);
    assert_eq!(report.failed(), 1);
    assert_eq!(report.completed(), 1);
    match OperationJournal::open(&config)
        .unwrap()
        .result(&repository, &operation_id, system_now_ms().unwrap())
        .unwrap()
    {
        OperationOutcome::Failed(error) => {
            let value: serde_json::Value = serde_json::from_str(error.as_str()).unwrap();
            assert_eq!(value["error"]["code"], "CONFLICT");
        }
        outcome => panic!("unexpected reclaimed file-drift outcome: {outcome:?}"),
    }
    assert!(matches!(
        OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &queued_operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Completed(_)
    ));
    let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        evidence
            .query_row(
                "SELECT COUNT(*) FROM completed_snapshots WHERE runtime_import_id=?1",
                [&import_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn runtime_import_digest_drift_fails_without_publishing_a_snapshot() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let (base_snapshot_id, _, mut durable_input) =
        runtime_import_fixture(&config, "runtime-digest-drift");
    durable_input["trace_digest"] = json!("runtime-trace:sha256:invalid-drift");
    let submitted_at_ms = system_now_ms().unwrap();
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &durable_input,
                b"runtime-digest-drift",
                submitted_at_ms + 10_000,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();

    assert_eq!(report.failed(), 1);
    let journal = OperationJournal::open(&config).unwrap();
    match journal
        .result(&repository, &operation_id, system_now_ms().unwrap())
        .unwrap()
    {
        OperationOutcome::Failed(error) => {
            let value: serde_json::Value = serde_json::from_str(error.as_str()).unwrap();
            assert_eq!(value["error"]["code"], "CONFLICT");
        }
        outcome => panic!("unexpected runtime drift outcome: {outcome:?}"),
    }
    assert_eq!(
        depgraph_core::open_store_read_only(config.store_path())
            .unwrap()
            .current_snapshot_id()
            .unwrap()
            .as_deref(),
        Some(base_snapshot_id.as_str())
    );
}

#[test]
fn runner_accepts_retained_normalized_runtime_trace_larger_than_transport_limit() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let (base_snapshot_id, trace, _) =
        runtime_import_fixture(&config, "runtime-normalized-over-transport");
    let mut raw_trace: serde_json::Value = serde_json::from_str(&trace).unwrap();
    let session = raw_trace["session"].as_object_mut().unwrap();
    session.remove("redaction");
    session["profile"]
        .as_object_mut()
        .unwrap()
        .remove("features");
    session["environment"]
        .as_object_mut()
        .unwrap()
        .remove("environment_keys");
    let mut event = raw_trace["events"][0].clone();
    let event_object = event.as_object_mut().unwrap();
    event_object.remove("count");
    event_object.remove("redaction");
    raw_trace["events"] = serde_json::Value::Array(
        (1..=3_400)
            .map(|sequence| {
                let mut event = event.clone();
                event["sequence"] = json!(sequence);
                event
            })
            .collect(),
    );
    let raw_trace = serde_json::to_string(&raw_trace).unwrap();
    assert!(
        raw_trace.len() <= depgraph_core::DEFAULT_SERVICE_MAX_INLINE_INPUT_BYTES,
        "raw transport input is {} bytes",
        raw_trace.len()
    );

    let durable_input = DepgraphService::new(config.clone())
        .prepare_runtime_import(
            &RuntimeValidateRequest {
                trace: Some(raw_trace),
                trace_file: None,
                snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                    base_snapshot_id,
                )),
            },
            &CancellationToken::new(),
        )
        .unwrap()
        .durable_input();
    let normalized_trace = serde_json::to_string(&durable_input["trace"]).unwrap();
    assert!(
        normalized_trace.len() > depgraph_core::DEFAULT_SERVICE_MAX_INLINE_INPUT_BYTES,
        "normalized retained trace is only {} bytes",
        normalized_trace.len()
    );
    let canonical_input = CanonicalInput::new(&durable_input).unwrap();
    assert!(canonical_input.as_str().len() <= crate::MAX_OPERATION_INPUT_BYTES);

    let submitted_at_ms = system_now_ms().unwrap();
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &durable_input,
                b"runtime-normalized-over-transport",
                submitted_at_ms + 60_000,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    let outcome = OperationJournal::open(&config)
        .unwrap()
        .result(&repository, &operation_id, system_now_ms().unwrap())
        .unwrap();
    match outcome {
        OperationOutcome::Completed(_) => {}
        OperationOutcome::Failed(error) => {
            let value: serde_json::Value = serde_json::from_str(error.as_str()).unwrap();
            panic!(
                "retained normalized trace was terminally rejected: {}",
                value["error"]["code"]
            );
        }
        outcome => panic!("unexpected expanding runtime trace outcome: {outcome:?}"),
    }
    assert_eq!(report.claimed(), 1);
    assert_eq!(report.completed(), 1);
    assert_eq!(report.failed(), 0);
}

#[test]
fn changed_valid_queued_file_fails_before_migrating_a_v15_store() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let (base_snapshot_id, trace, _) = runtime_import_fixture(&config, "runtime-v15-file-original");
    std::fs::create_dir_all(config.canonical_root().join("traces")).unwrap();
    let trace_path = config.canonical_root().join("traces/runtime.json");
    std::fs::write(&trace_path, &trace).unwrap();
    let trace_file = RepositoryRelativePath::parse("traces/runtime.json").unwrap();
    let service = DepgraphService::new(config.clone());
    let durable_input = service
        .prepare_runtime_import(
            &RuntimeValidateRequest {
                trace: None,
                trace_file: Some(trace_file),
                snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                    base_snapshot_id,
                )),
            },
            &CancellationToken::new(),
        )
        .unwrap()
        .durable_input();

    let connection = rusqlite::Connection::open(config.store_path()).unwrap();
    connection
        .execute_batch(
            "PRAGMA wal_checkpoint(TRUNCATE);
                 DROP TABLE scan_operation_staging;
                 DROP TABLE runtime_import_operation_owners;
                 PRAGMA user_version=15;
                 PRAGMA journal_mode=DELETE;",
        )
        .unwrap();
    drop(connection);
    let store_bytes_before = std::fs::read(config.store_path()).unwrap();

    std::fs::write(
        &trace_path,
        trace.replace("runtime-v15-file-original", "runtime-v15-file-different"),
    )
    .unwrap();
    let submitted_at_ms = system_now_ms().unwrap();
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &durable_input,
                b"runtime-v15-valid-file-drift",
                submitted_at_ms + 10_000,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();

    assert_eq!(report.claimed(), 1);
    assert_eq!(report.failed(), 1);
    match OperationJournal::open(&config)
        .unwrap()
        .result(&repository, &operation_id, system_now_ms().unwrap())
        .unwrap()
    {
        OperationOutcome::Failed(error) => {
            let value: serde_json::Value = serde_json::from_str(error.as_str()).unwrap();
            assert_eq!(value["error"]["code"], "CONFLICT");
        }
        outcome => panic!("unexpected v15 file-drift outcome: {outcome:?}"),
    }
    assert_eq!(
        std::fs::read(config.store_path()).unwrap(),
        store_bytes_before
    );
    let connection = rusqlite::Connection::open_with_flags(
        config.store_path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        15
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                      WHERE type='table' AND name='runtime_import_operation_owners'",
                [],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn retained_runtime_identity_mismatches_fail_before_migrating_v15() {
    for mismatch in [
        "session_id",
        "runtime_trace_digest",
        "paired_validated_trace_identity",
    ] {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let (base_snapshot_id, _, mut durable_input) =
            runtime_import_fixture(&config, "runtime-v15-binding-mismatch");
        if mismatch == "paired_validated_trace_identity" {
            durable_input["trace"]["session"]["started_at"] = json!("2026-08-07T23:59:59Z");
            let request = RuntimeValidateRequest {
                trace: Some(serde_json::to_string(&durable_input["trace"]).unwrap()),
                trace_file: None,
                snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                    base_snapshot_id,
                )),
            };
            let prevalidated = DepgraphService::new(config.clone())
                .prevalidate_runtime_trace_source(&request.source(), &CancellationToken::new())
                .unwrap();
            durable_input["trace_digest"] = json!(prevalidated.input_digest());
        } else {
            durable_input[mismatch] = json!(format!("forged-{mismatch}"));
        }
        let store_bytes_before = downgrade_store_to_v15(&config);
        let submitted_at_ms = system_now_ms().unwrap();
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &durable_input,
                    format!("runtime-v15-binding-mismatch-{mismatch}").as_bytes(),
                    submitted_at_ms + 10_000,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        drop(journal);

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();
        assert_eq!(report.failed(), 1, "{mismatch}");
        match OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap()
        {
            OperationOutcome::Failed(error) => {
                let value: serde_json::Value = serde_json::from_str(error.as_str()).unwrap();
                assert_eq!(value["error"]["code"], "CONFLICT", "{mismatch}");
            }
            outcome => {
                panic!("unexpected binding mismatch outcome for {mismatch}: {outcome:?}")
            }
        }
        assert_eq!(
            std::fs::read(config.store_path()).unwrap(),
            store_bytes_before,
            "{mismatch}"
        );
        let store = rusqlite::Connection::open_with_flags(
            config.store_path(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap();
        assert_eq!(
            store
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            15,
            "{mismatch}"
        );
    }
}

#[test]
fn legacy_runtime_completion_intent_recovers_after_crash_and_unblocks_queued_work() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let (base_snapshot_id, trace, durable_input) =
        runtime_import_fixture(&config, "runtime-completion-crash");
    let legacy_input = legacy_runtime_import_input(durable_input);
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 10_000;
    let lease_token = b"runtime-completion-intent-crash-token";
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &legacy_input,
                b"recover-committed-runtime-completion",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    let subsequent_operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &legacy_input,
                b"runtime-work-queued-behind-completion",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("crashing-runtime-completion-runner").unwrap(),
            lease_token,
            submitted_at_ms + 1,
            deadline_ms,
        )
        .unwrap();

    let service = DepgraphService::new(config.clone());
    let prepared = service
        .prepare_runtime_import(
            &RuntimeValidateRequest {
                trace: Some(trace),
                trace_file: None,
                snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                    base_snapshot_id,
                )),
            },
            &CancellationToken::new(),
        )
        .unwrap();
    let completion = match service
        .runtime_import_deferred_prepared(
            prepared,
            operation_id.as_str(),
            &CancellationToken::new(),
        )
        .unwrap()
    {
        DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
        DeferredRuntimeImportServiceOutcome::Finished(_) => {
            panic!("runtime import did not defer completion")
        }
    };
    let expected_snapshot = completion
        .outcome()
        .completed_snapshot_id()
        .as_str()
        .to_owned();
    let dispatcher = ScanOperationDispatcher::new(config.clone());
    let result = dispatcher
        .completed_runtime_output(completion.outcome())
        .ok()
        .unwrap();
    assert_eq!(
        journal
            .commit_completion_intent(
                &repository,
                &operation_id,
                lease_token,
                result,
                system_now_ms().unwrap(),
            )
            .unwrap(),
        CompletionDecision::Committed
    );
    drop(completion);
    drop(journal);

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();

    assert_eq!(report.claimed(), 1);
    assert_eq!(report.completed(), 2);
    let reopened_journal = OperationJournal::open(&config).unwrap();
    for completed_operation in [&operation_id, &subsequent_operation_id] {
        assert!(matches!(
            reopened_journal
                .result(&repository, completed_operation, system_now_ms().unwrap(),)
                .unwrap(),
            OperationOutcome::Completed(_)
        ));
    }
    assert_eq!(
        depgraph_core::open_store_read_only(config.store_path())
            .unwrap()
            .current_snapshot_id()
            .unwrap()
            .as_deref(),
        Some(expected_snapshot.as_str())
    );
}

#[test]
fn committed_runtime_completion_recovers_v15_staging_through_exact_legacy_owner() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let (base_snapshot_id, trace, durable_input) =
        runtime_import_fixture(&config, "runtime-v15-completion-recovery");
    let legacy_input = legacy_runtime_import_input(durable_input);
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 10_000;
    let lease_token = b"runtime-v15-completion-token";
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &legacy_input,
                b"runtime-v15-completion-recovery",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("v15-runtime-completion-runner").unwrap(),
            lease_token,
            submitted_at_ms + 1,
            deadline_ms,
        )
        .unwrap();

    let service = DepgraphService::new(config.clone());
    let completion = match service
        .runtime_import_deferred_prepared(
            service
                .prepare_runtime_import(
                    &RuntimeValidateRequest {
                        trace: Some(trace),
                        trace_file: None,
                        snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                            base_snapshot_id,
                        )),
                    },
                    &CancellationToken::new(),
                )
                .unwrap(),
            operation_id.as_str(),
            &CancellationToken::new(),
        )
        .unwrap()
    {
        DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
        DeferredRuntimeImportServiceOutcome::Finished(_) => {
            panic!("runtime import did not leave v15 recovery staging")
        }
    };
    let expected_snapshot = completion
        .outcome()
        .completed_snapshot_id()
        .as_str()
        .to_owned();
    let result = ScanOperationDispatcher::new(config.clone())
        .completed_runtime_output(completion.outcome())
        .ok()
        .unwrap();
    assert_eq!(
        journal
            .commit_completion_intent(
                &repository,
                &operation_id,
                lease_token,
                result,
                system_now_ms().unwrap(),
            )
            .unwrap(),
        CompletionDecision::Committed
    );
    drop(completion);
    drop(journal);

    let connection = rusqlite::Connection::open(config.store_path()).unwrap();
    connection
        .execute_batch(
            "DROP TABLE scan_operation_staging;
                 DROP TABLE runtime_import_operation_owners;
                 PRAGMA user_version=15;",
        )
        .unwrap();
    drop(connection);

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    assert_eq!(report.completed(), 1);
    assert!(matches!(
        OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Completed(_)
    ));
    let store = depgraph_core::open_store_read_only(config.store_path()).unwrap();
    assert_eq!(
        store.schema_version().unwrap(),
        depgraph_core::release_compatibility_contract().store_schema_version
    );
    assert_eq!(
        store.current_snapshot_id().unwrap().as_deref(),
        Some(expected_snapshot.as_str())
    );
}

#[test]
fn runtime_completion_recovery_rejects_envelope_identity_tampering_before_promotion() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let (base_snapshot_id, trace, durable_input) =
        runtime_import_fixture(&config, "runtime-envelope-recovery");
    let legacy_input = legacy_runtime_import_input(durable_input);
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 10_000;
    let lease_token = b"runtime-envelope-recovery-token";
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &legacy_input,
                b"runtime-envelope-recovery",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("runtime-envelope-recovery-runner").unwrap(),
            lease_token,
            submitted_at_ms + 1,
            deadline_ms,
        )
        .unwrap();

    let service = DepgraphService::new(config.clone());
    let completion = match service
        .runtime_import_deferred_prepared(
            service
                .prepare_runtime_import(
                    &RuntimeValidateRequest {
                        trace: Some(trace),
                        trace_file: None,
                        snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                            base_snapshot_id,
                        )),
                    },
                    &CancellationToken::new(),
                )
                .unwrap(),
            operation_id.as_str(),
            &CancellationToken::new(),
        )
        .unwrap()
    {
        DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
        DeferredRuntimeImportServiceOutcome::Finished(_) => {
            panic!("runtime import did not leave envelope recovery staging")
        }
    };
    let import_id = completion.outcome().result().import_id.clone();
    let session_id = completion.outcome().result().session_id.clone();
    let valid_result = ScanOperationDispatcher::new(config.clone())
        .completed_runtime_output(completion.outcome())
        .ok()
        .unwrap();
    journal
        .commit_completion_intent(
            &repository,
            &operation_id,
            lease_token,
            valid_result.clone(),
            system_now_ms().unwrap(),
        )
        .unwrap();
    drop(completion);

    let valid_value = valid_result.value().clone();
    let invalid_snapshot =
        "snapshot:sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let mut tampered_values = Vec::new();
    let mut invalid_contract = valid_value.clone();
    invalid_contract["contract_version"] = json!("depgraph-mcp-tools-v2");
    tampered_values.push(invalid_contract);
    let mut wrong_repository = valid_value.clone();
    wrong_repository["repository_id"] = json!("repo:other");
    tampered_values.push(wrong_repository);
    let mut wrong_envelope_snapshot = valid_value.clone();
    wrong_envelope_snapshot["snapshot_id"] = json!(invalid_snapshot);
    tampered_values.push(wrong_envelope_snapshot);
    let mut wrong_result_snapshot = valid_value.clone();
    wrong_result_snapshot["result"]["snapshot_id"] = json!(invalid_snapshot);
    tampered_values.push(wrong_result_snapshot);

    let mut dispatcher = ScanOperationDispatcher::new(config.clone());
    let replace_intent_result = |value| {
        let encoded = CanonicalJson::new(value).unwrap();
        let digest = JournalDigest::sha256(encoded.as_str());
        rusqlite::Connection::open(journal.path())
            .unwrap()
            .execute(
                "UPDATE operation_completion_intents
                        SET result_json=?1, result_digest=?2
                      WHERE operation_id=?3",
                rusqlite::params![
                    encoded.as_str(),
                    digest.as_bytes().as_slice(),
                    operation_id.as_str(),
                ],
            )
            .unwrap();
    };
    for tampered in tampered_values {
        replace_intent_result(tampered);
        let intent = journal
            .next_completion_intent(&repository, system_now_ms().unwrap())
            .unwrap()
            .unwrap();
        assert!(matches!(
            dispatcher.recover_completion(&intent),
            Err(RunnerError::Journal(JournalError::IntegrityFailure))
        ));
        assert_eq!(
            rusqlite::Connection::open(config.store_path())
                .unwrap()
                .query_row(
                    "SELECT status FROM runtime_imports WHERE id=?1",
                    [&import_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "staging"
        );
    }

    for (field, forged) in [
        ("session_id", "runtime-session:forged"),
        ("import_id", "runtime-import:forged"),
    ] {
        let mut tampered = valid_value.clone();
        tampered["result"][field] = json!(forged);
        replace_intent_result(tampered);
        let intent = journal
            .next_completion_intent(&repository, system_now_ms().unwrap())
            .unwrap()
            .unwrap();
        assert!(matches!(
            dispatcher.recover_completion(&intent),
            Err(RunnerError::Service(
                DepgraphServiceError::StoreOperation { .. }
            ))
        ));
        assert_eq!(
            rusqlite::Connection::open(config.store_path())
                .unwrap()
                .query_row(
                    "SELECT status FROM runtime_imports WHERE id=?1",
                    [&import_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "staging"
        );
    }

    replace_intent_result(valid_value);
    rusqlite::Connection::open(config.store_path())
        .unwrap()
        .execute(
            "UPDATE runtime_sessions SET trace_digest=?1 WHERE id=?2",
            rusqlite::params!["runtime-trace:sha256:forged", session_id],
        )
        .unwrap();
    let intent = journal
        .next_completion_intent(&repository, system_now_ms().unwrap())
        .unwrap()
        .unwrap();
    assert!(matches!(
        dispatcher.recover_completion(&intent),
        Err(RunnerError::Service(
            DepgraphServiceError::StoreOperation { .. }
        ))
    ));
    assert_eq!(
        rusqlite::Connection::open(config.store_path())
            .unwrap()
            .query_row(
                "SELECT status FROM runtime_imports WHERE id=?1",
                [&import_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "staging"
    );
}

#[test]
fn runtime_completion_intent_cannot_promote_another_operations_staging_import() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let (base_snapshot_id, trace, durable_input) =
        runtime_import_fixture(&config, "runtime-cross-operation-recovery");
    let legacy_input = legacy_runtime_import_input(durable_input.clone());
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 10_000;
    let lease_a = b"runtime-cross-operation-a-token";
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_a = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &legacy_input,
                b"runtime-cross-operation-a",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    let operation_b = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &durable_input,
                b"runtime-cross-operation-b",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_a,
            &LeaseOwner::parse("cross-operation-intent-a").unwrap(),
            lease_a,
            submitted_at_ms + 1,
            deadline_ms,
        )
        .unwrap();

    let service = DepgraphService::new(config.clone());
    let completion_b = match service
        .runtime_import_deferred_prepared(
            service
                .prepare_runtime_import(
                    &RuntimeValidateRequest {
                        trace: Some(trace),
                        trace_file: None,
                        snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                            base_snapshot_id.clone(),
                        )),
                    },
                    &CancellationToken::new(),
                )
                .unwrap(),
            operation_b.as_str(),
            &CancellationToken::new(),
        )
        .unwrap()
    {
        DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
        DeferredRuntimeImportServiceOutcome::Finished(_) => {
            panic!("operation B did not stage its runtime import")
        }
    };
    let import_id = completion_b.outcome().result().import_id.clone();
    let expected_snapshot = completion_b
        .outcome()
        .completed_snapshot_id()
        .as_str()
        .to_owned();
    let forged_for_a = ScanOperationDispatcher::new(config.clone())
        .completed_runtime_output(completion_b.outcome())
        .ok()
        .unwrap();
    assert_eq!(
        journal
            .commit_completion_intent(
                &repository,
                &operation_a,
                lease_a,
                forged_for_a,
                system_now_ms().unwrap(),
            )
            .unwrap(),
        CompletionDecision::Committed
    );
    drop(completion_b);
    drop(journal);

    let error = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap_err();
    assert!(matches!(
        error,
        RunnerError::Service(DepgraphServiceError::StoreOperation { .. })
    ));

    let journal = OperationJournal::open(&config).unwrap();
    assert_eq!(
        journal
            .get(&repository, &operation_a, system_now_ms().unwrap())
            .unwrap()
            .status(),
        OperationStatus::Running
    );
    assert_eq!(
        journal
            .next_completion_intent(&repository, system_now_ms().unwrap())
            .unwrap()
            .unwrap()
            .operation_id(),
        &operation_a
    );
    let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        evidence
            .query_row(
                "SELECT status FROM runtime_imports WHERE id=?1",
                [&import_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "staging"
    );
    assert_eq!(
        evidence
            .query_row(
                "SELECT operation_id FROM runtime_import_operation_owners
                      WHERE import_id=?1",
                [&import_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        operation_b.as_str()
    );
    assert_eq!(
        evidence
            .query_row(
                "SELECT COUNT(*) FROM completed_snapshots WHERE id=?1",
                [&expected_snapshot],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        evidence
            .query_row(
                "SELECT snapshot_id FROM current_completed_snapshot WHERE singleton=1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        base_snapshot_id
    );
}

#[test]
fn operation_owned_runtime_stage_survives_other_operation_cleanup_and_recovers() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let (base_snapshot_id, trace, durable_input) =
        runtime_import_fixture(&config, "runtime-shared-operation-stage");
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 10_000;
    let lease_a = b"runtime-shared-stage-a-token";
    let lease_b = b"runtime-shared-stage-b-token";
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_a = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &durable_input,
                b"runtime-shared-stage-a",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    let operation_b = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::RuntimeTraceImportSubmit,
                &durable_input,
                b"runtime-shared-stage-b",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    assert_ne!(operation_a, operation_b);
    journal
        .acquire_lease(
            &repository,
            &operation_a,
            &LeaseOwner::parse("crashing-shared-stage-a").unwrap(),
            lease_a,
            submitted_at_ms + 1,
            deadline_ms,
        )
        .unwrap();
    journal
        .acquire_lease(
            &repository,
            &operation_b,
            &LeaseOwner::parse("cancelling-shared-stage-b").unwrap(),
            lease_b,
            submitted_at_ms + 1,
            deadline_ms,
        )
        .unwrap();

    let service = DepgraphService::new(config.clone());
    let runtime_request = || RuntimeValidateRequest {
        trace: Some(trace.clone()),
        trace_file: None,
        snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
            base_snapshot_id.clone(),
        )),
    };
    let completion_a = match service
        .runtime_import_deferred_prepared(
            service
                .prepare_runtime_import(&runtime_request(), &CancellationToken::new())
                .unwrap(),
            operation_a.as_str(),
            &CancellationToken::new(),
        )
        .unwrap()
    {
        DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
        DeferredRuntimeImportServiceOutcome::Finished(_) => {
            panic!("operation A did not stage its runtime import")
        }
    };
    let import_id = completion_a.outcome().result().import_id.clone();
    let session_id = completion_a.outcome().result().session_id.clone();
    let expected_snapshot = completion_a
        .outcome()
        .completed_snapshot_id()
        .as_str()
        .to_owned();
    let result_a = ScanOperationDispatcher::new(config.clone())
        .completed_runtime_output(completion_a.outcome())
        .ok()
        .unwrap();
    assert_eq!(
        journal
            .commit_completion_intent(
                &repository,
                &operation_a,
                lease_a,
                result_a,
                system_now_ms().unwrap(),
            )
            .unwrap(),
        CompletionDecision::Committed
    );
    // Simulate the crash after A's completion decision but before store
    // promotion. Dropping releases only the process-local writer lock.
    drop(completion_a);

    let completion_b = match service
        .runtime_import_deferred_prepared(
            service
                .prepare_runtime_import(&runtime_request(), &CancellationToken::new())
                .unwrap(),
            operation_b.as_str(),
            &CancellationToken::new(),
        )
        .unwrap()
    {
        DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
        DeferredRuntimeImportServiceOutcome::Finished(_) => {
            panic!("operation B did not attach to A's staged runtime import")
        }
    };
    assert_eq!(completion_b.outcome().result().import_id, import_id);
    drop(completion_b);

    let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        evidence
            .query_row(
                "SELECT COUNT(*) FROM runtime_import_operation_owners WHERE import_id=?1",
                [&import_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        2
    );
    drop(evidence);

    assert_eq!(
        journal
            .cancel(
                &repository,
                &operation_b,
                &CapabilitySet::new([
                    depgraph_mcp_tools::AgentCapability::Read,
                    depgraph_mcp_tools::AgentCapability::StoreWrite,
                ])
                .unwrap(),
                system_now_ms().unwrap(),
            )
            .unwrap(),
        crate::CancelOutcome::Requested
    );
    let record_b = journal
        .get(&repository, &operation_b, system_now_ms().unwrap())
        .unwrap();
    let cleanup_guard = ScanOperationDispatcher::new(config.clone())
        .cleanup_abandoned(&RunnerWork {
            operation_id: operation_b.clone(),
            kind: OperationKind::RuntimeTraceImportSubmit,
            input: record_b.normalized_input().clone(),
            execution_deadline_ms: deadline_ms,
        })
        .unwrap();
    journal
        .mark_cancelled(&repository, &operation_b, lease_b, system_now_ms().unwrap())
        .unwrap();
    drop(cleanup_guard);

    let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        evidence
            .query_row(
                "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                [&import_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        evidence
            .query_row(
                "SELECT operation_id FROM runtime_import_operation_owners WHERE import_id=?1",
                [&import_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        operation_a.as_str()
    );
    drop(evidence);
    drop(journal);

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    assert_eq!(report.claimed(), 0);
    assert_eq!(report.completed(), 1);
    assert!(matches!(
        OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &operation_a, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Completed(_)
    ));
    assert!(matches!(
        OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &operation_b, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Cancelled
    ));
    let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        evidence
            .query_row(
                "SELECT COUNT(*) FROM runtime_import_operation_owners WHERE import_id=?1",
                [&import_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        evidence
            .query_row(
                "SELECT COUNT(*) FROM runtime_imports
                      WHERE id=?1 AND status='completed' AND result_snapshot_id=?2",
                rusqlite::params![import_id, expected_snapshot],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        evidence
            .query_row(
                "SELECT COUNT(*) FROM runtime_sessions WHERE id=?1",
                [&session_id],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        depgraph_core::open_store_read_only(config.store_path())
            .unwrap()
            .current_snapshot_id()
            .unwrap()
            .as_deref(),
        Some(expected_snapshot.as_str())
    );
}

#[test]
fn reclaimed_pre_intent_scan_attempt_completes_and_unblocks_the_queue() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 60_000;
    let expired_at_ms = submitted_at_ms + 50;
    let lease = b"pre-intent-scan-crash-token";
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"pre-intent-scan-crash",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("pre-intent-crashing-runner").unwrap(),
            lease,
            submitted_at_ms + 1,
            expired_at_ms,
        )
        .unwrap();
    let queued_operation = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"queued-after-pre-intent-scan-crash",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms + 2,
        )
        .unwrap()
        .operation_id()
        .clone();

    let service = DepgraphService::new(config.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let abandoned = match runtime
        .block_on(service.scan_deferred_cancellable_for_operation(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            operation_id.as_str(),
            CancellationToken::new(),
        ))
        .unwrap()
    {
        DeferredScanServiceOutcome::Pending(completion) => completion,
        DeferredScanServiceOutcome::Finished(_) => panic!("scan did not leave staging"),
    };
    let abandoned_scan_id = abandoned.outcome().outcome().scan_id.clone();
    drop(abandoned);
    drop(journal);
    while system_now_ms().unwrap() <= expired_at_ms {
        std::thread::yield_now();
    }

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();

    assert_eq!(report.claimed(), 2);
    assert_eq!(report.completed(), 2);
    let journal = OperationJournal::open(&config).unwrap();
    for operation in [&operation_id, &queued_operation] {
        assert!(matches!(
            journal
                .result(&repository, operation, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Completed(_)
        ));
    }
    let store = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        store
            .query_row(
                "SELECT status FROM scans WHERE id=?1",
                [&abandoned_scan_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "cancelled"
    );
    let completed_scan_id: String = store
        .query_row(
            "SELECT scan_id FROM scan_operation_staging WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_ne!(completed_scan_id, abandoned_scan_id);
}

#[test]
fn failed_first_scan_attempt_cleans_operation_owned_staging_and_unblocks_the_queue() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 60_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": "invalid"}),
                b"first-scan-attempt-fails-after-stage",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    let queued_operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"queued-after-first-scan-failure",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms + 1,
        )
        .unwrap()
        .operation_id()
        .clone();

    let service = DepgraphService::new(config.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let staged = match runtime
        .block_on(service.scan_deferred_cancellable_for_operation(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            operation_id.as_str(),
            CancellationToken::new(),
        ))
        .unwrap()
    {
        DeferredScanServiceOutcome::Pending(completion) => completion,
        DeferredScanServiceOutcome::Finished(_) => panic!("scan did not leave staging"),
    };
    let staged_scan_id = staged.outcome().outcome().scan_id.clone();
    drop(staged);
    drop(journal);

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    assert_eq!(report.claimed(), 2);
    assert_eq!(report.failed(), 1);
    assert_eq!(report.completed(), 1);
    let journal = OperationJournal::open(&config).unwrap();
    assert!(matches!(
        journal
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Failed(_)
    ));
    assert!(matches!(
        journal
            .result(&repository, &queued_operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Completed(_)
    ));
    let store = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        store
            .query_row(
                "SELECT status FROM scans WHERE id=?1",
                [&staged_scan_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "cancelled"
    );
    assert_eq!(
        store
            .query_row(
                "SELECT COUNT(*) FROM scan_operation_staging WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn expired_staged_scan_is_cleaned_before_deadline_failure_and_unblocks_the_queue() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 100;
    let queued_deadline_ms = submitted_at_ms + 60_000;
    let lease = b"expired-staged-scan-token";
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"expired-staged-scan",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("expired-staged-scan-runner").unwrap(),
            lease,
            submitted_at_ms + 1,
            deadline_ms,
        )
        .unwrap();
    let queued_operation = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"queued-after-expired-staged-scan",
                queued_deadline_ms,
            )
            .unwrap(),
            submitted_at_ms + 2,
        )
        .unwrap()
        .operation_id()
        .clone();

    let service = DepgraphService::new(config.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let staged = match runtime
        .block_on(service.scan_deferred_cancellable_for_operation(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            operation_id.as_str(),
            CancellationToken::new(),
        ))
        .unwrap()
    {
        DeferredScanServiceOutcome::Pending(completion) => completion,
        DeferredScanServiceOutcome::Finished(_) => panic!("scan did not leave staging"),
    };
    let staged_scan_id = staged.outcome().outcome().scan_id.clone();
    drop(staged);
    drop(journal);
    while system_now_ms().unwrap() <= deadline_ms {
        std::thread::yield_now();
    }

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();

    assert_eq!(report.failed(), 1);
    assert_eq!(report.completed(), 1);
    let journal = OperationJournal::open(&config).unwrap();
    assert!(matches!(
        journal
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Failed(_)
    ));
    assert!(matches!(
        journal
            .result(&repository, &queued_operation, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Completed(_)
    ));
    let store = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        store
            .query_row(
                "SELECT status FROM scans WHERE id=?1",
                [&staged_scan_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "cancelled"
    );
    assert_eq!(
        store
            .query_row(
                "SELECT COUNT(*) FROM scan_operation_staging WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn cancelled_scan_store_commit_retries_before_journal_terminal_and_unblocks_queue() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 60_000;
    let expired_at_ms = submitted_at_ms + 50;
    let lease = b"scan-cancel-store-first-token";
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"scan-cancel-store-first",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("scan-cancel-store-first-runner").unwrap(),
            lease,
            submitted_at_ms + 1,
            expired_at_ms,
        )
        .unwrap();
    let queued_operation = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"queued-after-scan-cancel-store-first",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms + 2,
        )
        .unwrap()
        .operation_id()
        .clone();
    let service = DepgraphService::new(config.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let staged = match runtime
        .block_on(service.scan_deferred_cancellable_for_operation(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            operation_id.as_str(),
            CancellationToken::new(),
        ))
        .unwrap()
    {
        DeferredScanServiceOutcome::Pending(completion) => completion,
        DeferredScanServiceOutcome::Finished(_) => panic!("scan did not leave staging"),
    };
    let scan_id = staged.outcome().outcome().scan_id.clone();
    drop(staged);
    journal
        .cancel(
            &repository,
            &operation_id,
            &cancellable_capabilities(),
            submitted_at_ms + 3,
        )
        .unwrap();
    drop(
        service
            .cancel_deferred_scan_for_operation(operation_id.as_str())
            .unwrap(),
    );
    assert_eq!(
        rusqlite::Connection::open(config.store_path())
            .unwrap()
            .query_row(
                "SELECT scan.status FROM scan_operation_staging owner
                     JOIN scans scan ON scan.id=owner.scan_id
                     WHERE owner.operation_id=?1",
                [operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "cancelled"
    );
    drop(journal);
    while system_now_ms().unwrap() <= expired_at_ms {
        std::thread::yield_now();
    }

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    assert_eq!(report.cancelled(), 1);
    assert_eq!(report.completed(), 1);
    let journal = OperationJournal::open(&config).unwrap();
    assert!(matches!(
        journal
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Cancelled
    ));
    assert!(matches!(
        journal
            .result(&repository, &queued_operation, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Completed(_)
    ));
    let store = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        store
            .query_row(
                "SELECT COUNT(*) FROM scan_operation_staging WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .query_row("SELECT status FROM scans WHERE id=?1", [&scan_id], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
        "cancelled"
    );
}

#[test]
fn terminal_journal_scan_cancellation_recovers_unacknowledged_store_proof() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 60_000;
    let lease = b"scan-cancel-journal-first-token";
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"scan-cancel-journal-first",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("scan-cancel-journal-first-runner").unwrap(),
            lease,
            submitted_at_ms + 1,
            deadline_ms,
        )
        .unwrap();
    let service = DepgraphService::new(config.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let staged = match runtime
        .block_on(service.scan_deferred_cancellable_for_operation(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            operation_id.as_str(),
            CancellationToken::new(),
        ))
        .unwrap()
    {
        DeferredScanServiceOutcome::Pending(completion) => completion,
        DeferredScanServiceOutcome::Finished(_) => panic!("scan did not leave staging"),
    };
    drop(staged);
    journal
        .cancel(
            &repository,
            &operation_id,
            &cancellable_capabilities(),
            submitted_at_ms + 2,
        )
        .unwrap();
    drop(
        service
            .cancel_deferred_scan_for_operation(operation_id.as_str())
            .unwrap(),
    );
    journal
        .mark_cancelled(&repository, &operation_id, lease, submitted_at_ms + 3)
        .unwrap();
    assert_eq!(
        rusqlite::Connection::open(config.store_path())
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM scan_operation_staging WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        1
    );
    drop(journal);

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    assert_eq!(report.claimed(), 0);
    assert_eq!(
        rusqlite::Connection::open(config.store_path())
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM scan_operation_staging WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn p1c_concurrent_purge_cannot_delete_unacknowledged_external_store_terminal_row() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let reference_ms = system_now_ms().unwrap();
    let terminal_at_ms = reference_ms - TERMINAL_RETENTION_MS - 10_000;
    let submitted_at_ms = terminal_at_ms - 3;
    let deadline_ms = terminal_at_ms + 1;
    let lease = b"p1c-unacknowledged-cleanup-token";
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"p1c-unacknowledged-cleanup",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("p1c-unacknowledged-cleanup-runner").unwrap(),
            lease,
            terminal_at_ms - 1,
            deadline_ms,
        )
        .unwrap();
    journal
        .cancel(
            &repository,
            &operation_id,
            &cancellable_capabilities(),
            terminal_at_ms,
        )
        .unwrap();

    let service = DepgraphService::new(config.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let staged = match runtime
        .block_on(service.scan_deferred_cancellable_for_operation(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            operation_id.as_str(),
            CancellationToken::new(),
        ))
        .unwrap()
    {
        DeferredScanServiceOutcome::Pending(completion) => completion,
        DeferredScanServiceOutcome::Finished(_) => panic!("scan did not leave staging"),
    };
    drop(staged);

    let queued_at_ms = system_now_ms().unwrap();
    let queued_operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"queued-after-p1c-purge-race",
                queued_at_ms + 60_000,
            )
            .unwrap(),
            queued_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let (terminal_committed, wait_for_terminal) = mpsc::sync_channel(0);
    let (release_acknowledgement, wait_for_acknowledgement) = mpsc::sync_channel(0);
    let runner = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .with_cleanup_acknowledgement_barrier_for_test(terminal_committed, wait_for_acknowledgement);
    let runner_thread = std::thread::spawn(move || runner.run_until_idle());

    wait_for_terminal
        .recv_timeout(Duration::from_secs(5))
        .expect("terminal journal transition signal");
    let store = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        store
            .query_row(
                "SELECT COUNT(*) FROM scan_operation_staging WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        1
    );
    let mut competing_journal = OperationJournal::open(&config).unwrap();
    assert_eq!(
        rusqlite::Connection::open(competing_journal.path())
            .unwrap()
            .query_row(
                "SELECT status FROM operations WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        OperationStatus::Failed.as_str()
    );
    let competing_purge = competing_journal.purge(system_now_ms().unwrap()).unwrap();
    assert_eq!(competing_purge.purged_operations(), 0);
    assert!(competing_purge.more_work());
    assert_eq!(
        rusqlite::Connection::open(competing_journal.path())
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM operations WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        1
    );
    drop(competing_journal);
    release_acknowledgement.send(()).unwrap();

    let report = runner_thread.join().unwrap().unwrap();
    assert_eq!(report.failed(), 1);
    assert_eq!(report.completed(), 1);
    assert_eq!(
        store
            .query_row(
                "SELECT COUNT(*) FROM scan_operation_staging WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
    assert!(matches!(
        OperationJournal::open(&config).unwrap().result(
            &repository,
            &queued_operation_id,
            system_now_ms().unwrap(),
        ),
        Ok(OperationOutcome::Completed(_))
    ));
}

#[test]
fn expired_scan_cleanup_pages_are_reconciled_before_purge_and_unblock_queue() {
    const CLEANUP_PROOF_COUNT: usize = 65;

    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let reconciliation_reference_ms = system_now_ms().unwrap();
    let terminal_at_ms = reconciliation_reference_ms - TERMINAL_RETENTION_MS - 10_000;
    let submitted_at_ms = terminal_at_ms - 3;
    let deadline_ms = terminal_at_ms + 1;
    let lease_owner = LeaseOwner::parse("expired-scan-cleanup-runner").unwrap();
    let lease_token = b"expired-scan-cleanup-token";
    let mut journal = OperationJournal::open(&config).unwrap();
    let service = DepgraphService::new(config.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cleanup_operation_ids = Vec::with_capacity(CLEANUP_PROOF_COUNT);

    for index in 0..CLEANUP_PROOF_COUNT {
        let idempotency_key = format!("expired-scan-cleanup-{index}");
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    idempotency_key.as_bytes(),
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &lease_owner,
                lease_token,
                terminal_at_ms - 2,
                deadline_ms,
            )
            .unwrap();
        let staged = match runtime
            .block_on(service.scan_deferred_cancellable_for_operation(
                &ScanRequest::new(false, ScanCacheMode::Disabled),
                operation_id.as_str(),
                CancellationToken::new(),
            ))
            .unwrap()
        {
            DeferredScanServiceOutcome::Pending(completion) => completion,
            DeferredScanServiceOutcome::Finished(_) => panic!("scan did not leave staging"),
        };
        drop(staged);
        journal
            .cancel(
                &repository,
                &operation_id,
                &cancellable_capabilities(),
                terminal_at_ms - 1,
            )
            .unwrap();
        drop(
            service
                .cancel_deferred_scan_for_operation(operation_id.as_str())
                .unwrap(),
        );
        journal
            .mark_cancelled(&repository, &operation_id, lease_token, terminal_at_ms)
            .unwrap();
        cleanup_operation_ids.push(operation_id);
    }

    assert!(cleanup_operation_ids.iter().all(|operation_id| {
        matches!(
            journal.result(&repository, operation_id, reconciliation_reference_ms),
            Err(JournalError::Expired)
        )
    }));
    let first_cleanup_page = service.pending_deferred_scan_cancellations(None).unwrap();
    assert_eq!(first_cleanup_page.operation_ids().len(), 64);
    assert!(first_cleanup_page.more_work());
    assert_eq!(
        service
            .pending_deferred_scan_cancellations(first_cleanup_page.next_after_operation_id())
            .unwrap()
            .operation_ids()
            .len(),
        1
    );

    let queued_at_ms = system_now_ms().unwrap();
    let queued_operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"queued-after-expired-scan-cleanup-pages",
                queued_at_ms + 60_000,
            )
            .unwrap(),
            queued_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();

    assert_eq!(report.claimed(), 1);
    assert_eq!(report.completed(), 1);
    assert!(matches!(
        OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &queued_operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Completed(_)
    ));
    assert!(
        service
            .pending_deferred_scan_cancellations(None)
            .unwrap()
            .operation_ids()
            .is_empty()
    );
}

#[test]
fn finalized_scan_intent_recovers_after_retention_and_unblocks_queued_work() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let recovery_reference_ms = system_now_ms().unwrap();
    let decided_at_ms = recovery_reference_ms - TERMINAL_RETENTION_MS - 10_000;
    let submitted_at_ms = decided_at_ms - 1_000;
    let deadline_ms = decided_at_ms + 1_000;
    let lease_token = b"completion-intent-crash-token";
    let mut journal = OperationJournal::open(&config).unwrap();
    let submitted = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"recover-committed-scan-completion",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap();
    let operation_id = submitted.operation_id().clone();
    let original_retain_until_ms = submitted.record().retain_until_ms();
    assert!(original_retain_until_ms < recovery_reference_ms);
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("crashing-completion-runner").unwrap(),
            lease_token,
            decided_at_ms - 1,
            deadline_ms,
        )
        .unwrap();

    let service = DepgraphService::new(config.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut completion = match runtime
        .block_on(service.scan_deferred_cancellable_for_operation(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            operation_id.as_str(),
            CancellationToken::new(),
        ))
        .unwrap()
    {
        DeferredScanServiceOutcome::Pending(completion) => completion,
        DeferredScanServiceOutcome::Finished(_) => panic!("scan did not defer completion"),
    };
    let expected_snapshot = completion
        .outcome()
        .completed_snapshot_id()
        .unwrap()
        .as_str()
        .to_owned();
    let dispatcher = ScanOperationDispatcher::new(config.clone());
    let result = dispatcher
        .completed_output(completion.outcome())
        .ok()
        .unwrap();
    completion
        .bind_recovery_result_digest(JournalDigest::sha256(result.as_str().as_bytes()).as_bytes())
        .unwrap();
    assert_eq!(
        journal
            .commit_completion_intent(
                &repository,
                &operation_id,
                lease_token,
                result,
                decided_at_ms,
            )
            .unwrap(),
        CompletionDecision::Committed
    );
    completion.promote().unwrap();
    assert_eq!(
        service
            .start_snapshot_request("current")
            .unwrap()
            .snapshot_id()
            .as_str(),
        expected_snapshot
    );

    let queued_at_ms = system_now_ms().unwrap();
    let queued_operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"queued-behind-expired-completion-intent",
                queued_at_ms + 60_000,
            )
            .unwrap(),
            queued_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let recovery_started_ms = system_now_ms().unwrap();
    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();

    assert_eq!(report.claimed(), 1);
    assert_eq!(report.completed(), 2);
    let reopened = OperationJournal::open(&config).unwrap();
    let recovered = reopened
        .get(&repository, &operation_id, system_now_ms().unwrap())
        .unwrap();
    assert_eq!(recovered.status(), OperationStatus::Completed);
    assert_eq!(recovered.updated_at_ms(), decided_at_ms);
    assert_eq!(recovered.terminal_at_ms(), Some(decided_at_ms));
    assert!(
        recovered.retain_until_ms() >= recovery_started_ms + TERMINAL_RETENTION_MS,
        "recovered completion must remain observable for a full terminal retention window"
    );
    assert!(matches!(
        reopened
            .result(&repository, &queued_operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Completed(_)
    ));
    assert!(
        reopened
            .next_completion_intent(&repository, system_now_ms().unwrap())
            .unwrap()
            .is_none()
    );
}

#[test]
fn legacy_scan_intent_without_operation_staging_binding_keeps_retry_evidence() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 10_000;
    let lease = b"legacy-unbound-scan-intent-token";
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"legacy-unbound-scan-intent",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("legacy-unbound-scan-runner").unwrap(),
            lease,
            submitted_at_ms + 1,
            deadline_ms,
        )
        .unwrap();
    let service = DepgraphService::new(config.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let completion = match runtime
        .block_on(service.scan_deferred_cancellable(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            CancellationToken::new(),
        ))
        .unwrap()
    {
        DeferredScanServiceOutcome::Pending(completion) => completion,
        DeferredScanServiceOutcome::Finished(_) => panic!("scan did not defer completion"),
    };
    let scan_id = completion.outcome().outcome().scan_id.clone();
    let result = ScanOperationDispatcher::new(config.clone())
        .completed_output(completion.outcome())
        .unwrap();
    journal
        .commit_completion_intent(
            &repository,
            &operation_id,
            lease,
            result,
            submitted_at_ms + 2,
        )
        .unwrap();
    drop(completion);
    drop(journal);

    let error = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap_err();
    assert!(matches!(
        error,
        RunnerError::Service(DepgraphServiceError::StoreOperation { .. })
    ));
    let journal = OperationJournal::open(&config).unwrap();
    assert_eq!(
        journal
            .get(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap()
            .status(),
        OperationStatus::Running
    );
    assert_eq!(
        journal
            .next_completion_intent(&repository, system_now_ms().unwrap())
            .unwrap()
            .unwrap()
            .operation_id(),
        &operation_id
    );
    assert_eq!(
        rusqlite::Connection::open(config.store_path())
            .unwrap()
            .query_row("SELECT status FROM scans WHERE id=?1", [&scan_id], |row| {
                row.get::<_, String>(0)
            },)
            .unwrap(),
        "staging"
    );
}

#[test]
fn p1a_genuine_v15_v16_scan_completion_intent_adopts_legacy_staging() {
    for legacy_version in [15_i64, 16_i64] {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 10_000;
        let lease = b"legacy-scan-completion-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    format!("legacy-scan-completion-v{legacy_version}").as_bytes(),
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("legacy-scan-completion-runner").unwrap(),
                lease,
                submitted_at_ms + 1,
                deadline_ms,
            )
            .unwrap();

        let service = DepgraphService::new(config.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // This is the genuine pre-v17 path: the deferred scan UUID was
        // generated independently and no operation ownership row existed.
        let completion = match runtime
            .block_on(service.scan_deferred_cancellable(
                &ScanRequest::new(false, ScanCacheMode::Disabled),
                CancellationToken::new(),
            ))
            .unwrap()
        {
            DeferredScanServiceOutcome::Pending(completion) => completion,
            DeferredScanServiceOutcome::Finished(_) => panic!("scan did not defer completion"),
        };
        let scan_id = completion.outcome().outcome().scan_id.clone();
        assert_ne!(scan_id, operation_id.as_str());
        let expected_snapshot_id = completion
            .outcome()
            .completed_snapshot_id()
            .unwrap()
            .as_str()
            .to_owned();
        let result = ScanOperationDispatcher::new(config.clone())
            .completed_output(completion.outcome())
            .unwrap();
        assert_eq!(
            journal
                .commit_completion_intent(
                    &repository,
                    &operation_id,
                    lease,
                    result,
                    submitted_at_ms + 2,
                )
                .unwrap(),
            CompletionDecision::Committed
        );
        drop(completion);
        drop(journal);

        let connection = rusqlite::Connection::open(config.store_path()).unwrap();
        let downgrade = if legacy_version == 15 {
            "DROP TABLE scan_operation_staging;
                 DROP TABLE runtime_import_operation_owners;
                 PRAGMA user_version=15;"
        } else {
            "DROP TABLE scan_operation_staging;
                 PRAGMA user_version=16;"
        };
        connection.execute_batch(downgrade).unwrap();
        drop(connection);

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();
        assert_eq!(report.completed(), 1, "legacy schema v{legacy_version}");
        assert!(matches!(
            OperationJournal::open(&config).unwrap().result(
                &repository,
                &operation_id,
                system_now_ms().unwrap(),
            ),
            Ok(OperationOutcome::Completed(_))
        ));
        let store = depgraph_core::open_store_read_only(config.store_path()).unwrap();
        assert_eq!(
            store.schema_version().unwrap(),
            depgraph_core::release_compatibility_contract().store_schema_version
        );
        assert_eq!(
            store.current_snapshot_id().unwrap().as_deref(),
            Some(expected_snapshot_id.as_str()),
            "legacy schema v{legacy_version}"
        );
    }
}

#[test]
fn p1a_runner_cancels_unclaimed_legacy_scan_staging_before_expiry_terminalization() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let reference_ms = system_now_ms().unwrap();
    let submitted_at_ms = reference_ms - 2_000;
    let deadline_ms = reference_ms - 1_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"unclaimed-legacy-scan-staging",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();

    let service = DepgraphService::new(config.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let completion = match runtime
        .block_on(service.scan_deferred_cancellable(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            CancellationToken::new(),
        ))
        .unwrap()
    {
        DeferredScanServiceOutcome::Pending(completion) => completion,
        DeferredScanServiceOutcome::Finished(_) => panic!("scan did not defer completion"),
    };
    let scan_id = completion.outcome().outcome().scan_id.clone();
    assert_ne!(scan_id, operation_id.as_str());
    drop(completion);
    drop(journal);

    let connection = rusqlite::Connection::open(config.store_path()).unwrap();
    connection
        .execute_batch(
            "DROP TABLE scan_operation_staging;
                 PRAGMA user_version=16;",
        )
        .unwrap();
    drop(connection);

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    assert_eq!(report.failed(), 1);
    let journal = OperationJournal::open(&config).unwrap();
    assert_eq!(
        journal
            .get(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap()
            .status(),
        OperationStatus::Failed
    );
    let connection = rusqlite::Connection::open(config.store_path()).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        17
    );
    assert_eq!(
        connection
            .query_row("SELECT status FROM scans WHERE id=?1", [&scan_id], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
        "cancelled"
    );
}

#[test]
fn p1a_runner_drains_legacy_candidates_in_bounded_pages_before_unblocking_queue() {
    const LEGACY_CANDIDATE_COUNT: usize = 65;

    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let service = DepgraphService::new(config.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let completion = match runtime
        .block_on(service.scan_deferred_cancellable(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            CancellationToken::new(),
        ))
        .unwrap()
    {
        DeferredScanServiceOutcome::Pending(completion) => completion,
        DeferredScanServiceOutcome::Finished(_) => panic!("scan did not leave staging"),
    };
    let original_scan_id = completion.outcome().outcome().scan_id.clone();
    drop(completion);

    let connection = rusqlite::Connection::open(config.store_path()).unwrap();
    let columns = connection
        .prepare("PRAGMA table_info(scans)")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    let column_list = columns.join(", ");
    let selected_columns = columns
        .iter()
        .map(|column| {
            if column == "id" {
                "?1".to_owned()
            } else {
                column.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let clone_scan = format!(
        "INSERT INTO scans ({column_list})
             SELECT {selected_columns} FROM scans WHERE id=?2"
    );
    for index in 1..LEGACY_CANDIDATE_COUNT {
        connection
            .execute(
                &clone_scan,
                rusqlite::params![format!("legacy-page-scan-{index:03}"), original_scan_id],
            )
            .unwrap();
    }
    connection
        .execute_batch(
            "DROP TABLE scan_operation_staging;
                 PRAGMA user_version=16;",
        )
        .unwrap();
    drop(connection);

    let submitted_at_ms = system_now_ms().unwrap();
    let mut journal = OperationJournal::open(&config).unwrap();
    let queued_operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"queued-after-legacy-scan-pages",
                submitted_at_ms + 60_000,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    assert_eq!(report.claimed(), 1);
    assert_eq!(report.completed(), 1);
    assert!(matches!(
        OperationJournal::open(&config).unwrap().result(
            &repository,
            &queued_operation_id,
            system_now_ms().unwrap(),
        ),
        Ok(OperationOutcome::Completed(_))
    ));
    let store = rusqlite::Connection::open(config.store_path()).unwrap();
    let sentinel_prefix = "__depgraph_reserved_legacy_scan_operation_candidate__:";
    assert_eq!(
        store
            .query_row(
                "SELECT COUNT(*) FROM scan_operation_staging
                      WHERE substr(operation_id, 1, length(?1))=?1",
                [sentinel_prefix],
                |row| row.get::<_, u64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .query_row(
                "SELECT COUNT(*) FROM scans
                      WHERE status='cancelled'
                        AND (id=?1 OR id GLOB 'legacy-page-scan-*')",
                [&original_scan_id],
                |row| row.get::<_, usize>(0),
            )
            .unwrap(),
        LEGACY_CANDIDATE_COUNT
    );
}

#[test]
fn scan_completion_recovery_rejects_forged_envelope_and_staging_bindings() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let service = DepgraphService::new(config.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(service.scan_cancellable(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            CancellationToken::new(),
        ))
        .unwrap();
    std::fs::write(
        config.canonical_root().join("scan-recovery-binding.rs"),
        "pub fn changed() {}\n",
    )
    .unwrap();
    let base_snapshot_id = service
        .start_snapshot_request("current")
        .unwrap()
        .snapshot_id()
        .as_str()
        .to_owned();
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 30_000;
    let lease = b"scan-recovery-binding-token";
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"scan-recovery-binding",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("scan-recovery-binding-runner").unwrap(),
            lease,
            submitted_at_ms + 1,
            deadline_ms,
        )
        .unwrap();
    let mut completion = match runtime
        .block_on(service.scan_deferred_cancellable_for_operation(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            operation_id.as_str(),
            CancellationToken::new(),
        ))
        .unwrap()
    {
        DeferredScanServiceOutcome::Pending(completion) => completion,
        DeferredScanServiceOutcome::Finished(_) => panic!("scan did not defer completion"),
    };
    let dispatcher = ScanOperationDispatcher::new(config.clone());
    let valid_result = dispatcher.completed_output(completion.outcome()).unwrap();
    let scan_id = completion.outcome().outcome().scan_id.clone();
    let expected_snapshot_id = completion
        .outcome()
        .completed_snapshot_id()
        .unwrap()
        .as_str()
        .to_owned();
    completion
        .bind_recovery_result_digest(
            JournalDigest::sha256(valid_result.as_str().as_bytes()).as_bytes(),
        )
        .unwrap();
    journal
        .commit_completion_intent(
            &repository,
            &operation_id,
            lease,
            valid_result.clone(),
            submitted_at_ms + 2,
        )
        .unwrap();
    drop(completion);

    let replace_intent_result = |value: serde_json::Value| {
        let result = CanonicalJson::new(value).unwrap();
        let digest = JournalDigest::sha256(result.as_str().as_bytes());
        rusqlite::Connection::open(journal.path())
            .unwrap()
            .execute(
                "UPDATE operation_completion_intents
                        SET result_json=?1, result_digest=?2
                      WHERE operation_id=?3",
                rusqlite::params![
                    result.as_str(),
                    digest.as_bytes().as_slice(),
                    operation_id.as_str()
                ],
            )
            .unwrap();
    };
    let assert_still_staging = || {
        let store = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            store
                .query_row("SELECT status FROM scans WHERE id=?1", [&scan_id], |row| {
                    row.get::<_, String>(0)
                },)
                .unwrap(),
            "staging"
        );
        assert_eq!(
            depgraph_core::open_store_read_only(config.store_path())
                .unwrap()
                .current_snapshot_id()
                .unwrap()
                .as_deref(),
            Some(base_snapshot_id.as_str())
        );
    };

    let valid_value = valid_result.value().clone();
    let mut forged_results = Vec::new();
    let mut forged = valid_value.clone();
    forged["contract_version"] = json!("depgraph-mcp-tools-v2");
    forged_results.push(forged);
    let mut forged = valid_value.clone();
    forged["repository_id"] = json!("repo:forged");
    forged_results.push(forged);
    let mut forged = valid_value.clone();
    forged["snapshot_id"] =
        json!("snapshot:sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    forged_results.push(forged);
    let mut forged = valid_value.clone();
    forged["result"]["scan_id"] = json!("forged-scan");
    forged_results.push(forged);
    let mut forged = valid_value.clone();
    forged["result"]["status"] = json!("partial");
    forged_results.push(forged);
    let mut forged = valid_value.clone();
    forged["result"]["project_code_executed"] = json!(true);
    forged_results.push(forged);
    let mut forged = valid_value.clone();
    forged["result"]["cache"]["hits"] = json!(1);
    forged_results.push(forged);
    let mut forged = valid_value.clone();
    forged["result"]["cache"]["misses"] = json!(1);
    forged_results.push(forged);
    let mut forged = valid_value.clone();
    forged["result"]["coverage"]["files_discovered"] = json!(1);
    forged_results.push(forged);

    let mut recovery_dispatcher = ScanOperationDispatcher::new(config.clone());
    for forged in forged_results {
        replace_intent_result(forged);
        let intent = journal
            .next_completion_intent(&repository, submitted_at_ms + 3)
            .unwrap()
            .unwrap();
        assert!(recovery_dispatcher.recover_completion(&intent).is_err());
        assert_still_staging();
    }
    replace_intent_result(valid_value);

    let store_binding = rusqlite::Connection::open(config.store_path()).unwrap();
    for (column, forged_sql) in [
        ("repository_binding_digest", "zeroblob(32)"),
        ("configuration_digest", "zeroblob(32)"),
        ("strict", "1-strict"),
        ("cache_enabled", "1-cache_enabled"),
        ("base_snapshot_id", "'forged-base'"),
        ("validated_mutation_count", "validated_mutation_count+1"),
        ("prospective_snapshot_id", "'forged-snapshot'"),
        ("result_digest", "zeroblob(32)"),
    ] {
        let original: rusqlite::types::Value = store_binding
            .query_row(
                &format!("SELECT {column} FROM scan_operation_staging WHERE operation_id=?1"),
                [operation_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        store_binding
            .execute(
                &format!(
                    "UPDATE scan_operation_staging SET {column}={forged_sql}
                          WHERE operation_id=?1"
                ),
                [operation_id.as_str()],
            )
            .unwrap();
        let intent = journal
            .next_completion_intent(&repository, submitted_at_ms + 3)
            .unwrap()
            .unwrap();
        assert!(recovery_dispatcher.recover_completion(&intent).is_err());
        assert_still_staging();
        store_binding
            .execute(
                &format!(
                    "UPDATE scan_operation_staging SET {column}=?1
                          WHERE operation_id=?2"
                ),
                rusqlite::params![original, operation_id.as_str()],
            )
            .unwrap();
    }
    drop(store_binding);

    let intent = journal
        .next_completion_intent(&repository, submitted_at_ms + 3)
        .unwrap()
        .unwrap();
    assert_eq!(
        recovery_dispatcher.recover_completion(&intent).unwrap(),
        CompletionRecovery::Finalized
    );
    assert_eq!(
        recovery_dispatcher.recover_completion(&intent).unwrap(),
        CompletionRecovery::Finalized
    );
    journal
        .finish_completion_intent(&repository, &operation_id, submitted_at_ms + 3)
        .unwrap();
    assert_eq!(
        service
            .start_snapshot_request("current")
            .unwrap()
            .snapshot_id()
            .as_str(),
        expected_snapshot_id
    );
}

#[test]
fn p1b_decided_scan_recovers_after_live_configuration_changes_without_current_rollback() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 60_000;
    let lease = b"decision-config-recovery-token";
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"decision-config-recovery",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("decision-config-recovery-runner").unwrap(),
            lease,
            submitted_at_ms + 1,
            deadline_ms,
        )
        .unwrap();

    let service = DepgraphService::new(config.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut completion = match runtime
        .block_on(service.scan_deferred_cancellable_for_operation(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            operation_id.as_str(),
            CancellationToken::new(),
        ))
        .unwrap()
    {
        DeferredScanServiceOutcome::Pending(completion) => completion,
        DeferredScanServiceOutcome::Finished(_) => panic!("scan did not defer completion"),
    };
    let scan_id = completion.outcome().outcome().scan_id.clone();
    let decided_snapshot_id = completion
        .outcome()
        .completed_snapshot_id()
        .unwrap()
        .as_str()
        .to_owned();
    let result = ScanOperationDispatcher::new(config.clone())
        .completed_output(completion.outcome())
        .unwrap();
    completion
        .bind_recovery_result_digest(JournalDigest::sha256(result.as_str().as_bytes()).as_bytes())
        .unwrap();
    assert_eq!(
        journal
            .commit_completion_intent(
                &repository,
                &operation_id,
                lease,
                result,
                submitted_at_ms + 2,
            )
            .unwrap(),
        CompletionDecision::Committed
    );
    drop(completion);
    drop(journal);

    std::fs::write(
        config.canonical_root().join(".depgraph.toml"),
        "schema_version = 1\n[scan]\nworker_timeout_seconds = 301\n",
    )
    .unwrap();
    let newer_scan_id = "decision-config-newer-current";
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
    let mut store = depgraph_core::open_store(config.store_path()).unwrap();
    store
        .start_scan_with_revision(
            newer_scan_id,
            config.canonical_root(),
            false,
            Some("decision-config-newer-current-revision"),
        )
        .unwrap();
    for event in [
        json!({
            "event": "scan_started",
            "protocol_version": "1.0",
            "scan_id": newer_scan_id,
            "adapter": "fixture",
            "adapter_version": "1.0",
            "seq": 1,
            "root": config.canonical_root(),
            "project_code_executed": false,
            "safe_mode": true
        }),
        json!({
            "event": "scan_completed",
            "protocol_version": "1.0",
            "scan_id": newer_scan_id,
            "adapter": "fixture",
            "adapter_version": "1.0",
            "seq": 2,
            "coverage": coverage
        }),
    ] {
        store.ingest_event(&event).unwrap();
    }
    store
        .finish_scan(newer_scan_id, "completed", None, true)
        .unwrap();
    let newer_snapshot_id = store.current_snapshot_id().unwrap().unwrap();
    drop(store);
    assert_ne!(newer_snapshot_id, decided_snapshot_id);

    let report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap();
    assert_eq!(report.completed(), 1);
    let journal = OperationJournal::open(&config).unwrap();
    assert!(matches!(
        journal.result(&repository, &operation_id, system_now_ms().unwrap()),
        Ok(OperationOutcome::Completed(_))
    ));
    assert!(
        journal
            .next_completion_intent(&repository, system_now_ms().unwrap())
            .unwrap()
            .is_none()
    );
    let store = depgraph_core::open_store_read_only(config.store_path()).unwrap();
    assert_eq!(
        store.current_snapshot_id().unwrap().as_deref(),
        Some(newer_snapshot_id.as_str())
    );
    assert_eq!(
        rusqlite::Connection::open(config.store_path())
            .unwrap()
            .query_row("SELECT status FROM scans WHERE id=?1", [&scan_id], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
        "completed"
    );
}

#[test]
fn p1b_tampered_decision_time_configuration_evidence_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 60_000;
    let lease = b"tampered-config-evidence-token";
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"strict": false, "no_cache": true}),
                b"tampered-config-evidence",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("tampered-config-evidence-runner").unwrap(),
            lease,
            submitted_at_ms + 1,
            deadline_ms,
        )
        .unwrap();
    let service = DepgraphService::new(config.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut completion = match runtime
        .block_on(service.scan_deferred_cancellable_for_operation(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            operation_id.as_str(),
            CancellationToken::new(),
        ))
        .unwrap()
    {
        DeferredScanServiceOutcome::Pending(completion) => completion,
        DeferredScanServiceOutcome::Finished(_) => panic!("scan did not defer completion"),
    };
    let scan_id = completion.outcome().outcome().scan_id.clone();
    let result = ScanOperationDispatcher::new(config.clone())
        .completed_output(completion.outcome())
        .unwrap();
    completion
        .bind_recovery_result_digest(JournalDigest::sha256(result.as_str().as_bytes()).as_bytes())
        .unwrap();
    journal
        .commit_completion_intent(
            &repository,
            &operation_id,
            lease,
            result,
            submitted_at_ms + 2,
        )
        .unwrap();
    drop(completion);
    drop(journal);

    rusqlite::Connection::open(config.store_path())
        .unwrap()
        .execute(
            "UPDATE scan_operation_staging
                    SET configuration_digest=zeroblob(32)
                  WHERE operation_id=?1",
            [operation_id.as_str()],
        )
        .unwrap();

    let recovery_error = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        ScanOperationDispatcher::new(config.clone()),
    )
    .run_until_idle()
    .unwrap_err();
    assert!(matches!(
        recovery_error,
        RunnerError::Service(
            DepgraphServiceError::MutatingStoreUnavailable { .. }
                | DepgraphServiceError::StoreOperation { .. }
        )
    ));
    let journal = OperationJournal::open(&config).unwrap();
    assert_eq!(
        journal
            .next_completion_intent(&repository, system_now_ms().unwrap())
            .unwrap()
            .unwrap()
            .operation_id(),
        &operation_id
    );
    assert_eq!(
        rusqlite::Connection::open(config.store_path())
            .unwrap()
            .query_row("SELECT status FROM scans WHERE id=?1", [&scan_id], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
        "staging"
    );
}

#[test]
fn guardian_cancels_the_dispatch_token_when_cancellation_is_requested() {
    // Wake after one second, but leave enough renewed lease headroom for a
    // contended CI runner to terminalize cancellation without losing ownership.
    const LEASE_DURATION_MS: i64 = 5_000;
    const RENEWAL_MARGIN_MS: i64 = 4_000;

    struct CancellationAwareDispatcher {
        started: mpsc::SyncSender<()>,
    }

    impl OperationDispatcher for CancellationAwareDispatcher {
        fn dispatch(
            &mut self,
            _work: &RunnerWork,
            control: &mut ExecutionControl<'_>,
        ) -> DispatchOutcome {
            let cancellation = control.cancellation_token().clone();
            self.started.send(()).expect("dispatcher start signal");
            let timeout = std::time::Instant::now() + Duration::from_secs(5);
            while !cancellation.is_cancelled() {
                assert!(
                    std::time::Instant::now() < timeout,
                    "guardian did not cancel the dispatch token"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            DispatchOutcome::Cancelled
        }
    }

    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 10_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"guardian_cancellation": true}),
                b"guardian-cancellation-token",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let (dispatch_started, wait_for_dispatch) = mpsc::sync_channel(0);
    let (guardian_events, _wait_for_guardian) = mpsc::channel();
    let runner = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        CancellationAwareDispatcher {
            started: dispatch_started,
        },
    )
    .with_lease_timing_for_test(LEASE_DURATION_MS, RENEWAL_MARGIN_MS, guardian_events);
    let runner_thread = std::thread::spawn(move || runner.run_until_idle());
    wait_for_dispatch
        .recv_timeout(Duration::from_secs(5))
        .expect("dispatcher starts");

    let mut journal = OperationJournal::open(&config).unwrap();
    journal
        .cancel(
            &repository,
            &operation_id,
            &CapabilitySet::new([
                depgraph_mcp_tools::AgentCapability::Read,
                depgraph_mcp_tools::AgentCapability::StoreWrite,
            ])
            .unwrap(),
            system_now_ms().unwrap(),
        )
        .unwrap();

    let report = runner_thread.join().unwrap().unwrap();
    assert_eq!(report.claimed(), 1);
    assert_eq!(report.cancelled(), 1);
    assert_eq!(report.completed(), 0);
    assert!(matches!(
        journal
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap(),
        OperationOutcome::Cancelled
    ));
}

#[test]
fn guardian_prevents_reclaim_while_dispatch_blocks_past_original_lease() {
    const LEASE_DURATION_MS: i64 = 500;
    const RENEWAL_MARGIN_MS: i64 = 400;

    let root = tempfile::tempdir().unwrap();
    let config = config(root.path());
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let submitted_at_ms = system_now_ms().unwrap();
    let deadline_ms = submitted_at_ms + 10_000;
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"blocking": true}),
                b"guardian-blocking-dispatch",
                deadline_ms,
            )
            .unwrap(),
            submitted_at_ms,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let calls = Arc::new(AtomicUsize::new(0));
    let competing_calls = Arc::new(AtomicUsize::new(0));
    let (dispatch_started, wait_for_dispatch) = mpsc::sync_channel(0);
    let (release_dispatch, wait_for_release) = mpsc::sync_channel(0);
    let (guardian_events, wait_for_guardian) = mpsc::channel();
    let runner = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        BlockingDispatcher {
            calls: Arc::clone(&calls),
            started: dispatch_started,
            release: wait_for_release,
        },
    )
    .with_lease_timing_for_test(LEASE_DURATION_MS, RENEWAL_MARGIN_MS, guardian_events);
    let runner_thread = std::thread::spawn(move || runner.run_until_idle());

    let dispatch_started_at_ms = wait_for_dispatch
        .recv_timeout(Duration::from_secs(5))
        .expect("dispatcher start signal");
    let original_lease_expires_at_ms = match wait_for_guardian
        .recv_timeout(Duration::from_secs(5))
        .expect("guardian start signal")
    {
        LeaseGuardianEvent::Started {
            lease_expires_at_ms,
        } => lease_expires_at_ms,
        event => panic!("unexpected first guardian event: {event:?}"),
    };
    assert!(dispatch_started_at_ms < original_lease_expires_at_ms);

    let active_lease_expires_at_ms = loop {
        match wait_for_guardian
            .recv_timeout(Duration::from_secs(5))
            .expect("guardian renewal signal")
        {
            LeaseGuardianEvent::Renewed {
                renewed_at_ms,
                lease_expires_at_ms,
            } if renewed_at_ms >= original_lease_expires_at_ms => {
                break lease_expires_at_ms;
            }
            LeaseGuardianEvent::Renewed { .. } => {}
            event => panic!("unexpected guardian event after startup: {event:?}"),
        }
    };
    let competing_at_ms = system_now_ms().unwrap();
    assert!(competing_at_ms >= original_lease_expires_at_ms);
    assert!(active_lease_expires_at_ms > competing_at_ms);

    let mut competing_journal = OperationJournal::open(&config).unwrap();
    assert!(matches!(
        competing_journal.acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("competing-blocked-runner").unwrap(),
            b"competing-blocked-token",
            competing_at_ms,
            (competing_at_ms + LEASE_DURATION_MS).min(deadline_ms),
        ),
        Err(JournalError::LeaseHeld)
    ));

    struct CompetingDispatcher(Arc<AtomicUsize>);
    impl OperationDispatcher for CompetingDispatcher {
        fn dispatch(
            &mut self,
            _work: &RunnerWork,
            _control: &mut ExecutionControl<'_>,
        ) -> DispatchOutcome {
            self.0.fetch_add(1, Ordering::SeqCst);
            DispatchOutcome::Cancelled
        }
    }
    let competing_report = OperationRunner::new(
        RunnerStartupConfig::new(config.clone()).unwrap(),
        CompetingDispatcher(Arc::clone(&competing_calls)),
    )
    .run_until_idle()
    .unwrap();
    assert_eq!(competing_report.claimed(), 0);
    assert_eq!(competing_calls.load(Ordering::SeqCst), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    release_dispatch.send(()).unwrap();
    let report = runner_thread.join().unwrap().unwrap();
    assert_eq!(report.claimed(), 1);
    assert_eq!(report.completed(), 1);
    assert_eq!(report.failed(), 0);
    assert_eq!(report.cancelled(), 0);
    assert_eq!(report.lease_lost(), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let journal = OperationJournal::open(&config).unwrap();
    match journal
        .result(&repository, &operation_id, system_now_ms().unwrap())
        .unwrap()
    {
        OperationOutcome::Completed(result) => {
            assert_eq!(result.as_str(), r#"{"completed":true}"#);
        }
        outcome => panic!("unexpected terminal outcome: {outcome:?}"),
    }
    assert!(
        journal
            .runner_handoff(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap()
            .completed_at_ms()
            .is_some()
    );
}
