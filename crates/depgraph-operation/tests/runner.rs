use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use depgraph_core::{
    DepgraphCapability, DepgraphCapabilitySet, DepgraphService, DepgraphServiceConfig,
    DepgraphServiceLimits,
};
use depgraph_mcp_tools::LogicalRepositoryId;
use depgraph_operation::{
    CanonicalJson, DispatchOutcome, EXECUTION_STATE_UNKNOWN_ERROR_JSON, ExecutionControl,
    OperationDispatcher, OperationJournal, OperationKind, OperationOutcome, OperationRunner,
    OperationStatus, RunnerStartupConfig, RunnerWork, ScanOperationDispatcher, SubmitRequest,
    UNSUPPORTED_OPERATION_ERROR_JSON, UnsupportedOperationDispatcher,
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
