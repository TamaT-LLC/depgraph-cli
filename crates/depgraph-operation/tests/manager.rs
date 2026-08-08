use std::path::Path;

use depgraph_core::{
    DepgraphCapability, DepgraphCapabilitySet, DepgraphServiceConfig, DepgraphServiceLimits,
};
use depgraph_mcp_tools::LogicalRepositoryId;
use depgraph_operation::{
    CancelOutcome, CanonicalJson, JournalError, LeaseOwner, OperationJournal, OperationKind,
    OperationManager, OperationOutcome, OperationStatus, SubmitRequest, operation_journal_path,
};
use rusqlite::Connection;
use serde_json::json;
use sha2::{Digest as _, Sha256};

const NOW: i64 = 1_800_000_000_000;
const DEADLINE: i64 = NOW + 60_000;

fn service_config(
    root: &Path,
    graph_store: &Path,
    capabilities: impl IntoIterator<Item = DepgraphCapability>,
) -> DepgraphServiceConfig {
    let repository_root = root.join("repo-primary");
    std::fs::create_dir_all(&repository_root).unwrap();
    DepgraphServiceConfig::new(
        repository_root,
        graph_store,
        DepgraphCapabilitySet::try_new(capabilities).unwrap(),
        DepgraphServiceLimits::default(),
    )
    .unwrap()
}

fn full_config(root: &Path, graph_store: &Path) -> DepgraphServiceConfig {
    service_config(
        root,
        graph_store,
        [DepgraphCapability::Read, DepgraphCapability::StoreWrite],
    )
}

fn read_only_config(root: &Path, graph_store: &Path) -> DepgraphServiceConfig {
    service_config(root, graph_store, [DepgraphCapability::Read])
}

fn repository(config: &DepgraphServiceConfig) -> LogicalRepositoryId {
    LogicalRepositoryId::parse(config.logical_repository_id()).unwrap()
}

fn submit_request(
    config: &DepgraphServiceConfig,
    input: serde_json::Value,
    key: &[u8],
) -> SubmitRequest {
    SubmitRequest::new(config, OperationKind::ScanSubmit, &input, key, DEADLINE).unwrap()
}

fn journal_state_digest(path: &Path) -> [u8; 32] {
    let connection = Connection::open(path).unwrap();
    let mut digest = Sha256::new();
    for query in [
        "SELECT * FROM operations ORDER BY operation_id",
        "SELECT * FROM runner_handoffs ORDER BY operation_id",
        "SELECT * FROM operation_tombstones ORDER BY operation_id",
    ] {
        digest.update((query.len() as u64).to_le_bytes());
        digest.update(query.as_bytes());
        let mut statement = connection.prepare(query).unwrap();
        let column_count = statement.column_count();
        let mut rows = statement.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            digest.update([0xff]);
            for index in 0..column_count {
                use rusqlite::types::ValueRef;
                match row.get_ref(index).unwrap() {
                    ValueRef::Null => digest.update([0]),
                    ValueRef::Integer(value) => {
                        digest.update([1]);
                        digest.update(value.to_le_bytes());
                    }
                    ValueRef::Real(value) => {
                        digest.update([2]);
                        digest.update(value.to_bits().to_le_bytes());
                    }
                    ValueRef::Text(value) => {
                        digest.update([3]);
                        digest.update((value.len() as u64).to_le_bytes());
                        digest.update(value);
                    }
                    ValueRef::Blob(value) => {
                        digest.update([4]);
                        digest.update((value.len() as u64).to_le_bytes());
                        digest.update(value);
                    }
                }
            }
        }
    }
    digest.finalize().into()
}

#[test]
fn submit_returns_only_after_the_record_and_runner_handoff_are_committed() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = full_config(root.path(), &graph_store);
    let request = submit_request(
        &config,
        json!({"secret_input": "not-agent-visible", "z": 2, "a": 1}),
        b"accepted-after-handoff",
    );
    let mut manager = OperationManager::open(&config).unwrap();

    let handle = manager.submit(&request, NOW).unwrap();

    assert!(handle.created());
    assert_eq!(handle.status(), OperationStatus::Queued);
    assert_eq!(handle.progress().completed_units(), 0);
    assert_eq!(handle.progress().total_units(), 1);
    assert_eq!(handle.timestamps().created_at_ms(), NOW);
    assert_eq!(handle.timestamps().updated_at_ms(), NOW);
    assert_eq!(handle.timestamps().terminal_at_ms(), None);
    assert_eq!(handle.retention().execution_deadline_ms(), DEADLINE);
    assert!(handle.retention().retain_until_ms() > DEADLINE);
    assert!(!format!("{handle:?}").contains("secret_input"));

    let journal = OperationJournal::open(&config).unwrap();
    let handoff = journal
        .runner_handoff(&repository(&config), handle.operation_id(), NOW)
        .unwrap();
    assert_eq!(handoff.operation_id(), handle.operation_id());
    assert_eq!(
        handoff.payload().as_str(),
        r#"{"a":1,"secret_input":"not-agent-visible","z":2}"#
    );
    assert_eq!(handoff.enqueued_at_ms(), NOW);
}

#[test]
fn submit_same_key_retry_reuses_the_handle_and_conflict_does_not_add_work() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = full_config(root.path(), &graph_store);
    let mut manager = OperationManager::open(&config).unwrap();
    let first = submit_request(&config, json!({"z": 2, "a": 1}), b"same-key");
    let retry = submit_request(&config, json!({"a": 1, "z": 2}), b"same-key");
    let conflict = submit_request(&config, json!({"a": 2, "z": 2}), b"same-key");

    let created = manager.submit(&first, NOW).unwrap();
    let resolved = manager.submit(&retry, NOW + 1).unwrap();

    assert!(created.created());
    assert!(!resolved.created());
    assert_eq!(created.operation_id(), resolved.operation_id());
    assert_eq!(created.operation_id().as_str().len(), 35);
    assert!(matches!(
        manager.submit(&conflict, NOW + 2),
        Err(JournalError::IdempotencyConflict)
    ));
    let connection = Connection::open(operation_journal_path(&config)).unwrap();
    let counts: (i64, i64) = (
        connection
            .query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))
            .unwrap(),
        connection
            .query_row("SELECT COUNT(*) FROM runner_handoffs", [], |row| row.get(0))
            .unwrap(),
    );
    assert_eq!(counts, (1, 1));
}

#[test]
fn read_only_reopened_manager_can_get_and_resolve_a_terminal_result() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let full = full_config(root.path(), &graph_store);
    let repository = repository(&full);
    let mut manager = OperationManager::open(&full).unwrap();
    let operation_id = manager
        .submit(
            &submit_request(&full, json!({"value": 1}), b"authorized-reads"),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(manager);

    let mut journal = OperationJournal::open(&full).unwrap();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("manager-test-runner").unwrap(),
            b"manager-test-lease",
            NOW + 1,
            NOW + 10_000,
        )
        .unwrap();
    journal
        .complete(
            &repository,
            &operation_id,
            b"manager-test-lease",
            CanonicalJson::new(json!({"answer": 42})).unwrap(),
            NOW + 2,
        )
        .unwrap();
    drop(journal);

    let read_only = read_only_config(root.path(), &graph_store);
    let manager = OperationManager::open(&read_only).unwrap();
    let status = manager.get(&operation_id, NOW + 3).unwrap();
    assert_eq!(status.status(), OperationStatus::Completed);
    assert_eq!(status.timestamps().terminal_at_ms(), Some(NOW + 2));
    assert!(!format!("{status:?}").contains("manager-test-lease"));
    match manager.result(&operation_id, NOW + 3).unwrap().outcome() {
        OperationOutcome::Completed(payload) => {
            assert_eq!(payload.as_str(), r#"{"answer":42}"#);
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn result_rejects_a_nonterminal_operation() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = full_config(root.path(), &graph_store);
    let mut manager = OperationManager::open(&config).unwrap();
    let operation_id = manager
        .submit(
            &submit_request(&config, json!({"value": 1}), b"not-ready"),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();

    assert!(matches!(
        manager.result(&operation_id, NOW + 1),
        Err(JournalError::OperationNotReady)
    ));
}

#[test]
fn read_only_cancel_preserves_digest_status_lease_and_handoff_then_full_cancel_succeeds() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = full_config(root.path(), &graph_store);
    let repository = repository(&config);
    let mut manager = OperationManager::open(&config).unwrap();
    let operation_id = manager
        .submit(
            &submit_request(&config, json!({"value": 1}), b"cancel-auth"),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(manager);

    let mut journal = OperationJournal::open(&config).unwrap();
    let before_record = journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("cancel-runner").unwrap(),
            b"cancel-lease",
            NOW + 1,
            NOW + 10_000,
        )
        .unwrap();
    let before_handoff = journal
        .runner_handoff(&repository, &operation_id, NOW + 1)
        .unwrap();
    let path = journal.path().to_path_buf();
    let before_digest = journal_state_digest(&path);
    drop(journal);

    let read_only = read_only_config(root.path(), &graph_store);
    let mut downgraded = OperationManager::open(&read_only).unwrap();
    assert!(matches!(
        downgraded.cancel(&operation_id, NOW + 2),
        Err(JournalError::CapabilityDenied)
    ));
    assert_eq!(journal_state_digest(&path), before_digest);
    drop(downgraded);

    let journal = OperationJournal::open(&config).unwrap();
    assert_eq!(
        journal.get(&repository, &operation_id, NOW + 2).unwrap(),
        before_record
    );
    assert_eq!(
        journal
            .runner_handoff(&repository, &operation_id, NOW + 2)
            .unwrap(),
        before_handoff
    );
    drop(journal);

    let mut manager = OperationManager::open(&config).unwrap();
    assert_eq!(
        manager.cancel(&operation_id, NOW + 3).unwrap(),
        CancelOutcome::Requested
    );
    assert_eq!(
        manager.get(&operation_id, NOW + 3).unwrap().status(),
        OperationStatus::Cancelling
    );
}

#[test]
fn terminal_cancel_is_a_successful_noop() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = full_config(root.path(), &graph_store);
    let repository = repository(&config);
    let mut manager = OperationManager::open(&config).unwrap();
    let operation_id = manager
        .submit(
            &submit_request(&config, json!({"value": 1}), b"terminal-cancel"),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(manager);

    let mut journal = OperationJournal::open(&config).unwrap();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("terminal-runner").unwrap(),
            b"terminal-lease",
            NOW + 1,
            NOW + 10_000,
        )
        .unwrap();
    journal
        .complete(
            &repository,
            &operation_id,
            b"terminal-lease",
            CanonicalJson::new(json!({"ok": true})).unwrap(),
            NOW + 2,
        )
        .unwrap();
    let path = journal.path().to_path_buf();
    let before_digest = journal_state_digest(&path);
    drop(journal);

    let mut manager = OperationManager::open(&config).unwrap();
    assert_eq!(
        manager.cancel(&operation_id, NOW + 3).unwrap(),
        CancelOutcome::TerminalNoOp
    );
    assert_eq!(journal_state_digest(&path), before_digest);
    match manager.result(&operation_id, NOW + 3).unwrap().outcome() {
        OperationOutcome::Completed(payload) => assert_eq!(payload.as_str(), r#"{"ok":true}"#),
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn manager_reopens_the_same_handle_and_terminal_result_after_restart() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = full_config(root.path(), &graph_store);
    let repository = repository(&config);
    let request = submit_request(&config, json!({"value": 1}), b"restart-manager");
    let mut manager = OperationManager::open(&config).unwrap();
    let operation_id = manager
        .submit(&request, NOW)
        .unwrap()
        .operation_id()
        .clone();
    drop(manager);

    let mut restarted = OperationManager::open(&config).unwrap();
    let recovered = restarted.get(&operation_id, NOW + 1).unwrap();
    assert_eq!(recovered.status(), OperationStatus::Queued);
    let retried = restarted.submit(&request, NOW + 1).unwrap();
    assert_eq!(retried.operation_id(), &operation_id);
    assert!(!retried.created());
    drop(restarted);

    let mut journal = OperationJournal::open(&config).unwrap();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("restart-runner").unwrap(),
            b"restart-lease",
            NOW + 2,
            NOW + 10_000,
        )
        .unwrap();
    journal
        .fail(
            &repository,
            &operation_id,
            b"restart-lease",
            CanonicalJson::new(json!({"code": "typed_failure"})).unwrap(),
            NOW + 3,
        )
        .unwrap();
    drop(journal);

    let read_only = read_only_config(root.path(), &graph_store);
    let restarted = OperationManager::open(&read_only).unwrap();
    match restarted.result(&operation_id, NOW + 4).unwrap().outcome() {
        OperationOutcome::Failed(error) => {
            assert_eq!(error.as_str(), r#"{"code":"typed_failure"}"#);
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn same_basename_different_roots_cannot_share_manager_handles() {
    let first_parent = tempfile::tempdir().unwrap();
    let second_parent = tempfile::tempdir().unwrap();
    let shared_store_parent = tempfile::tempdir().unwrap();
    let graph_store = shared_store_parent.path().join("graph.sqlite");
    let first = full_config(first_parent.path(), &graph_store);
    let second = full_config(second_parent.path(), &graph_store);
    assert_eq!(
        first.logical_repository_id(),
        second.logical_repository_id()
    );
    assert_ne!(first.canonical_root(), second.canonical_root());

    let mut manager = OperationManager::open(&first).unwrap();
    manager
        .submit(
            &submit_request(&first, json!({"value": 1}), b"root-binding"),
            NOW,
        )
        .unwrap();
    drop(manager);

    assert!(matches!(
        OperationManager::open(&second),
        Err(JournalError::RepositoryMismatch)
    ));
    assert!(matches!(
        OperationJournal::open(&second),
        Err(JournalError::RepositoryMismatch)
    ));
}

#[test]
fn same_basename_cross_root_submit_request_cannot_reuse_idempotent_work() {
    let first_parent = tempfile::tempdir().unwrap();
    let second_parent = tempfile::tempdir().unwrap();
    let graph_store = first_parent.path().join("graph.sqlite");
    let first = full_config(first_parent.path(), &graph_store);
    let second = full_config(
        second_parent.path(),
        &second_parent.path().join("graph.sqlite"),
    );
    assert_eq!(
        first.logical_repository_id(),
        second.logical_repository_id()
    );
    assert_ne!(first.canonical_root(), second.canonical_root());

    let first_request = submit_request(&first, json!({"value": 1}), b"cross-root-request");
    let second_request = submit_request(&second, json!({"value": 1}), b"cross-root-request");
    let mut manager = OperationManager::open(&first).unwrap();
    manager.submit(&first_request, NOW).unwrap();
    let path = operation_journal_path(&first);
    let before_digest = journal_state_digest(path.as_path());

    assert!(matches!(
        manager.submit(&second_request, NOW + 1),
        Err(JournalError::RepositoryMismatch)
    ));
    assert_eq!(journal_state_digest(path.as_path()), before_digest);

    let root_digest = second.repository_root_seal().binding_digest();
    let root_digest_hex: String = root_digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert!(!format!("{second_request:?}").contains(&root_digest_hex));
}

#[test]
fn root_replacement_after_open_rejects_every_lifecycle_call_without_mutation() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = full_config(root.path(), &graph_store);
    let request = submit_request(&config, json!({"value": 1}), b"replace-root");
    let mut manager = OperationManager::open(&config).unwrap();
    let operation_id = manager
        .submit(&request, NOW)
        .unwrap()
        .operation_id()
        .clone();
    let path = operation_journal_path(&config);
    let before_digest = journal_state_digest(path.as_path());

    let original_root = config.canonical_root().to_path_buf();
    std::fs::rename(&original_root, root.path().join("original-repository")).unwrap();
    std::fs::create_dir(&original_root).unwrap();

    assert!(matches!(
        manager.get(&operation_id, NOW + 1),
        Err(JournalError::RepositoryMismatch)
    ));
    assert_eq!(journal_state_digest(path.as_path()), before_digest);
    assert!(matches!(
        manager.result(&operation_id, NOW + 1),
        Err(JournalError::RepositoryMismatch)
    ));
    assert_eq!(journal_state_digest(path.as_path()), before_digest);
    assert!(matches!(
        manager.cancel(&operation_id, NOW + 1),
        Err(JournalError::RepositoryMismatch)
    ));
    assert_eq!(journal_state_digest(path.as_path()), before_digest);
    assert!(matches!(
        manager.submit(&request, NOW + 1),
        Err(JournalError::RepositoryMismatch)
    ));
    assert_eq!(journal_state_digest(path.as_path()), before_digest);
}
