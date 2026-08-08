use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use depgraph_core::{
    DepgraphCapability, DepgraphCapabilitySet, DepgraphServiceConfig, DepgraphServiceLimits,
};
use depgraph_mcp_tools::{
    AgentCapability, LogicalRepositoryId, MAX_TASK_TTL_MS, OperationBehavior, OperationId,
    ToolCatalog,
};
use depgraph_operation::{
    CancelOutcome, CanonicalJson, CapabilitySet, DEADLINE_EXCEEDED_ERROR_JSON,
    EXECUTION_STATE_UNKNOWN_ERROR_JSON, JOURNAL_SCHEMA_VERSION, JournalDigest, JournalError,
    LeaseOwner, MAX_CAPABILITY_JSON_BYTES, MAX_OPERATION_INPUT_BYTES, MAX_PURGE_BATCH_SIZE,
    MAX_TERMINAL_PAYLOAD_BYTES, OperationJournal, OperationKind, OperationOutcome,
    OperationProgress, OperationStatus, SubmitRequest, TERMINAL_RETENTION_MS,
    TOMBSTONE_RETENTION_MS, operation_journal_path,
};
use rusqlite::{Connection, params};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

const NOW: i64 = 1_800_000_000_000;
const DEADLINE: i64 = NOW + 60_000;

fn repository() -> LogicalRepositoryId {
    LogicalRepositoryId::parse("repo-primary").unwrap()
}

fn other_repository() -> LogicalRepositoryId {
    LogicalRepositoryId::parse("repo:other").unwrap()
}

fn kind() -> OperationKind {
    OperationKind::ScanSubmit
}

fn read_capabilities() -> CapabilitySet {
    CapabilitySet::new([AgentCapability::Read]).unwrap()
}

fn write_capabilities() -> CapabilitySet {
    CapabilitySet::new([AgentCapability::StoreWrite, AgentCapability::Read]).unwrap()
}

fn request(
    config: &DepgraphServiceConfig,
    input: serde_json::Value,
    key: &[u8],
    deadline: i64,
) -> SubmitRequest {
    request_for_kind(config, kind(), input, key, deadline)
}

fn request_for_kind(
    config: &DepgraphServiceConfig,
    operation_kind: OperationKind,
    input: serde_json::Value,
    key: &[u8],
    deadline: i64,
) -> SubmitRequest {
    SubmitRequest::new(config, operation_kind, &input, key, deadline).unwrap()
}

fn service_config(root: &Path, graph_store: &Path) -> DepgraphServiceConfig {
    service_config_with_capabilities(
        root,
        graph_store,
        [
            DepgraphCapability::Read,
            DepgraphCapability::StoreWrite,
            DepgraphCapability::DaemonControl,
            DepgraphCapability::ProjectExec,
        ],
    )
}

fn service_config_with_capabilities(
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

fn open_journal(root: &Path, graph_store: &Path) -> OperationJournal {
    OperationJournal::open(&service_config(root, graph_store)).unwrap()
}

fn journal() -> (TempDir, PathBuf, DepgraphServiceConfig, OperationJournal) {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = service_config(root.path(), &graph_store);
    let journal = OperationJournal::open(&config).unwrap();
    (root, graph_store, config, journal)
}

fn assert_integrity_failure(journal: &OperationJournal, operation_id: &OperationId) {
    assert!(matches!(
        journal.get(&repository(), operation_id, NOW + 1),
        Err(JournalError::IntegrityFailure)
    ));
    assert!(matches!(
        journal.runner_handoff(&repository(), operation_id, NOW + 1),
        Err(JournalError::IntegrityFailure)
    ));
    assert!(matches!(
        journal.validate(),
        Err(JournalError::IntegrityFailure)
    ));
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

fn assert_capability_denied_without_mutation<T>(
    path: &Path,
    expected_digest: [u8; 32],
    outcome: Result<T, JournalError>,
) {
    assert!(matches!(outcome, Err(JournalError::CapabilityDenied)));
    assert_eq!(journal_state_digest(path), expected_digest);
}

#[test]
fn journal_path_is_deterministic_and_separate_from_graph_store() {
    let root = tempfile::tempdir().unwrap();
    let store = root.path().join("state/graph.sqlite");
    let config = service_config(root.path(), &store);
    let first = operation_journal_path(&config);
    let second = operation_journal_path(&config);

    assert_eq!(first, second);
    assert_ne!(first.as_path(), config.store_path());
    let mut expected = config.store_path().as_os_str().to_os_string();
    expected.push(".operations.sqlite");
    assert_eq!(first.as_path(), PathBuf::from(expected));

    let (_root, graph_store, config, journal) = journal();
    assert_eq!(journal.path(), operation_journal_path(&config).as_path());
    assert!(!graph_store.exists());
    assert!(journal.path().exists());
}

#[cfg(unix)]
#[test]
fn precreated_journal_symlink_is_rejected_without_modifying_its_target() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = service_config(root.path(), &graph_store);
    let journal_path = operation_journal_path(&config);
    let target = root.path().join("unrelated.sqlite");
    Connection::open(&target)
        .unwrap()
        .execute_batch("CREATE TABLE marker(value TEXT); INSERT INTO marker VALUES ('unchanged');")
        .unwrap();
    let before = std::fs::read(&target).unwrap();
    symlink(&target, journal_path.as_path()).unwrap();

    assert!(matches!(
        OperationJournal::open(&config),
        Err(JournalError::Io(_))
    ));
    assert_eq!(std::fs::read(&target).unwrap(), before);
    let marker: String = Connection::open(&target)
        .unwrap()
        .query_row("SELECT value FROM marker", [], |row| row.get(0))
        .unwrap();
    assert_eq!(marker, "unchanged");
    assert!(
        !Connection::open(&target)
            .unwrap()
            .table_exists(None, "operations")
            .unwrap()
    );
}

#[test]
fn operation_kind_is_closed_over_the_durable_submit_catalog() {
    let kinds = [
        (OperationKind::ScanSubmit, "scan_submit"),
        (
            OperationKind::RuntimeTraceImportSubmit,
            "runtime_trace_import_submit",
        ),
        (OperationKind::DaemonStartSubmit, "daemon_start_submit"),
        (OperationKind::DaemonStop, "daemon_stop"),
        (OperationKind::ResolveBuildSubmit, "resolve_build_submit"),
    ];
    for (kind, encoded) in kinds {
        assert_eq!(kind.as_str(), encoded);
        assert_eq!(OperationKind::parse(encoded).unwrap(), kind);
    }
    assert!(matches!(
        OperationKind::parse("snapshot_create"),
        Err(JournalError::InvalidArgument)
    ));
}

#[test]
fn operation_kind_and_capabilities_do_not_drift_from_the_production_tool_catalog() {
    let full_capabilities = DepgraphCapabilitySet::try_new([
        DepgraphCapability::Read,
        DepgraphCapability::StoreWrite,
        DepgraphCapability::RepositoryWrite,
        DepgraphCapability::DaemonControl,
        DepgraphCapability::ProjectExec,
    ])
    .unwrap();
    let catalog = ToolCatalog::for_capabilities(&full_capabilities).unwrap();
    let mut durable_tools: BTreeMap<_, _> = catalog
        .tools()
        .iter()
        .filter(|tool| {
            tool.operation_behavior() == OperationBehavior::AlwaysCreatesDurableOperation
        })
        .map(|tool| (tool.name(), tool.required_capabilities()))
        .collect();

    assert_eq!(durable_tools.len(), OperationKind::ALL.len());
    for kind in OperationKind::ALL {
        assert_eq!(
            durable_tools.remove(kind.as_str()).unwrap(),
            kind.capability_profile().required_capabilities(),
            "capability drift for {}",
            kind.as_str()
        );
    }
    assert!(durable_tools.is_empty());
}

#[test]
fn every_closed_operation_kind_is_accepted_by_the_production_schema() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = service_config(root.path(), &graph_store);
    let mut journal = OperationJournal::open(&config).unwrap();

    for kind in OperationKind::ALL {
        let request = SubmitRequest::new(
            &config,
            kind,
            &json!({}),
            kind.as_str().as_bytes(),
            DEADLINE,
        )
        .unwrap();
        let submitted = journal.submit(&request, NOW).unwrap();
        assert_eq!(submitted.record().kind(), &kind);
        assert_eq!(
            journal
                .runner_handoff(&repository(), submitted.operation_id(), NOW + 1)
                .unwrap()
                .operation_kind(),
            kind
        );
    }
    journal.validate().unwrap();
}

#[test]
fn submit_binding_is_derived_from_config_and_kind_and_rechecked_by_the_journal() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let read_only =
        service_config_with_capabilities(root.path(), &graph_store, [DepgraphCapability::Read]);
    assert!(matches!(
        SubmitRequest::new(
            &read_only,
            OperationKind::ScanSubmit,
            &json!({}),
            b"read-only",
            DEADLINE
        ),
        Err(JournalError::CapabilityDenied)
    ));

    let store_write = service_config_with_capabilities(
        root.path(),
        &graph_store,
        [DepgraphCapability::Read, DepgraphCapability::StoreWrite],
    );
    let scan = SubmitRequest::new(
        &store_write,
        OperationKind::ScanSubmit,
        &json!({}),
        b"scan",
        DEADLINE,
    )
    .unwrap();
    assert_eq!(scan.repository_id(), &repository());
    assert_eq!(scan.required_capabilities(), &write_capabilities());
    assert!(matches!(
        SubmitRequest::new(
            &store_write,
            OperationKind::DaemonStop,
            &json!({}),
            b"daemon-stop",
            DEADLINE
        ),
        Err(JournalError::CapabilityDenied)
    ));

    let mut read_only_journal = OperationJournal::open(&read_only).unwrap();
    assert!(matches!(
        read_only_journal.submit(&scan, NOW),
        Err(JournalError::CapabilityDenied)
    ));
}

#[test]
fn submit_request_retains_bounded_canonical_normalized_input() {
    let root = tempfile::tempdir().unwrap();
    let config = service_config(root.path(), &root.path().join("request.sqlite"));
    let input = json!({"z": 2, "a": 1});
    let request = request(&config, input, b"canonical-input", DEADLINE);
    assert_eq!(request.normalized_input().as_str(), r#"{"a":1,"z":2}"#);
    assert_eq!(request.normalized_input().digest(), request.input_digest());

    let maximum = json!("x".repeat(MAX_OPERATION_INPUT_BYTES - 2));
    assert!(SubmitRequest::new(&config, kind(), &maximum, b"maximum-input", DEADLINE,).is_ok());
    let oversized = json!("x".repeat(MAX_OPERATION_INPUT_BYTES - 1));
    assert!(matches!(
        SubmitRequest::new(&config, kind(), &oversized, b"oversized-input", DEADLINE,),
        Err(JournalError::InvalidArgument)
    ));
}

#[test]
fn task_ttl_bound_includes_terminal_retention_at_the_exact_boundary() {
    let (_root, _graph_store, config, mut journal) = journal();
    let maximum_ttl = i64::try_from(MAX_TASK_TTL_MS).unwrap();
    let boundary_deadline = NOW + maximum_ttl - TERMINAL_RETENTION_MS;
    let accepted = journal
        .submit(
            &request(
                &config,
                json!({"boundary": true}),
                b"ttl-boundary",
                boundary_deadline,
            ),
            NOW,
        )
        .unwrap();
    assert_eq!(accepted.record().retain_until_ms(), NOW + maximum_ttl);

    assert!(matches!(
        journal.submit(
            &request(
                &config,
                json!({"boundary": false}),
                b"ttl-over-boundary",
                boundary_deadline + 1
            ),
            NOW
        ),
        Err(JournalError::InvalidArgument)
    ));
    assert!(matches!(
        journal.submit(
            &request(
                &config,
                json!({"overflow": true}),
                b"ttl-overflow",
                i64::MAX,
            ),
            i64::MAX - 1
        ),
        Err(JournalError::InvalidArgument)
    ));
}

#[test]
fn current_schema_integrity_binding_metadata_and_required_objects_are_validated() {
    let (_root, _graph_store, _config, journal) = journal();
    assert_eq!(journal.schema_version().unwrap(), JOURNAL_SCHEMA_VERSION);
    journal.validate().unwrap();

    let connection = Connection::open(journal.path()).unwrap();
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    let handoff_columns: Vec<String> = connection
        .prepare("PRAGMA table_info(runner_handoffs)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        handoff_columns,
        [
            "operation_id",
            "operation_kind",
            "payload_json",
            "payload_digest",
            "enqueued_at_ms",
            "claimed_at_ms",
            "completed_at_ms",
        ]
    );
    let metadata_columns: Vec<String> = connection
        .prepare("PRAGMA table_info(operation_journal_metadata)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        metadata_columns,
        ["singleton", "metadata_version", "repository_binding_digest"]
    );
    let metadata: (i64, i64, String) = connection
        .query_row(
            "SELECT metadata_version, length(repository_binding_digest),
                    typeof(repository_binding_digest)
             FROM operation_journal_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(metadata, (1, 32, "blob".to_owned()));
    let (foreign_table, on_delete): (String, String) = connection
        .query_row("PRAGMA foreign_key_list(runner_handoffs)", [], |row| {
            Ok((row.get(2)?, row.get(6)?))
        })
        .unwrap();
    assert_eq!(
        (foreign_table.as_str(), on_delete.as_str()),
        ("operations", "CASCADE")
    );
    let claim_index_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'index' AND name = 'operations_runner_claim_next'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        claim_index_sql,
        concat!(
            "CREATE INDEX operations_runner_claim_next\n",
            "    ON operations(repository_id, created_at_ms, operation_id)\n",
            "    WHERE status IN ('queued', 'running', 'cancelling')"
        )
    );
    let deadline_index_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'index' AND name = 'operations_deadline_purge'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        deadline_index_sql,
        concat!(
            "CREATE INDEX operations_deadline_purge\n",
            "    ON operations(execution_deadline_ms, operation_id)\n",
            "    WHERE status IN ('queued', 'running', 'cancelling')"
        )
    );
    let deadline_plan: Vec<String> = connection
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT substr(operation_id, 1, 36) FROM operations
             WHERE status IN ('queued', 'running', 'cancelling')
               AND execution_deadline_ms <= ?1
             ORDER BY execution_deadline_ms, operation_id
             LIMIT ?2",
        )
        .unwrap()
        .query_map(params![DEADLINE, MAX_PURGE_BATCH_SIZE as i64], |row| {
            row.get(3)
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(
        deadline_plan
            .iter()
            .any(|detail| detail.contains("operations_deadline_purge")),
        "deadline purge query must use its bounded-order index: {deadline_plan:?}"
    );
    let retention_index_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'index' AND name = 'operations_retention'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        retention_index_sql,
        concat!(
            "CREATE INDEX operations_retention\n",
            "    ON operations(retain_until_ms, operation_id)\n",
            "    WHERE status IN ('completed', 'failed', 'cancelled')"
        )
    );
    let retention_plan: Vec<String> = connection
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT substr(operation_id, 1, 36) FROM operations
             WHERE status IN ('completed', 'failed', 'cancelled')
               AND retain_until_ms <= ?1
             ORDER BY retain_until_ms, operation_id
             LIMIT ?2",
        )
        .unwrap()
        .query_map(params![DEADLINE, MAX_PURGE_BATCH_SIZE as i64], |row| {
            row.get(3)
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(
        retention_plan
            .iter()
            .any(|detail| detail.contains("operations_retention")),
        "terminal retention query must use its bounded-order index: {retention_plan:?}"
    );
    connection
        .execute_batch("DROP INDEX operations_idempotency_scope")
        .unwrap();
    assert!(matches!(
        journal.validate(),
        Err(JournalError::IntegrityFailure)
    ));

    let extra_root = tempfile::tempdir().unwrap();
    let extra_store = extra_root.path().join("graph.sqlite");
    let extra = open_journal(extra_root.path(), &extra_store);
    Connection::open(extra.path())
        .unwrap()
        .execute_batch("CREATE INDEX unexpected_operation_index ON operations(status)")
        .unwrap();
    assert!(matches!(
        extra.validate(),
        Err(JournalError::IntegrityFailure)
    ));

    let second_root = tempfile::tempdir().unwrap();
    let store = second_root.path().join("graph.sqlite");
    let config = service_config(second_root.path(), &store);
    let second = OperationJournal::open(&config).unwrap();
    let path = second.path().to_path_buf();
    drop(second);
    Connection::open(&path)
        .unwrap()
        .execute_batch("PRAGMA user_version = 4")
        .unwrap();
    assert!(matches!(
        OperationJournal::open(&config),
        Err(JournalError::UnsupportedSchemaVersion)
    ));

    let corrupt_root = tempfile::tempdir().unwrap();
    let corrupt_store = corrupt_root.path().join("graph.sqlite");
    let corrupt_config = service_config(corrupt_root.path(), &corrupt_store);
    let corrupt_path = operation_journal_path(&corrupt_config);
    std::fs::write(&corrupt_path, b"not a SQLite database").unwrap();
    assert!(matches!(
        OperationJournal::open(&corrupt_config),
        Err(JournalError::IntegrityFailure)
    ));
}

#[test]
fn empty_issue_307_schema_migrates_atomically() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = service_config(root.path(), &graph_store);
    let journal = OperationJournal::open(&config).unwrap();
    let path = journal.path().to_path_buf();
    drop(journal);

    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "DROP TABLE operation_completion_intents;
             DROP TABLE operation_journal_metadata;
             PRAGMA user_version = 1;",
        )
        .unwrap();

    let migrated = OperationJournal::open(&config).unwrap();
    assert_eq!(migrated.schema_version().unwrap(), JOURNAL_SCHEMA_VERSION);
    migrated.validate().unwrap();
}

#[test]
fn root_bound_v2_journal_with_queued_work_migrates_completion_intents_atomically() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = service_config(root.path(), &graph_store);
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &request(
                &config,
                json!({"migration": "v2-to-v3"}),
                b"v2-completion-intent-migration",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    let path = journal.path().to_path_buf();
    drop(journal);
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "DROP TABLE operation_completion_intents;
             PRAGMA user_version = 2;",
        )
        .unwrap();

    let migrated = OperationJournal::open(&config).unwrap();

    assert_eq!(migrated.schema_version().unwrap(), JOURNAL_SCHEMA_VERSION);
    assert_eq!(
        migrated
            .get(&repository(), &operation_id, NOW + 1)
            .unwrap()
            .status(),
        OperationStatus::Queued
    );
    migrated.validate().unwrap();
}

type LegacySchemaObject = (String, String, String, String);

#[derive(Debug, Eq, PartialEq)]
struct LegacyDatabaseSnapshot {
    rows_digest: [u8; 32],
    version: i64,
    schema: Vec<LegacySchemaObject>,
}

fn legacy_database_snapshot(path: &Path) -> LegacyDatabaseSnapshot {
    let connection = Connection::open(path).unwrap();
    let version = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    let schema = connection
        .prepare(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema
             WHERE sql IS NOT NULL ORDER BY type, name",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    LegacyDatabaseSnapshot {
        rows_digest: journal_state_digest(path),
        version,
        schema,
    }
}

fn assert_nonempty_v1_fails_closed(config: &DepgraphServiceConfig, path: &Path) {
    let before = legacy_database_snapshot(path);
    assert!(matches!(
        OperationJournal::open(config),
        Err(JournalError::IntegrityFailure)
    ));
    assert_eq!(legacy_database_snapshot(path), before);
    assert!(
        !Connection::open(path)
            .unwrap()
            .table_exists(None, "operation_journal_metadata")
            .unwrap()
    );
}

#[test]
fn nonempty_issue_307_operations_and_handoffs_fail_closed_without_migration() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = service_config(root.path(), &graph_store);
    let mut journal = OperationJournal::open(&config).unwrap();
    let request = SubmitRequest::new(
        &config,
        kind(),
        &json!({"value": 1}),
        b"legacy-operation",
        DEADLINE,
    )
    .unwrap();
    journal.submit(&request, NOW).unwrap();
    let path = journal.path().to_path_buf();
    drop(journal);
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "DROP TABLE operation_journal_metadata;
             PRAGMA user_version = 1;",
        )
        .unwrap();

    assert_nonempty_v1_fails_closed(&config, &path);
}

#[test]
fn nonempty_issue_307_tombstones_fail_closed_without_migration() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = service_config(root.path(), &graph_store);
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let mut journal = OperationJournal::open(&config).unwrap();
    let request = SubmitRequest::new(
        &config,
        kind(),
        &json!({"value": 1}),
        b"legacy-tombstone",
        DEADLINE,
    )
    .unwrap();
    let operation_id = journal
        .submit(&request, NOW)
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("legacy-runner").unwrap(),
            b"legacy-lease",
            NOW + 1,
            NOW + 10_000,
        )
        .unwrap();
    journal
        .complete(
            &repository,
            &operation_id,
            b"legacy-lease",
            CanonicalJson::new(json!({"ok": true})).unwrap(),
            NOW + 2,
        )
        .unwrap();
    journal.purge(DEADLINE + TERMINAL_RETENTION_MS).unwrap();
    let path = journal.path().to_path_buf();
    drop(journal);
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "DROP TABLE operation_journal_metadata;
             PRAGMA user_version = 1;",
        )
        .unwrap();

    assert_nonempty_v1_fails_closed(&config, &path);
}

#[test]
fn same_basename_wrong_root_cannot_claim_a_nonempty_issue_307_journal() {
    let first_parent = tempfile::tempdir().unwrap();
    let second_parent = tempfile::tempdir().unwrap();
    let store_parent = tempfile::tempdir().unwrap();
    let graph_store = store_parent.path().join("graph.sqlite");
    let first = service_config(first_parent.path(), &graph_store);
    let second = service_config(second_parent.path(), &graph_store);
    assert_eq!(
        first.logical_repository_id(),
        second.logical_repository_id()
    );
    assert_ne!(first.canonical_root(), second.canonical_root());
    let mut journal = OperationJournal::open(&first).unwrap();
    let request = SubmitRequest::new(
        &first,
        kind(),
        &json!({"value": 1}),
        b"unproven-v1-root",
        DEADLINE,
    )
    .unwrap();
    journal.submit(&request, NOW).unwrap();
    let path = journal.path().to_path_buf();
    drop(journal);
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "DROP TABLE operation_journal_metadata;
             PRAGMA user_version = 1;",
        )
        .unwrap();

    assert_nonempty_v1_fails_closed(&second, &path);
}

#[test]
fn already_open_journal_rejects_runner_reads_and_mutations_after_root_replacement() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = service_config(root.path(), &graph_store);
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let mut journal = OperationJournal::open(&config).unwrap();
    let request = SubmitRequest::new(
        &config,
        kind(),
        &json!({"value": 1}),
        b"open-journal-root-replacement",
        DEADLINE,
    )
    .unwrap();
    let operation_id = journal
        .submit(&request, NOW)
        .unwrap()
        .operation_id()
        .clone();
    let path = journal.path().to_path_buf();
    let before_digest = journal_state_digest(&path);

    let original_root = config.canonical_root().to_path_buf();
    std::fs::rename(&original_root, root.path().join("original-repository")).unwrap();
    std::fs::create_dir(&original_root).unwrap();

    assert!(matches!(
        journal.get(&repository, &operation_id, NOW + 1),
        Err(JournalError::RepositoryMismatch)
    ));
    assert!(matches!(
        journal.runner_handoff(&repository, &operation_id, NOW + 1),
        Err(JournalError::RepositoryMismatch)
    ));
    assert!(matches!(
        journal.claim_next_runner_handoff(
            &repository,
            &LeaseOwner::parse("replacement-claim").unwrap(),
            b"replacement-claim-token",
            NOW + 1,
            NOW + 10_000,
        ),
        Err(JournalError::RepositoryMismatch)
    ));
    assert!(matches!(
        journal.acquire_lease(
            &repository,
            &operation_id,
            &LeaseOwner::parse("replacement-acquire").unwrap(),
            b"replacement-acquire-token",
            NOW + 1,
            NOW + 10_000,
        ),
        Err(JournalError::RepositoryMismatch)
    ));
    assert!(matches!(
        journal.update_progress(
            &repository,
            &operation_id,
            b"replacement-token",
            OperationProgress::new(0, 1).unwrap(),
            NOW + 1,
        ),
        Err(JournalError::RepositoryMismatch)
    ));
    assert!(matches!(
        journal.complete(
            &repository,
            &operation_id,
            b"replacement-token",
            CanonicalJson::new(json!({"ok": true})).unwrap(),
            NOW + 1,
        ),
        Err(JournalError::RepositoryMismatch)
    ));
    assert!(matches!(
        journal.cancel(&repository, &operation_id, &write_capabilities(), NOW + 1),
        Err(JournalError::RepositoryMismatch)
    ));
    assert_eq!(journal_state_digest(&path), before_digest);
}

#[test]
fn issue_307_migration_rejects_unexpected_schema_without_partial_metadata() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = service_config(root.path(), &graph_store);
    let journal = OperationJournal::open(&config).unwrap();
    let path = journal.path().to_path_buf();
    drop(journal);
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "DROP TABLE operation_journal_metadata;
             CREATE TABLE unexpected_legacy_state(value TEXT);
             PRAGMA user_version = 1;",
        )
        .unwrap();

    assert!(matches!(
        OperationJournal::open(&config),
        Err(JournalError::IntegrityFailure)
    ));
    let connection = Connection::open(&path).unwrap();
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 1);
    assert!(
        !connection
            .table_exists(None, "operation_journal_metadata")
            .unwrap()
    );
}

#[test]
fn schema_enforces_octet_limits_before_canonical_payload_decoding() {
    let (_root, _graph_store, config, mut journal) = journal();
    let operation_id = journal
        .submit(
            &request(
                &config,
                json!({"value": 1}),
                b"schema-octet-limits",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    let connection = Connection::open(journal.path()).unwrap();
    let operations_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'operations'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(operations_sql.contains("octet_length(required_capabilities_json)"));
    assert!(operations_sql.contains("octet_length(input_json)"));
    assert!(operations_sql.contains("octet_length(result_json)"));
    assert!(operations_sql.contains("octet_length(error_json)"));
    let handoff_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'runner_handoffs'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(handoff_sql.contains("octet_length(payload_json)"));
    let tombstone_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'operation_tombstones'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(tombstone_sql.contains("octet_length(required_capabilities_json)"));

    assert!(
        connection
            .execute(
                "UPDATE operations SET input_json = ?1 WHERE operation_id = ?2",
                params![
                    "x".repeat(MAX_OPERATION_INPUT_BYTES + 1),
                    operation_id.as_str()
                ],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE operations SET required_capabilities_json = ?1 WHERE operation_id = ?2",
                params![
                    "x".repeat(MAX_CAPABILITY_JSON_BYTES + 1),
                    operation_id.as_str()
                ],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE runner_handoffs SET payload_json = ?1 WHERE operation_id = ?2",
                params![
                    "x".repeat(MAX_OPERATION_INPUT_BYTES + 1),
                    operation_id.as_str()
                ],
            )
            .is_err()
    );
    journal.validate().unwrap();
}

#[test]
fn operation_and_runner_handoff_are_created_in_one_immediate_transaction() {
    let (_root, _graph_store, config, mut journal) = journal();
    Connection::open(journal.path())
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_runner_handoff
             BEFORE INSERT ON runner_handoffs
             BEGIN
                 SELECT RAISE(ABORT, 'test handoff rejection');
             END;",
        )
        .unwrap();

    assert!(matches!(
        journal.submit(
            &request(&config, json!({"value": 1}), b"rollback-key", DEADLINE),
            NOW
        ),
        Err(JournalError::Storage(_))
    ));
    let connection = Connection::open(journal.path()).unwrap();
    let counts: (i64, i64) = (
        connection
            .query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))
            .unwrap(),
        connection
            .query_row("SELECT COUNT(*) FROM runner_handoffs", [], |row| row.get(0))
            .unwrap(),
    );
    assert_eq!(counts, (0, 0));
}

#[test]
fn claim_next_rolls_back_lease_when_handoff_claim_update_fails() {
    let (_root, _graph_store, config, mut journal) = journal();
    let operation_id = journal
        .submit(
            &request(&config, json!({"value": 1}), b"atomic-claim-next", DEADLINE),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    Connection::open(journal.path())
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_handoff_claim
             BEFORE UPDATE OF claimed_at_ms ON runner_handoffs
             BEGIN
                 SELECT RAISE(ABORT, 'test handoff claim rejection');
             END;",
        )
        .unwrap();
    let expected_digest = journal_state_digest(journal.path());

    assert!(matches!(
        journal.claim_next_runner_handoff(
            &repository(),
            &LeaseOwner::parse("atomic-runner").unwrap(),
            b"atomic-lease",
            NOW + 1,
            NOW + 100,
        ),
        Err(JournalError::Storage(_))
    ));
    assert_eq!(journal_state_digest(journal.path()), expected_digest);
    let record = journal.get(&repository(), &operation_id, NOW + 1).unwrap();
    assert_eq!(record.status(), OperationStatus::Queued);
    assert!(record.lease().is_none());
    assert_eq!(
        journal
            .runner_handoff(&repository(), &operation_id, NOW + 1)
            .unwrap()
            .claimed_at_ms(),
        None
    );
}

#[test]
fn validation_runs_foreign_key_check_and_requires_one_handoff_per_operation() {
    let (_missing_root, _missing_store, missing_config, mut missing_journal) = journal();
    let operation_id = missing_journal
        .submit(
            &request(
                &missing_config,
                json!({"value": 1}),
                b"missing-handoff",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    Connection::open(missing_journal.path())
        .unwrap()
        .execute(
            "DELETE FROM runner_handoffs WHERE operation_id = ?1",
            params![operation_id.as_str()],
        )
        .unwrap();
    assert_integrity_failure(&missing_journal, &operation_id);

    let (_orphan_root, _orphan_store, _orphan_config, orphan_journal) = journal();
    let orphan_payload = json!({});
    let orphan_digest = JournalDigest::canonical_json(&orphan_payload).unwrap();
    let connection = Connection::open(orphan_journal.path()).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = OFF")
        .unwrap();
    connection
        .execute(
            "INSERT INTO runner_handoffs (
                operation_id, operation_kind, payload_json, payload_digest,
                enqueued_at_ms, claimed_at_ms, completed_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL)",
            params![
                "op_550e8400e29b41d4a716446655440000",
                OperationKind::ScanSubmit.as_str(),
                "{}",
                orphan_digest.as_bytes().as_slice(),
                NOW,
            ],
        )
        .unwrap();
    assert!(matches!(
        orphan_journal.validate(),
        Err(JournalError::IntegrityFailure)
    ));
}

#[test]
fn identical_retry_returns_one_128_bit_random_id_and_stores_only_key_digest() {
    let (_root, _graph_store, config, mut journal) = journal();
    let first = request(
        &config,
        json!({"z": 2, "a": 1}),
        b"idempotency-secret",
        DEADLINE,
    );
    let retry = request(
        &config,
        json!({"a": 1, "z": 2}),
        b"idempotency-secret",
        DEADLINE,
    );

    let created = journal.submit(&first, NOW).unwrap();
    assert!(matches!(
        journal.submit(&retry, NOW - 1),
        Err(JournalError::IntegrityFailure)
    ));
    let resolved = journal.submit(&retry, NOW + 1).unwrap();
    let resolved_after_deadline = journal.submit(&retry, DEADLINE + 1).unwrap();

    assert!(created.created());
    assert!(!resolved.created());
    assert!(!resolved_after_deadline.created());
    assert_eq!(created.operation_id(), resolved.operation_id());
    assert_eq!(
        created.operation_id(),
        resolved_after_deadline.operation_id()
    );
    assert_eq!(created.operation_id().as_str().len(), 35);
    let suffix = created.operation_id().as_str().strip_prefix("op_").unwrap();
    assert_eq!(suffix.len(), 32);
    assert!(
        suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );

    let handoff = journal
        .runner_handoff(&repository(), created.operation_id(), NOW + 1)
        .unwrap();
    assert_eq!(handoff.operation_id(), created.operation_id());
    assert_eq!(handoff.operation_kind(), OperationKind::ScanSubmit);
    assert_eq!(handoff.payload().as_str(), r#"{"a":1,"z":2}"#);
    assert_eq!(handoff.payload_digest(), created.record().input_digest());
    assert_eq!(handoff.enqueued_at_ms(), NOW);
    assert_eq!(handoff.claimed_at_ms(), None);
    assert_eq!(handoff.completed_at_ms(), None);

    let connection = Connection::open(journal.path()).unwrap();
    let counts: (i64, i64) = (
        connection
            .query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))
            .unwrap(),
        connection
            .query_row("SELECT COUNT(*) FROM runner_handoffs", [], |row| row.get(0))
            .unwrap(),
    );
    let (kind, length, digest): (String, i64, Vec<u8>) = connection
        .query_row(
            "SELECT typeof(idempotency_key_digest), length(idempotency_key_digest),
                    idempotency_key_digest FROM operations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(counts, (1, 1));
    assert_eq!(kind, "blob");
    assert_eq!(length, 32);
    assert_ne!(digest, b"idempotency-secret");
}

#[test]
fn scoped_key_reuse_rejects_input_conflicts() {
    let (_root, _graph_store, config, mut journal) = journal();
    journal
        .submit(
            &request(&config, json!({"value": 1}), b"same-key", DEADLINE),
            NOW,
        )
        .unwrap();

    assert!(matches!(
        journal.submit(
            &request(&config, json!({"value": 2}), b"same-key", DEADLINE),
            NOW + 1
        ),
        Err(JournalError::IdempotencyConflict)
    ));
    let connection = Connection::open(journal.path()).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn repository_mismatch_and_forged_capability_digest_fail_closed() {
    let (_root, _graph_store, config, mut journal) = journal();
    let submitted = journal
        .submit(
            &request(&config, json!({"value": 1}), b"key", DEADLINE),
            NOW,
        )
        .unwrap();
    let operation_id = submitted.operation_id().clone();

    assert!(matches!(
        journal.get(&other_repository(), &operation_id, NOW + 1),
        Err(JournalError::RepositoryMismatch)
    ));
    assert!(matches!(
        journal.runner_handoff(&other_repository(), &operation_id, NOW + 1),
        Err(JournalError::RepositoryMismatch)
    ));

    Connection::open(journal.path())
        .unwrap()
        .execute(
            "UPDATE operations SET required_capabilities_digest = ?1
             WHERE operation_id = ?2",
            params![vec![0x5a_u8; 32], operation_id.as_str()],
        )
        .unwrap();
    assert!(matches!(
        journal.get(&repository(), &operation_id, NOW + 1),
        Err(JournalError::IntegrityFailure)
    ));
    assert!(matches!(
        journal.validate(),
        Err(JournalError::IntegrityFailure)
    ));
}

#[test]
fn canonical_but_wrong_capability_binding_fails_closed_for_operations_and_tombstones() {
    let (_root, _graph_store, operation_config, mut operation_journal) = journal();
    let submitted = operation_journal
        .submit(
            &request(
                &operation_config,
                json!({"value": 1}),
                b"wrong-capability-binding",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap();
    let operation_id = submitted.operation_id().clone();
    let wrong_json = r#"["read"]"#;
    let wrong_digest = JournalDigest::sha256(wrong_json);
    Connection::open(operation_journal.path())
        .unwrap()
        .execute(
            "UPDATE operations
             SET required_capabilities_json = ?1, required_capabilities_digest = ?2
             WHERE operation_id = ?3",
            params![
                wrong_json,
                wrong_digest.as_bytes().as_slice(),
                operation_id.as_str()
            ],
        )
        .unwrap();
    assert_integrity_failure(&operation_journal, &operation_id);

    let (_tombstone_root, _tombstone_store, tombstone_config, mut tombstone_journal) = journal();
    let submitted = tombstone_journal
        .submit(
            &request(
                &tombstone_config,
                json!({"value": 1}),
                b"wrong-tombstone-binding",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap();
    let tombstone_id = submitted.operation_id().clone();
    let expiry = submitted.record().retain_until_ms();
    tombstone_journal.purge(expiry).unwrap();
    Connection::open(tombstone_journal.path())
        .unwrap()
        .execute(
            "UPDATE operation_tombstones
             SET required_capabilities_json = ?1, required_capabilities_digest = ?2
             WHERE operation_id = ?3",
            params![
                wrong_json,
                wrong_digest.as_bytes().as_slice(),
                tombstone_id.as_str()
            ],
        )
        .unwrap();
    assert!(matches!(
        tombstone_journal.get(&repository(), &tombstone_id, expiry + 1),
        Err(JournalError::IntegrityFailure)
    ));
    assert!(matches!(
        tombstone_journal.validate(),
        Err(JournalError::IntegrityFailure)
    ));
}

#[test]
fn canonical_operation_input_tampering_fails_closed() {
    let (_json_root, _json_store, json_config, mut json_journal) = journal();
    let json_operation_id = json_journal
        .submit(
            &request(
                &json_config,
                json!({"value": 1}),
                b"operation-json-tamper",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    let noncanonical = r#"{ "value": 1 }"#;
    let noncanonical_digest = JournalDigest::sha256(noncanonical);
    Connection::open(json_journal.path())
        .unwrap()
        .execute(
            "UPDATE operations SET input_json = ?1, input_digest = ?2 WHERE operation_id = ?3",
            params![
                noncanonical,
                noncanonical_digest.as_bytes().as_slice(),
                json_operation_id.as_str()
            ],
        )
        .unwrap();
    assert_integrity_failure(&json_journal, &json_operation_id);

    let (_digest_root, _digest_store, digest_config, mut digest_journal) = journal();
    let digest_operation_id = digest_journal
        .submit(
            &request(
                &digest_config,
                json!({"value": 1}),
                b"operation-digest-tamper",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    Connection::open(digest_journal.path())
        .unwrap()
        .execute(
            "UPDATE operations SET input_digest = ?1 WHERE operation_id = ?2",
            params![vec![0x5a_u8; 32], digest_operation_id.as_str()],
        )
        .unwrap();
    assert_integrity_failure(&digest_journal, &digest_operation_id);
}

#[test]
fn handoff_payload_and_digest_tampering_fail_closed() {
    let (_payload_root, _payload_store, payload_config, mut payload_journal) = journal();
    let payload_operation_id = payload_journal
        .submit(
            &request(
                &payload_config,
                json!({"value": 1}),
                b"handoff-payload-tamper",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    let forged_payload = json!({"value": 2});
    let forged_digest = JournalDigest::canonical_json(&forged_payload).unwrap();
    Connection::open(payload_journal.path())
        .unwrap()
        .execute(
            "UPDATE runner_handoffs SET payload_json = ?1, payload_digest = ?2
             WHERE operation_id = ?3",
            params![
                r#"{"value":2}"#,
                forged_digest.as_bytes().as_slice(),
                payload_operation_id.as_str()
            ],
        )
        .unwrap();
    assert_integrity_failure(&payload_journal, &payload_operation_id);

    let (_digest_root, _digest_store, digest_config, mut digest_journal) = journal();
    let digest_operation_id = digest_journal
        .submit(
            &request(
                &digest_config,
                json!({"value": 1}),
                b"handoff-digest-tamper",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    Connection::open(digest_journal.path())
        .unwrap()
        .execute(
            "UPDATE runner_handoffs SET payload_digest = ?1 WHERE operation_id = ?2",
            params![vec![0x5a_u8; 32], digest_operation_id.as_str()],
        )
        .unwrap();
    assert_integrity_failure(&digest_journal, &digest_operation_id);
}

#[test]
fn handoff_kind_and_enqueue_timestamp_must_match_the_operation() {
    let (_kind_root, _kind_store, kind_config, mut kind_journal) = journal();
    let kind_operation_id = kind_journal
        .submit(
            &request(
                &kind_config,
                json!({"value": 1}),
                b"handoff-kind-tamper",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    Connection::open(kind_journal.path())
        .unwrap()
        .execute(
            "UPDATE runner_handoffs SET operation_kind = ?1 WHERE operation_id = ?2",
            params![
                OperationKind::DaemonStartSubmit.as_str(),
                kind_operation_id.as_str()
            ],
        )
        .unwrap();
    assert_integrity_failure(&kind_journal, &kind_operation_id);

    let (_time_root, _time_store, time_config, mut time_journal) = journal();
    let time_operation_id = time_journal
        .submit(
            &request(
                &time_config,
                json!({"value": 1}),
                b"handoff-time-tamper",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    Connection::open(time_journal.path())
        .unwrap()
        .execute(
            "UPDATE runner_handoffs SET enqueued_at_ms = ?1 WHERE operation_id = ?2",
            params![NOW + 1, time_operation_id.as_str()],
        )
        .unwrap();
    assert_integrity_failure(&time_journal, &time_operation_id);
}

#[test]
fn terminal_record_and_result_are_immutable_and_cancel_is_a_noop() {
    let (_root, _graph_store, config, mut journal) = journal();
    let submitted = journal
        .submit(
            &request(&config, json!({"value": 1}), b"key", DEADLINE),
            NOW,
        )
        .unwrap();
    let operation_id = submitted.operation_id().clone();
    let result = CanonicalJson::new(json!({"z": 2, "a": 1})).unwrap();

    assert!(matches!(
        journal.complete(
            &repository(),
            &operation_id,
            b"lease-token",
            result.clone(),
            NOW + 1
        ),
        Err(JournalError::InvalidTransition)
    ));
    journal
        .acquire_lease(
            &repository(),
            &operation_id,
            &LeaseOwner::parse("runner-1").unwrap(),
            b"lease-token",
            NOW + 1,
            NOW + 10_000,
        )
        .unwrap();
    let invalid_transition = Connection::open(journal.path()).unwrap().execute(
        "UPDATE operations SET status = 'queued' WHERE operation_id = ?1",
        params![operation_id.as_str()],
    );
    assert!(invalid_transition.is_err());
    let terminal = journal
        .complete(
            &repository(),
            &operation_id,
            b"lease-token",
            result,
            NOW + 2,
        )
        .unwrap();
    assert_eq!(terminal.status(), OperationStatus::Completed);
    assert_eq!(terminal.result().unwrap().as_str(), r#"{"a":1,"z":2}"#);
    assert!(terminal.lease().is_none());

    assert!(matches!(
        journal.fail(
            &repository(),
            &operation_id,
            b"lease-token",
            CanonicalJson::new(json!({"code": "late"})).unwrap(),
            NOW + 3
        ),
        Err(JournalError::InvalidTransition)
    ));
    let before_cancel = journal.get(&repository(), &operation_id, NOW + 3).unwrap();
    assert_eq!(
        journal
            .cancel(&repository(), &operation_id, &write_capabilities(), NOW + 4)
            .unwrap(),
        CancelOutcome::TerminalNoOp
    );
    let after_cancel = journal.get(&repository(), &operation_id, NOW + 4).unwrap();
    assert_eq!(before_cancel, after_cancel);

    let direct_update = Connection::open(journal.path()).unwrap().execute(
        "UPDATE operations SET result_json = '{\"forged\":true}' WHERE operation_id = ?1",
        params![operation_id.as_str()],
    );
    assert!(direct_update.is_err());
    match journal
        .result(&repository(), &operation_id, NOW + 5)
        .unwrap()
    {
        OperationOutcome::Completed(payload) => {
            assert_eq!(payload.as_str(), r#"{"a":1,"z":2}"#);
        }
        other => panic!("unexpected terminal outcome: {other:?}"),
    }
}

#[test]
fn terminal_payload_exact_byte_limit_is_writable_and_one_more_byte_is_rejected() {
    let exact = CanonicalJson::new(json!("x".repeat(MAX_TERMINAL_PAYLOAD_BYTES - 2))).unwrap();
    assert_eq!(exact.as_str().len(), MAX_TERMINAL_PAYLOAD_BYTES);
    assert!(matches!(
        CanonicalJson::new(json!("x".repeat(MAX_TERMINAL_PAYLOAD_BYTES - 1))),
        Err(JournalError::InvalidArgument)
    ));

    let (_root, _graph_store, config, mut journal) = journal();
    let operation_id = journal
        .submit(
            &request(
                &config,
                json!({"value": 1}),
                b"terminal-payload-boundary",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository(),
            &operation_id,
            &LeaseOwner::parse("payload-runner").unwrap(),
            b"payload-lease",
            NOW + 1,
            NOW + 10_000,
        )
        .unwrap();
    let completed = journal
        .complete(
            &repository(),
            &operation_id,
            b"payload-lease",
            exact,
            NOW + 2,
        )
        .unwrap();
    assert_eq!(
        completed.result().unwrap().as_str().len(),
        MAX_TERMINAL_PAYLOAD_BYTES
    );
}

#[test]
fn lease_claim_renew_expiry_reclaim_and_progress_are_enforced() {
    let (_root, _graph_store, config, mut journal) = journal();
    let submitted = journal
        .submit(
            &request(&config, json!({"value": 1}), b"key", DEADLINE)
                .with_progress_total(10)
                .unwrap(),
            NOW,
        )
        .unwrap();
    let operation_id = submitted.operation_id().clone();
    let owner_one = LeaseOwner::parse("runner-1").unwrap();
    let owner_two = LeaseOwner::parse("runner-2").unwrap();

    let claimed = journal
        .acquire_lease(
            &repository(),
            &operation_id,
            &owner_one,
            b"lease-one",
            NOW + 1,
            NOW + 100,
        )
        .unwrap();
    assert_eq!(claimed.status(), OperationStatus::Running);
    assert_eq!(claimed.lease().unwrap().owner(), &owner_one);
    assert!(matches!(
        journal.acquire_lease(
            &repository(),
            &operation_id,
            &owner_two,
            b"lease-two",
            NOW + 2,
            NOW + 200,
        ),
        Err(JournalError::LeaseHeld)
    ));
    assert!(matches!(
        journal.renew_lease(
            &repository(),
            &operation_id,
            b"wrong-token",
            NOW + 2,
            NOW + 200,
        ),
        Err(JournalError::LeaseMismatch)
    ));
    journal
        .renew_lease(
            &repository(),
            &operation_id,
            b"lease-one",
            NOW + 2,
            NOW + 200,
        )
        .unwrap();
    let progressed = journal
        .update_progress(
            &repository(),
            &operation_id,
            b"lease-one",
            OperationProgress::new(4, 10).unwrap(),
            NOW + 3,
        )
        .unwrap();
    assert_eq!(
        progressed.progress(),
        OperationProgress::new(4, 10).unwrap()
    );
    assert!(matches!(
        journal.update_progress(
            &repository(),
            &operation_id,
            b"lease-one",
            OperationProgress::new(3, 10).unwrap(),
            NOW + 4,
        ),
        Err(JournalError::InvalidArgument)
    ));
    assert!(matches!(
        journal.update_progress(
            &repository(),
            &operation_id,
            b"lease-one",
            OperationProgress::new(5, 10).unwrap(),
            NOW + 200,
        ),
        Err(JournalError::LeaseExpired)
    ));

    let reclaimed = journal
        .acquire_lease(
            &repository(),
            &operation_id,
            &owner_two,
            b"lease-two",
            NOW + 200,
            NOW + 300,
        )
        .unwrap();
    assert_eq!(reclaimed.lease().unwrap().owner(), &owner_two);
    assert!(matches!(
        journal.update_progress(
            &repository(),
            &operation_id,
            b"lease-one",
            OperationProgress::new(5, 10).unwrap(),
            NOW + 201,
        ),
        Err(JournalError::LeaseMismatch)
    ));
    let released = journal
        .release_lease(&repository(), &operation_id, b"lease-two", NOW + 202)
        .unwrap();
    assert!(released.lease().is_none());

    let connection = Connection::open(journal.path()).unwrap();
    let token: Option<Vec<u8>> = connection
        .query_row(
            "SELECT lease_token_digest FROM operations WHERE operation_id = ?1",
            params![operation_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(token.is_none());
}

#[test]
fn cancel_requires_recorded_capabilities_and_reaches_cancelled_cooperatively() {
    let (_root, _graph_store, config, mut journal) = journal();
    let submitted = journal
        .submit(
            &request(&config, json!({"value": 1}), b"key", DEADLINE),
            NOW,
        )
        .unwrap();
    let operation_id = submitted.operation_id().clone();
    let before = journal.get(&repository(), &operation_id, NOW + 1).unwrap();

    assert!(matches!(
        journal.cancel(&repository(), &operation_id, &read_capabilities(), NOW + 1),
        Err(JournalError::CapabilityDenied)
    ));
    assert_eq!(
        journal.get(&repository(), &operation_id, NOW + 1).unwrap(),
        before
    );
    assert_eq!(
        journal
            .cancel(&repository(), &operation_id, &write_capabilities(), NOW + 2)
            .unwrap(),
        CancelOutcome::Requested
    );
    let cancelling = journal.get(&repository(), &operation_id, NOW + 2).unwrap();
    assert_eq!(cancelling.status(), OperationStatus::Cancelling);
    assert_eq!(
        journal
            .cancel(&repository(), &operation_id, &write_capabilities(), NOW + 3)
            .unwrap(),
        CancelOutcome::AlreadyRequested
    );
    assert_eq!(
        journal
            .get(&repository(), &operation_id, NOW + 3)
            .unwrap()
            .updated_at_ms(),
        cancelling.updated_at_ms()
    );

    journal
        .acquire_lease(
            &repository(),
            &operation_id,
            &LeaseOwner::parse("runner-1").unwrap(),
            b"lease-token",
            NOW + 4,
            NOW + 10_000,
        )
        .unwrap();
    let cancelled = journal
        .mark_cancelled(&repository(), &operation_id, b"lease-token", NOW + 5)
        .unwrap();
    assert_eq!(cancelled.status(), OperationStatus::Cancelled);
    let terminal_before = cancelled.clone();
    assert_eq!(
        journal
            .cancel(&repository(), &operation_id, &write_capabilities(), NOW + 6)
            .unwrap(),
        CancelOutcome::TerminalNoOp
    );
    assert_eq!(
        journal.get(&repository(), &operation_id, NOW + 6).unwrap(),
        terminal_before
    );
}

#[test]
fn capability_downgrade_denies_every_runner_mutation_without_state_changes() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let full_config = service_config(root.path(), &graph_store);
    let mut journal = OperationJournal::open(&full_config).unwrap();

    let queued_id = journal
        .submit(
            &request(
                &full_config,
                json!({"state": "queued"}),
                b"downgrade-queued",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    let running_id = journal
        .submit(
            &request(
                &full_config,
                json!({"state": "running"}),
                b"downgrade-running",
                DEADLINE,
            )
            .with_progress_total(10)
            .unwrap(),
            NOW + 1,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository(),
            &running_id,
            &LeaseOwner::parse("privileged-runner").unwrap(),
            b"privileged-lease",
            NOW + 2,
            NOW + 10_000,
        )
        .unwrap();
    let terminal_id = journal
        .submit(
            &request(
                &full_config,
                json!({"state": "terminal"}),
                b"downgrade-terminal",
                DEADLINE,
            ),
            NOW + 3,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository(),
            &terminal_id,
            &LeaseOwner::parse("terminal-runner").unwrap(),
            b"terminal-lease",
            NOW + 4,
            NOW + 10_000,
        )
        .unwrap();
    journal
        .complete(
            &repository(),
            &terminal_id,
            b"terminal-lease",
            CanonicalJson::new(json!({"ok": true})).unwrap(),
            NOW + 5,
        )
        .unwrap();
    let journal_path = journal.path().to_path_buf();
    drop(journal);

    let read_only_config =
        service_config_with_capabilities(root.path(), &graph_store, [DepgraphCapability::Read]);
    let mut journal = OperationJournal::open(&read_only_config).unwrap();
    let expected_digest = journal_state_digest(&journal_path);
    let supplied_write_capabilities = write_capabilities();

    assert_capability_denied_without_mutation(
        &journal_path,
        expected_digest,
        journal.cancel(
            &repository(),
            &queued_id,
            &supplied_write_capabilities,
            NOW + 6,
        ),
    );
    assert_capability_denied_without_mutation(
        &journal_path,
        expected_digest,
        journal.cancel(
            &repository(),
            &terminal_id,
            &supplied_write_capabilities,
            NOW + 6,
        ),
    );
    assert_capability_denied_without_mutation(
        &journal_path,
        expected_digest,
        journal.acquire_lease(
            &repository(),
            &queued_id,
            &LeaseOwner::parse("downgraded-runner").unwrap(),
            b"downgraded-lease",
            NOW + 6,
            NOW + 20_000,
        ),
    );
    assert!(
        journal
            .claim_next_runner_handoff(
                &repository(),
                &LeaseOwner::parse("downgraded-runner").unwrap(),
                b"claim-next-lease",
                NOW + 6,
                NOW + 20_000,
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(journal_state_digest(&journal_path), expected_digest);
    assert_capability_denied_without_mutation(
        &journal_path,
        expected_digest,
        journal.renew_lease(
            &repository(),
            &running_id,
            b"privileged-lease",
            NOW + 6,
            NOW + 20_000,
        ),
    );
    assert_capability_denied_without_mutation(
        &journal_path,
        expected_digest,
        journal.release_lease(&repository(), &running_id, b"privileged-lease", NOW + 6),
    );
    assert_capability_denied_without_mutation(
        &journal_path,
        expected_digest,
        journal.update_progress(
            &repository(),
            &running_id,
            b"privileged-lease",
            OperationProgress::new(1, 10).unwrap(),
            NOW + 6,
        ),
    );
    assert_capability_denied_without_mutation(
        &journal_path,
        expected_digest,
        journal.complete(
            &repository(),
            &running_id,
            b"privileged-lease",
            CanonicalJson::new(json!({"ok": true})).unwrap(),
            NOW + 6,
        ),
    );
    assert_capability_denied_without_mutation(
        &journal_path,
        expected_digest,
        journal.fail(
            &repository(),
            &running_id,
            b"privileged-lease",
            CanonicalJson::new(json!({"code": "failed"})).unwrap(),
            NOW + 6,
        ),
    );
    assert_capability_denied_without_mutation(
        &journal_path,
        expected_digest,
        journal.mark_cancelled(&repository(), &running_id, b"privileged-lease", NOW + 6),
    );
    assert_capability_denied_without_mutation(
        &journal_path,
        expected_digest,
        journal.fail_deadline(&repository(), &queued_id, DEADLINE + 1),
    );
}

#[test]
fn only_deadline_reaping_can_fail_unclaimed_queued_work() {
    let (_root, _graph_store, config, mut journal) = journal();
    let operation_id = journal
        .submit(
            &request(&config, json!({"value": 1}), b"queued-deadline", DEADLINE),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    let error = CanonicalJson::new(json!({"code": "worker-failure"})).unwrap();

    assert!(matches!(
        journal.fail(
            &repository(),
            &operation_id,
            b"never-claimed",
            error.clone(),
            NOW + 1,
        ),
        Err(JournalError::InvalidTransition)
    ));
    assert!(matches!(
        journal.fail_deadline(&repository(), &operation_id, DEADLINE - 1),
        Err(JournalError::InvalidArgument)
    ));

    let failed = journal
        .fail_deadline(&repository(), &operation_id, DEADLINE)
        .unwrap();
    assert_eq!(failed.status(), OperationStatus::Failed);
    let handoff = journal
        .runner_handoff(&repository(), &operation_id, DEADLINE)
        .unwrap();
    assert_eq!(handoff.claimed_at_ms(), None);
    assert_eq!(handoff.completed_at_ms(), Some(DEADLINE));
}

#[test]
fn forged_early_unclaimed_failure_is_rejected_by_every_read_path() {
    let (_root, _graph_store, config, mut journal) = journal();
    let operation_id = journal
        .submit(
            &request(
                &config,
                json!({"value": 1}),
                b"forged-early-failure",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    let forged_at = NOW + 1;
    let connection = Connection::open(journal.path()).unwrap();
    connection
        .execute(
            "UPDATE operations
             SET status = 'failed', error_json = ?1,
                 updated_at_ms = ?2, terminal_at_ms = ?2
             WHERE operation_id = ?3",
            params![
                DEADLINE_EXCEEDED_ERROR_JSON,
                forged_at,
                operation_id.as_str()
            ],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE runner_handoffs SET completed_at_ms = ?1 WHERE operation_id = ?2",
            params![forged_at, operation_id.as_str()],
        )
        .unwrap();

    assert!(matches!(
        journal.get(&repository(), &operation_id, forged_at),
        Err(JournalError::IntegrityFailure)
    ));
    assert!(matches!(
        journal.result(&repository(), &operation_id, forged_at),
        Err(JournalError::IntegrityFailure)
    ));
    assert!(matches!(
        journal.validate(),
        Err(JournalError::IntegrityFailure)
    ));
}

#[test]
fn forged_future_deadline_failure_is_not_visible_before_its_deadline() {
    let (_root, _graph_store, config, mut journal) = journal();
    let operation_id = journal
        .submit(
            &request(
                &config,
                json!({"value": 1}),
                b"forged-future-failure",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    let connection = Connection::open(journal.path()).unwrap();
    connection
        .execute(
            "UPDATE operations
             SET status = 'failed', error_json = ?1,
                 updated_at_ms = ?2, terminal_at_ms = ?2
             WHERE operation_id = ?3",
            params![
                DEADLINE_EXCEEDED_ERROR_JSON,
                DEADLINE,
                operation_id.as_str()
            ],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE runner_handoffs SET completed_at_ms = ?1 WHERE operation_id = ?2",
            params![DEADLINE, operation_id.as_str()],
        )
        .unwrap();

    for outcome in [
        journal
            .get(&repository(), &operation_id, NOW + 1)
            .map(|_| ()),
        journal
            .result(&repository(), &operation_id, NOW + 1)
            .map(|_| ()),
        journal
            .runner_handoff(&repository(), &operation_id, NOW + 1)
            .map(|_| ()),
    ] {
        assert!(matches!(outcome, Err(JournalError::IntegrityFailure)));
    }
}

#[test]
fn unclaimed_completed_and_cancelled_records_fail_closed() {
    for (status, result_json) in [("completed", Some(r#"{"ok":true}"#)), ("cancelled", None)] {
        let (_root, _graph_store, config, mut operation_journal) = journal();
        let operation_id = operation_journal
            .submit(
                &request(
                    &config,
                    json!({"status": status}),
                    format!("forged-unclaimed-{status}").as_bytes(),
                    DEADLINE,
                ),
                NOW,
            )
            .unwrap()
            .operation_id()
            .clone();
        let connection = Connection::open(operation_journal.path()).unwrap();
        if status == "completed" {
            connection
                .execute(
                    "UPDATE operations
                     SET status = 'running', lease_owner = 'forged-runner',
                         lease_token_digest = zeroblob(32), lease_expires_at_ms = ?1,
                         updated_at_ms = ?2
                     WHERE operation_id = ?3",
                    params![DEADLINE, NOW + 1, operation_id.as_str()],
                )
                .unwrap();
        } else {
            connection
                .execute(
                    "UPDATE operations SET status = 'cancelling', updated_at_ms = ?1
                     WHERE operation_id = ?2",
                    params![NOW + 1, operation_id.as_str()],
                )
                .unwrap();
        }
        let forged_at = NOW + 2;
        connection
            .execute(
                "UPDATE operations
                 SET status = ?1, result_json = ?2,
                     lease_owner = NULL, lease_token_digest = NULL,
                     lease_expires_at_ms = NULL,
                     updated_at_ms = ?3, terminal_at_ms = ?3
                 WHERE operation_id = ?4",
                params![status, result_json, forged_at, operation_id.as_str()],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE runner_handoffs SET completed_at_ms = ?1 WHERE operation_id = ?2",
                params![forged_at, operation_id.as_str()],
            )
            .unwrap();

        assert!(matches!(
            operation_journal.get(&repository(), &operation_id, forged_at),
            Err(JournalError::IntegrityFailure)
        ));
        assert!(matches!(
            operation_journal.validate(),
            Err(JournalError::IntegrityFailure)
        ));
    }
}

#[test]
fn late_deadline_sweep_uses_hard_deadline_at_the_exact_maximum_ttl_bound() {
    let (_root, _graph_store, config, mut journal) = journal();
    let maximum_ttl = i64::try_from(MAX_TASK_TTL_MS).unwrap();
    let boundary_deadline = NOW + maximum_ttl - TERMINAL_RETENTION_MS;
    let operation_id = journal
        .submit(
            &request(
                &config,
                json!({"boundary": "late-deadline"}),
                b"late-deadline-boundary",
                boundary_deadline,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    let swept_at = NOW + maximum_ttl + TOMBSTONE_RETENTION_MS;

    let failed = journal
        .fail_deadline(&repository(), &operation_id, swept_at)
        .unwrap();
    assert_eq!(failed.status(), OperationStatus::Failed);
    assert_eq!(failed.updated_at_ms(), boundary_deadline);
    assert_eq!(failed.terminal_at_ms(), Some(boundary_deadline));
    assert_eq!(failed.retain_until_ms(), NOW + maximum_ttl);
    assert!(failed.retain_until_ms() < swept_at);
    let handoff = journal
        .runner_handoff(&repository(), &operation_id, boundary_deadline)
        .unwrap();
    assert_eq!(handoff.completed_at_ms(), Some(boundary_deadline));
    journal.validate().unwrap();
}

#[test]
fn purge_reaps_queued_running_and_cancelling_before_terminal_only_deletion() {
    let (_root, _graph_store, config, mut journal) = journal();
    let queued_id = journal
        .submit(
            &request(
                &config,
                json!({"state": "queued"}),
                b"purge-queued",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    let running_id = journal
        .submit(
            &request(
                &config,
                json!({"state": "running"}),
                b"purge-running",
                DEADLINE,
            ),
            NOW + 1,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository(),
            &running_id,
            &LeaseOwner::parse("purge-running-runner").unwrap(),
            b"purge-running-lease",
            NOW + 2,
            DEADLINE,
        )
        .unwrap();
    let cancelling_id = journal
        .submit(
            &request(
                &config,
                json!({"state": "cancelling"}),
                b"purge-cancelling",
                DEADLINE,
            ),
            NOW + 3,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository(),
            &cancelling_id,
            &LeaseOwner::parse("purge-cancelling-runner").unwrap(),
            b"purge-cancelling-lease",
            NOW + 4,
            DEADLINE,
        )
        .unwrap();
    journal
        .cancel(
            &repository(),
            &cancelling_id,
            &write_capabilities(),
            NOW + 5,
        )
        .unwrap();

    let report = journal.purge(DEADLINE).unwrap();
    assert_eq!(report.reaped_operations(), 3);
    assert_eq!(report.purged_operations(), 0);
    assert_eq!(report.created_tombstones(), 0);
    assert_eq!(report.purged_tombstones(), 0);
    assert!(!report.more_work());

    for (operation_id, claimed_at_ms) in [
        (&queued_id, None),
        (&running_id, Some(NOW + 2)),
        (&cancelling_id, Some(NOW + 4)),
    ] {
        let failed = journal.get(&repository(), operation_id, DEADLINE).unwrap();
        assert_eq!(failed.status(), OperationStatus::Failed);
        assert_eq!(
            failed.error().unwrap().as_str(),
            DEADLINE_EXCEEDED_ERROR_JSON
        );
        assert!(failed.result().is_none());
        assert_eq!(failed.updated_at_ms(), DEADLINE);
        assert_eq!(failed.terminal_at_ms(), Some(DEADLINE));
        assert_eq!(failed.retain_until_ms(), DEADLINE + TERMINAL_RETENTION_MS);
        assert!(failed.lease().is_none());
        let handoff = journal
            .runner_handoff(&repository(), operation_id, DEADLINE)
            .unwrap();
        assert_eq!(handoff.claimed_at_ms(), claimed_at_ms);
        assert_eq!(handoff.completed_at_ms(), Some(DEADLINE));
    }
    journal.validate().unwrap();

    Connection::open(journal.path())
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER test_purge_rejects_nonterminal_delete
             BEFORE DELETE ON operations
             WHEN OLD.status NOT IN ('completed', 'failed', 'cancelled')
             BEGIN
                 SELECT RAISE(ABORT, 'purge attempted nonterminal delete');
             END;",
        )
        .unwrap();
    let report = journal.purge(DEADLINE + TERMINAL_RETENTION_MS).unwrap();
    assert_eq!(report.reaped_operations(), 0);
    assert_eq!(report.purged_operations(), 3);
    assert_eq!(report.created_tombstones(), 3);
    Connection::open(journal.path())
        .unwrap()
        .execute_batch("DROP TRIGGER test_purge_rejects_nonterminal_delete")
        .unwrap();
    journal.validate().unwrap();
}

#[test]
fn purge_rolls_back_the_whole_reap_batch_when_handoff_completion_fails() {
    let (_root, _graph_store, config, mut journal) = journal();
    for index in 0..2 {
        journal
            .submit(
                &request(
                    &config,
                    json!({"index": index}),
                    format!("purge-rollback-{index}").as_bytes(),
                    DEADLINE,
                ),
                NOW,
            )
            .unwrap();
    }
    let expected_digest = journal_state_digest(journal.path());
    Connection::open(journal.path())
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER test_reject_second_purge_handoff_completion
             BEFORE UPDATE OF completed_at_ms ON runner_handoffs
             WHEN (SELECT COUNT(*) FROM operations WHERE status = 'failed') = 2
             BEGIN
                 SELECT RAISE(ABORT, 'test purge handoff completion rejection');
             END;",
        )
        .unwrap();

    assert!(matches!(
        journal.purge(DEADLINE),
        Err(JournalError::Storage(_))
    ));
    assert_eq!(journal_state_digest(journal.path()), expected_digest);
    Connection::open(journal.path())
        .unwrap()
        .execute_batch("DROP TRIGGER test_reject_second_purge_handoff_completion")
        .unwrap();
    journal.validate().unwrap();
}

#[test]
fn purge_reaps_all_expired_lifecycle_states_after_capability_downgrade_and_reopen() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = service_config(root.path(), &graph_store);
    let mut journal = OperationJournal::open(&config).unwrap();
    let privileged_capabilities = CapabilitySet::new([
        AgentCapability::Read,
        AgentCapability::StoreWrite,
        AgentCapability::ProjectExec,
    ])
    .unwrap();
    let mut operation_ids = Vec::new();
    for (index, state) in ["queued", "running", "cancelling"].into_iter().enumerate() {
        operation_ids.push(
            journal
                .submit(
                    &request_for_kind(
                        &config,
                        OperationKind::ResolveBuildSubmit,
                        json!({"state": state}),
                        format!("purge-project-exec-{state}").as_bytes(),
                        DEADLINE,
                    ),
                    NOW + i64::try_from(index).unwrap(),
                )
                .unwrap()
                .operation_id()
                .clone(),
        );
    }
    journal
        .acquire_lease(
            &repository(),
            &operation_ids[1],
            &LeaseOwner::parse("downgrade-running-runner").unwrap(),
            b"downgrade-running-lease",
            NOW + 3,
            DEADLINE,
        )
        .unwrap();
    journal
        .acquire_lease(
            &repository(),
            &operation_ids[2],
            &LeaseOwner::parse("downgrade-cancelling-runner").unwrap(),
            b"downgrade-cancelling-lease",
            NOW + 4,
            DEADLINE,
        )
        .unwrap();
    journal
        .cancel(
            &repository(),
            &operation_ids[2],
            &privileged_capabilities,
            NOW + 5,
        )
        .unwrap();
    drop(journal);

    let read_only_config =
        service_config_with_capabilities(root.path(), &graph_store, [DepgraphCapability::Read]);
    let mut journal = OperationJournal::open(&read_only_config).unwrap();
    let report = journal.purge(DEADLINE).unwrap();
    assert_eq!(report.reaped_operations(), 3);
    assert!(!report.more_work());
    for operation_id in operation_ids {
        let failed = journal.get(&repository(), &operation_id, DEADLINE).unwrap();
        assert_eq!(failed.status(), OperationStatus::Failed);
        assert_eq!(
            failed.error().unwrap().as_str(),
            DEADLINE_EXCEEDED_ERROR_JSON
        );
    }
    let drained = journal.purge(DEADLINE).unwrap();
    assert_eq!(drained.reaped_operations(), 0);
    assert!(!drained.more_work());
    journal.validate().unwrap();
}

#[test]
fn purge_validates_one_terminal_record_at_a_time_and_rolls_back_on_payload_tamper() {
    let (_root, _graph_store, config, mut journal) = journal();
    let operation_id = journal
        .submit(
            &request(
                &config,
                json!({"value": 1}),
                b"purge-lightweight-row",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository(),
            &operation_id,
            &LeaseOwner::parse("purge-lightweight-runner").unwrap(),
            b"purge-lightweight-lease",
            NOW + 1,
            NOW + 10_000,
        )
        .unwrap();
    let completed = journal
        .complete(
            &repository(),
            &operation_id,
            b"purge-lightweight-lease",
            CanonicalJson::new(json!({"ok": true})).unwrap(),
            NOW + 2,
        )
        .unwrap();
    let retain_until_ms = completed.retain_until_ms();

    let connection = Connection::open(journal.path()).unwrap();
    let terminal_immutable_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'trigger' AND name = 'operations_terminal_immutable'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute_batch(
            "PRAGMA ignore_check_constraints = ON;
             DROP TRIGGER operations_terminal_immutable;",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE operations
             SET input_json = X'00', progress_completed = X'00', progress_total = X'00',
                 result_json = X'00', error_json = X'00'
             WHERE operation_id = ?1",
            params![operation_id.as_str()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE runner_handoffs SET payload_json = X'00' WHERE operation_id = ?1",
            params![operation_id.as_str()],
        )
        .unwrap();
    connection.execute_batch(&terminal_immutable_sql).unwrap();
    drop(connection);

    let expected_digest = journal_state_digest(journal.path());
    assert!(matches!(
        journal.purge(retain_until_ms),
        Err(JournalError::IntegrityFailure)
    ));
    assert_eq!(journal_state_digest(journal.path()), expected_digest);
    let connection = Connection::open(journal.path()).unwrap();
    let counts: (i64, i64, i64) = (
        connection
            .query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))
            .unwrap(),
        connection
            .query_row("SELECT COUNT(*) FROM runner_handoffs", [], |row| row.get(0))
            .unwrap(),
        connection
            .query_row("SELECT COUNT(*) FROM operation_tombstones", [], |row| {
                row.get(0)
            })
            .unwrap(),
    );
    assert_eq!(counts, (1, 1, 0));
}

#[test]
fn seven_day_retention_and_thirty_day_tombstone_prevent_duplicate_work() {
    let (_root, _graph_store, config, mut journal) = journal();
    let deadline = NOW + 1_000;
    let original_request = request(&config, json!({"value": 1}), b"retained-key", deadline);
    let submitted = journal.submit(&original_request, NOW).unwrap();
    let operation_id = submitted.operation_id().clone();
    journal
        .acquire_lease(
            &repository(),
            &operation_id,
            &LeaseOwner::parse("runner-1").unwrap(),
            b"lease-token",
            NOW + 1,
            NOW + 500,
        )
        .unwrap();
    let terminal = journal
        .complete(
            &repository(),
            &operation_id,
            b"lease-token",
            CanonicalJson::new(json!({"ok": true})).unwrap(),
            NOW + 10,
        )
        .unwrap();
    assert!(
        terminal.retain_until_ms() >= terminal.terminal_at_ms().unwrap() + TERMINAL_RETENTION_MS
    );
    let expiry = terminal.retain_until_ms();
    journal
        .get(&repository(), &operation_id, expiry - 1)
        .unwrap();
    assert!(matches!(
        journal.get(&repository(), &operation_id, expiry),
        Err(JournalError::Expired)
    ));

    let report = journal.purge(expiry).unwrap();
    assert_eq!(report.purged_operations(), 1);
    assert_eq!(report.created_tombstones(), 1);
    assert!(matches!(
        journal.get(&repository(), &operation_id, expiry + 1),
        Err(JournalError::Expired)
    ));
    let retry = request(
        &config,
        json!({"value": 1}),
        b"retained-key",
        expiry + TOMBSTONE_RETENTION_MS + 60_000,
    );
    assert!(matches!(
        journal.submit(&retry, expiry + 1),
        Err(JournalError::Expired)
    ));
    let conflicting = request(
        &config,
        json!({"value": 2}),
        b"retained-key",
        expiry + TOMBSTONE_RETENTION_MS + 60_000,
    );
    assert!(matches!(
        journal.submit(&conflicting, expiry + 1),
        Err(JournalError::IdempotencyConflict)
    ));

    let connection = Connection::open(journal.path()).unwrap();
    let (operations, handoffs, tombstones): (i64, i64, i64) = (
        connection
            .query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))
            .unwrap(),
        connection
            .query_row("SELECT COUNT(*) FROM runner_handoffs", [], |row| row.get(0))
            .unwrap(),
        connection
            .query_row("SELECT COUNT(*) FROM operation_tombstones", [], |row| {
                row.get(0)
            })
            .unwrap(),
    );
    assert_eq!((operations, handoffs, tombstones), (0, 0, 1));
    assert!(matches!(
        journal.runner_handoff(&repository(), &operation_id, expiry + 1),
        Err(JournalError::Expired)
    ));
    drop(connection);

    let tombstone_expiry = expiry + TOMBSTONE_RETENTION_MS;
    let report = journal.purge(tombstone_expiry).unwrap();
    assert_eq!(report.purged_tombstones(), 1);
    let replacement = journal.submit(&retry, tombstone_expiry).unwrap();
    assert!(replacement.created());
    assert_ne!(replacement.operation_id(), &operation_id);
}

#[test]
fn purge_batches_operations_and_tombstones_in_exact_deterministic_bounds() {
    let (_root, _graph_store, config, mut journal) = journal();
    let operation_count = MAX_PURGE_BATCH_SIZE + 1;
    let mut operation_ids = Vec::with_capacity(operation_count);
    for index in 0..operation_count {
        operation_ids.push(
            journal
                .submit(
                    &request(
                        &config,
                        json!({"index": index}),
                        format!("purge-batch-{index}").as_bytes(),
                        DEADLINE,
                    ),
                    NOW,
                )
                .unwrap()
                .operation_id()
                .clone(),
        );
    }
    operation_ids.sort();
    journal.validate().unwrap();

    let retain_until_ms = DEADLINE + TERMINAL_RETENTION_MS;
    let first = journal.purge(retain_until_ms).unwrap();
    assert_eq!(
        first.reaped_operations(),
        u64::try_from(MAX_PURGE_BATCH_SIZE).unwrap()
    );
    assert_eq!(
        first.purged_operations(),
        u64::try_from(MAX_PURGE_BATCH_SIZE).unwrap()
    );
    assert_eq!(
        first.created_tombstones(),
        u64::try_from(MAX_PURGE_BATCH_SIZE).unwrap()
    );
    assert_eq!(first.purged_tombstones(), 0);
    assert!(first.more_work());
    let remaining_operation_id: String = Connection::open(journal.path())
        .unwrap()
        .query_row("SELECT operation_id FROM operations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        remaining_operation_id,
        operation_ids[MAX_PURGE_BATCH_SIZE].as_str()
    );
    journal.validate().unwrap();

    let second = journal.purge(retain_until_ms).unwrap();
    assert_eq!(second.reaped_operations(), 1);
    assert_eq!(second.purged_operations(), 1);
    assert_eq!(second.created_tombstones(), 1);
    assert_eq!(second.purged_tombstones(), 0);
    assert!(!second.more_work());
    journal.validate().unwrap();

    let tombstone_until_ms = retain_until_ms + TOMBSTONE_RETENTION_MS;
    let third = journal.purge(tombstone_until_ms).unwrap();
    assert_eq!(third.reaped_operations(), 0);
    assert_eq!(third.purged_operations(), 0);
    assert_eq!(third.created_tombstones(), 0);
    assert_eq!(
        third.purged_tombstones(),
        u64::try_from(MAX_PURGE_BATCH_SIZE).unwrap()
    );
    assert!(third.more_work());
    let fourth = journal.purge(tombstone_until_ms).unwrap();
    assert_eq!(fourth.reaped_operations(), 0);
    assert_eq!(fourth.purged_operations(), 0);
    assert_eq!(fourth.created_tombstones(), 0);
    assert_eq!(fourth.purged_tombstones(), 1);
    assert!(!fourth.more_work());
    journal.validate().unwrap();
}

#[test]
fn cross_table_triggers_reject_operation_id_and_idempotency_scope_overlap() {
    let (_root, _graph_store, config, mut journal) = journal();
    let submitted = journal
        .submit(
            &request(&config, json!({"value": 1}), b"overlap-key", DEADLINE),
            NOW,
        )
        .unwrap();
    let operation_id = submitted.operation_id().clone();
    let retain_until_ms = submitted.record().retain_until_ms();
    let connection = Connection::open(journal.path()).unwrap();
    let (repository_id, kind, capability_json, capability_digest, input_digest, key_digest): (
        String,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) = connection
        .query_row(
            "SELECT repository_id, kind, required_capabilities_json,
                    required_capabilities_digest, input_digest, idempotency_key_digest
             FROM operations WHERE operation_id = ?1",
            params![operation_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    let tombstone_until_ms = retain_until_ms + TOMBSTONE_RETENTION_MS;
    let insert_tombstone =
        |candidate_id: &str, candidate_repository: &str, candidate_key_digest: &[u8]| {
            connection.execute(
                "INSERT INTO operation_tombstones (
                operation_id, repository_id, kind,
                required_capabilities_json, required_capabilities_digest,
                input_digest, idempotency_key_digest, expired_at_ms, tombstone_until_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    candidate_id,
                    candidate_repository,
                    &kind,
                    &capability_json,
                    &capability_digest,
                    &input_digest,
                    candidate_key_digest,
                    retain_until_ms,
                    tombstone_until_ms,
                ],
            )
        };
    assert!(insert_tombstone(operation_id.as_str(), "repo-other", &[0x44; 32]).is_err());
    assert!(
        insert_tombstone(
            "op_11111111111111111111111111111111",
            &repository_id,
            &key_digest
        )
        .is_err()
    );
    drop(connection);

    journal.purge(retain_until_ms).unwrap();
    let connection = Connection::open(journal.path()).unwrap();
    assert!(
        connection
            .execute(
                "INSERT INTO operations (
                operation_id, repository_id, kind,
                required_capabilities_json, required_capabilities_digest,
                input_json, input_digest, idempotency_key_digest, status,
                progress_completed, progress_total,
                lease_owner, lease_token_digest, lease_expires_at_ms,
                execution_deadline_ms, result_json, error_json,
                created_at_ms, updated_at_ms, terminal_at_ms, retain_until_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', 0, 1,
                NULL, NULL, NULL, ?9, NULL, NULL, ?10, ?10, NULL, ?11
             )",
                params![
                    "op_22222222222222222222222222222222",
                    repository_id,
                    kind,
                    capability_json,
                    capability_digest,
                    r#"{"value":1}"#,
                    input_digest,
                    key_digest,
                    DEADLINE,
                    NOW,
                    DEADLINE + TERMINAL_RETENTION_MS,
                ],
            )
            .is_err()
    );
}

#[test]
fn validation_detects_preexisting_cross_table_overlap_in_one_snapshot() {
    let (_root, _graph_store, config, mut journal) = journal();
    let submitted = journal
        .submit(
            &request(
                &config,
                json!({"value": 1}),
                b"validation-overlap",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap();
    let operation_id = submitted.operation_id().clone();
    let retain_until_ms = submitted.record().retain_until_ms();
    journal.purge(retain_until_ms).unwrap();

    let connection = Connection::open(journal.path()).unwrap();
    let trigger_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'trigger' AND name = 'operations_reject_tombstone_overlap_insert'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute_batch("DROP TRIGGER operations_reject_tombstone_overlap_insert")
        .unwrap();
    let (repository_id, kind, capability_json, capability_digest, input_digest, key_digest): (
        String,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) = connection
        .query_row(
            "SELECT repository_id, kind, required_capabilities_json,
                    required_capabilities_digest, input_digest, idempotency_key_digest
             FROM operation_tombstones WHERE operation_id = ?1",
            params![operation_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO operations (
                operation_id, repository_id, kind,
                required_capabilities_json, required_capabilities_digest,
                input_json, input_digest, idempotency_key_digest, status,
                progress_completed, progress_total,
                lease_owner, lease_token_digest, lease_expires_at_ms,
                execution_deadline_ms, result_json, error_json,
                created_at_ms, updated_at_ms, terminal_at_ms, retain_until_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', 0, 1,
                NULL, NULL, NULL, ?9, NULL, NULL, ?10, ?10, NULL, ?11
             )",
            params![
                operation_id.as_str(),
                repository_id,
                kind.as_str(),
                capability_json,
                capability_digest,
                r#"{"value":1}"#,
                input_digest.clone(),
                key_digest,
                DEADLINE,
                NOW,
                DEADLINE + TERMINAL_RETENTION_MS,
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO runner_handoffs (
                operation_id, operation_kind, payload_json, payload_digest,
                enqueued_at_ms, claimed_at_ms, completed_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL)",
            params![
                operation_id.as_str(),
                kind,
                r#"{"value":1}"#,
                input_digest,
                NOW,
            ],
        )
        .unwrap();
    connection.execute_batch(&trigger_sql).unwrap();

    assert!(matches!(
        journal.validate(),
        Err(JournalError::IntegrityFailure)
    ));
}

#[test]
fn reopen_preserves_queued_work_and_canonical_terminal_error() {
    let (root, graph_store, config, mut journal) = journal();
    let submission = request(&config, json!({"value": 1}), b"restart-key", DEADLINE);
    let submitted = journal.submit(&submission, NOW).unwrap();
    let operation_id = submitted.operation_id().clone();
    drop(journal);

    let mut reopened = open_journal(root.path(), &graph_store);
    let queued = reopened.get(&repository(), &operation_id, NOW + 1).unwrap();
    assert_eq!(queued.status(), OperationStatus::Queued);
    assert_eq!(queued.normalized_input().as_str(), r#"{"value":1}"#);
    let recovered_handoff = reopened
        .runner_handoff(&repository(), &operation_id, NOW + 1)
        .unwrap();
    assert_eq!(recovered_handoff.operation_id(), &operation_id);
    assert_eq!(recovered_handoff.payload(), queued.normalized_input());
    assert_eq!(recovered_handoff.enqueued_at_ms(), NOW);
    assert_eq!(recovered_handoff.claimed_at_ms(), None);
    assert_eq!(recovered_handoff.completed_at_ms(), None);
    let handoff_count: i64 = Connection::open(reopened.path())
        .unwrap()
        .query_row("SELECT COUNT(*) FROM runner_handoffs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(handoff_count, 1);
    let retry = reopened.submit(&submission, NOW + 1).unwrap();
    assert!(!retry.created());
    assert_eq!(retry.operation_id(), &operation_id);
    reopened
        .acquire_lease(
            &repository(),
            &operation_id,
            &LeaseOwner::parse("runner-after-restart").unwrap(),
            b"restart-lease",
            NOW + 2,
            NOW + 10_000,
        )
        .unwrap();
    reopened
        .fail(
            &repository(),
            &operation_id,
            b"restart-lease",
            CanonicalJson::new(json!({"z": "failure", "a": "typed"})).unwrap(),
            NOW + 3,
        )
        .unwrap();
    drop(reopened);

    let reopened = open_journal(root.path(), &graph_store);
    let recovered_handoff = reopened
        .runner_handoff(&repository(), &operation_id, NOW + 4)
        .unwrap();
    assert_eq!(recovered_handoff.claimed_at_ms(), Some(NOW + 2));
    assert_eq!(recovered_handoff.completed_at_ms(), Some(NOW + 3));
    match reopened
        .result(&repository(), &operation_id, NOW + 4)
        .unwrap()
    {
        OperationOutcome::Failed(error) => {
            assert_eq!(error.as_str(), r#"{"a":"typed","z":"failure"}"#);
        }
        other => panic!("unexpected durable outcome: {other:?}"),
    }
}

#[test]
fn claim_next_recovers_deterministically_after_restart_and_expired_crash_lease() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = service_config(root.path(), &graph_store);
    let mut journal = OperationJournal::open(&config).unwrap();
    let mut operation_ids = Vec::new();
    for index in 0..2 {
        operation_ids.push(
            journal
                .submit(
                    &request(
                        &config,
                        json!({"index": index}),
                        format!("claim-next-{index}").as_bytes(),
                        DEADLINE,
                    ),
                    NOW,
                )
                .unwrap()
                .operation_id()
                .clone(),
        );
    }
    operation_ids.sort();
    drop(journal);

    let mut restarted = open_journal(root.path(), &graph_store);
    let first = restarted
        .claim_next_runner_handoff(
            &repository(),
            &LeaseOwner::parse("runner-before-crash").unwrap(),
            b"lease-before-crash",
            NOW + 1,
            NOW + 10,
        )
        .unwrap()
        .unwrap();
    assert_eq!(first.record().operation_id(), &operation_ids[0]);
    assert_eq!(first.handoff().operation_id(), &operation_ids[0]);
    assert_eq!(first.handoff().claimed_at_ms(), Some(NOW + 1));
    assert_eq!(
        first.record().lease().unwrap().token_digest(),
        JournalDigest::sha256(b"lease-before-crash")
    );
    drop(restarted);

    let mut restarted = open_journal(root.path(), &graph_store);
    let competing = restarted
        .claim_next_runner_handoff(
            &repository(),
            &LeaseOwner::parse("runner-while-first-live").unwrap(),
            b"second-live-lease",
            NOW + 2,
            NOW + 11,
        )
        .unwrap();
    assert!(competing.is_none());
    restarted
        .cancel(
            &repository(),
            &operation_ids[0],
            &write_capabilities(),
            NOW + 3,
        )
        .unwrap();
    drop(restarted);

    let mut restarted = open_journal(root.path(), &graph_store);
    let reclaimed = restarted
        .claim_next_runner_handoff(
            &repository(),
            &LeaseOwner::parse("runner-after-crash").unwrap(),
            b"lease-after-crash",
            NOW + 10,
            NOW + 20,
        )
        .unwrap()
        .unwrap();
    assert_eq!(reclaimed.record().operation_id(), &operation_ids[0]);
    assert_eq!(reclaimed.handoff().operation_id(), &operation_ids[0]);
    assert_eq!(reclaimed.record().status(), OperationStatus::Cancelling);
    assert_eq!(
        reclaimed.record().lease().unwrap().owner(),
        &LeaseOwner::parse("runner-after-crash").unwrap()
    );
    assert_eq!(
        reclaimed.record().lease().unwrap().token_digest(),
        JournalDigest::sha256(b"lease-after-crash")
    );
    restarted
        .mark_cancelled(
            &repository(),
            &operation_ids[0],
            b"lease-after-crash",
            NOW + 11,
        )
        .unwrap();
    let second = restarted
        .claim_next_runner_handoff(
            &repository(),
            &LeaseOwner::parse("runner-after-recovery").unwrap(),
            b"second-recovered-lease",
            NOW + 12,
            NOW + 22,
        )
        .unwrap()
        .unwrap();
    assert_eq!(second.record().operation_id(), &operation_ids[1]);
    assert_eq!(second.handoff().operation_id(), &operation_ids[1]);
    assert_eq!(second.handoff().claimed_at_ms(), Some(NOW + 12));
    assert_eq!(reclaimed.handoff().claimed_at_ms(), Some(NOW + 1));
    assert!(
        restarted
            .claim_next_runner_handoff(
                &repository(),
                &LeaseOwner::parse("no-more-work").unwrap(),
                b"no-more-work-lease",
                NOW + 10,
                NOW + 20,
            )
            .unwrap()
            .is_none()
    );
    restarted.validate().unwrap();
}

#[test]
fn claim_next_recovers_released_running_and_cancelling_work_after_restart() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = service_config(root.path(), &graph_store);
    let mut journal = OperationJournal::open(&config).unwrap();
    let running_id = journal
        .submit(
            &request(
                &config,
                json!({"state": "running"}),
                b"released-running",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    let cancelling_id = journal
        .submit(
            &request(
                &config,
                json!({"state": "cancelling"}),
                b"released-cancelling",
                DEADLINE,
            ),
            NOW + 1,
        )
        .unwrap()
        .operation_id()
        .clone();

    journal
        .acquire_lease(
            &repository(),
            &running_id,
            &LeaseOwner::parse("released-running-runner").unwrap(),
            b"released-running-lease",
            NOW + 2,
            NOW + 100,
        )
        .unwrap();
    let running = journal
        .release_lease(
            &repository(),
            &running_id,
            b"released-running-lease",
            NOW + 3,
        )
        .unwrap();
    assert_eq!(running.status(), OperationStatus::Running);
    assert!(running.lease().is_none());

    journal
        .acquire_lease(
            &repository(),
            &cancelling_id,
            &LeaseOwner::parse("released-cancelling-runner").unwrap(),
            b"released-cancelling-lease",
            NOW + 4,
            NOW + 100,
        )
        .unwrap();
    journal
        .cancel(
            &repository(),
            &cancelling_id,
            &write_capabilities(),
            NOW + 5,
        )
        .unwrap();
    let cancelling = journal
        .release_lease(
            &repository(),
            &cancelling_id,
            b"released-cancelling-lease",
            NOW + 6,
        )
        .unwrap();
    assert_eq!(cancelling.status(), OperationStatus::Cancelling);
    assert!(cancelling.lease().is_none());
    drop(journal);

    let mut restarted = open_journal(root.path(), &graph_store);
    let reclaimed_running = restarted
        .claim_next_runner_handoff(
            &repository(),
            &LeaseOwner::parse("reclaimed-running-runner").unwrap(),
            b"reclaimed-running-lease",
            NOW + 7,
            NOW + 200,
        )
        .unwrap()
        .unwrap();
    assert_eq!(reclaimed_running.record().operation_id(), &running_id);
    assert_eq!(
        reclaimed_running.record().status(),
        OperationStatus::Running
    );
    assert_eq!(reclaimed_running.handoff().claimed_at_ms(), Some(NOW + 2));
    restarted
        .fail(
            &repository(),
            &running_id,
            b"reclaimed-running-lease",
            CanonicalJson::new(json!({"code": "test_recovery_complete"})).unwrap(),
            NOW + 8,
        )
        .unwrap();

    let reclaimed_cancelling = restarted
        .claim_next_runner_handoff(
            &repository(),
            &LeaseOwner::parse("reclaimed-cancelling-runner").unwrap(),
            b"reclaimed-cancelling-lease",
            NOW + 9,
            NOW + 200,
        )
        .unwrap()
        .unwrap();
    assert_eq!(reclaimed_cancelling.record().operation_id(), &cancelling_id);
    assert_eq!(
        reclaimed_cancelling.record().status(),
        OperationStatus::Cancelling
    );
    assert_eq!(
        reclaimed_cancelling.handoff().claimed_at_ms(),
        Some(NOW + 4)
    );
    restarted.validate().unwrap();
}

#[test]
fn claim_next_skips_deadline_expired_work_without_exposing_an_operation_list() {
    let (_root, _graph_store, config, mut journal) = journal();
    let expired_id = journal
        .submit(
            &request(
                &config,
                json!({"state": "expired"}),
                b"claim-next-expired",
                NOW + 5,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    let eligible_id = journal
        .submit(
            &request(
                &config,
                json!({"state": "eligible"}),
                b"claim-next-eligible",
                DEADLINE,
            ),
            NOW + 1,
        )
        .unwrap()
        .operation_id()
        .clone();

    let claimed = journal
        .claim_next_runner_handoff(
            &repository(),
            &LeaseOwner::parse("deadline-aware-runner").unwrap(),
            b"deadline-aware-lease",
            NOW + 5,
            NOW + 100,
        )
        .unwrap()
        .unwrap();
    assert_eq!(claimed.record().operation_id(), &eligible_id);
    assert_eq!(claimed.handoff().operation_id(), &eligible_id);
    assert_eq!(
        journal
            .get(&repository(), &expired_id, NOW + 5)
            .unwrap()
            .status(),
        OperationStatus::Queued
    );
}

#[test]
fn claim_next_clamps_the_lease_to_a_near_operation_deadline() {
    let (_root, _graph_store, config, mut journal) = journal();
    let operation_id = journal
        .submit(
            &request(
                &config,
                json!({"deadline": "near"}),
                b"near-deadline-claim",
                NOW + 50,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();

    let claimed = journal
        .claim_next_runner_handoff(
            &repository(),
            &LeaseOwner::parse("near-deadline-runner").unwrap(),
            b"near-deadline-token",
            NOW + 25,
            NOW + 1_000,
        )
        .unwrap()
        .unwrap();

    assert_eq!(claimed.record().operation_id(), &operation_id);
    assert_eq!(claimed.record().lease().unwrap().expires_at_ms(), NOW + 50);
}

#[test]
fn claim_next_skips_an_older_unauthorized_kind_after_capability_downgrade() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = service_config(root.path(), &graph_store);
    let mut journal = OperationJournal::open(&config).unwrap();
    let unauthorized_id = journal
        .submit(
            &request_for_kind(
                &config,
                OperationKind::ResolveBuildSubmit,
                json!({"state": "older-project-exec"}),
                b"claim-next-project-exec",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    let authorized_id = journal
        .submit(
            &request(
                &config,
                json!({"state": "later-store-write"}),
                b"claim-next-store-write",
                DEADLINE,
            ),
            NOW + 1,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let store_write_config = service_config_with_capabilities(
        root.path(),
        &graph_store,
        [DepgraphCapability::Read, DepgraphCapability::StoreWrite],
    );
    let mut journal = OperationJournal::open(&store_write_config).unwrap();
    let claimed = journal
        .claim_next_runner_handoff(
            &repository(),
            &LeaseOwner::parse("store-write-runner").unwrap(),
            b"store-write-lease",
            NOW + 2,
            NOW + 100,
        )
        .unwrap()
        .unwrap();

    assert_eq!(claimed.record().operation_id(), &authorized_id);
    assert_eq!(claimed.handoff().operation_id(), &authorized_id);
    let unauthorized = journal
        .get(&repository(), &unauthorized_id, NOW + 2)
        .unwrap();
    assert_eq!(unauthorized.status(), OperationStatus::Queued);
    assert!(unauthorized.lease().is_none());
    assert!(matches!(
        journal.runner_handoff(&repository(), &unauthorized_id, NOW + 2),
        Err(JournalError::CapabilityDenied)
    ));
}

#[test]
fn claim_next_enforces_one_global_store_writer_slot_across_runners() {
    let (_root, _graph_store, config, mut journal) = journal();
    let first = journal
        .submit(
            &request(
                &config,
                json!({"writer": 1}),
                b"writer-slot-first",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    let second = journal
        .submit(
            &request(
                &config,
                json!({"writer": 2}),
                b"writer-slot-second",
                DEADLINE,
            ),
            NOW + 1,
        )
        .unwrap()
        .operation_id()
        .clone();

    let claimed = journal
        .claim_next_runner_handoff(
            &repository(),
            &LeaseOwner::parse("writer-runner-one").unwrap(),
            b"writer-runner-one-token",
            NOW + 2,
            NOW + 1_000,
        )
        .unwrap()
        .unwrap();
    assert_eq!(claimed.record().operation_id(), &first);

    let competing = journal
        .claim_next_runner_handoff(
            &repository(),
            &LeaseOwner::parse("writer-runner-two").unwrap(),
            b"writer-runner-two-token",
            NOW + 3,
            NOW + 1_000,
        )
        .unwrap();
    assert!(competing.is_none());
    assert_eq!(
        journal
            .get(&repository(), &second, NOW + 3)
            .unwrap()
            .status(),
        OperationStatus::Queued
    );
}

#[test]
fn claim_next_enforces_one_global_project_exec_slot_across_runners() {
    let (_root, _graph_store, config, mut journal) = journal();
    let first = journal
        .submit(
            &request_for_kind(
                &config,
                OperationKind::ResolveBuildSubmit,
                json!({"execution": 1}),
                b"project-slot-first",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    let second = journal
        .submit(
            &request_for_kind(
                &config,
                OperationKind::ResolveBuildSubmit,
                json!({"execution": 2}),
                b"project-slot-second",
                DEADLINE,
            ),
            NOW + 1,
        )
        .unwrap()
        .operation_id()
        .clone();

    let claimed = journal
        .claim_next_runner_handoff(
            &repository(),
            &LeaseOwner::parse("project-runner-one").unwrap(),
            b"project-runner-one-token",
            NOW + 2,
            NOW + 1_000,
        )
        .unwrap()
        .unwrap();
    assert_eq!(claimed.record().operation_id(), &first);

    let competing = journal
        .claim_next_runner_handoff(
            &repository(),
            &LeaseOwner::parse("project-runner-two").unwrap(),
            b"project-runner-two-token",
            NOW + 3,
            NOW + 1_000,
        )
        .unwrap();
    assert!(competing.is_none());
    assert_eq!(
        journal
            .get(&repository(), &second, NOW + 3)
            .unwrap()
            .status(),
        OperationStatus::Queued
    );
}

#[test]
fn project_exec_lease_loss_fails_closed_without_reclaiming_the_handoff() {
    let (_root, _graph_store, config, mut journal) = journal();
    let operation_id = journal
        .submit(
            &request_for_kind(
                &config,
                OperationKind::ResolveBuildSubmit,
                json!({"execution": "unsafe"}),
                b"unsafe-lease-loss",
                DEADLINE,
            ),
            NOW,
        )
        .unwrap()
        .operation_id()
        .clone();
    journal
        .acquire_lease(
            &repository(),
            &operation_id,
            &LeaseOwner::parse("lost-project-runner").unwrap(),
            b"lost-project-token",
            NOW + 1,
            NOW + 10,
        )
        .unwrap();

    let reclaimed = journal
        .claim_next_runner_handoff(
            &repository(),
            &LeaseOwner::parse("replacement-project-runner").unwrap(),
            b"replacement-project-token",
            NOW + 10,
            NOW + 1_000,
        )
        .unwrap();

    assert!(reclaimed.is_none());
    let record = journal.get(&repository(), &operation_id, NOW + 10).unwrap();
    assert_eq!(record.status(), OperationStatus::Failed);
    assert_eq!(
        record.error().unwrap().as_str(),
        EXECUTION_STATE_UNKNOWN_ERROR_JSON
    );
    assert_eq!(
        journal
            .runner_handoff(&repository(), &operation_id, NOW + 10)
            .unwrap()
            .completed_at_ms(),
        Some(NOW + 10)
    );
}

#[test]
fn concurrent_submit_is_serialized_by_transaction_and_unique_scope() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    drop(open_journal(root.path(), &graph_store));
    let repository_root = root.path().to_path_buf();
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let barrier = Arc::clone(&barrier);
        let graph_store = graph_store.clone();
        let repository_root = repository_root.clone();
        handles.push(thread::spawn(move || {
            let config = service_config(&repository_root, &graph_store);
            let mut journal = OperationJournal::open(&config).unwrap();
            let request = request(&config, json!({"value": 1}), b"concurrent-key", DEADLINE);
            barrier.wait();
            journal.submit(&request, NOW).unwrap()
        }));
    }
    barrier.wait();
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();

    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.created()).count(),
        1
    );
    assert_eq!(outcomes[0].operation_id(), outcomes[1].operation_id());
    let journal = open_journal(root.path(), &graph_store);
    let connection = Connection::open(journal.path()).unwrap();
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
fn concurrent_finish_and_purge_never_expose_a_split_operation_handoff_snapshot() {
    let root = tempfile::tempdir().unwrap();
    let graph_store = root.path().join("graph.sqlite");
    let config = service_config(root.path(), &graph_store);
    let mut setup = OperationJournal::open(&config).unwrap();
    let mut operation_ids = Vec::new();
    for index in 0..48 {
        let operation_id = setup
            .submit(
                &request(
                    &config,
                    json!({"index": index}),
                    format!("snapshot-race-{index}").as_bytes(),
                    DEADLINE,
                ),
                NOW,
            )
            .unwrap()
            .operation_id()
            .clone();
        setup
            .acquire_lease(
                &repository(),
                &operation_id,
                &LeaseOwner::parse(format!("runner-{index}")).unwrap(),
                format!("lease-{index}").as_bytes(),
                NOW + 1,
                DEADLINE - 1,
            )
            .unwrap();
        operation_ids.push(operation_id);
    }
    drop(setup);

    let mut writer = open_journal(root.path(), &graph_store);
    let reader_one = open_journal(root.path(), &graph_store);
    let reader_two = open_journal(root.path(), &graph_store);
    let operation_ids = Arc::new(operation_ids);
    let barrier = Arc::new(Barrier::new(4));
    let finished = Arc::new(AtomicBool::new(false));

    let writer_ids = Arc::clone(&operation_ids);
    let writer_barrier = Arc::clone(&barrier);
    let writer_finished = Arc::clone(&finished);
    let writer_handle = thread::spawn(move || {
        writer_barrier.wait();
        for (index, operation_id) in writer_ids.iter().enumerate() {
            writer
                .complete(
                    &repository(),
                    operation_id,
                    format!("lease-{index}").as_bytes(),
                    CanonicalJson::new(json!({"index": index})).unwrap(),
                    NOW + 2,
                )
                .unwrap();
        }
        writer.purge(DEADLINE + TERMINAL_RETENTION_MS).unwrap();
        writer_finished.store(true, Ordering::Release);
    });

    let spawn_reader = |reader: OperationJournal| {
        let reader_ids = Arc::clone(&operation_ids);
        let reader_barrier = Arc::clone(&barrier);
        let reader_finished = Arc::clone(&finished);
        thread::spawn(move || {
            reader_barrier.wait();
            let mut iterations = 0;
            while iterations < 25 || !reader_finished.load(Ordering::Acquire) {
                for operation_id in reader_ids.iter() {
                    for outcome in [
                        reader.get(&repository(), operation_id, NOW + 3).map(|_| ()),
                        reader
                            .runner_handoff(&repository(), operation_id, NOW + 3)
                            .map(|_| ()),
                    ] {
                        assert!(
                            matches!(
                                outcome,
                                Ok(()) | Err(JournalError::Expired) | Err(JournalError::NotFound)
                            ),
                            "read observed a transient operation/handoff failure: {outcome:?}"
                        );
                    }
                }
                reader.validate().unwrap();
                iterations += 1;
            }
        })
    };
    let reader_one_handle = spawn_reader(reader_one);
    let reader_two_handle = spawn_reader(reader_two);
    barrier.wait();

    writer_handle.join().unwrap();
    reader_one_handle.join().unwrap();
    reader_two_handle.join().unwrap();
    open_journal(root.path(), &graph_store).validate().unwrap();
}
