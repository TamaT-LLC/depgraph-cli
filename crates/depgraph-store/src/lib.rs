use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    path::Path,
};

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use depgraph_protocol::{
    Coverage, Diagnostic, Evidence, ProtocolEvent, ValidatedProtocol, stable_id_from_value,
    validate_build_contract,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use serde::{Serialize, Serializer, ser::SerializeMap};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

mod cache;
mod diff;
mod impact_cache;
mod incremental;
mod profile_matrix;
mod read;
mod records;
mod runtime;

pub use cache::{
    BuildCacheLookup, CACHE_CONTRACT_VERSION, COMPILER_PRECISE_CACHE_MAX_ENTRIES,
    COMPILER_PRECISE_CACHE_MAX_PAYLOAD_BYTES, COMPILER_PRECISE_CACHE_MAX_TOTAL_BYTES,
    CacheEntryCounts, CacheEventRecord, CacheKey, CacheLayer, CacheLookupResult,
    CompilerPreciseCacheLookup, ValidatedScanCacheHit,
};
pub use diff::{
    ChangedRecord, GraphSnapshotDiff, NodeRename, NodeRenameEvidence, RecordDiff, RenameConfidence,
    SNAPSHOT_DIFF_SCHEMA_VERSION, diff_graph_snapshots,
};
pub use impact_cache::{
    IMPACT_QUERY_CACHE_CONTRACT_VERSION, IMPACT_QUERY_CACHE_MAX_ENTRIES,
    IMPACT_QUERY_CACHE_MAX_PAYLOAD_BYTES,
};
pub use incremental::{IncrementalDeltaRecord, IncrementalReplacementScope};
use profile_matrix::refresh_profile_matrix;
pub use profile_matrix::{
    PROFILE_MATRIX_SCHEMA_VERSION, PhaseCoverageRecord, ProfileAxisConflictRecord,
    ProfileCorrelationRecord, ProfileMatrixEntryRecord, ProfileMatrixRecord,
    canonical_effective_input_id, correlation_for_edge, correlation_for_site,
    declared_effective_input_id, declared_parent_profile_id, phase_coverage_for_effective_profile,
    refresh_profile_matrix_view,
};
use read::{
    EdgeValidationRecord, load_adapter_logs, load_diagnostics, load_edge_validation_records,
    load_edges, load_evidence, load_file_coverage, load_nodes, load_profiles,
    load_scan_attempt_summary, load_scan_topology, load_site_validation_records, load_sites,
    merge_coverage, observed_coverage, topology_from_snapshot,
};
pub use records::*;
pub use runtime::{
    PreparedRuntimeImport, RuntimeEdgeContext, RuntimeImportRecoveryIdentity, RuntimeImportResult,
    RuntimeSessionDelta, RuntimeSessionRecord, runtime_context_for_edge,
};

pub const STORE_SCHEMA_VERSION: i64 = 17;
const COMPLETED_SNAPSHOT_SEAL_VERSION: i64 = 1;
const MAX_PENDING_CANCELLED_SCAN_OPERATIONS: usize = 64;
// This namespace is not a real operation ID and is rejected by attach/release APIs.
const LEGACY_RUNTIME_IMPORT_OWNER_PREFIX: &str =
    "__depgraph_reserved_legacy_runtime_import_owner__:";
// A v17 migration records legacy scan candidates under an identity that can
// never be supplied by an operation. The row is not an ownership assertion:
// it carries zeroed authority fields and must either be adopted from a
// validated completion decision or cancelled by coordinated reconciliation.
const LEGACY_SCAN_OPERATION_CANDIDATE_PREFIX: &str =
    "__depgraph_reserved_legacy_scan_operation_candidate__:";
const RUNTIME_IMPORT_OPERATION_OWNERS_TABLE_SQL: &str =
    "CREATE TABLE runtime_import_operation_owners (
        import_id TEXT NOT NULL
            REFERENCES runtime_imports(id) ON DELETE CASCADE,
        operation_id TEXT NOT NULL UNIQUE
            CHECK (length(operation_id) BETWEEN 1 AND 512),
        created_at TEXT NOT NULL,
        PRIMARY KEY (import_id, operation_id)
     )";
const RUNTIME_IMPORT_OPERATION_OWNERS_INDEX_SQL: &str =
    "CREATE INDEX runtime_import_operation_owners_import
        ON runtime_import_operation_owners(import_id, operation_id)";
const SCAN_OPERATION_STAGING_TABLE_SQL: &str = "CREATE TABLE scan_operation_staging (
        operation_id TEXT PRIMARY KEY
            CHECK (length(operation_id) BETWEEN 1 AND 512),
        scan_id TEXT NOT NULL UNIQUE
            REFERENCES scans(id) ON DELETE CASCADE,
        repository_binding_digest BLOB NOT NULL
            CHECK (typeof(repository_binding_digest)='blob'
                AND length(repository_binding_digest)=32),
        configuration_digest BLOB NOT NULL
            CHECK (typeof(configuration_digest)='blob'
                AND length(configuration_digest)=32),
        strict INTEGER NOT NULL CHECK (strict IN (0, 1)),
        cache_enabled INTEGER NOT NULL CHECK (cache_enabled IN (0, 1)),
        base_snapshot_id TEXT,
        validated_mutation_count INTEGER
            CHECK (validated_mutation_count IS NULL
                OR validated_mutation_count >= 0),
        prospective_snapshot_id TEXT,
        result_digest BLOB
            CHECK (result_digest IS NULL
                OR (typeof(result_digest)='blob' AND length(result_digest)=32)),
        decision_authorization_digest BLOB
            CHECK (decision_authorization_digest IS NULL
                OR (typeof(decision_authorization_digest)='blob'
                    AND length(decision_authorization_digest)=32)),
        created_at TEXT NOT NULL,
        CHECK ((validated_mutation_count IS NULL
                    AND prospective_snapshot_id IS NULL
                    AND result_digest IS NULL)
            OR (validated_mutation_count IS NOT NULL
                    AND prospective_snapshot_id IS NOT NULL))
     )";
const SCAN_OPERATION_STAGING_SCAN_INDEX_SQL: &str = "CREATE INDEX scan_operation_staging_scan
        ON scan_operation_staging(scan_id, operation_id)";
const SCAN_OPERATION_STAGING_PENDING_INDEX_SQL: &str =
    "CREATE INDEX scan_operation_staging_pending_cancelled
        ON scan_operation_staging(operation_id COLLATE BINARY, scan_id)";
// Larger pages keep the representative semantic graph's multi-kilobyte rows
// from forcing one B-tree page per row. Existing stores retain their page size.
const STORE_PAGE_SIZE_BYTES: i64 = 16 * 1024;
const STORE_CACHE_SIZE_KIB: i64 = 64 * 1024;
const DOCTOR_SUMMARY_MAX_DIAGNOSTIC_GROUPS: usize = 64;
const DOCTOR_SUMMARY_MAX_DIAGNOSTIC_SAMPLES: usize = 5;
const DOCTOR_SUMMARY_MAX_KEY_BYTES: usize = 128;
const DOCTOR_SUMMARY_MAX_TEXT_BYTES: usize = 240;
const DOCTOR_OVERLAY_LAYERS_CTE: &str = "
WITH RECURSIVE
latest_snapshot(
    id, parent_snapshot_id, build_attempt_id, runtime_session_set_json, depth
) AS (
    SELECT seed.id, seed.parent_snapshot_id, seed.build_attempt_id,
           seed.runtime_session_set_json, 0
      FROM (
          SELECT id, parent_snapshot_id, build_attempt_id, runtime_session_set_json
            FROM completed_snapshots
           WHERE scan_id=?1 AND status='completed'
           ORDER BY julianday(created_at) DESC, rowid DESC
           LIMIT 1
      ) AS seed
    UNION ALL
    SELECT parent.id, parent.parent_snapshot_id, parent.build_attempt_id,
           parent.runtime_session_set_json, child.depth + 1
      FROM completed_snapshots AS parent
      JOIN latest_snapshot AS child ON parent.id=child.parent_snapshot_id
),
build_layers(build_attempt_id, depth) AS (
    SELECT build_attempt_id, MAX(depth)
      FROM latest_snapshot
     WHERE build_attempt_id IS NOT NULL
     GROUP BY build_attempt_id
),
runtime_layers(session_id) AS (
    SELECT DISTINCT CAST(item.value AS TEXT)
      FROM latest_snapshot AS snapshot
      JOIN json_each(snapshot.runtime_session_set_json) AS item
     WHERE snapshot.depth=0
)";
const DOCTOR_EFFECTIVE_DIAGNOSTICS_CTE: &str = ",
diagnostic_candidates(
    id, severity, code, message, path, adapter, source_rank, layer_depth, ordinal
) AS (
    SELECT id, severity, code, message, path, adapter, 0, 0, ordinal
      FROM diagnostics
     WHERE scan_id=?1
    UNION ALL
    SELECT COALESCE(json_extract(item.value, '$.id'), 'unknown'),
           COALESCE(json_extract(item.value, '$.severity'), 'warning'),
           COALESCE(json_extract(item.value, '$.code'), 'unknown'),
           COALESCE(json_extract(item.value, '$.message'), 'unknown diagnostic'),
           json_extract(item.value, '$.path'),
           json_extract(item.value, '$.adapter'),
           1,
           layers.depth,
           CAST(item.key AS INTEGER)
      FROM build_layers AS layers
      JOIN build_attempts AS attempts ON attempts.id=layers.build_attempt_id
      JOIN json_each(attempts.delta_json, '$.diagnostics') AS item
     WHERE attempts.status='completed' AND attempts.delta_json IS NOT NULL
    UNION ALL
    SELECT COALESCE(json_extract(diagnostic.raw_json, '$.id'), 'unknown'),
           COALESCE(json_extract(diagnostic.raw_json, '$.severity'), 'warning'),
           COALESCE(json_extract(diagnostic.raw_json, '$.code'), 'unknown'),
           COALESCE(json_extract(diagnostic.raw_json, '$.message'), 'unknown diagnostic'),
           json_extract(diagnostic.raw_json, '$.path'),
           json_extract(diagnostic.raw_json, '$.adapter'),
           2,
           0,
           diagnostic.ordinal
      FROM runtime_layers AS layers
      JOIN runtime_diagnostics AS diagnostic ON diagnostic.session_id=layers.session_id
),
effective_diagnostics(
    id, severity, code, message, path, adapter, source_rank, layer_depth, ordinal
) AS (
    SELECT id, MIN(severity), MIN(code), MIN(message), MIN(path), MIN(adapter),
           MIN(source_rank), MIN(layer_depth), MIN(ordinal)
      FROM diagnostic_candidates
     GROUP BY id
)";

pub struct Store {
    connection: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create store directory {}", parent.display())
            })?;
        }
        let connection = Connection::open(path.as_ref())
            .with_context(|| format!("failed to open SQLite store {}", path.as_ref().display()))?;
        let mut store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_read_only_with_schema_range(path, STORE_SCHEMA_VERSION, STORE_SCHEMA_VERSION)
    }

    /// Open a read-only handle for semantic validation immediately before a
    /// writer migration. Schema 15 is the oldest compatible layout because it
    /// introduced the completed-snapshot seals required by this read path; the
    /// later operation-ownership migrations do not change snapshot semantics.
    pub fn open_read_only_for_migration(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_read_only_with_schema_range(path, 15, STORE_SCHEMA_VERSION)
    }

    fn open_read_only_with_schema_range(
        path: impl AsRef<Path>,
        minimum_schema: i64,
        maximum_schema: i64,
    ) -> Result<Self> {
        let connection = Connection::open_with_flags(
            path.as_ref(),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| {
            format!(
                "failed to open SQLite store read-only {}",
                path.as_ref().display()
            )
        })?;
        let store = Self { connection };
        let current = store.schema_version()?;
        if !(minimum_schema..=maximum_schema).contains(&current) {
            bail!(
                "store schema {current} is outside supported read-only schema range \
                 {minimum_schema}..={maximum_schema}"
            );
        }
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory()?;
        let mut store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    /// Decide under an external writer exclusion whether exact operation-ID
    /// runtime cleanup can be proven empty without migrating a legacy store.
    /// Schema 15 predates the operation owner table, so it cannot contain a
    /// runtime staging row authorized by a durable operation ID. A forbidden
    /// pre-existing future table is deliberately not treated as empty; the
    /// writable open must authenticate and reject it.
    pub fn runtime_operation_cleanup_requires_writable_store(&self) -> Result<bool> {
        let version = self.schema_version()?;
        Ok(version >= 16 || table_exists(&self.connection, "runtime_import_operation_owners")?)
    }

    /// Decide under an external writer exclusion whether exact operation-ID
    /// scan cleanup can be proven empty without migrating a legacy store.
    /// Before schema 17, a scan whose ID equals the operation ID is retained as
    /// ambiguous evidence and must go through authenticated migration. If no
    /// such scan and no forbidden future ownership table exists, there is no
    /// operation-owned staging state to clean.
    pub fn scan_operation_cleanup_requires_writable_store(
        &self,
        operation_id: &str,
    ) -> Result<bool> {
        let version = self.schema_version()?;
        if version >= 17 || table_exists(&self.connection, "scan_operation_staging")? {
            return Ok(true);
        }
        if !table_exists(&self.connection, "scans")? {
            return Ok(false);
        }
        Ok(self
            .connection
            .query_row(
                "SELECT 1 FROM scans WHERE id=?1",
                [operation_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Decide under an external writer exclusion whether legacy scan
    /// reconciliation needs a writable migration. Completed history alone is
    /// immutable and can wait until a later authorized store mutation; active
    /// staging must be migrated so it can be adopted or cancelled. A forbidden
    /// future ownership table is deliberately sent through authenticated open.
    pub fn legacy_scan_reconciliation_requires_writable_store(&self) -> Result<bool> {
        let version = self.schema_version()?;
        if version >= 17 || table_exists(&self.connection, "scan_operation_staging")? {
            return Ok(true);
        }
        if !table_exists(&self.connection, "scans")?
            || !table_has_column(&self.connection, "scans", "status")?
        {
            return Ok(false);
        }
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM scans WHERE status='staging')",
                [],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    /// Run read-only store work with a SQLite progress callback.
    ///
    /// The callback is checked before the operation and periodically while
    /// SQLite traverses rows. Returning `true` interrupts the active query.
    pub fn interruptible_read<T, C, F>(&mut self, mut cancelled: C, operation: F) -> Result<T>
    where
        C: FnMut() -> bool + Send + 'static,
        F: FnOnce(&Store) -> Result<T>,
    {
        if cancelled() {
            bail!("store read cancelled before traversal");
        }
        self.connection.progress_handler(100, Some(cancelled));
        let begin = self.connection.execute_batch("BEGIN DEFERRED TRANSACTION");
        let began = begin.is_ok();
        let result = match begin {
            Ok(()) => {
                operation(self).context("store read failed or was cancelled during traversal")
            }
            Err(error) => Err(error.into()),
        };
        self.connection.progress_handler(0, None::<fn() -> bool>);
        if !began {
            return result;
        }
        let finish = if result.is_ok() {
            self.connection.execute_batch("COMMIT")
        } else {
            self.connection.execute_batch("ROLLBACK")
        };
        match (result, finish) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error).context("failed to finish store read transaction"),
        }
    }

    pub fn schema_version(&self) -> Result<i64> {
        self.connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .context("failed to read schema version")
    }

    fn migrate(&mut self) -> Result<()> {
        self.connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        let current = self.schema_version()?;
        if current == 0 {
            self.connection
                .pragma_update(None, "page_size", STORE_PAGE_SIZE_BYTES)?;
        }
        self.connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA temp_store = MEMORY;",
        )?;
        self.connection
            .pragma_update(None, "cache_size", -STORE_CACHE_SIZE_KIB)?;
        if current > STORE_SCHEMA_VERSION {
            bail!("store schema {current} is newer than supported schema {STORE_SCHEMA_VERSION}");
        }
        if current == 0 {
            let tx = self.connection.transaction()?;
            tx.execute_batch(
                "CREATE TABLE scans (
                    id TEXT PRIMARY KEY,
                    root TEXT NOT NULL,
                    status TEXT NOT NULL,
                    strict INTEGER NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    project_code_executed INTEGER NOT NULL DEFAULT 0,
                    protocol_version TEXT NOT NULL,
                    error TEXT
                );
                CREATE TABLE current_successful (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    scan_id TEXT NOT NULL REFERENCES scans(id)
                );
                CREATE TABLE profiles (
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    id TEXT NOT NULL,
                    json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, id)
                );
                CREATE TABLE nodes (
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    locator TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    properties_json TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, id)
                );
                CREATE INDEX nodes_scan_kind ON nodes(scan_id, kind);
                CREATE INDEX nodes_scan_locator ON nodes(scan_id, locator);
                CREATE TABLE sites (
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    specifier TEXT,
                    profile_id TEXT NOT NULL,
                    resolution_status TEXT NOT NULL,
                    precision TEXT NOT NULL,
                    condition_json TEXT NOT NULL,
                    target_ids_json TEXT NOT NULL,
                    reason TEXT,
                    raw_json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, id)
                );
                CREATE INDEX sites_scan_status ON sites(scan_id, resolution_status);
                CREATE TABLE edges (
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    id TEXT NOT NULL,
                    site_id TEXT,
                    source TEXT NOT NULL,
                    target TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    resolution_status TEXT NOT NULL,
                    precision TEXT NOT NULL,
                    condition_json TEXT NOT NULL,
                    generated INTEGER NOT NULL,
                    raw_json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, id),
                    FOREIGN KEY (scan_id, site_id) REFERENCES sites(scan_id, id)
                );
                CREATE INDEX edges_scan_source ON edges(scan_id, source);
                CREATE INDEX edges_scan_target ON edges(scan_id, target);
                CREATE INDEX edges_scan_kind ON edges(scan_id, kind);
                CREATE INDEX edges_scan_site ON edges(scan_id, site_id);
                CREATE TABLE evidence (
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    owner_type TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    extractor TEXT NOT NULL,
                    extractor_version TEXT NOT NULL,
                    path TEXT NOT NULL,
                    start_line INTEGER NOT NULL,
                    start_column INTEGER NOT NULL,
                    end_line INTEGER NOT NULL,
                    end_column INTEGER NOT NULL,
                    raw_json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, owner_type, owner_id, ordinal)
                );
                CREATE INDEX evidence_scan_path ON evidence(scan_id, path);
                CREATE TABLE diagnostics (
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    ordinal INTEGER NOT NULL,
                    id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    code TEXT NOT NULL,
                    message TEXT NOT NULL,
                    path TEXT,
                    adapter TEXT,
                    raw_json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, ordinal),
                    UNIQUE (scan_id, id)
                );
                CREATE TABLE file_coverage (
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    path TEXT NOT NULL,
                    discovered_sites INTEGER NOT NULL,
                    emitted_sites INTEGER NOT NULL,
                    skipped_sites INTEGER NOT NULL DEFAULT 0,
                    skipped INTEGER NOT NULL,
                    reason TEXT,
                    adapter TEXT NOT NULL,
                    PRIMARY KEY (scan_id, adapter, path)
                );
                CREATE TABLE coverage (
                    scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
                    json TEXT NOT NULL
                );
                CREATE TABLE adapter_logs (
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    adapter TEXT NOT NULL,
                    stderr TEXT NOT NULL,
                    truncated INTEGER NOT NULL,
                    PRIMARY KEY (scan_id, adapter)
                );
                PRAGMA user_version = 4;",
            )?;
            tx.commit()?;
        }
        if current == 1 {
            let tx = self.connection.transaction()?;
            tx.execute_batch(
                "ALTER TABLE evidence ADD COLUMN kind TEXT NOT NULL DEFAULT 'source';
                 ALTER TABLE diagnostics ADD COLUMN id TEXT NOT NULL DEFAULT '';
                 UPDATE diagnostics
                    SET id = 'diagnostic:' || scan_id || ':' || ordinal
                  WHERE id = '';
                 CREATE UNIQUE INDEX diagnostics_scan_id ON diagnostics(scan_id, id);
                 DROP INDEX IF EXISTS edges_scan_source;
                 DROP INDEX IF EXISTS edges_scan_target;
                 DROP INDEX IF EXISTS edges_scan_kind;
                 ALTER TABLE edges RENAME TO edges_v1;
                 CREATE TABLE edges (
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    id TEXT NOT NULL,
                    site_id TEXT,
                    source TEXT NOT NULL,
                    target TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    resolution_status TEXT NOT NULL,
                    precision TEXT NOT NULL,
                    condition_json TEXT NOT NULL,
                    generated INTEGER NOT NULL,
                    raw_json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, id),
                    FOREIGN KEY (scan_id, site_id) REFERENCES sites(scan_id, id)
                 );
                 INSERT INTO edges
                    SELECT scan_id, id, site_id, source, target, kind, phase, environment,
                           profile_id, resolution_status, precision, condition_json, generated, raw_json
                      FROM edges_v1;
                 DROP TABLE edges_v1;
                 CREATE INDEX edges_scan_source ON edges(scan_id, source);
                 CREATE INDEX edges_scan_target ON edges(scan_id, target);
                 CREATE INDEX edges_scan_kind ON edges(scan_id, kind);
                 CREATE INDEX edges_scan_site ON edges(scan_id, site_id);
                 ALTER TABLE file_coverage ADD COLUMN skipped_sites INTEGER NOT NULL DEFAULT 0;
                 PRAGMA user_version = 4;",
            )?;
            tx.commit()?;
        }
        if current == 2 {
            let tx = self.connection.transaction()?;
            tx.execute_batch(
                "ALTER TABLE file_coverage ADD COLUMN skipped_sites INTEGER NOT NULL DEFAULT 0;
                 CREATE INDEX IF NOT EXISTS edges_scan_site ON edges(scan_id, site_id);
                 PRAGMA user_version = 4;",
            )?;
            tx.commit()?;
        }
        if current == 3 {
            let tx = self.connection.transaction()?;
            tx.execute_batch(
                "CREATE INDEX IF NOT EXISTS edges_scan_site ON edges(scan_id, site_id);
                 PRAGMA user_version = 4;",
            )?;
            tx.commit()?;
        }
        if current < 5 {
            let tx = self.connection.transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS profile_coverage (
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    profile_id TEXT NOT NULL,
                    json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, profile_id)
                 );
                 PRAGMA user_version = 5;",
            )?;
            tx.commit()?;
        }
        if current < 6 {
            let tx = self.connection.transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS build_audits (
                    run_id TEXT PRIMARY KEY,
                    outcome TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    audit_json TEXT NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS build_audits_started_at
                    ON build_audits(started_at, run_id);
                 PRAGMA user_version = 6;",
            )?;
            tx.commit()?;
        }
        if current < 7 {
            let tx = self.connection.transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS build_attempts (
                    id TEXT PRIMARY KEY,
                    base_scan_id TEXT NOT NULL REFERENCES scans(id),
                    audit_run_id TEXT NOT NULL UNIQUE REFERENCES build_audits(run_id),
                    status TEXT NOT NULL,
                    observer TEXT NOT NULL,
                    observer_version TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    command_plan_digest TEXT NOT NULL,
                    toolchain_executable_digest TEXT NOT NULL,
                    environment_key_set_digest TEXT NOT NULL,
                    validated_output_digest TEXT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    error TEXT,
                    delta_json TEXT
                 );
                 CREATE INDEX IF NOT EXISTS build_attempts_base_status
                    ON build_attempts(base_scan_id, status, started_at, id);
                 CREATE TABLE IF NOT EXISTS current_build_successful (
                    base_scan_id TEXT PRIMARY KEY REFERENCES scans(id),
                    attempt_id TEXT NOT NULL UNIQUE REFERENCES build_attempts(id)
                 );
                 PRAGMA user_version = 7;",
            )?;
            tx.commit()?;
        }
        if current < 8 {
            let tx = self.connection.transaction()?;
            tx.execute_batch(
                "ALTER TABLE scans ADD COLUMN parent_snapshot_id TEXT;
                 ALTER TABLE scans ADD COLUMN source_revision TEXT;
                 ALTER TABLE scans ADD COLUMN mutation_count INTEGER NOT NULL DEFAULT 0;
                 ALTER TABLE build_attempts ADD COLUMN base_snapshot_id TEXT;
                 CREATE TABLE completed_snapshots (
                    id TEXT PRIMARY KEY,
                    source_kind TEXT NOT NULL
                        CHECK (source_kind IN ('scan', 'build', 'runtime')),
                    source_attempt_id TEXT NOT NULL,
                    scan_id TEXT NOT NULL REFERENCES scans(id),
                    build_attempt_id TEXT REFERENCES build_attempts(id),
                    runtime_import_id TEXT,
                    runtime_session_set_json TEXT NOT NULL DEFAULT '[]',
                    parent_snapshot_id TEXT REFERENCES completed_snapshots(id),
                    source_revision TEXT,
                    profile_set_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status = 'completed'),
                    created_at TEXT NOT NULL,
                    CHECK (
                        (source_kind = 'scan'
                            AND build_attempt_id IS NULL
                            AND runtime_import_id IS NULL
                            AND runtime_session_set_json = '[]')
                        OR (source_kind = 'build'
                            AND build_attempt_id IS NOT NULL
                            AND runtime_import_id IS NULL)
                        OR (source_kind = 'runtime'
                            AND runtime_import_id IS NOT NULL
                            AND runtime_session_set_json != '[]')
                    )
                 );
                 CREATE INDEX completed_snapshots_scan_created
                    ON completed_snapshots(scan_id, created_at, id);
                 CREATE INDEX completed_snapshots_parent
                    ON completed_snapshots(parent_snapshot_id, id);
                 CREATE TABLE snapshot_sources (
                    source_kind TEXT NOT NULL
                        CHECK (source_kind IN ('scan', 'build', 'runtime')),
                    source_attempt_id TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL REFERENCES completed_snapshots(id) ON DELETE CASCADE,
                    promoted_at TEXT NOT NULL,
                    PRIMARY KEY (source_kind, source_attempt_id)
                 );
                 CREATE INDEX snapshot_sources_snapshot
                    ON snapshot_sources(snapshot_id, source_kind, source_attempt_id);
                 CREATE TABLE current_completed_snapshot (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    snapshot_id TEXT NOT NULL REFERENCES completed_snapshots(id)
                 );",
            )?;
            backfill_completed_snapshots(&tx)?;
            tx.execute_batch("PRAGMA user_version = 8;")?;
            tx.commit()?;
        }
        if current < 9 {
            let tx = self.connection.transaction()?;
            tx.execute_batch(
                "CREATE TABLE snapshot_names (
                    name TEXT PRIMARY KEY COLLATE NOCASE,
                    snapshot_id TEXT NOT NULL REFERENCES completed_snapshots(id),
                    named_at TEXT NOT NULL
                 );
                 CREATE INDEX snapshot_names_snapshot
                    ON snapshot_names(snapshot_id, name);
                 CREATE TRIGGER snapshot_names_immutable_update
                    BEFORE UPDATE ON snapshot_names
                    BEGIN SELECT RAISE(ABORT, 'snapshot names are immutable'); END;
                 CREATE TRIGGER snapshot_names_immutable_delete
                    BEFORE DELETE ON snapshot_names
                    BEGIN SELECT RAISE(ABORT, 'snapshot names are immutable'); END;
                 PRAGMA user_version = 9;",
            )?;
            tx.commit()?;
        }
        if current < 10 {
            let tx = self.connection.transaction()?;
            tx.execute_batch(
                "CREATE TABLE syntax_cache (
                    key TEXT PRIMARY KEY,
                    contract_version INTEGER NOT NULL,
                    dimensions_json TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL REFERENCES completed_snapshots(id) ON DELETE CASCADE,
                    payload_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE semantic_cache (
                    key TEXT PRIMARY KEY,
                    contract_version INTEGER NOT NULL,
                    dimensions_json TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL REFERENCES completed_snapshots(id) ON DELETE CASCADE,
                    payload_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE build_cache (
                    key TEXT PRIMARY KEY,
                    contract_version INTEGER NOT NULL,
                    dimensions_json TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL REFERENCES completed_snapshots(id) ON DELETE CASCADE,
                    payload_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE cache_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
                    build_attempt_id TEXT REFERENCES build_attempts(id) ON DELETE CASCADE,
                    layer TEXT NOT NULL CHECK (layer IN ('syntax', 'semantic', 'build')),
                    cache_key TEXT,
                    outcome TEXT NOT NULL CHECK (outcome IN ('hit', 'miss', 'reject', 'stored')),
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    CHECK ((scan_id IS NOT NULL AND build_attempt_id IS NULL)
                        OR (scan_id IS NULL AND build_attempt_id IS NOT NULL))
                 );
                 CREATE INDEX cache_events_scan_created
                    ON cache_events(scan_id, created_at, id);
                 CREATE INDEX cache_events_build_created
                    ON cache_events(build_attempt_id, created_at, id);
                 PRAGMA user_version = 10;",
            )?;
            tx.commit()?;
        }
        if current < 11 {
            self.connection
                .execute_batch("PRAGMA foreign_keys = OFF;")?;
            let migration = (|| -> Result<()> {
                let tx = self.connection.transaction()?;
                tx.execute_batch(
                    "CREATE TABLE completed_snapshots_v11 (
                        id TEXT PRIMARY KEY,
                        source_kind TEXT NOT NULL
                            CHECK (source_kind IN ('scan', 'build', 'runtime')),
                        source_attempt_id TEXT NOT NULL,
                        scan_id TEXT NOT NULL REFERENCES scans(id),
                        build_attempt_id TEXT REFERENCES build_attempts(id),
                        runtime_import_id TEXT,
                        runtime_session_set_json TEXT NOT NULL DEFAULT '[]',
                        parent_snapshot_id TEXT REFERENCES completed_snapshots_v11(id),
                        source_revision TEXT,
                        profile_set_json TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (status = 'completed'),
                        created_at TEXT NOT NULL,
                        CHECK (
                            (source_kind = 'scan'
                                AND build_attempt_id IS NULL
                                AND runtime_import_id IS NULL
                                AND runtime_session_set_json = '[]')
                            OR (source_kind = 'build'
                                AND build_attempt_id IS NOT NULL
                                AND runtime_import_id IS NULL)
                            OR (source_kind = 'runtime'
                                AND runtime_import_id IS NOT NULL
                                AND runtime_session_set_json != '[]')
                        )
                     );
                     INSERT INTO completed_snapshots_v11(
                        id, source_kind, source_attempt_id, scan_id, build_attempt_id,
                        runtime_import_id, runtime_session_set_json, parent_snapshot_id,
                        source_revision, profile_set_json, status, created_at
                     )
                     SELECT id, source_kind, source_attempt_id, scan_id, build_attempt_id,
                            NULL, '[]', parent_snapshot_id, source_revision,
                            profile_set_json, status, created_at
                       FROM completed_snapshots;
                     DROP TABLE completed_snapshots;
                     ALTER TABLE completed_snapshots_v11 RENAME TO completed_snapshots;
                     CREATE INDEX completed_snapshots_scan_created
                        ON completed_snapshots(scan_id, created_at, id);
                     CREATE INDEX completed_snapshots_parent
                        ON completed_snapshots(parent_snapshot_id, id);

                     CREATE TABLE snapshot_sources_v11 (
                        source_kind TEXT NOT NULL
                            CHECK (source_kind IN ('scan', 'build', 'runtime')),
                        source_attempt_id TEXT NOT NULL,
                        snapshot_id TEXT NOT NULL
                            REFERENCES completed_snapshots(id) ON DELETE CASCADE,
                        promoted_at TEXT NOT NULL,
                        PRIMARY KEY (source_kind, source_attempt_id)
                     );
                     INSERT INTO snapshot_sources_v11
                        SELECT source_kind, source_attempt_id, snapshot_id, promoted_at
                          FROM snapshot_sources;
                     DROP TABLE snapshot_sources;
                     ALTER TABLE snapshot_sources_v11 RENAME TO snapshot_sources;
                     CREATE INDEX snapshot_sources_snapshot
                        ON snapshot_sources(snapshot_id, source_kind, source_attempt_id);

                     CREATE TABLE IF NOT EXISTS runtime_sessions (
                        id TEXT PRIMARY KEY,
                        base_snapshot_id TEXT NOT NULL REFERENCES completed_snapshots(id),
                        source_session_id TEXT NOT NULL,
                        schema_version TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (status IN ('completed', 'partial')),
                        trace_digest TEXT NOT NULL,
                        profile_id TEXT NOT NULL,
                        parent_profile_id TEXT,
                        profile_status TEXT NOT NULL,
                        profile_reason TEXT,
                        profile_json TEXT NOT NULL,
                        environment_json TEXT NOT NULL,
                        redaction_json TEXT NOT NULL,
                        started_at TEXT NOT NULL,
                        ended_at TEXT,
                        first_observed_at TEXT NOT NULL,
                        last_observed_at TEXT NOT NULL,
                        event_count INTEGER NOT NULL,
                        observation_count INTEGER NOT NULL,
                        resolved_targets INTEGER NOT NULL,
                        external_targets INTEGER NOT NULL,
                        unresolved_targets INTEGER NOT NULL,
                        redacted_values INTEGER NOT NULL,
                        coverage_json TEXT NOT NULL,
                        created_at TEXT NOT NULL
                     );
                     CREATE INDEX IF NOT EXISTS runtime_sessions_base_created
                        ON runtime_sessions(base_snapshot_id, created_at, id);
                     CREATE INDEX IF NOT EXISTS runtime_sessions_profile
                        ON runtime_sessions(profile_id, id);

                     CREATE TABLE IF NOT EXISTS runtime_nodes (
                        session_id TEXT NOT NULL
                            REFERENCES runtime_sessions(id) ON DELETE CASCADE,
                        id TEXT NOT NULL,
                        raw_json TEXT NOT NULL,
                        PRIMARY KEY (session_id, id)
                     );
                     CREATE TABLE IF NOT EXISTS runtime_sites (
                        session_id TEXT NOT NULL
                            REFERENCES runtime_sessions(id) ON DELETE CASCADE,
                        id TEXT NOT NULL,
                        raw_json TEXT NOT NULL,
                        PRIMARY KEY (session_id, id)
                     );
                     CREATE TABLE IF NOT EXISTS runtime_edges (
                        session_id TEXT NOT NULL
                            REFERENCES runtime_sessions(id) ON DELETE CASCADE,
                        id TEXT NOT NULL,
                        raw_json TEXT NOT NULL,
                        PRIMARY KEY (session_id, id)
                     );
                     CREATE INDEX IF NOT EXISTS runtime_edges_session_source
                        ON runtime_edges(session_id, id);
                     CREATE TABLE IF NOT EXISTS runtime_evidence (
                        session_id TEXT NOT NULL
                            REFERENCES runtime_sessions(id) ON DELETE CASCADE,
                        owner_type TEXT NOT NULL,
                        owner_id TEXT NOT NULL,
                        ordinal INTEGER NOT NULL,
                        raw_json TEXT NOT NULL,
                        PRIMARY KEY (session_id, owner_type, owner_id, ordinal)
                     );
                     CREATE INDEX IF NOT EXISTS runtime_evidence_owner
                        ON runtime_evidence(owner_type, owner_id, session_id, ordinal);
                     CREATE TABLE IF NOT EXISTS runtime_diagnostics (
                        session_id TEXT NOT NULL
                            REFERENCES runtime_sessions(id) ON DELETE CASCADE,
                        ordinal INTEGER NOT NULL,
                        id TEXT NOT NULL,
                        raw_json TEXT NOT NULL,
                        PRIMARY KEY (session_id, ordinal),
                        UNIQUE (session_id, id)
                     );

                     CREATE TABLE IF NOT EXISTS runtime_imports (
                        id TEXT PRIMARY KEY,
                        parent_snapshot_id TEXT NOT NULL REFERENCES completed_snapshots(id),
                        session_id TEXT NOT NULL REFERENCES runtime_sessions(id),
                        status TEXT NOT NULL CHECK (status IN ('staging', 'completed', 'failed')),
                        result_snapshot_id TEXT REFERENCES completed_snapshots(id),
                        created_at TEXT NOT NULL,
                        completed_at TEXT,
                        error TEXT
                     );
                     CREATE INDEX IF NOT EXISTS runtime_imports_parent_created
                        ON runtime_imports(parent_snapshot_id, created_at, id);
                     PRAGMA user_version = 11;",
                )?;
                tx.commit()?;
                Ok(())
            })();
            self.connection.execute_batch("PRAGMA foreign_keys = ON;")?;
            migration?;
            let violations = self.connection.query_row(
                "SELECT COUNT(*) FROM pragma_foreign_key_check",
                [],
                |row| row.get::<_, u64>(0),
            )?;
            if violations != 0 {
                bail!("store schema 11 migration left {violations} foreign key violations");
            }
        }
        if current < 12 {
            let tx = self.connection.transaction()?;
            tx.execute_batch(
                "CREATE TABLE incremental_deltas (
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    delta_id TEXT NOT NULL,
                    adapter TEXT NOT NULL,
                    base_snapshot_id TEXT NOT NULL REFERENCES completed_snapshots(id),
                    base_graph_digest TEXT NOT NULL,
                    result_graph_digest TEXT NOT NULL,
                    scope_json TEXT NOT NULL,
                    events_json TEXT NOT NULL,
                    mutation_count INTEGER NOT NULL CHECK (mutation_count > 0),
                    status TEXT NOT NULL
                        CHECK (status IN ('staging', 'applied', 'failed', 'cancelled')),
                    prospective_snapshot_id TEXT,
                    staged_at TEXT NOT NULL,
                    completed_at TEXT,
                    error TEXT,
                    PRIMARY KEY (scan_id, delta_id)
                 );
                 CREATE INDEX incremental_deltas_base_status
                    ON incremental_deltas(base_snapshot_id, status, staged_at, scan_id, delta_id);
                 PRAGMA user_version = 12;",
            )?;
            tx.commit()?;
        }
        if current < 13 {
            let tx = self.connection.transaction()?;
            tx.execute_batch(
                "CREATE TABLE impact_query_cache (
                    key TEXT PRIMARY KEY,
                    contract_version INTEGER NOT NULL,
                    snapshot_id TEXT NOT NULL
                        REFERENCES completed_snapshots(id) ON DELETE CASCADE,
                    payload_json TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT NOT NULL,
                    last_used_sequence INTEGER NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE INDEX impact_query_cache_snapshot_used
                    ON impact_query_cache(snapshot_id, last_used_sequence, key);
                 CREATE INDEX impact_query_cache_lru
                    ON impact_query_cache(last_used_sequence, key);
                 PRAGMA user_version = 13;",
            )?;
            tx.commit()?;
        }
        if current < 14 {
            let tx = self.connection.transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS compiler_precise_cache (
                    key TEXT PRIMARY KEY,
                    contract_version INTEGER NOT NULL,
                    dimensions_json TEXT NOT NULL,
                    source_snapshot_id TEXT NOT NULL
                        REFERENCES completed_snapshots(id),
                    source_attempt_id TEXT NOT NULL
                        REFERENCES build_attempts(id),
                    base_snapshot_id TEXT NOT NULL
                        REFERENCES completed_snapshots(id),
                    payload_json TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    payload_bytes INTEGER NOT NULL CHECK (payload_bytes > 0),
                    created_at TEXT NOT NULL,
                    last_used_at TEXT NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE INDEX IF NOT EXISTS compiler_precise_cache_lru
                    ON compiler_precise_cache(last_used_at, key);

                 CREATE TABLE IF NOT EXISTS cache_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
                    build_attempt_id TEXT REFERENCES build_attempts(id) ON DELETE CASCADE,
                    layer TEXT NOT NULL CHECK (layer IN ('syntax', 'semantic', 'build')),
                    cache_key TEXT,
                    outcome TEXT NOT NULL
                        CHECK (outcome IN ('hit', 'miss', 'reject', 'stored')),
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    CHECK ((scan_id IS NOT NULL AND build_attempt_id IS NULL)
                        OR (scan_id IS NULL AND build_attempt_id IS NOT NULL))
                 );

                 CREATE TABLE cache_events_v14 (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
                    build_attempt_id TEXT REFERENCES build_attempts(id) ON DELETE CASCADE,
                    layer TEXT NOT NULL
                        CHECK (layer IN ('syntax', 'semantic', 'build', 'compiler-precise')),
                    cache_key TEXT,
                    outcome TEXT NOT NULL
                        CHECK (outcome IN ('hit', 'miss', 'reject', 'stored')),
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    CHECK ((scan_id IS NOT NULL AND build_attempt_id IS NULL)
                        OR (scan_id IS NULL AND build_attempt_id IS NOT NULL))
                 );
                 INSERT INTO cache_events_v14(
                    id, scan_id, build_attempt_id, layer, cache_key, outcome, reason, created_at
                 )
                 SELECT id, scan_id, build_attempt_id, layer, cache_key, outcome, reason, created_at
                   FROM cache_events;
                 DROP TABLE cache_events;
                 ALTER TABLE cache_events_v14 RENAME TO cache_events;
                 CREATE INDEX cache_events_scan_created
                    ON cache_events(scan_id, created_at, id);
                 CREATE INDEX cache_events_build_created
                    ON cache_events(build_attempt_id, created_at, id);
                 PRAGMA user_version = 14;",
            )?;
            tx.commit()?;
        }
        if current < 15 {
            let tx = self.connection.transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS completed_snapshot_seals (
                    snapshot_id TEXT PRIMARY KEY
                        REFERENCES completed_snapshots(id) ON DELETE CASCADE,
                    seal_version INTEGER NOT NULL CHECK (seal_version = 1),
                    seal_sha256 TEXT NOT NULL
                        CHECK (length(seal_sha256) = 64
                            AND seal_sha256 NOT GLOB '*[^0-9a-f]*')
                 );",
            )?;
            backfill_completed_snapshot_seals(&tx)?;
            tx.execute_batch("PRAGMA user_version = 15;")?;
            tx.commit()?;
        }
        if current < 17 {
            let tx = self.connection.transaction()?;
            let legacy_runtime_imports = if current < 16 {
                authenticate_store_schema_before_v16(&tx)?;
                validate_store_foreign_keys(&tx, 16)?;
                authenticate_legacy_runtime_import_candidates(&tx)?
            } else {
                authenticate_store_schema_before_v17(&tx)?;
                validate_store_foreign_keys(&tx, 17)?;
                Vec::new()
            };
            let legacy_scans = authenticate_legacy_scan_operation_candidates(&tx)?;

            if current < 16 {
                tx.execute_batch(RUNTIME_IMPORT_OPERATION_OWNERS_TABLE_SQL)?;
                tx.execute_batch(RUNTIME_IMPORT_OPERATION_OWNERS_INDEX_SQL)?;
                for candidate in legacy_runtime_imports {
                    let operation_id = legacy_runtime_import_owner_id(&candidate.import_id);
                    tx.execute(
                        "INSERT INTO runtime_import_operation_owners(
                             import_id, operation_id, created_at
                         ) VALUES (?1, ?2, ?3)",
                        params![candidate.import_id, operation_id, candidate.created_at],
                    )?;
                }
                validate_runtime_import_operation_ownership_schema_and_rows(&tx)?;
                validate_store_foreign_keys(&tx, 16)?;
                tx.execute_batch("PRAGMA user_version = 16;")?;
            }

            tx.execute_batch(SCAN_OPERATION_STAGING_TABLE_SQL)?;
            tx.execute_batch(SCAN_OPERATION_STAGING_SCAN_INDEX_SQL)?;
            tx.execute_batch(SCAN_OPERATION_STAGING_PENDING_INDEX_SQL)?;
            for candidate in legacy_scans {
                let operation_id = legacy_scan_operation_candidate_id(&candidate.scan_id);
                tx.execute(
                    "INSERT INTO scan_operation_staging(
                         operation_id, scan_id, repository_binding_digest,
                         configuration_digest, strict, cache_enabled,
                         base_snapshot_id, validated_mutation_count,
                         prospective_snapshot_id, result_digest,
                         decision_authorization_digest, created_at
                     ) VALUES (?1, ?2, zeroblob(32), zeroblob(32), ?3, 0,
                               ?4, ?5, ?6, NULL, zeroblob(32), ?7)",
                    params![
                        operation_id,
                        candidate.scan_id,
                        candidate.strict,
                        candidate.parent_snapshot_id,
                        candidate.validated_mutation_count,
                        candidate.prospective_snapshot_id,
                        candidate.started_at,
                    ],
                )?;
            }
            validate_runtime_import_operation_ownership_schema_and_rows(&tx)?;
            validate_scan_operation_staging_schema_and_rows(&tx)?;
            validate_store_foreign_keys(&tx, 17)?;
            tx.execute_batch("PRAGMA user_version = 17;")?;
            tx.commit()?;
            return Ok(());
        }
        validate_runtime_import_operation_ownership_schema_and_rows(&self.connection)?;
        validate_scan_operation_staging_schema_and_rows(&self.connection)?;
        validate_store_foreign_keys(&self.connection, STORE_SCHEMA_VERSION)?;
        Ok(())
    }

    pub fn save_build_audit(&mut self, audit: &Value) -> Result<()> {
        let object = audit
            .as_object()
            .context("build audit must be a JSON object")?;
        let run_id = required_str(audit, "run_id")?;
        let outcome = required_str(audit, "outcome")?;
        let started_at = required_str(audit, "started_at")?;
        let finished_at = required_str(audit, "finished_at")?;
        if run_id.trim().is_empty() {
            bail!("build audit run_id must not be empty");
        }
        if !matches!(
            outcome,
            "completed" | "failed" | "timed_out" | "cancelled" | "security_failed"
        ) {
            bail!("invalid build audit outcome {outcome}");
        }
        let environment_keys = object
            .get("environment_keys")
            .and_then(Value::as_array)
            .context("build audit environment_keys must be an array")?;
        for key in environment_keys {
            let key = key
                .as_str()
                .context("build audit environment key must be a string")?;
            if is_secret_like_key(key) {
                bail!("build audit contains a secret-like environment key");
            }
        }
        let raw = serde_json::to_string(audit)?;
        let tx = self.connection.transaction()?;
        tx.execute(
            "INSERT INTO build_audits(run_id, outcome, started_at, finished_at, audit_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![run_id, outcome, started_at, finished_at, raw],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn build_audit(&self, run_id: &str) -> Result<Option<BuildAuditRecord>> {
        self.connection
            .query_row(
                "SELECT run_id, outcome, started_at, finished_at, audit_json
                   FROM build_audits WHERE run_id=?1",
                [run_id],
                |row| {
                    let raw = row.get::<_, String>(4)?;
                    let audit = serde_json::from_str(&raw).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            raw.len(),
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                    Ok(BuildAuditRecord {
                        run_id: row.get(0)?,
                        outcome: row.get(1)?,
                        started_at: row.get(2)?,
                        finished_at: row.get(3)?,
                        audit,
                    })
                },
            )
            .optional()
            .context("failed to load build audit")
    }

    pub fn latest_build_audit(&self) -> Result<Option<BuildAuditRecord>> {
        self.connection
            .query_row(
                "SELECT run_id, outcome, started_at, finished_at, audit_json
                   FROM build_audits ORDER BY started_at DESC, rowid DESC LIMIT 1",
                [],
                |row| {
                    let raw = row.get::<_, String>(4)?;
                    let audit = serde_json::from_str(&raw).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            raw.len(),
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                    Ok(BuildAuditRecord {
                        run_id: row.get(0)?,
                        outcome: row.get(1)?,
                        started_at: row.get(2)?,
                        finished_at: row.get(3)?,
                        audit,
                    })
                },
            )
            .optional()
            .context("failed to load latest build audit")
    }

    /// Starts an immutable build-evidence attempt tied to one completed base
    /// scan and one supervisor audit. Only completed audits may later stage a
    /// graph delta; failed audits remain queryable attempt metadata.
    pub fn start_build_attempt(&mut self, base_scan_id: &str, audit: &Value) -> Result<String> {
        self.start_build_attempt_with_base_snapshot(base_scan_id, audit, None)
    }

    pub fn start_build_attempt_at_base_snapshot(
        &mut self,
        base_scan_id: &str,
        base_snapshot_id: &str,
        audit: &Value,
    ) -> Result<String> {
        self.start_build_attempt_with_base_snapshot(base_scan_id, audit, Some(base_snapshot_id))
    }

    fn start_build_attempt_with_base_snapshot(
        &mut self,
        base_scan_id: &str,
        audit: &Value,
        requested_base_snapshot_id: Option<&str>,
    ) -> Result<String> {
        let run_id = required_str(audit, "run_id")?;
        let outcome = required_str(audit, "outcome")?;
        let output_digest = audit
            .get("validated_output_digest")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        if outcome == "completed" && output_digest.is_none() {
            bail!("completed build audit must include validated_output_digest");
        }
        for (field, digest) in [
            (
                "command_plan_digest",
                required_str(audit, "command_plan_digest")?,
            ),
            (
                "toolchain_executable_digest",
                required_str(audit, "toolchain_executable_digest")?,
            ),
            (
                "environment_key_set_digest",
                required_str(audit, "environment_key_set_digest")?,
            ),
        ] {
            if !is_sha256_hex(digest) {
                bail!("build audit {field} must be a lowercase SHA-256 digest");
            }
        }
        if let Some(output_digest) = output_digest
            && !is_sha256_hex(output_digest)
        {
            bail!("build audit validated_output_digest must be a lowercase SHA-256 digest");
        }
        let stored_audit = self
            .build_audit(run_id)?
            .with_context(|| format!("build audit {run_id} must be saved before its attempt"))?;
        if stored_audit.audit != *audit {
            bail!("build attempt audit does not match the saved audit");
        }
        let base_status = self
            .scan(base_scan_id)?
            .with_context(|| format!("base scan {base_scan_id} was not found"))?
            .status;
        if base_status != "completed" {
            bail!("build evidence requires a completed base scan");
        }
        // Build profiles are additive evidence layers. A later build attempt
        // validates against the latest completed snapshot for the same safe
        // scan so it cannot silently replace an already-promoted build (or
        // runtime) layer.
        let base_snapshot_id = if let Some(snapshot_id) = requested_base_snapshot_id {
            let safe_snapshot_id = self
                .snapshot_id_for_source("scan", base_scan_id)?
                .with_context(|| format!("base scan {base_scan_id} has no safe snapshot"))?;
            if safe_snapshot_id != snapshot_id {
                bail!("requested build base snapshot is not the selected safe scan snapshot");
            }
            if !self.verify_snapshot_integrity(snapshot_id)?.valid {
                bail!("requested build base snapshot failed integrity validation");
            }
            snapshot_id.to_owned()
        } else {
            self.snapshot_id_for_scan_selection(base_scan_id)?
                .with_context(|| format!("base scan {base_scan_id} has no completed snapshot"))?
        };
        let tx = self.connection.transaction()?;
        tx.execute(
            "INSERT INTO build_attempts(
                id, base_scan_id, base_snapshot_id, audit_run_id, status, observer, observer_version,
                profile_id, command_plan_digest, toolchain_executable_digest,
                environment_key_set_digest, validated_output_digest, started_at
             ) VALUES (?1, ?2, ?3, ?4, 'staging', ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                run_id,
                base_scan_id,
                base_snapshot_id,
                run_id,
                required_str(audit, "adapter")?,
                required_str(audit, "adapter_version")?,
                required_str(audit, "profile_id")?,
                required_str(audit, "command_plan_digest")?,
                required_str(audit, "toolchain_executable_digest")?,
                required_str(audit, "environment_key_set_digest")?,
                output_digest,
                required_str(audit, "started_at")?,
            ],
        )?;
        tx.commit()?;
        Ok(run_id.to_owned())
    }

    /// Atomically validates and stages a complete build delta. A rejected
    /// protocol leaves the attempt without any partial graph payload.
    pub fn save_build_delta(
        &mut self,
        attempt_id: &str,
        protocol: &ValidatedProtocol,
    ) -> Result<()> {
        validate_build_contract(protocol).context("invalid build evidence protocol")?;
        let attempt = self
            .build_attempt(attempt_id)?
            .with_context(|| format!("build attempt {attempt_id} was not found"))?;
        if attempt.status != "staging" {
            bail!(
                "build attempt {attempt_id} is immutable after reaching {}",
                attempt.status
            );
        }
        let mut delta = build_delta_from_protocol(protocol)?;
        let audit = self
            .build_audit(&attempt.audit_run_id)?
            .context("build attempt audit is missing")?;
        if audit.outcome != "completed" || attempt.validated_output_digest.is_none() {
            bail!("only a completed supervisor attempt can stage build evidence");
        }
        validate_delta_attempt_metadata(&delta, &attempt)?;
        let base_snapshot_id = attempt
            .base_snapshot_id
            .as_deref()
            .context("build attempt has no completed base snapshot")?;
        if !self.verify_snapshot_integrity(base_snapshot_id)?.valid {
            bail!("build attempt base snapshot {base_snapshot_id} failed integrity validation");
        }
        let base = self.load_completed_snapshot(base_snapshot_id)?;
        deduplicate_identical_build_evidence(&base, &mut delta)?;
        validate_build_union(&base, &delta, &attempt)?;
        let encoded = serde_json::to_string(&delta)?;
        let tx = self.connection.transaction()?;
        ensure_build_staging(&tx, attempt_id)?;
        tx.execute(
            "UPDATE build_attempts SET delta_json=?2 WHERE id=?1",
            params![attempt_id, encoded],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn finish_build_attempt(
        &mut self,
        attempt_id: &str,
        status: &str,
        error: Option<&str>,
        promote: bool,
    ) -> Result<()> {
        if !matches!(
            status,
            "completed" | "partial" | "failed" | "timed_out" | "cancelled" | "security_failed"
        ) {
            bail!("invalid terminal build attempt status {status}");
        }
        if promote && status != "completed" {
            bail!("only completed build attempts can be promoted");
        }
        let tx = self.connection.transaction()?;
        ensure_build_staging(&tx, attempt_id)?;
        let (base_scan_id, base_snapshot_id, has_delta, audit_outcome): (
            String,
            Option<String>,
            bool,
            String,
        ) = tx.query_row(
            "SELECT a.base_scan_id, a.base_snapshot_id, a.delta_json IS NOT NULL, b.outcome
               FROM build_attempts a JOIN build_audits b ON b.run_id=a.audit_run_id
              WHERE a.id=?1",
            [attempt_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        if status == "completed" && !has_delta {
            bail!("completed build attempt {attempt_id} has no validated delta");
        }
        if status == "completed" && audit_outcome != "completed" {
            bail!("completed build attempt requires a completed supervisor audit");
        }
        if audit_outcome != "completed" && status != audit_outcome {
            bail!(
                "build attempt status {status} does not match supervisor outcome {audit_outcome}"
            );
        }
        let completed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        tx.execute(
            "UPDATE build_attempts
                SET status=?2, completed_at=?3, error=?4,
                    delta_json=CASE WHEN ?2='completed' THEN delta_json ELSE NULL END
              WHERE id=?1",
            params![attempt_id, status, completed_at, error],
        )?;
        let completed_snapshot_id = if status == "completed" {
            let attempt_base_snapshot_id = base_snapshot_id.with_context(|| {
                format!("build attempt {attempt_id} has no base completed snapshot")
            })?;
            let latest_snapshot_id = tx
                .query_row(
                    "SELECT id FROM completed_snapshots
                      WHERE scan_id=?1 AND status='completed'
                      ORDER BY julianday(created_at) DESC, rowid DESC LIMIT 1",
                    [&base_scan_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .with_context(|| format!("base scan {base_scan_id} has no completed snapshot"))?;
            let latest_snapshot = load_completed_snapshot_record(&tx, &latest_snapshot_id)?
                .context("latest completed snapshot metadata was not found")?;
            let preserve_runtime = !latest_snapshot.runtime_session_ids.is_empty();
            let parent_snapshot_id = if preserve_runtime {
                latest_snapshot.id.as_str()
            } else {
                attempt_base_snapshot_id.as_str()
            };
            let source_revision = if preserve_runtime {
                latest_snapshot.source_revision.clone()
            } else {
                tx.query_row(
                    "SELECT source_revision FROM completed_snapshots WHERE id=?1",
                    [parent_snapshot_id],
                    |row| row.get::<_, Option<String>>(0),
                )?
            };
            let runtime_session_ids = if preserve_runtime {
                latest_snapshot.runtime_session_ids.as_slice()
            } else {
                &[]
            };
            Some(create_completed_snapshot(
                &tx,
                SnapshotSource {
                    source_kind: "build",
                    source_attempt_id: attempt_id,
                    scan_id: &base_scan_id,
                    build_attempt_id: Some(attempt_id),
                    runtime_import_id: None,
                    runtime_session_ids,
                    parent_snapshot_id: Some(parent_snapshot_id),
                    source_revision: source_revision.as_deref(),
                    created_at: &completed_at,
                },
            )?)
        } else {
            None
        };
        if promote {
            let snapshot_id = completed_snapshot_id
                .as_deref()
                .context("completed build attempt did not create a snapshot")?;
            tx.execute(
                "INSERT INTO current_build_successful(base_scan_id, attempt_id) VALUES (?1, ?2)
                 ON CONFLICT(base_scan_id) DO UPDATE SET attempt_id=excluded.attempt_id",
                params![base_scan_id, attempt_id],
            )?;
            promote_completed_snapshot(&tx, snapshot_id)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn build_attempt(&self, attempt_id: &str) -> Result<Option<BuildAttemptRecord>> {
        self.connection
            .query_row(
                "SELECT id, base_scan_id, base_snapshot_id, audit_run_id, status, observer, observer_version,
                        profile_id, command_plan_digest, toolchain_executable_digest,
                        environment_key_set_digest, validated_output_digest, started_at,
                        completed_at, error
                   FROM build_attempts WHERE id=?1",
                [attempt_id],
                |row| {
                    Ok(BuildAttemptRecord {
                        id: row.get(0)?,
                        base_scan_id: row.get(1)?,
                        base_snapshot_id: row.get(2)?,
                        audit_run_id: row.get(3)?,
                        status: row.get(4)?,
                        observer: row.get(5)?,
                        observer_version: row.get(6)?,
                        profile_id: row.get(7)?,
                        command_plan_digest: row.get(8)?,
                        toolchain_executable_digest: row.get(9)?,
                        environment_key_set_digest: row.get(10)?,
                        validated_output_digest: row.get(11)?,
                        started_at: row.get(12)?,
                        completed_at: row.get(13)?,
                        error: row.get(14)?,
                    })
                },
            )
            .optional()
            .context("failed to load build attempt")
    }

    pub fn current_build_attempt_id(&self, base_scan_id: &str) -> Result<Option<String>> {
        self.connection
            .query_row(
                "SELECT attempt_id FROM current_build_successful WHERE base_scan_id=?1",
                [base_scan_id],
                |row| row.get(0),
            )
            .optional()
            .context("failed to load current build attempt")
    }

    pub fn current_snapshot_id(&self) -> Result<Option<String>> {
        self.connection
            .query_row(
                "SELECT snapshot_id FROM current_completed_snapshot WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .context("failed to load current completed snapshot")
    }

    pub fn snapshot_id_for_source(
        &self,
        source_kind: &str,
        source_attempt_id: &str,
    ) -> Result<Option<String>> {
        if !matches!(source_kind, "scan" | "build" | "runtime") {
            bail!("invalid snapshot source kind {source_kind}");
        }
        self.connection
            .query_row(
                "SELECT snapshot_id FROM snapshot_sources
                  WHERE source_kind=?1 AND source_attempt_id=?2",
                params![source_kind, source_attempt_id],
                |row| row.get(0),
            )
            .optional()
            .context("failed to resolve completed snapshot source")
    }

    pub fn snapshot_id_for_scan_selection(&self, scan_id: &str) -> Result<Option<String>> {
        let completed = self
            .connection
            .query_row(
                "SELECT id FROM completed_snapshots
                  WHERE scan_id=?1 AND status='completed'
                  ORDER BY julianday(created_at) DESC, rowid DESC LIMIT 1",
                [scan_id],
                |row| row.get(0),
            )
            .optional()
            .context("failed to resolve completed snapshot for scan")?;
        if completed.is_some() {
            return Ok(completed);
        }
        self.snapshot_id_for_source("scan", scan_id)
    }

    pub fn completed_snapshot(&self, snapshot_id: &str) -> Result<Option<CompletedSnapshotRecord>> {
        load_completed_snapshot_record(&self.connection, snapshot_id)
    }

    pub fn create_snapshot_name(
        &mut self,
        name: &str,
        snapshot_id: &str,
    ) -> Result<SnapshotNameRecord> {
        validate_snapshot_name(name)?;
        let snapshot = self
            .completed_snapshot(snapshot_id)?
            .with_context(|| format!("completed snapshot {snapshot_id} was not found"))?;
        if snapshot.status != "completed" {
            bail!("snapshot {snapshot_id} is not completed");
        }
        let integrity = self.verify_snapshot_integrity(snapshot_id)?;
        if !integrity.valid {
            bail!(
                "completed snapshot {snapshot_id} failed integrity validation: {}",
                integrity.reasons.join(",")
            );
        }
        let named_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let tx = self.connection.transaction()?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO snapshot_names(name, snapshot_id, named_at)
             VALUES (?1, ?2, ?3)",
            params![name, snapshot_id, named_at],
        )?;
        if inserted == 0 {
            let existing = tx.query_row(
                "SELECT name, snapshot_id FROM snapshot_names WHERE name=?1 COLLATE NOCASE",
                [name],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?;
            bail!(
                "snapshot name {:?} already exists for {}; choose another name",
                existing.0,
                existing.1
            );
        }
        tx.commit()?;
        Ok(SnapshotNameRecord {
            name: name.to_owned(),
            snapshot_id: snapshot_id.to_owned(),
            named_at,
        })
    }

    pub fn snapshot_names(&self) -> Result<Vec<SnapshotNameRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT name, snapshot_id, named_at
               FROM snapshot_names
              ORDER BY name COLLATE BINARY, snapshot_id",
        )?;
        statement
            .query_map([], |row| {
                Ok(SnapshotNameRecord {
                    name: row.get(0)?,
                    snapshot_id: row.get(1)?,
                    named_at: row.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to list snapshot names")
    }

    pub fn snapshot_names_page<C>(
        &mut self,
        offset: usize,
        limit: usize,
        cancelled: C,
    ) -> Result<StorePage<SnapshotNameRecord>>
    where
        C: FnMut() -> bool + Send + 'static,
    {
        if limit == 0 {
            bail!("snapshot name page limit must be positive");
        }
        let offset = i64::try_from(offset).context("snapshot name page offset is too large")?;
        let limit = i64::try_from(limit).context("snapshot name page limit is too large")?;
        self.interruptible_read(cancelled, |store| {
            let total_items =
                store
                    .connection
                    .query_row("SELECT COUNT(*) FROM snapshot_names", [], |row| {
                        row.get::<_, u64>(0)
                    })?;
            let mut statement = store.connection.prepare(
                "SELECT name, snapshot_id, named_at
                   FROM snapshot_names
                  ORDER BY name COLLATE BINARY, snapshot_id COLLATE BINARY
                  LIMIT ?1 OFFSET ?2",
            )?;
            let items = statement
                .query_map(params![limit, offset], |row| {
                    Ok(SnapshotNameRecord {
                        name: row.get(0)?,
                        snapshot_id: row.get(1)?,
                        named_at: row.get(2)?,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(StorePage { items, total_items })
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn find_completed_snapshot_nodes_page<C>(
        &mut self,
        snapshot_id: &str,
        query: &str,
        match_mode: NodeTextMatch,
        kinds: &[String],
        offset: usize,
        limit: usize,
        cancelled: C,
    ) -> Result<StorePage<NodeSummaryRecord>>
    where
        C: FnMut() -> bool + Send + 'static,
    {
        if limit == 0 {
            bail!("completed snapshot node page limit must be positive");
        }
        let offset = i64::try_from(offset).context("node page offset is too large")?;
        let limit = i64::try_from(limit).context("node page limit is too large")?;
        let kinds = serde_json::to_string(kinds)?;
        self.interruptible_read(cancelled, |store| {
            verify_completed_snapshot_seal(&store.connection, snapshot_id)?;
            let sql = r#"
WITH RECURSIVE
snapshot_records(
    id, parent_snapshot_id, scan_parent_snapshot_id, scan_id, source_kind,
    build_attempt_id, runtime_session_set_json, scan_exists,
    semantic_noop, follow_parent
) AS (
    SELECT snapshot.id, snapshot.parent_snapshot_id, scan.parent_snapshot_id,
           snapshot.scan_id, snapshot.source_kind, snapshot.build_attempt_id,
           snapshot.runtime_session_set_json, scan.id IS NOT NULL,
           CASE
               WHEN snapshot.build_attempt_id IS NULL
                AND snapshot.runtime_session_set_json='[]'
                AND scan.parent_snapshot_id IS NOT NULL
                AND (SELECT COUNT(*) FROM profiles WHERE scan_id=snapshot.scan_id)=0
                AND (SELECT COUNT(*) FROM incremental_deltas
                      WHERE scan_id=snapshot.scan_id AND status='applied')=1
               THEN 1
               ELSE 0
           END,
           CASE
               WHEN snapshot.source_kind IN ('build', 'runtime') THEN 1
               WHEN snapshot.build_attempt_id IS NULL
                AND snapshot.runtime_session_set_json='[]'
                AND scan.parent_snapshot_id IS NOT NULL
                AND (SELECT COUNT(*) FROM profiles WHERE scan_id=snapshot.scan_id)=0
                AND (SELECT COUNT(*) FROM incremental_deltas
                      WHERE scan_id=snapshot.scan_id AND status='applied')=1
               THEN 1
               ELSE 0
           END
      FROM completed_snapshots AS snapshot
      LEFT JOIN scans AS scan ON scan.id=snapshot.scan_id
     WHERE snapshot.status='completed'
),
snapshot_layers(
    id, parent_snapshot_id, scan_parent_snapshot_id, scan_id, source_kind,
    build_attempt_id, runtime_session_set_json, scan_exists,
    semantic_noop, follow_parent, depth, visited_path, cycle
) AS (
    SELECT record.id, record.parent_snapshot_id, record.scan_parent_snapshot_id,
           record.scan_id, record.source_kind, record.build_attempt_id,
           record.runtime_session_set_json, record.scan_exists,
           record.semantic_noop, record.follow_parent, 0,
           char(31) || record.id || char(31), 0
      FROM snapshot_records AS record
     WHERE record.id=?1
    UNION ALL
    SELECT parent.id, parent.parent_snapshot_id, parent.scan_parent_snapshot_id,
           parent.scan_id, parent.source_kind, parent.build_attempt_id,
           parent.runtime_session_set_json, parent.scan_exists,
           parent.semantic_noop, parent.follow_parent, child.depth + 1,
           child.visited_path || parent.id || char(31),
           instr(
               child.visited_path,
               char(31) || parent.id || char(31)
           ) > 0
      FROM snapshot_layers AS child
      JOIN snapshot_records AS parent ON parent.id=child.parent_snapshot_id
     WHERE child.follow_parent=1 AND child.cycle=0
),
applicable_build_layers AS (
    SELECT layer.*
      FROM snapshot_layers AS layer
     WHERE layer.build_attempt_id IS NOT NULL
       AND NOT EXISTS (
           SELECT 1
             FROM snapshot_layers AS parent
            WHERE parent.depth=layer.depth + 1
              AND parent.build_attempt_id=layer.build_attempt_id
       )
),
runtime_layer_sessions(layer_depth, session_id, session_ordinal) AS (
    SELECT layer.depth, CAST(session.value AS TEXT), CAST(session.key AS INTEGER)
      FROM snapshot_layers AS layer
      JOIN json_each(layer.runtime_session_set_json) AS session
     WHERE NOT EXISTS (
           SELECT 1
             FROM snapshot_layers AS parent
             JOIN json_each(parent.runtime_session_set_json) AS inherited
            WHERE parent.depth=layer.depth + 1
              AND inherited.type='text'
              AND inherited.value=session.value
       )
),
node_candidates(
    id, kind, locator, display_name,
    layer_depth, source_order, collection_order, item_order
) AS (
    SELECT node.id, node.kind, node.locator, node.display_name,
           layer.depth, 0, 0, node.rowid
      FROM snapshot_layers AS layer
      JOIN nodes AS node ON node.scan_id=layer.scan_id
     WHERE layer.follow_parent=0 AND layer.cycle=0
    UNION ALL
    SELECT json_extract(item.value, '$.id'),
           json_extract(item.value, '$.kind'),
           json_extract(item.value, '$.locator'),
           json_extract(item.value, '$.display_name'),
           layer.depth, 1, 0, CAST(item.key AS INTEGER)
      FROM applicable_build_layers AS layer
      JOIN build_attempts AS attempt ON attempt.id=layer.build_attempt_id
      JOIN json_each(attempt.delta_json, '$.nodes') AS item
     WHERE attempt.base_scan_id=layer.scan_id
       AND attempt.status='completed'
       AND attempt.delta_json IS NOT NULL
    UNION ALL
    SELECT json_extract(node.raw_json, '$.id'),
           json_extract(node.raw_json, '$.kind'),
           json_extract(node.raw_json, '$.locator'),
           json_extract(node.raw_json, '$.display_name'),
           session.layer_depth, 2, session.session_ordinal, node.rowid
      FROM runtime_layer_sessions AS session
      JOIN runtime_nodes AS node ON node.session_id=session.session_id
),
ranked_nodes AS (
    SELECT id, kind, locator, display_name,
           ROW_NUMBER() OVER (
               PARTITION BY id
               ORDER BY layer_depth DESC, source_order,
                        collection_order, item_order
           ) AS precedence
      FROM node_candidates
),
semantic_parent_candidates AS (
    SELECT layer.depth AS overlay_depth,
           overlay.id AS overlay_id,
           overlay.kind AS overlay_kind,
           overlay.locator AS overlay_locator,
           overlay.display_name AS overlay_display_name,
           candidate.kind AS parent_kind,
           candidate.locator AS parent_locator,
           candidate.display_name AS parent_display_name,
           ROW_NUMBER() OVER (
               PARTITION BY layer.depth, overlay.id
               ORDER BY candidate.layer_depth DESC, candidate.source_order,
                        candidate.collection_order, candidate.item_order
           ) AS precedence
      FROM snapshot_layers AS layer
      JOIN nodes AS overlay ON overlay.scan_id=layer.scan_id
      JOIN node_candidates AS candidate
        ON candidate.id=overlay.id AND candidate.layer_depth>layer.depth
     WHERE layer.semantic_noop=1
),
projection_state(target_exists, integrity_valid) AS (
    SELECT EXISTS(SELECT 1 FROM snapshot_layers WHERE depth=0),
           CASE
               WHEN NOT EXISTS(SELECT 1 FROM snapshot_layers WHERE depth=0) THEN 0
               WHEN EXISTS(
                   SELECT 1 FROM snapshot_layers
                    WHERE cycle=1 OR scan_exists=0
               ) THEN 0
               WHEN EXISTS(
                   SELECT 1
                     FROM snapshot_layers AS layer
                    WHERE layer.follow_parent=1
                      AND (
                          layer.parent_snapshot_id IS NULL
                          OR NOT EXISTS (
                              SELECT 1 FROM snapshot_layers AS parent
                               WHERE parent.depth=layer.depth + 1
                          )
                      )
               ) THEN 0
               WHEN EXISTS(
                   SELECT 1
                     FROM snapshot_layers AS layer
                    WHERE layer.semantic_noop=1
                      AND (
                          layer.parent_snapshot_id IS NOT layer.scan_parent_snapshot_id
                          OR (SELECT COUNT(*) FROM nodes
                               WHERE scan_id=layer.scan_id) != 1
                          OR EXISTS (
                              SELECT 1 FROM nodes
                               WHERE scan_id=layer.scan_id
                                 AND json_valid(properties_json)=0
                          )
                          OR NOT EXISTS (
                              SELECT 1
                                FROM semantic_parent_candidates AS parent
                               WHERE parent.overlay_depth=layer.depth
                                 AND parent.precedence=1
                                 AND parent.overlay_kind=parent.parent_kind
                                 AND parent.overlay_locator=parent.parent_locator
                                 AND parent.overlay_display_name=parent.parent_display_name
                          )
                      )
               ) THEN 0
               WHEN EXISTS(
                   SELECT 1
                     FROM applicable_build_layers AS layer
                     LEFT JOIN build_attempts AS attempt
                       ON attempt.id=layer.build_attempt_id
                      AND attempt.base_scan_id=layer.scan_id
                      AND attempt.status='completed'
                    WHERE attempt.id IS NULL
                       OR attempt.delta_json IS NULL
                       OR json_valid(attempt.delta_json)=0
                       OR json_type(attempt.delta_json, '$.profiles')!='array'
                       OR json_type(attempt.delta_json, '$.nodes')!='array'
                       OR json_type(attempt.delta_json, '$.sites')!='array'
                       OR json_type(attempt.delta_json, '$.edges')!='array'
                       OR json_type(attempt.delta_json, '$.evidence')!='array'
                       OR json_type(attempt.delta_json, '$.diagnostics')!='array'
                       OR json_type(attempt.delta_json, '$.coverage')!='object'
               ) THEN 0
               WHEN EXISTS(
                   SELECT 1
                     FROM applicable_build_layers AS layer
                     JOIN build_attempts AS attempt ON attempt.id=layer.build_attempt_id
                     JOIN json_each(attempt.delta_json, '$.nodes') AS node
                    WHERE json_type(node.value, '$.id')!='text'
                       OR json_type(node.value, '$.kind')!='text'
                       OR json_type(node.value, '$.locator')!='text'
                       OR json_type(node.value, '$.display_name')!='text'
                       OR json_type(node.value, '$.properties') IS NULL
               ) THEN 0
               WHEN EXISTS(
                   SELECT 1 FROM snapshot_layers AS layer
                    WHERE json_valid(layer.runtime_session_set_json)=0
                       OR json_type(layer.runtime_session_set_json)!='array'
                       OR EXISTS (
                           SELECT 1 FROM json_each(layer.runtime_session_set_json)
                            WHERE type!='text'
                       )
               ) THEN 0
               WHEN EXISTS(
                   SELECT 1
                     FROM runtime_layer_sessions AS earlier
                     JOIN runtime_layer_sessions AS later
                       ON later.layer_depth=earlier.layer_depth
                      AND later.session_ordinal>earlier.session_ordinal
                    WHERE earlier.session_id>=later.session_id
               ) THEN 0
               WHEN EXISTS(
                   SELECT 1
                     FROM runtime_layer_sessions AS layer
                     LEFT JOIN runtime_sessions AS session
                       ON session.id=layer.session_id
                    WHERE session.id IS NULL
               ) THEN 0
               WHEN EXISTS(
                   SELECT 1
                     FROM runtime_layer_sessions AS layer
                     JOIN runtime_nodes AS node ON node.session_id=layer.session_id
                    WHERE json_valid(node.raw_json)=0
                       OR json_type(node.raw_json, '$.id')!='text'
                       OR json_type(node.raw_json, '$.kind')!='text'
                       OR json_type(node.raw_json, '$.locator')!='text'
                       OR json_type(node.raw_json, '$.display_name')!='text'
                       OR json_type(node.raw_json, '$.properties') IS NULL
               ) THEN 0
               ELSE 1
           END
),
filtered_nodes AS (
    SELECT id, kind, locator, display_name
      FROM ranked_nodes
     WHERE precedence=1
       AND (
           json_array_length(?4)=0
           OR kind IN (SELECT CAST(value AS TEXT) FROM json_each(?4))
       )
       AND CASE ?3
           WHEN 'exact' THEN
               id=?2 OR kind=?2 OR locator=?2 OR display_name=?2
           WHEN 'prefix' THEN
               substr(id, 1, length(?2))=?2
               OR substr(kind, 1, length(?2))=?2
               OR substr(locator, 1, length(?2))=?2
               OR substr(display_name, 1, length(?2))=?2
           WHEN 'contains' THEN
               instr(id, ?2)>0 OR instr(kind, ?2)>0
               OR instr(locator, ?2)>0 OR instr(display_name, ?2)>0
           ELSE 0
       END
),
total AS (
    SELECT COUNT(*) AS item_count FROM filtered_nodes
),
paged AS (
    SELECT id, kind, locator, display_name
      FROM filtered_nodes
     ORDER BY id COLLATE BINARY
     LIMIT ?5 OFFSET ?6
)
SELECT page.id, page.kind, page.locator, page.display_name, total.item_count,
       state.target_exists, state.integrity_valid
  FROM paged AS page CROSS JOIN total CROSS JOIN projection_state AS state
 WHERE state.integrity_valid=1
UNION ALL
SELECT NULL, NULL, NULL, NULL,
       CASE WHEN state.integrity_valid=1 THEN total.item_count ELSE 0 END,
       state.target_exists, state.integrity_valid
  FROM total CROSS JOIN projection_state AS state
 WHERE state.integrity_valid=0 OR NOT EXISTS (SELECT 1 FROM paged)
ORDER BY id COLLATE BINARY
"#;
            let mut statement = store.connection.prepare(sql)?;
            let mut rows = statement.query(params![
                snapshot_id,
                query,
                match_mode.as_str(),
                kinds,
                limit,
                offset
            ])?;
            let mut items = Vec::new();
            let mut total_items = None;
            let mut target_exists = None;
            let mut integrity_valid = None;
            while let Some(row) = rows.next()? {
                total_items = Some(row.get::<_, u64>(4)?);
                target_exists = Some(row.get::<_, bool>(5)?);
                integrity_valid = Some(row.get::<_, bool>(6)?);
                let Some(id) = row.get::<_, Option<String>>(0)? else {
                    continue;
                };
                items.push(NodeSummaryRecord {
                    id,
                    kind: row.get(1)?,
                    locator: row.get(2)?,
                    display_name: row.get(3)?,
                });
            }
            if !target_exists.unwrap_or(false) {
                bail!("completed snapshot {snapshot_id} was not found");
            }
            if !integrity_valid.unwrap_or(false) {
                bail!(
                    "completed snapshot {snapshot_id} node projection failed integrity validation"
                );
            }
            let total_items =
                total_items.context("completed snapshot node projection was empty")?;
            Ok(StorePage { items, total_items })
        })
    }

    pub fn snapshot_id_for_name(&self, name: &str) -> Result<Option<String>> {
        self.connection
            .query_row(
                "SELECT snapshot_id FROM snapshot_names WHERE name=?1 COLLATE NOCASE",
                [name],
                |row| row.get(0),
            )
            .optional()
            .context("failed to resolve completed snapshot name")
    }

    pub fn resolve_completed_snapshot_selector(&self, selector: &str) -> Result<String> {
        if selector.trim().is_empty() {
            bail!("snapshot selector must not be empty");
        }
        if selector.eq_ignore_ascii_case("current") {
            return self
                .current_snapshot_id()?
                .context("no current completed snapshot is available");
        }
        if selector.eq_ignore_ascii_case("latest") {
            bail!(
                "snapshot selector \"latest\" is reserved; use current, a snapshot name, or a stable ID"
            );
        }
        let by_id = self
            .completed_snapshot(selector)?
            .map(|snapshot| snapshot.id);
        let by_name = self.snapshot_id_for_name(selector)?;
        match (by_id, by_name) {
            (Some(id), Some(named_id)) if id != named_id => bail!(
                "snapshot selector {selector:?} is ambiguous between stable ID {id} and named snapshot {named_id}"
            ),
            (Some(id), _) | (_, Some(id)) => Ok(id),
            (None, None) => bail!("snapshot selector {selector:?} was not found"),
        }
    }

    pub fn completed_snapshot_details(
        &self,
        snapshot_id: &str,
    ) -> Result<CompletedSnapshotDetails> {
        verify_completed_snapshot_seal(&self.connection, snapshot_id)?;
        let snapshot = self
            .completed_snapshot(snapshot_id)?
            .with_context(|| format!("completed snapshot {snapshot_id} was not found"))?;
        let mut names = {
            let mut statement = self.connection.prepare(
                "SELECT name FROM snapshot_names
                  WHERE snapshot_id=?1 ORDER BY name COLLATE BINARY",
            )?;
            statement
                .query_map([snapshot_id], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        names.sort();
        let mut coverage = self.load_completed_snapshot(snapshot_id)?.coverage;
        coverage.completeness.sort();
        coverage.completeness.dedup();
        coverage.reasons.sort();
        coverage.reasons.dedup();
        Ok(CompletedSnapshotDetails {
            snapshot,
            names,
            coverage,
        })
    }

    pub fn verify_snapshot_integrity(&self, snapshot_id: &str) -> Result<SnapshotIntegrityRecord> {
        let record = self
            .completed_snapshot(snapshot_id)?
            .with_context(|| format!("completed snapshot {snapshot_id} was not found"))?;
        let (observed_id, observed_profiles) = completed_snapshot_identity(
            &self.connection,
            &record.scan_id,
            record.build_attempt_id.as_deref(),
            &record.runtime_session_ids,
            record.parent_snapshot_id.as_deref(),
            record.source_revision.as_deref(),
        )?;
        let mut reasons = Vec::new();
        if observed_id != record.id {
            reasons.push("content_digest_mismatch".to_owned());
        }
        if observed_profiles != record.profile_ids {
            reasons.push("profile_set_mismatch".to_owned());
        }
        if record.status != "completed" {
            reasons.push("snapshot_not_completed".to_owned());
        }
        if record.build_attempt_id.is_none()
            && record.runtime_session_ids.is_empty()
            && incremental::scan_is_semantic_noop_overlay(&self.connection, &record.scan_id)?
        {
            let mut parent_id = record
                .parent_snapshot_id
                .clone()
                .context("semantic no-op overlay integrity has no parent")?;
            let mut visited = BTreeSet::from([record.id.clone()]);
            let mut parent_invalid = false;
            loop {
                if !visited.insert(parent_id.clone()) {
                    parent_invalid = true;
                    break;
                }
                let parent = self
                    .completed_snapshot(&parent_id)?
                    .with_context(|| format!("completed snapshot {parent_id} was not found"))?;
                let (parent_observed_id, parent_observed_profiles) = completed_snapshot_identity(
                    &self.connection,
                    &parent.scan_id,
                    parent.build_attempt_id.as_deref(),
                    &parent.runtime_session_ids,
                    parent.parent_snapshot_id.as_deref(),
                    parent.source_revision.as_deref(),
                )?;
                if parent_observed_id != parent.id
                    || parent_observed_profiles != parent.profile_ids
                    || parent.status != "completed"
                {
                    parent_invalid = true;
                    break;
                }
                if parent.build_attempt_id.is_some()
                    || !parent.runtime_session_ids.is_empty()
                    || !incremental::scan_is_semantic_noop_overlay(
                        &self.connection,
                        &parent.scan_id,
                    )?
                {
                    break;
                }
                parent_id = parent
                    .parent_snapshot_id
                    .context("semantic no-op overlay integrity has no parent")?;
            }
            if parent_invalid {
                reasons.push("parent_integrity_mismatch".to_owned());
            }
        }
        Ok(SnapshotIntegrityRecord {
            snapshot_id: record.id.clone(),
            valid: reasons.is_empty(),
            expected_id: record.id,
            observed_id,
            reasons,
        })
    }

    /// Explicitly removes terminal attempts that never produced a completed
    /// snapshot. Completed snapshot payloads, their source attempts, staging
    /// attempts, and the current pointer are always retained.
    pub fn garbage_collect_unreferenced_attempts(&mut self) -> Result<GarbageCollectionReport> {
        let tx = self.connection.transaction()?;
        let build_attempts_deleted = tx.execute(
            "DELETE FROM build_attempts
              WHERE status!='staging'
                AND NOT EXISTS (
                    SELECT 1 FROM snapshot_sources ss
                     WHERE ss.source_kind='build' AND ss.source_attempt_id=build_attempts.id
                )
                AND NOT EXISTS (
                    SELECT 1 FROM current_build_successful cb
                     WHERE cb.attempt_id=build_attempts.id
                )",
            [],
        )? as u64;
        let build_audits_deleted = tx.execute(
            "DELETE FROM build_audits
              WHERE NOT EXISTS (
                    SELECT 1 FROM build_attempts ba WHERE ba.audit_run_id=build_audits.run_id
              )",
            [],
        )? as u64;
        let scan_attempts_deleted = tx.execute(
            "DELETE FROM scans
              WHERE status!='staging'
                AND NOT EXISTS (
                    SELECT 1 FROM snapshot_sources ss
                     WHERE ss.source_kind='scan' AND ss.source_attempt_id=scans.id
                )
                AND NOT EXISTS (
                    SELECT 1 FROM build_attempts ba WHERE ba.base_scan_id=scans.id
                )
                AND NOT EXISTS (
                    SELECT 1 FROM current_successful cs WHERE cs.scan_id=scans.id
                )",
            [],
        )? as u64;
        tx.commit()?;
        Ok(GarbageCollectionReport {
            scan_attempts_deleted,
            build_attempts_deleted,
            build_audits_deleted,
        })
    }

    /// Finalizes staging attempts left behind when a repository daemon or one
    /// of its worker process trees exited without completing its transaction.
    /// Completed snapshot pointers are intentionally never changed.
    pub fn recover_interrupted_attempts(
        &mut self,
        root: &Path,
    ) -> Result<InterruptedAttemptRecovery> {
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let root = canonical_root.to_string_lossy().into_owned();
        let tx = self.connection.transaction()?;
        let scan_attempt_ids = {
            let mut statement = tx.prepare(
                "SELECT id FROM scans WHERE root=?1 AND status='staging' ORDER BY started_at, id",
            )?;
            statement
                .query_map([&root], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let build_attempt_ids = {
            let mut statement = tx.prepare(
                "SELECT attempt.id
                   FROM build_attempts attempt
                   JOIN scans base ON base.id=attempt.base_scan_id
                  WHERE base.root=?1 AND attempt.status='staging'
                  ORDER BY attempt.started_at, attempt.id",
            )?;
            statement
                .query_map([&root], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let completed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        for attempt_id in &build_attempt_ids {
            tx.execute(
                "UPDATE build_attempts
                    SET status='cancelled', completed_at=?2,
                        error='daemon recovered interrupted build attempt', delta_json=NULL
                  WHERE id=?1 AND status='staging'",
                params![attempt_id, completed_at],
            )?;
        }
        for scan_id in &scan_attempt_ids {
            tx.execute(
                "UPDATE incremental_deltas
                    SET status='cancelled', completed_at=?2,
                        error='daemon recovered interrupted incremental delta'
                  WHERE scan_id=?1 AND status='staging'",
                params![scan_id, completed_at],
            )?;
            tx.execute(
                "UPDATE scans
                    SET status='cancelled', completed_at=?2,
                        error='daemon recovered interrupted scan attempt'
                  WHERE id=?1 AND status='staging'",
                params![scan_id, completed_at],
            )?;
        }
        tx.commit()?;
        Ok(InterruptedAttemptRecovery {
            scan_attempt_ids,
            build_attempt_ids,
        })
    }

    pub fn start_scan(&mut self, scan_id: &str, root: &Path, strict: bool) -> Result<()> {
        self.start_scan_with_revision(scan_id, root, strict, None)
    }

    pub fn start_scan_with_revision(
        &mut self,
        scan_id: &str,
        root: &Path,
        strict: bool,
        source_revision: Option<&str>,
    ) -> Result<()> {
        self.start_scan_with_revision_and_operation(scan_id, root, strict, source_revision, None)
    }

    pub fn start_scan_for_operation(
        &mut self,
        scan_id: &str,
        root: &Path,
        strict: bool,
        source_revision: Option<&str>,
        identity: &ScanOperationStagingIdentity<'_>,
    ) -> Result<()> {
        self.start_scan_with_revision_and_operation(
            scan_id,
            root,
            strict,
            source_revision,
            Some(identity),
        )
    }

    fn start_scan_with_revision_and_operation(
        &mut self,
        scan_id: &str,
        root: &Path,
        strict: bool,
        source_revision: Option<&str>,
        identity: Option<&ScanOperationStagingIdentity<'_>>,
    ) -> Result<()> {
        if source_revision.is_some_and(|revision| revision.trim().is_empty()) {
            bail!("source revision must not be empty");
        }
        if let Some(identity) = identity
            && (identity.operation_id.is_empty()
                || identity.operation_id.len() > 512
                || identity.operation_id.chars().any(char::is_control)
                || identity
                    .operation_id
                    .starts_with(LEGACY_SCAN_OPERATION_CANDIDATE_PREFIX)
                || !scan_attempt_is_bound_to_operation(scan_id, identity.operation_id, false))
        {
            bail!("operation-owned scan attempt identity is invalid");
        }
        if identity.is_some() && self.legacy_scan_operation_candidate_exists()? {
            bail!("legacy scan operation staging must be reconciled before new operation scans");
        }
        let parent_snapshot_id = self.current_snapshot_id()?;
        let tx = self.connection.transaction()?;
        if let Some(identity) = identity {
            replace_abandoned_scan_attempt(&tx, root, strict, identity)?;
        }
        tx.execute(
            "INSERT INTO scans(
                id, root, status, strict, started_at, protocol_version,
                parent_snapshot_id, source_revision
             ) VALUES (?1, ?2, 'staging', ?3, ?4, '1.0', ?5, ?6)",
            params![
                scan_id,
                root.to_string_lossy(),
                strict,
                Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                parent_snapshot_id,
                source_revision,
            ],
        )?;
        if let Some(identity) = identity {
            tx.execute(
                "INSERT INTO scan_operation_staging(
                     operation_id, scan_id, repository_binding_digest,
                     configuration_digest, strict, cache_enabled,
                     base_snapshot_id, validated_mutation_count,
                     prospective_snapshot_id, result_digest,
                     decision_authorization_digest, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7,
                           NULL, NULL, NULL, NULL, ?8)",
                params![
                    identity.operation_id,
                    scan_id,
                    identity.repository_binding_digest.as_slice(),
                    identity.configuration_digest.as_slice(),
                    strict,
                    identity.cache_enabled,
                    parent_snapshot_id,
                    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn ingest_event(&mut self, event: &Value) -> Result<()> {
        self.ingest_events(&[event])
    }

    pub fn ingest_events(&mut self, events: &[&Value]) -> Result<()> {
        let Some(first) = events.first() else {
            return Ok(());
        };
        let scan_id = required_str(first, "scan_id")?;
        let tx = self.connection.transaction()?;
        ensure_scan_staging(&tx, scan_id)?;
        // Adapter logs may already have advanced mutation_count, so evidence
        // itself is the authoritative signal that an owner can need replacing.
        let replace_existing_evidence: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM evidence WHERE scan_id=?1 LIMIT 1)",
            [scan_id],
            |row| row.get(0),
        )?;
        let mut evidence_owners = HashSet::new();
        for event in events {
            if required_str(event, "scan_id")? != scan_id {
                bail!("event batch contains multiple scan IDs");
            }
            ingest_event_in_transaction(
                &tx,
                event,
                replace_existing_evidence,
                &mut evidence_owners,
            )?;
        }
        tx.execute(
            "UPDATE scans SET mutation_count=mutation_count+1 WHERE id=?1",
            [scan_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn save_adapter_log(
        &mut self,
        scan_id: &str,
        adapter: &str,
        stderr: &str,
        truncated: bool,
    ) -> Result<()> {
        let tx = self.connection.transaction()?;
        ensure_scan_staging(&tx, scan_id)?;
        tx.execute(
            "INSERT INTO adapter_logs(scan_id, adapter, stderr, truncated) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(scan_id, adapter) DO UPDATE SET stderr = excluded.stderr, truncated = excluded.truncated",
            params![scan_id, adapter, stderr, truncated],
        )?;
        tx.execute(
            "UPDATE scans SET mutation_count=mutation_count+1 WHERE id=?1",
            [scan_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn validate_scan(&self, scan_id: &str) -> Result<()> {
        let missing_nodes: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM edges e
             LEFT JOIN nodes src ON src.scan_id = e.scan_id AND src.id = e.source
             LEFT JOIN nodes dst ON dst.scan_id = e.scan_id AND dst.id = e.target
             WHERE e.scan_id = ?1 AND (src.id IS NULL OR dst.id IS NULL)",
            [scan_id],
            |row| row.get(0),
        )?;
        if missing_nodes > 0 {
            bail!("scan {scan_id} has {missing_nodes} edges with missing endpoint nodes");
        }

        let (site_count, resolved, candidates, external, unresolved): (i64, i64, i64, i64, i64) =
            self.connection.query_row(
                "SELECT COUNT(*),
                        COALESCE(SUM(CASE WHEN resolution_status='resolved' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN resolution_status='candidates' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN resolution_status='external' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN resolution_status='unresolved' THEN 1 ELSE 0 END), 0)
                 FROM sites WHERE scan_id = ?1",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )?;
        if site_count != resolved + candidates + external + unresolved {
            bail!("coverage invariant failed for scan {scan_id}");
        }

        let invalid_sentinels: i64 = self.connection.query_row(
            "SELECT COUNT(*)
               FROM sites s
               JOIN edges e ON e.scan_id=s.scan_id AND e.site_id=s.id
               JOIN nodes n ON n.scan_id=e.scan_id AND n.id=e.target
              WHERE s.scan_id=?1
                AND ((s.resolution_status='resolved' AND n.kind IN ('external_system','unknown_target'))
                  OR (s.resolution_status='external' AND n.kind!='external_system')
                  OR (s.resolution_status='unresolved' AND n.kind!='unknown_target'))",
            [scan_id],
            |row| row.get(0),
        )?;
        if invalid_sentinels > 0 {
            bail!(
                "scan {scan_id} has {invalid_sentinels} invalid resolution target classifications"
            );
        }

        let sites = load_site_validation_records(&self.connection, scan_id)?;
        let edges = load_edge_validation_records(&self.connection, scan_id)?;
        let mut edges_by_site = BTreeMap::<&str, Vec<&EdgeValidationRecord>>::new();
        for edge in &edges {
            if let Some(site_id) = &edge.site_id {
                edges_by_site.entry(site_id).or_default().push(edge);
            }
        }
        for site in &sites {
            let expected = site
                .target_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            if expected.len() != site.target_ids.len() {
                bail!("site {} contains duplicate target IDs", site.id);
            }
            let site_edges = edges_by_site
                .get(site.id.as_str())
                .map(Vec::as_slice)
                .unwrap_or_default();
            match site.resolution_status.as_str() {
                "resolved" | "external" | "unresolved"
                    if expected.len() == 1 && site_edges.len() == 1 => {}
                "candidates" if !expected.is_empty() && site_edges.len() == expected.len() => {}
                "resolved" | "candidates" | "external" | "unresolved" => bail!(
                    "site {} violates {} cardinality: {} targets, {} edges",
                    site.id,
                    site.resolution_status,
                    expected.len(),
                    site_edges.len()
                ),
                status => bail!("site {} has unknown resolution status {status}", site.id),
            }
            let observed = site_edges
                .iter()
                .map(|edge| edge.target.as_str())
                .collect::<BTreeSet<_>>();
            if expected != observed || site_edges.len() != expected.len() {
                bail!("site {} target IDs do not match its edge targets", site.id);
            }
            for edge in site_edges {
                if edge.source != site.source
                    || edge.profile_id != site.profile_id
                    || edge.resolution_status != site.resolution_status
                    || edge.precision != site.precision
                {
                    bail!(
                        "site {} and edge {} disagree on contract fields",
                        site.id,
                        edge.id
                    );
                }
            }
        }

        let coverage_json = self
            .connection
            .query_row(
                "SELECT json FROM coverage WHERE scan_id=?1",
                [scan_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .with_context(|| format!("scan {scan_id} has no final coverage"))?;
        let coverage: CoverageRecord = serde_json::from_str(&coverage_json)?;
        let aggregate_completeness = coverage
            .completeness
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if aggregate_completeness.len() != coverage.completeness.len() {
            bail!("scan {scan_id} coverage contains duplicate completeness levels");
        }
        let profile_count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM profiles WHERE scan_id=?1",
            [scan_id],
            |row| row.get(0),
        )?;
        let actual = [
            ("profiles", coverage.profiles, profile_count as u64),
            (
                "dependency_sites",
                coverage.dependency_sites,
                site_count as u64,
            ),
            ("resolved", coverage.resolved, resolved as u64),
            ("candidates", coverage.candidates, candidates as u64),
            ("external", coverage.external, external as u64),
            ("unresolved", coverage.unresolved, unresolved as u64),
        ];
        for (field, reported, observed) in actual {
            if reported != observed {
                bail!(
                    "scan {scan_id} coverage {field}={reported}, but the store contains {observed}"
                );
            }
        }
        let profile_coverage_count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM profile_coverage WHERE scan_id=?1",
            [scan_id],
            |row| row.get(0),
        )?;
        if profile_coverage_count != profile_count {
            bail!(
                "scan {scan_id} has {profile_count} profiles but {profile_coverage_count} profile coverage records"
            );
        }
        let mut profile_statement = self.connection.prepare(
            "SELECT profile_id, json FROM profile_coverage WHERE scan_id=?1 ORDER BY profile_id",
        )?;
        let profile_rows = profile_statement.query_map([scan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut expected_completeness: Option<BTreeSet<String>> = None;
        let mut max_profile_files_discovered = 0_u64;
        let mut max_profile_files_analyzed = 0_u64;
        let mut max_profile_files_skipped = 0_u64;
        let mut max_profile_unsupported_syntax = 0_u64;
        let mut profile_executed_project_code = false;
        for row in profile_rows {
            let (profile_id, raw) = row?;
            let profile: CoverageRecord = serde_json::from_str(&raw)?;
            if profile.profiles != 1 {
                bail!(
                    "profile {profile_id} coverage must report profiles=1, found {}",
                    profile.profiles
                );
            }
            if profile.files_analyzed.checked_add(profile.files_skipped)
                != Some(profile.files_discovered)
            {
                bail!(
                    "profile {profile_id} file coverage does not satisfy discovered=analyzed+skipped"
                );
            }
            let profile_completeness = profile
                .completeness
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            if profile_completeness.len() != profile.completeness.len() {
                bail!("profile {profile_id} coverage contains duplicate completeness levels");
            }
            if let Some(intersection) = &mut expected_completeness {
                intersection.retain(|level| profile_completeness.contains(level));
            } else {
                expected_completeness = Some(profile_completeness);
            }
            max_profile_files_discovered =
                max_profile_files_discovered.max(profile.files_discovered);
            max_profile_files_analyzed = max_profile_files_analyzed.max(profile.files_analyzed);
            max_profile_files_skipped = max_profile_files_skipped.max(profile.files_skipped);
            max_profile_unsupported_syntax =
                max_profile_unsupported_syntax.max(profile.unsupported_syntax);
            profile_executed_project_code |= profile.project_code_executed;
            let (total, resolved, candidates, external, unresolved):
                (i64, i64, i64, i64, i64) = self.connection.query_row(
                "SELECT COUNT(*),
                        COALESCE(SUM(CASE WHEN resolution_status='resolved' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN resolution_status='candidates' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN resolution_status='external' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN resolution_status='unresolved' THEN 1 ELSE 0 END), 0)
                   FROM sites WHERE scan_id=?1 AND profile_id=?2",
                params![scan_id, profile_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )?;
            let reported = (
                profile.dependency_sites,
                profile.resolved,
                profile.candidates,
                profile.external,
                profile.unresolved,
            );
            let observed = (
                total as u64,
                resolved as u64,
                candidates as u64,
                external as u64,
                unresolved as u64,
            );
            if reported != observed {
                bail!(
                    "profile {profile_id} coverage site counts {reported:?} do not match stored counts {observed:?}"
                );
            }
        }
        if let Some(expected) = expected_completeness
            && aggregate_completeness != expected
        {
            bail!(
                "scan {scan_id} completeness {aggregate_completeness:?} does not equal the profile intersection {expected:?}"
            );
        }
        let profile_maximums = [
            (
                "files_discovered",
                coverage.files_discovered,
                max_profile_files_discovered,
            ),
            (
                "files_analyzed",
                coverage.files_analyzed,
                max_profile_files_analyzed,
            ),
            (
                "files_skipped",
                coverage.files_skipped,
                max_profile_files_skipped,
            ),
            (
                "unsupported_syntax",
                coverage.unsupported_syntax,
                max_profile_unsupported_syntax,
            ),
        ];
        for (field, reported, minimum) in profile_maximums {
            if reported < minimum {
                bail!(
                    "scan {scan_id} coverage {field}={reported}, below the profile maximum {minimum}"
                );
            }
        }
        if profile_executed_project_code && !coverage.project_code_executed {
            bail!("scan {scan_id} coverage hides project code execution reported by a profile");
        }
        let (files, skipped, emitted): (i64, i64, i64) = self.connection.query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(CASE WHEN skipped THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(emitted_sites), 0)
               FROM file_coverage WHERE scan_id=?1",
            [scan_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if coverage.files_discovered != files as u64
            || coverage.files_skipped != skipped as u64
            || coverage.files_analyzed != (files - skipped) as u64
        {
            bail!("scan {scan_id} file coverage does not match the per-file ledger");
        }
        if emitted as u64 > coverage.dependency_sites {
            bail!(
                "scan {scan_id} file ledger emitted {emitted} sites, more than the {} classified sites",
                coverage.dependency_sites
            );
        }
        let invalid_file_ledgers: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM file_coverage
              WHERE scan_id=?1 AND discovered_sites != emitted_sites + skipped_sites",
            [scan_id],
            |row| row.get(0),
        )?;
        if invalid_file_ledgers > 0 {
            bail!("scan {scan_id} has {invalid_file_ledgers} invalid per-file site ledgers");
        }
        Ok(())
    }

    pub fn validate_scan_for_completion(&self, scan_id: &str) -> Result<ValidatedScan> {
        let (current, mutation_count) = self
            .connection
            .query_row(
                "SELECT status, mutation_count FROM scans WHERE id=?1",
                [scan_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .with_context(|| format!("scan {scan_id} was not started"))?;
        if current != "staging" {
            bail!("scan {scan_id} is immutable after reaching status {current}");
        }
        self.validate_scan(scan_id)
            .with_context(|| format!("scan {scan_id} cannot be promoted before validation"))?;
        Ok(ValidatedScan {
            scan_id: scan_id.to_owned(),
            mutation_count,
        })
    }

    pub fn finish_validated_scan(
        &mut self,
        validation: ValidatedScan,
        promote: bool,
    ) -> Result<CompletedScanSnapshot> {
        let finished = self.finish_scan_inner(
            &validation.scan_id,
            "completed",
            None,
            promote,
            Some(validation.mutation_count),
        )?;
        let snapshot_id = finished
            .completed_snapshot_id
            .context("validated completed scan did not create a snapshot")?;
        Ok(CompletedScanSnapshot {
            scan_id: validation.scan_id,
            snapshot_id,
        })
    }

    pub fn load_validated_scan_summary(
        &self,
        validation: &ValidatedScan,
    ) -> Result<ValidatedScanSummary> {
        let (status, mutation_count) = self
            .connection
            .query_row(
                "SELECT status, mutation_count FROM scans WHERE id=?1",
                [&validation.scan_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .with_context(|| format!("scan {} was not started", validation.scan_id))?;
        if status != "staging" || mutation_count != validation.mutation_count {
            bail!(
                "scan {} changed after completion validation",
                validation.scan_id
            );
        }
        let coverage = self
            .connection
            .query_row(
                "SELECT json FROM coverage WHERE scan_id=?1",
                [&validation.scan_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .with_context(|| format!("scan {} has no final coverage", validation.scan_id))
            .and_then(|raw| serde_json::from_str(&raw).map_err(Into::into))?;
        Ok(ValidatedScanSummary {
            coverage,
            diagnostics: load_diagnostics(&self.connection, &validation.scan_id)?,
        })
    }

    /// Seal the mutation and prospective snapshot identities of an
    /// operation-owned staging scan after complete graph validation.
    pub fn seal_scan_operation_staging(
        &mut self,
        operation_id: &str,
        validation: &ValidatedScan,
        prospective_snapshot_id: &str,
    ) -> Result<()> {
        if prospective_snapshot_id.is_empty()
            || !scan_attempt_is_bound_to_operation(&validation.scan_id, operation_id, true)
        {
            bail!("operation-owned scan staging seal is invalid");
        }
        let tx = self.connection.transaction()?;
        let updated = tx.execute(
            "UPDATE scan_operation_staging
                SET validated_mutation_count=?1, prospective_snapshot_id=?2
              WHERE operation_id=?3 AND scan_id=?4
                AND validated_mutation_count IS NULL
                AND prospective_snapshot_id IS NULL
                AND result_digest IS NULL
                AND EXISTS (
                    SELECT 1 FROM scans
                     WHERE id=scan_operation_staging.scan_id
                       AND status='staging' AND mutation_count=?1
                       AND parent_snapshot_id IS base_snapshot_id
                )",
            params![
                validation.mutation_count,
                prospective_snapshot_id,
                operation_id,
                validation.scan_id,
            ],
        )?;
        if updated != 1 {
            bail!("operation-owned scan staging seal does not match durable staging");
        }
        tx.commit()?;
        Ok(())
    }

    /// Bind the complete canonical journal result to a previously sealed scan
    /// before its completion intent can be committed.
    pub fn bind_scan_operation_result(
        &mut self,
        operation_id: &str,
        result_digest: &[u8; 32],
    ) -> Result<()> {
        let binding = self.load_scan_operation_recovery_binding(operation_id)?;
        validate_internal_scan_operation_binding(&binding)?;
        let validated_mutation_count = binding
            .validated_mutation_count
            .context("operation-owned scan result has no sealed mutation count")?;
        let prospective_snapshot_id = binding
            .prospective_snapshot_id
            .as_deref()
            .context("operation-owned scan result has no sealed snapshot")?;
        if binding.operation_id != operation_id
            || binding.status != "staging"
            || validated_mutation_count != binding.mutation_count
        {
            bail!("operation-owned scan result does not match sealed staging");
        }
        let decision_authorization_digest = scan_decision_authorization_digest_from_parts(
            operation_id,
            &binding.scan_id,
            &binding.root,
            &binding.repository_binding_digest,
            &binding.configuration_digest,
            binding.strict,
            binding.cache_enabled,
            binding.base_snapshot_id.as_deref(),
            validated_mutation_count,
            prospective_snapshot_id,
            result_digest,
        );
        let tx = self.connection.transaction()?;
        let updated = tx.execute(
            "UPDATE scan_operation_staging
                SET result_digest=?1, decision_authorization_digest=?2
              WHERE operation_id=?3
                AND validated_mutation_count IS NOT NULL
                AND prospective_snapshot_id IS NOT NULL
                AND (result_digest IS NULL OR result_digest=?1)
                AND (decision_authorization_digest IS NULL
                     OR decision_authorization_digest=?2)
                AND EXISTS (
                    SELECT 1 FROM scans
                     WHERE id=scan_operation_staging.scan_id
                       AND status='staging'
                       AND mutation_count=validated_mutation_count
                       AND parent_snapshot_id IS base_snapshot_id
                )",
            params![
                result_digest.as_slice(),
                decision_authorization_digest.as_slice(),
                operation_id,
            ],
        )?;
        if updated != 1 {
            bail!("operation-owned scan result does not match sealed staging");
        }
        tx.commit()?;
        Ok(())
    }

    fn load_scan_operation_recovery_binding(
        &self,
        operation_id: &str,
    ) -> Result<ScanOperationRecoveryBinding> {
        load_scan_operation_recovery_binding_from(&self.connection, operation_id)
    }

    /// Recover and promote only after every operation, request, repository,
    /// staging, snapshot, and complete-result binding has matched.
    pub fn recover_scan_completion_for_operation(
        &mut self,
        identity: &ScanCompletionRecoveryIdentity<'_>,
    ) -> Result<()> {
        if !self.scan_operation_owner_exists(identity.operation_id)? {
            self.adopt_legacy_scan_completion_for_operation(identity)?;
        }
        let binding = self.load_scan_operation_recovery_binding(identity.operation_id)?;
        validate_scan_operation_recovery_binding(&binding, identity)?;
        match binding.status.as_str() {
            "staging" => {
                let validation = self.validate_scan_for_completion(identity.scan_id)?;
                if Some(validation.mutation_count) != binding.validated_mutation_count {
                    bail!("scan staging changed after its operation result was bound");
                }
                let prospective = self.prospective_scan_snapshot_id(identity.scan_id)?;
                if prospective != identity.snapshot_id
                    || binding.prospective_snapshot_id.as_deref() != Some(prospective.as_str())
                {
                    bail!("scan staging prospective snapshot does not match recovery");
                }
                let finished = self.finish_scan_inner(
                    &validation.scan_id,
                    "completed",
                    None,
                    true,
                    Some(validation.mutation_count),
                )?;
                if finished.completed_snapshot_id.as_deref() != Some(identity.snapshot_id) {
                    bail!("recovered scan created an unexpected completed snapshot");
                }
                if !finished.promoted
                    && self.current_snapshot_id()?.as_deref() == binding.base_snapshot_id.as_deref()
                {
                    bail!("recovered scan promotion did not update current snapshot");
                }
            }
            "completed" => {
                let snapshot_id = self
                    .snapshot_id_for_source("scan", identity.scan_id)?
                    .context("completed operation-owned scan has no snapshot source")?;
                if snapshot_id != identity.snapshot_id {
                    bail!("completed scan snapshot does not match recovery");
                }
            }
            _ => bail!("operation-owned scan is not recoverably promotable"),
        }
        // A completed scan may have been superseded before or after its
        // promotion. The expected-parent CAS above leaves that newer current
        // snapshot unchanged while still finishing the intended scan.
        Ok(())
    }

    fn scan_operation_owner_exists(&self, operation_id: &str) -> Result<bool> {
        self.connection
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM scan_operation_staging WHERE operation_id=?1
                 )",
                [operation_id],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    fn legacy_scan_operation_candidate_exists(&self) -> Result<bool> {
        self.connection
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM scan_operation_staging
                      WHERE substr(operation_id, 1, length(?1))=?1
                 )",
                [LEGACY_SCAN_OPERATION_CANDIDATE_PREFIX],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    /// Convert one migration sentinel into strict operation ownership only
    /// after complete immutable journal evidence has selected the exact scan.
    fn adopt_legacy_scan_completion_for_operation(
        &mut self,
        identity: &ScanCompletionRecoveryIdentity<'_>,
    ) -> Result<()> {
        let candidate_id = legacy_scan_operation_candidate_id(identity.scan_id);
        let candidate = self.load_scan_operation_recovery_binding(&candidate_id)?;
        validate_legacy_scan_operation_candidate(&candidate)?;
        if candidate.scan_id != identity.scan_id {
            bail!("legacy scan candidate identity does not match recovery");
        }
        let (validated_mutation_count, prospective_snapshot_id) = match candidate.status.as_str() {
            "staging" => {
                let validation = self.validate_scan_for_completion(identity.scan_id)?;
                let prospective = self.prospective_scan_snapshot_id(identity.scan_id)?;
                (validation.mutation_count, prospective)
            }
            "completed" => (
                candidate
                    .validated_mutation_count
                    .context("completed legacy scan candidate has no sealed mutation count")?,
                candidate
                    .prospective_snapshot_id
                    .clone()
                    .context("completed legacy scan candidate has no immutable snapshot")?,
            ),
            _ => bail!("legacy scan candidate is not recoverably promotable"),
        };
        if prospective_snapshot_id != identity.snapshot_id {
            bail!("legacy scan candidate snapshot does not match durable recovery");
        }
        let zero_configuration_digest = [0_u8; 32];
        let authorization_digest = scan_decision_authorization_digest_from_parts(
            identity.operation_id,
            identity.scan_id,
            &identity.repository_root.to_string_lossy(),
            identity.repository_binding_digest,
            &zero_configuration_digest,
            identity.strict,
            identity.cache_enabled,
            candidate.base_snapshot_id.as_deref(),
            validated_mutation_count,
            &prospective_snapshot_id,
            identity.result_digest,
        );
        let tx = self.connection.transaction()?;
        let updated = tx.execute(
            "UPDATE scan_operation_staging
                SET operation_id=?1, repository_binding_digest=?2,
                    configuration_digest=?3, cache_enabled=?4,
                    validated_mutation_count=?5, prospective_snapshot_id=?6,
                    result_digest=?7, decision_authorization_digest=?8
              WHERE operation_id=?9 AND scan_id=?10
                AND repository_binding_digest=zeroblob(32)
                AND configuration_digest=zeroblob(32)
                AND decision_authorization_digest=zeroblob(32)",
            params![
                identity.operation_id,
                identity.repository_binding_digest.as_slice(),
                zero_configuration_digest.as_slice(),
                identity.cache_enabled,
                validated_mutation_count,
                prospective_snapshot_id,
                identity.result_digest.as_slice(),
                authorization_digest.as_slice(),
                candidate_id,
                identity.scan_id,
            ],
        )?;
        if updated != 1 {
            bail!("legacy scan candidate changed before durable adoption");
        }
        tx.commit()?;
        let adopted = self.load_scan_operation_recovery_binding(identity.operation_id)?;
        validate_scan_operation_recovery_binding(&adopted, identity)
    }

    /// Cancel one bounded page of migration sentinels that no validated
    /// completion decision adopted. Completed historical candidates only lose
    /// their sentinel; immutable snapshots are never deleted or republished.
    pub fn reconcile_legacy_scan_operation_candidates(&mut self) -> Result<bool> {
        let tx = self.connection.transaction()?;
        let candidate_ids = {
            let mut statement = tx.prepare(
                "SELECT operation_id FROM scan_operation_staging
                  WHERE substr(operation_id, 1, length(?1))=?1
                  ORDER BY operation_id COLLATE BINARY
                  LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![
                        LEGACY_SCAN_OPERATION_CANDIDATE_PREFIX,
                        (MAX_PENDING_CANCELLED_SCAN_OPERATIONS + 1) as i64,
                    ],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let more_work = candidate_ids.len() > MAX_PENDING_CANCELLED_SCAN_OPERATIONS;
        for candidate_id in candidate_ids
            .iter()
            .take(MAX_PENDING_CANCELLED_SCAN_OPERATIONS)
        {
            let candidate = load_scan_operation_recovery_binding_from(&tx, candidate_id)?;
            validate_legacy_scan_operation_candidate(&candidate)?;
            if candidate.status == "staging" {
                let completed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
                tx.execute(
                    "UPDATE incremental_deltas
                        SET status='cancelled', completed_at=?2,
                            error='unclaimed legacy operation scan staging reconciled'
                      WHERE scan_id=?1 AND status='staging'",
                    params![candidate.scan_id, completed_at],
                )?;
                let updated = tx.execute(
                    "UPDATE scans
                        SET status='cancelled', completed_at=?2,
                            error='unclaimed legacy operation scan staging reconciled'
                      WHERE id=?1 AND status='staging'",
                    params![candidate.scan_id, completed_at],
                )?;
                if updated != 1 {
                    bail!("legacy scan candidate changed before cancellation");
                }
            }
            let deleted = tx.execute(
                "DELETE FROM scan_operation_staging
                  WHERE operation_id=?1 AND scan_id=?2
                    AND decision_authorization_digest=zeroblob(32)",
                params![candidate_id, candidate.scan_id],
            )?;
            if deleted != 1 {
                bail!("legacy scan candidate changed before reconciliation");
            }
        }
        tx.commit()?;
        Ok(more_work)
    }

    /// Cancel only a scan selected by its durable operation ownership record.
    /// Absence is safe only when no scan with that operation identity exists.
    pub fn cancel_scan_for_operation(&mut self, operation_id: &str) -> Result<()> {
        let scan_id = self
            .connection
            .query_row(
                "SELECT scan_id FROM scan_operation_staging WHERE operation_id=?1",
                [operation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(scan_id) = scan_id else {
            if self.scan(operation_id)?.is_some() {
                bail!("scan has no durable operation-owned staging binding");
            }
            return Ok(());
        };
        let binding = self.load_scan_operation_recovery_binding(operation_id)?;
        validate_internal_scan_operation_binding(&binding)?;
        if binding.scan_id != scan_id {
            bail!("scan staging operation identity changed during cancellation");
        }
        match binding.status.as_str() {
            "staging" => self.finish_scan(
                &scan_id,
                "cancelled",
                Some("operation cancelled before scan promotion"),
                false,
            ),
            "cancelled" => Ok(()),
            _ => bail!("operation-owned scan is already terminal"),
        }
    }

    /// Return one fixed-size page of cancellation ownership proofs awaiting a
    /// terminal journal acknowledgement. Each row remains until explicitly
    /// finalized after the journal transition commits.
    pub fn pending_cancelled_scan_operations(&self) -> Result<PendingCancelledScanOperations> {
        self.pending_cancelled_scan_operations_after(None)
    }

    pub fn pending_cancelled_scan_operations_after(
        &self,
        after_operation_id: Option<&str>,
    ) -> Result<PendingCancelledScanOperations> {
        let mut statement = self.connection.prepare(
            "SELECT substr(CAST(owner.operation_id AS BLOB), 1, 513)
               FROM scan_operation_staging AS owner
                    INDEXED BY scan_operation_staging_pending_cancelled
               JOIN scans AS scan ON scan.id=owner.scan_id
              WHERE scan.status='cancelled'
                AND (?1 IS NULL OR owner.operation_id COLLATE BINARY > ?1)
              ORDER BY owner.operation_id COLLATE BINARY
              LIMIT ?2",
        )?;
        let limit = i64::try_from(MAX_PENDING_CANCELLED_SCAN_OPERATIONS + 1)
            .context("cancelled scan reconciliation batch limit overflowed")?;
        let mut rows = statement.query(params![after_operation_id, limit])?;
        let mut operation_ids = Vec::with_capacity(MAX_PENDING_CANCELLED_SCAN_OPERATIONS);
        let mut more_work = false;
        while let Some(row) = rows.next()? {
            let bounded = row.get::<_, Vec<u8>>(0)?;
            if bounded.len() > 512 {
                bail!("cancelled scan operation ID exceeds its storage bound");
            }
            let operation_id = String::from_utf8(bounded)
                .context("cancelled scan operation ID is not valid UTF-8")?;
            if operation_ids.len() == MAX_PENDING_CANCELLED_SCAN_OPERATIONS {
                more_work = true;
                break;
            }
            operation_ids.push(operation_id);
        }
        let next_after_operation_id = more_work.then(|| {
            operation_ids
                .last()
                .expect("a full reconciliation page has a final operation ID")
                .clone()
        });
        Ok(PendingCancelledScanOperations {
            operation_ids,
            more_work,
            next_after_operation_id,
        })
    }

    /// Acknowledge a terminal journal cancellation/failure and remove only its
    /// already-cancelled scan ownership proof. Replays after removal are safe
    /// no-ops; active or forged bindings fail closed.
    pub fn finalize_cancelled_scan_for_operation(&mut self, operation_id: &str) -> Result<bool> {
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM scan_operation_staging WHERE operation_id=?1
             )",
            [operation_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Ok(false);
        }
        let binding = self.load_scan_operation_recovery_binding(operation_id)?;
        validate_internal_scan_operation_binding(&binding)?;
        if binding.status != "cancelled" {
            bail!("scan cancellation cannot be finalized before store cancellation");
        }
        let tx = self.connection.transaction()?;
        let deleted = tx.execute(
            "DELETE FROM scan_operation_staging
              WHERE operation_id=?1 AND scan_id=?2
                AND EXISTS (
                    SELECT 1 FROM scans
                     WHERE id=?2 AND status='cancelled'
                )",
            params![operation_id, binding.scan_id],
        )?;
        if deleted != 1 {
            bail!("scan cancellation ownership changed before acknowledgement");
        }
        tx.commit()?;
        Ok(true)
    }

    pub fn finish_scan(
        &mut self,
        scan_id: &str,
        status: &str,
        error: Option<&str>,
        promote: bool,
    ) -> Result<()> {
        if !matches!(
            status,
            "completed" | "partial" | "failed" | "cancelled" | "policy_failed" | "security_failed"
        ) {
            bail!("invalid terminal scan status {status}");
        }
        if promote && status != "completed" {
            bail!("only completed scans can become the current successful scan");
        }
        let validated_mutation_count = if status == "completed" {
            Some(self.validate_scan_for_completion(scan_id)?.mutation_count)
        } else {
            None
        };
        self.finish_scan_inner(scan_id, status, error, promote, validated_mutation_count)
            .map(|_| ())
    }

    fn finish_scan_inner(
        &mut self,
        scan_id: &str,
        status: &str,
        error: Option<&str>,
        promote: bool,
        validated_mutation_count: Option<i64>,
    ) -> Result<FinishedScan> {
        let tx = self.connection.transaction()?;
        ensure_scan_staging(&tx, scan_id)?;
        if status == "completed" {
            let non_applied_delta_count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM incremental_deltas
                  WHERE scan_id=?1 AND status!='applied'",
                [scan_id],
                |row| row.get(0),
            )?;
            if non_applied_delta_count != 0 {
                bail!(
                    "scan {scan_id} has {non_applied_delta_count} incremental deltas that were not applied successfully"
                );
            }
        } else {
            let delta_status = if status == "cancelled" {
                "cancelled"
            } else {
                "failed"
            };
            tx.execute(
                "UPDATE incremental_deltas
                    SET status=?2, completed_at=?3,
                        error='scan terminated before incremental delta promotion'
                  WHERE scan_id=?1 AND status='staging'",
                params![
                    scan_id,
                    delta_status,
                    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
                ],
            )?;
        }
        if let Some(validated_mutation_count) = validated_mutation_count {
            let observed_mutation_count: i64 = tx.query_row(
                "SELECT mutation_count FROM scans WHERE id=?1",
                [scan_id],
                |row| row.get(0),
            )?;
            if observed_mutation_count != validated_mutation_count {
                bail!("scan {scan_id} changed concurrently after validation; retry promotion");
            }
        }
        if promote {
            let project_code_executed: bool = tx.query_row(
                "SELECT project_code_executed FROM scans WHERE id=?1",
                [scan_id],
                |row| row.get(0),
            )?;
            if project_code_executed {
                bail!("a scan that executed project code cannot be promoted in safe mode");
            }
        }
        let completed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        tx.execute(
            "UPDATE scans SET status = ?2, completed_at = ?3, error = ?4 WHERE id = ?1",
            params![scan_id, status, completed_at, error],
        )?;
        let completed_snapshot_id = if status == "completed" {
            let (parent_snapshot_id, source_revision): (Option<String>, Option<String>) = tx
                .query_row(
                    "SELECT parent_snapshot_id, source_revision FROM scans WHERE id=?1",
                    [scan_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
            Some(create_completed_snapshot(
                &tx,
                SnapshotSource {
                    source_kind: "scan",
                    source_attempt_id: scan_id,
                    scan_id,
                    build_attempt_id: None,
                    runtime_import_id: None,
                    runtime_session_ids: &[],
                    parent_snapshot_id: parent_snapshot_id.as_deref(),
                    source_revision: source_revision.as_deref(),
                    created_at: &completed_at,
                },
            )?)
        } else {
            None
        };
        let mut promoted = false;
        if promote {
            let snapshot_id = completed_snapshot_id
                .as_deref()
                .context("completed scan did not create a snapshot")?;
            let expected_parent = tx.query_row(
                "SELECT parent_snapshot_id FROM scans WHERE id=?1",
                [scan_id],
                |row| row.get::<_, Option<String>>(0),
            )?;
            promoted = promote_completed_snapshot_if_current_parent(
                &tx,
                snapshot_id,
                expected_parent.as_deref(),
            )?;
            if promoted {
                tx.execute(
                    "INSERT INTO current_successful(singleton, scan_id) VALUES (1, ?1)
                     ON CONFLICT(singleton) DO UPDATE SET scan_id = excluded.scan_id",
                    [scan_id],
                )?;
            }
        }
        if !matches!(status, "completed" | "cancelled") {
            tx.execute(
                "DELETE FROM scan_operation_staging WHERE scan_id=?1",
                [scan_id],
            )?;
        }
        tx.commit()?;
        Ok(FinishedScan {
            completed_snapshot_id,
            promoted,
        })
    }

    pub fn latest_attempt_id(&self) -> Result<Option<String>> {
        self.connection
            .query_row(
                "SELECT id FROM scans ORDER BY started_at DESC, rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .context("failed to load latest scan")
    }

    pub fn latest_successful_id(&self) -> Result<Option<String>> {
        self.connection
            .query_row(
                "SELECT scan_id FROM current_successful WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .context("failed to load current successful scan")
    }

    pub fn scan(&self, scan_id: &str) -> Result<Option<ScanRecord>> {
        self.connection
            .query_row(
                "SELECT id, root, status, strict, started_at, completed_at,
                        project_code_executed, error, parent_snapshot_id, source_revision
                 FROM scans WHERE id = ?1",
                [scan_id],
                |row| {
                    Ok(ScanRecord {
                        id: row.get(0)?,
                        root: row.get(1)?,
                        status: row.get(2)?,
                        strict: row.get(3)?,
                        started_at: row.get(4)?,
                        completed_at: row.get(5)?,
                        project_code_executed: row.get(6)?,
                        error: row.get(7)?,
                        parent_snapshot_id: row.get(8)?,
                        source_revision: row.get(9)?,
                    })
                },
            )
            .optional()
            .context("failed to load scan")
    }

    /// Load the bounded metadata projection used by the default doctor view.
    ///
    /// This path deliberately never reads diagnostic `raw_json`, evidence,
    /// graph edges, or adapter stderr payloads.
    pub fn scan_attempt_summary(&self, scan_id: &str) -> Result<ScanAttemptSummaryRecord> {
        load_scan_attempt_summary(&self.connection, scan_id)
    }

    pub fn load_snapshot(&self, scan_id: &str) -> Result<GraphSnapshot> {
        if self.completed_snapshot(scan_id)?.is_some() {
            return self.load_completed_snapshot(scan_id);
        }
        if self
            .scan(scan_id)?
            .is_some_and(|scan| scan.status == "completed")
            && let Some(snapshot_id) = self.snapshot_id_for_scan_selection(scan_id)?
        {
            return self.load_completed_snapshot(&snapshot_id);
        }
        let mut snapshot = self.load_base_snapshot(scan_id)?;
        let Some(attempt_id) = self.current_build_attempt_id(scan_id)? else {
            return Ok(snapshot);
        };
        let raw = self
            .connection
            .query_row(
                "SELECT delta_json FROM build_attempts
                  WHERE id=?1 AND base_scan_id=?2 AND status='completed'",
                params![attempt_id, scan_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten()
            .with_context(|| {
                format!("promoted build attempt {attempt_id} has no completed delta")
            })?;
        let delta: BuildGraphDelta = serde_json::from_str(&raw)?;
        merge_build_delta(&mut snapshot, delta, &attempt_id)?;
        Ok(snapshot)
    }

    /// Compute the content-addressed identity a validated scan graph would
    /// receive if it were promoted, without creating a completed snapshot or
    /// changing the current pointer.
    pub fn prospective_scan_snapshot_id(&self, scan_id: &str) -> Result<String> {
        let scan = self
            .scan(scan_id)?
            .with_context(|| format!("scan {scan_id} was not found"))?;
        let (snapshot_id, _) = completed_snapshot_identity(
            &self.connection,
            scan_id,
            None,
            &[],
            scan.parent_snapshot_id.as_deref(),
            scan.source_revision.as_deref(),
        )?;
        Ok(snapshot_id)
    }

    pub fn load_completed_snapshot(&self, snapshot_id: &str) -> Result<GraphSnapshot> {
        load_completed_snapshot_from_connection(&self.connection, snapshot_id)
    }

    /// Load only node identities/kinds and edge endpoints for graph-topology
    /// queries such as cycle detection.
    ///
    /// Plain scan snapshots can be projected directly from normalized tables
    /// without parsing node properties, edge conditions, sites, or evidence.
    /// Layered snapshots retain the full reconstruction path so build/runtime
    /// overlays and semantic no-op inheritance preserve their exact semantics.
    pub fn load_completed_topology(&self, snapshot_id: &str) -> Result<GraphTopology> {
        let record = load_completed_snapshot_record(&self.connection, snapshot_id)?
            .with_context(|| format!("completed snapshot {snapshot_id} was not found"))?;
        let semantic_noop = record.build_attempt_id.is_none()
            && record.runtime_session_ids.is_empty()
            && incremental::scan_is_semantic_noop_overlay(&self.connection, &record.scan_id)?;
        let layered = record.source_kind != "scan"
            || record.build_attempt_id.is_some()
            || !record.runtime_session_ids.is_empty()
            || semantic_noop;
        if !layered {
            return load_scan_topology(&self.connection, &record.scan_id);
        }
        Ok(topology_from_snapshot(
            load_completed_snapshot_from_connection(&self.connection, snapshot_id)?,
        ))
    }

    /// Loads only the effective profile records for a completed snapshot.
    ///
    /// Semantic no-op snapshots inherit profiles unchanged from their parent,
    /// so this metadata projection avoids reconstructing the repository graph.
    pub fn load_completed_snapshot_profiles(
        &self,
        snapshot_id: &str,
    ) -> Result<Vec<ProfileRecord>> {
        load_completed_snapshot_profiles_from_connection(&self.connection, snapshot_id)
    }

    fn load_base_snapshot(&self, scan_id: &str) -> Result<GraphSnapshot> {
        load_base_snapshot_from_connection(&self.connection, scan_id)
    }

    pub fn resolve_scan_id(&self, requested: Option<&str>, latest_attempt: bool) -> Result<String> {
        if let Some(id) = requested {
            if self.scan(id)?.is_none() {
                bail!("scan {id} was not found");
            }
            return Ok(id.to_owned());
        }
        let id = if latest_attempt {
            self.latest_attempt_id()?
        } else {
            self.latest_successful_id()?
        };
        id.context("no matching scan is available")
    }

    pub fn has_final_coverage(&self, scan_id: &str) -> Result<bool> {
        Ok(self
            .connection
            .query_row("SELECT 1 FROM coverage WHERE scan_id=?1", [scan_id], |_| {
                Ok(())
            })
            .optional()?
            .is_some())
    }

    pub fn mark_coverage_incomplete(&mut self, scan_id: &str, reason: &str) -> Result<()> {
        let mut coverage = self.load_snapshot(scan_id)?.coverage;
        coverage.completeness.clear();
        coverage.reasons.push(reason.to_owned());
        coverage.reasons.sort();
        coverage.reasons.dedup();
        let tx = self.connection.transaction()?;
        ensure_scan_staging(&tx, scan_id)?;
        tx.execute(
            "INSERT INTO coverage(scan_id, json) VALUES (?1, ?2)
             ON CONFLICT(scan_id) DO UPDATE SET json=excluded.json",
            params![scan_id, serde_json::to_string(&coverage)?],
        )?;
        tx.execute(
            "UPDATE scans SET mutation_count=mutation_count+1 WHERE id=?1",
            [scan_id],
        )?;
        tx.commit()?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct SnapshotSource<'a> {
    source_kind: &'a str,
    source_attempt_id: &'a str,
    scan_id: &'a str,
    build_attempt_id: Option<&'a str>,
    runtime_import_id: Option<&'a str>,
    runtime_session_ids: &'a [String],
    parent_snapshot_id: Option<&'a str>,
    source_revision: Option<&'a str>,
    created_at: &'a str,
}

const SNAPSHOT_SEAL_CLOSURE_CTE: &str = "
WITH RECURSIVE snapshot_closure(id) AS (
    SELECT ?1
    UNION
    SELECT snapshot.parent_snapshot_id
      FROM completed_snapshots AS snapshot
      JOIN snapshot_closure AS child ON child.id=snapshot.id
     WHERE snapshot.parent_snapshot_id IS NOT NULL
)";

const SNAPSHOT_SEAL_RUNTIME_CTES: &str = ",
referenced_runtime_sessions(id) AS (
    SELECT DISTINCT CAST(session.value AS TEXT)
      FROM snapshot_closure AS closure
      JOIN completed_snapshots AS snapshot ON snapshot.id=closure.id
      JOIN json_each(
          CASE
              WHEN json_valid(snapshot.runtime_session_set_json)
               AND json_type(snapshot.runtime_session_set_json)='array'
              THEN snapshot.runtime_session_set_json
              ELSE '[]'
          END
      ) AS session
     WHERE session.type='text'
)";

struct SnapshotSealHasher(Sha256);

impl SnapshotSealHasher {
    fn new(snapshot_id: &str) -> Self {
        let mut hasher = Self(Sha256::new());
        hasher.write_bytes(b"depgraph-completed-snapshot-storage-seal-v1");
        hasher.write_bytes(snapshot_id.as_bytes());
        hasher
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.0.update((bytes.len() as u64).to_be_bytes());
        self.0.update(bytes);
    }

    fn write_query(
        &mut self,
        connection: &Connection,
        snapshot_id: &str,
        domain: &str,
        suffix: &str,
    ) -> Result<()> {
        self.write_bytes(domain.as_bytes());
        let sql = format!("{SNAPSHOT_SEAL_CLOSURE_CTE}{suffix}");
        let mut statement = connection.prepare(&sql)?;
        let column_count = statement.column_count();
        let mut rows = statement.query([snapshot_id])?;
        let mut row_count = 0_u64;
        while let Some(row) = rows.next()? {
            row_count += 1;
            self.write_bytes(b"row");
            self.0.update((column_count as u64).to_be_bytes());
            for index in 0..column_count {
                match row.get_ref(index)? {
                    rusqlite::types::ValueRef::Null => self.write_bytes(b"null"),
                    rusqlite::types::ValueRef::Integer(value) => {
                        self.write_bytes(b"integer");
                        self.0.update(value.to_be_bytes());
                    }
                    rusqlite::types::ValueRef::Real(value) => {
                        self.write_bytes(b"real");
                        self.0.update(value.to_bits().to_be_bytes());
                    }
                    rusqlite::types::ValueRef::Text(value) => {
                        self.write_bytes(b"text");
                        self.write_bytes(value);
                    }
                    rusqlite::types::ValueRef::Blob(value) => {
                        self.write_bytes(b"blob");
                        self.write_bytes(value);
                    }
                }
            }
        }
        self.0.update(row_count.to_be_bytes());
        Ok(())
    }

    fn finish(self) -> String {
        self.0
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

fn completed_snapshot_storage_seal(connection: &Connection, snapshot_id: &str) -> Result<String> {
    let mut hasher = SnapshotSealHasher::new(snapshot_id);
    for (domain, suffix) in [
        (
            "completed_snapshots",
            "
SELECT snapshot.id, snapshot.source_kind, snapshot.source_attempt_id,
       snapshot.scan_id, snapshot.build_attempt_id, snapshot.runtime_import_id,
       snapshot.runtime_session_set_json, snapshot.parent_snapshot_id,
       snapshot.source_revision, snapshot.profile_set_json, snapshot.status,
       snapshot.created_at
  FROM completed_snapshots AS snapshot
  JOIN snapshot_closure AS closure ON closure.id=snapshot.id
 ORDER BY snapshot.id COLLATE BINARY",
        ),
        (
            "scans",
            "
SELECT scan.id, scan.root, scan.status, scan.strict, scan.started_at,
       scan.completed_at, scan.project_code_executed, scan.protocol_version,
       scan.error, scan.parent_snapshot_id, scan.source_revision,
       scan.mutation_count
  FROM scans AS scan
 WHERE scan.id IN (
       SELECT snapshot.scan_id
         FROM completed_snapshots AS snapshot
         JOIN snapshot_closure AS closure ON closure.id=snapshot.id
 )
 ORDER BY scan.id COLLATE BINARY",
        ),
        (
            "profiles",
            "
SELECT profile.scan_id, profile.id, profile.json
  FROM profiles AS profile
 WHERE profile.scan_id IN (
       SELECT snapshot.scan_id
         FROM completed_snapshots AS snapshot
         JOIN snapshot_closure AS closure ON closure.id=snapshot.id
 )
 ORDER BY profile.scan_id COLLATE BINARY, profile.id COLLATE BINARY",
        ),
        (
            "profile_coverage",
            "
SELECT coverage.scan_id, coverage.profile_id, coverage.json
  FROM profile_coverage AS coverage
 WHERE coverage.scan_id IN (
       SELECT snapshot.scan_id
         FROM completed_snapshots AS snapshot
         JOIN snapshot_closure AS closure ON closure.id=snapshot.id
 )
 ORDER BY coverage.scan_id COLLATE BINARY, coverage.profile_id COLLATE BINARY",
        ),
        (
            "nodes",
            "
SELECT node.scan_id, node.id, node.kind, node.locator, node.display_name,
       node.properties_json, node.raw_json
  FROM nodes AS node
 WHERE node.scan_id IN (
       SELECT snapshot.scan_id
         FROM completed_snapshots AS snapshot
         JOIN snapshot_closure AS closure ON closure.id=snapshot.id
 )
 ORDER BY node.scan_id COLLATE BINARY, node.id COLLATE BINARY",
        ),
        (
            "sites",
            "
SELECT site.scan_id, site.id, site.source, site.kind, site.specifier,
       site.profile_id, site.resolution_status, site.precision,
       site.condition_json, site.target_ids_json, site.reason, site.raw_json
  FROM sites AS site
 WHERE site.scan_id IN (
       SELECT snapshot.scan_id
         FROM completed_snapshots AS snapshot
         JOIN snapshot_closure AS closure ON closure.id=snapshot.id
 )
 ORDER BY site.scan_id COLLATE BINARY, site.id COLLATE BINARY",
        ),
        (
            "edges",
            "
SELECT edge.scan_id, edge.id, edge.site_id, edge.source, edge.target,
       edge.kind, edge.phase, edge.environment, edge.profile_id,
       edge.resolution_status, edge.precision, edge.condition_json,
       edge.generated, edge.raw_json
  FROM edges AS edge
 WHERE edge.scan_id IN (
       SELECT snapshot.scan_id
         FROM completed_snapshots AS snapshot
         JOIN snapshot_closure AS closure ON closure.id=snapshot.id
 )
 ORDER BY edge.scan_id COLLATE BINARY, edge.id COLLATE BINARY",
        ),
        (
            "evidence",
            "
SELECT evidence.scan_id, evidence.owner_type, evidence.owner_id,
       evidence.ordinal, evidence.kind, evidence.extractor,
       evidence.extractor_version, evidence.path, evidence.start_line,
       evidence.start_column, evidence.end_line, evidence.end_column,
       evidence.raw_json
  FROM evidence
 WHERE evidence.scan_id IN (
       SELECT snapshot.scan_id
         FROM completed_snapshots AS snapshot
         JOIN snapshot_closure AS closure ON closure.id=snapshot.id
 )
 ORDER BY evidence.scan_id COLLATE BINARY, evidence.owner_type COLLATE BINARY,
          evidence.owner_id COLLATE BINARY, evidence.ordinal",
        ),
        (
            "diagnostics",
            "
SELECT diagnostic.scan_id, diagnostic.ordinal, diagnostic.id,
       diagnostic.severity, diagnostic.code, diagnostic.message,
       diagnostic.path, diagnostic.adapter, diagnostic.raw_json
  FROM diagnostics AS diagnostic
 WHERE diagnostic.scan_id IN (
       SELECT snapshot.scan_id
         FROM completed_snapshots AS snapshot
         JOIN snapshot_closure AS closure ON closure.id=snapshot.id
 )
 ORDER BY diagnostic.scan_id COLLATE BINARY, diagnostic.ordinal,
          diagnostic.id COLLATE BINARY",
        ),
        (
            "file_coverage",
            "
SELECT coverage.scan_id, coverage.adapter, coverage.path,
       coverage.discovered_sites, coverage.emitted_sites,
       coverage.skipped_sites, coverage.skipped, coverage.reason
  FROM file_coverage AS coverage
 WHERE coverage.scan_id IN (
       SELECT snapshot.scan_id
         FROM completed_snapshots AS snapshot
         JOIN snapshot_closure AS closure ON closure.id=snapshot.id
 )
 ORDER BY coverage.scan_id COLLATE BINARY, coverage.adapter COLLATE BINARY,
          coverage.path COLLATE BINARY",
        ),
        (
            "coverage",
            "
SELECT coverage.scan_id, coverage.json
  FROM coverage
 WHERE coverage.scan_id IN (
       SELECT snapshot.scan_id
         FROM completed_snapshots AS snapshot
         JOIN snapshot_closure AS closure ON closure.id=snapshot.id
 )
 ORDER BY coverage.scan_id COLLATE BINARY",
        ),
        (
            "adapter_logs",
            "
SELECT log.scan_id, log.adapter, log.stderr, log.truncated
  FROM adapter_logs AS log
 WHERE log.scan_id IN (
       SELECT snapshot.scan_id
         FROM completed_snapshots AS snapshot
         JOIN snapshot_closure AS closure ON closure.id=snapshot.id
 )
 ORDER BY log.scan_id COLLATE BINARY, log.adapter COLLATE BINARY",
        ),
        (
            "incremental_deltas",
            "
SELECT delta.scan_id, delta.delta_id, delta.adapter,
       delta.base_snapshot_id, delta.base_graph_digest,
       delta.result_graph_digest, delta.scope_json, delta.events_json,
       delta.mutation_count, delta.status, delta.prospective_snapshot_id,
       delta.staged_at, delta.completed_at, delta.error
  FROM incremental_deltas AS delta
 WHERE delta.scan_id IN (
       SELECT snapshot.scan_id
         FROM completed_snapshots AS snapshot
         JOIN snapshot_closure AS closure ON closure.id=snapshot.id
 )
 ORDER BY delta.scan_id COLLATE BINARY, delta.delta_id COLLATE BINARY",
        ),
        (
            "build_attempts",
            "
SELECT attempt.id, attempt.base_scan_id, attempt.base_snapshot_id,
       attempt.audit_run_id, attempt.status, attempt.observer,
       attempt.observer_version, attempt.profile_id,
       attempt.command_plan_digest, attempt.toolchain_executable_digest,
       attempt.environment_key_set_digest, attempt.validated_output_digest,
       attempt.started_at, attempt.completed_at, attempt.error,
       attempt.delta_json
  FROM build_attempts AS attempt
 WHERE attempt.id IN (
       SELECT snapshot.build_attempt_id
         FROM completed_snapshots AS snapshot
         JOIN snapshot_closure AS closure ON closure.id=snapshot.id
        WHERE snapshot.build_attempt_id IS NOT NULL
 )
 ORDER BY attempt.id COLLATE BINARY",
        ),
    ] {
        hasher.write_query(connection, snapshot_id, domain, suffix)?;
    }

    for (domain, suffix) in [
        (
            "runtime_sessions",
            "
SELECT session.id, session.base_snapshot_id, session.source_session_id,
       session.schema_version, session.status, session.trace_digest,
       session.profile_id, session.parent_profile_id, session.profile_status,
       session.profile_reason, session.profile_json, session.environment_json,
       session.redaction_json, session.started_at, session.ended_at,
       session.first_observed_at, session.last_observed_at,
       session.event_count, session.observation_count,
       session.resolved_targets, session.external_targets,
       session.unresolved_targets, session.redacted_values,
       session.coverage_json, session.created_at
  FROM runtime_sessions AS session
  JOIN referenced_runtime_sessions AS referenced ON referenced.id=session.id
 ORDER BY session.id COLLATE BINARY",
        ),
        (
            "runtime_nodes",
            "
SELECT node.session_id, node.id, node.raw_json
  FROM runtime_nodes AS node
  JOIN referenced_runtime_sessions AS referenced ON referenced.id=node.session_id
 ORDER BY node.session_id COLLATE BINARY, node.id COLLATE BINARY",
        ),
        (
            "runtime_sites",
            "
SELECT site.session_id, site.id, site.raw_json
  FROM runtime_sites AS site
  JOIN referenced_runtime_sessions AS referenced ON referenced.id=site.session_id
 ORDER BY site.session_id COLLATE BINARY, site.id COLLATE BINARY",
        ),
        (
            "runtime_edges",
            "
SELECT edge.session_id, edge.id, edge.raw_json
  FROM runtime_edges AS edge
  JOIN referenced_runtime_sessions AS referenced ON referenced.id=edge.session_id
 ORDER BY edge.session_id COLLATE BINARY, edge.id COLLATE BINARY",
        ),
        (
            "runtime_evidence",
            "
SELECT evidence.session_id, evidence.owner_type, evidence.owner_id,
       evidence.ordinal, evidence.raw_json
  FROM runtime_evidence AS evidence
  JOIN referenced_runtime_sessions AS referenced ON referenced.id=evidence.session_id
 ORDER BY evidence.session_id COLLATE BINARY,
          evidence.owner_type COLLATE BINARY, evidence.owner_id COLLATE BINARY,
          evidence.ordinal",
        ),
        (
            "runtime_diagnostics",
            "
SELECT diagnostic.session_id, diagnostic.ordinal, diagnostic.id,
       diagnostic.raw_json
  FROM runtime_diagnostics AS diagnostic
  JOIN referenced_runtime_sessions AS referenced ON referenced.id=diagnostic.session_id
 ORDER BY diagnostic.session_id COLLATE BINARY, diagnostic.ordinal,
          diagnostic.id COLLATE BINARY",
        ),
    ] {
        let suffix = format!("{SNAPSHOT_SEAL_RUNTIME_CTES}{suffix}");
        hasher.write_query(connection, snapshot_id, domain, &suffix)?;
    }
    Ok(hasher.finish())
}

fn validate_completed_snapshot_for_seal(connection: &Connection, snapshot_id: &str) -> Result<()> {
    let record = load_completed_snapshot_record(connection, snapshot_id)?
        .with_context(|| format!("completed snapshot {snapshot_id} was not found"))?;
    load_completed_snapshot_from_connection(connection, snapshot_id)
        .with_context(|| format!("completed snapshot {snapshot_id} failed canonical validation"))?;
    let (observed_id, observed_profiles) = completed_snapshot_identity(
        connection,
        &record.scan_id,
        record.build_attempt_id.as_deref(),
        &record.runtime_session_ids,
        record.parent_snapshot_id.as_deref(),
        record.source_revision.as_deref(),
    )?;
    if observed_id != record.id
        || observed_profiles != record.profile_ids
        || record.status != "completed"
    {
        bail!("completed snapshot {snapshot_id} failed canonical identity validation");
    }
    Ok(())
}

fn persist_completed_snapshot_seal(connection: &Connection, snapshot_id: &str) -> Result<()> {
    if !completed_snapshot_seal_table_exists(connection)? {
        return Ok(());
    }
    validate_completed_snapshot_for_seal(connection, snapshot_id)?;
    let observed = completed_snapshot_storage_seal(connection, snapshot_id)?;
    connection.execute(
        "INSERT INTO completed_snapshot_seals(snapshot_id, seal_version, seal_sha256)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(snapshot_id) DO NOTHING",
        params![snapshot_id, COMPLETED_SNAPSHOT_SEAL_VERSION, observed],
    )?;
    let stored = connection.query_row(
        "SELECT seal_sha256 FROM completed_snapshot_seals
          WHERE snapshot_id=?1 AND seal_version=?2",
        params![snapshot_id, COMPLETED_SNAPSHOT_SEAL_VERSION],
        |row| row.get::<_, String>(0),
    )?;
    if stored != observed {
        bail!("completed snapshot {snapshot_id} storage seal does not match immutable rows");
    }
    Ok(())
}

fn verify_completed_snapshot_seal(connection: &Connection, snapshot_id: &str) -> Result<()> {
    let expected = connection
        .query_row(
            "SELECT seal_sha256 FROM completed_snapshot_seals
              WHERE snapshot_id=?1 AND seal_version=?2",
            params![snapshot_id, COMPLETED_SNAPSHOT_SEAL_VERSION],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .with_context(|| format!("completed snapshot {snapshot_id} has no storage seal"))?;
    let observed = completed_snapshot_storage_seal(connection, snapshot_id)?;
    if observed != expected {
        bail!("completed snapshot {snapshot_id} storage seal mismatch");
    }
    Ok(())
}

fn completed_snapshot_seal_table_exists(connection: &Connection) -> Result<bool> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM sqlite_master
              WHERE type='table' AND name='completed_snapshot_seals'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn backfill_completed_snapshot_seals(connection: &Connection) -> Result<()> {
    // A few early development migration fixtures contain only the key column
    // needed by the cache migration under test. They are not readable graph
    // stores, so there is no canonical snapshot payload to validate or seal.
    if !table_has_column(connection, "completed_snapshots", "created_at")? {
        return Ok(());
    }
    let snapshot_ids = {
        let mut statement = connection
            .prepare("SELECT id FROM completed_snapshots ORDER BY created_at, id COLLATE BINARY")?;
        statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for snapshot_id in snapshot_ids {
        persist_completed_snapshot_seal(connection, &snapshot_id)
            .with_context(|| format!("failed to backfill storage seal for {snapshot_id}"))?;
    }
    Ok(())
}

fn load_completed_snapshot_record(
    connection: &Connection,
    snapshot_id: &str,
) -> Result<Option<CompletedSnapshotRecord>> {
    connection
        .query_row(
            "SELECT id, source_kind, source_attempt_id, scan_id, build_attempt_id,
                    runtime_import_id, runtime_session_set_json, parent_snapshot_id,
                    source_revision, profile_set_json, status, created_at
               FROM completed_snapshots WHERE id=?1",
            [snapshot_id],
            |row| {
                let raw_runtime_sessions = row.get::<_, String>(6)?;
                let runtime_session_ids =
                    serde_json::from_str(&raw_runtime_sessions).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            raw_runtime_sessions.len(),
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                let raw_profiles = row.get::<_, String>(9)?;
                let profile_ids = serde_json::from_str(&raw_profiles).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        raw_profiles.len(),
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
                Ok(CompletedSnapshotRecord {
                    id: row.get(0)?,
                    source_kind: row.get(1)?,
                    source_attempt_id: row.get(2)?,
                    scan_id: row.get(3)?,
                    build_attempt_id: row.get(4)?,
                    runtime_import_id: row.get(5)?,
                    runtime_session_ids,
                    parent_snapshot_id: row.get(7)?,
                    source_revision: row.get(8)?,
                    profile_ids,
                    status: row.get(10)?,
                    created_at: row.get(11)?,
                })
            },
        )
        .optional()
        .context("failed to load completed snapshot metadata")
}

fn load_base_snapshot_from_connection(
    connection: &Connection,
    scan_id: &str,
) -> Result<GraphSnapshot> {
    let scan = connection
        .query_row(
            "SELECT id, root, status, strict, started_at, completed_at,
                    project_code_executed, error, parent_snapshot_id, source_revision
               FROM scans WHERE id=?1",
            [scan_id],
            |row| {
                Ok(ScanRecord {
                    id: row.get(0)?,
                    root: row.get(1)?,
                    status: row.get(2)?,
                    strict: row.get(3)?,
                    started_at: row.get(4)?,
                    completed_at: row.get(5)?,
                    project_code_executed: row.get(6)?,
                    error: row.get(7)?,
                    parent_snapshot_id: row.get(8)?,
                    source_revision: row.get(9)?,
                })
            },
        )
        .optional()?
        .with_context(|| format!("scan {scan_id} was not found"))?;
    let profiles = load_profiles(connection, scan_id)?;
    let nodes = load_nodes(connection, scan_id)?;
    let sites = load_sites(connection, scan_id)?;
    let edges = load_edges(connection, scan_id)?;
    let evidence = load_evidence(connection, scan_id)?;
    let diagnostics = load_diagnostics(connection, scan_id)?;
    let file_coverage = load_file_coverage(connection, scan_id)?;
    let adapter_logs = load_adapter_logs(connection, scan_id)?;
    let stored_coverage = connection
        .query_row(
            "SELECT json FROM coverage WHERE scan_id=?1",
            [scan_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|raw| serde_json::from_str(&raw))
        .transpose()?;
    let coverage = observed_coverage(
        connection,
        scan_id,
        &sites,
        scan.project_code_executed,
        stored_coverage,
    )?;
    let mut snapshot = GraphSnapshot {
        scan,
        profiles,
        nodes,
        sites,
        edges,
        evidence,
        diagnostics,
        file_coverage,
        adapter_logs,
        coverage,
        profile_matrix: ProfileMatrixRecord::default(),
    };
    refresh_profile_matrix(&mut snapshot, false);
    Ok(snapshot)
}

fn load_completed_snapshot_from_connection(
    connection: &Connection,
    snapshot_id: &str,
) -> Result<GraphSnapshot> {
    fn load_inner(
        connection: &Connection,
        snapshot_id: &str,
        visited: &mut BTreeSet<String>,
    ) -> Result<GraphSnapshot> {
        if !visited.insert(snapshot_id.to_owned()) {
            bail!("completed snapshot parent cycle detected while loading snapshot");
        }
        let record = load_completed_snapshot_record(connection, snapshot_id)?
            .with_context(|| format!("completed snapshot {snapshot_id} was not found"))?;
        let semantic_noop = record.build_attempt_id.is_none()
            && record.runtime_session_ids.is_empty()
            && incremental::scan_is_semantic_noop_overlay(connection, &record.scan_id)?;
        if semantic_noop {
            let overlay = load_base_snapshot_from_connection(connection, &record.scan_id)?;
            if record.parent_snapshot_id != overlay.scan.parent_snapshot_id {
                bail!("completed snapshot parent differs from its semantic overlay scan parent");
            }
            let parent_id = record
                .parent_snapshot_id
                .as_deref()
                .context("semantic no-op overlay has no parent completed snapshot")?;
            let mut snapshot = load_inner(connection, parent_id, visited)?;
            apply_semantic_noop_overlay(&mut snapshot, overlay)?;
            return Ok(snapshot);
        }

        let parent_record = record
            .parent_snapshot_id
            .as_deref()
            .map(|parent_id| {
                load_completed_snapshot_record(connection, parent_id)?
                    .with_context(|| format!("parent completed snapshot {parent_id} was not found"))
            })
            .transpose()?;
        let layered = matches!(record.source_kind.as_str(), "build" | "runtime");
        let mut snapshot = if layered {
            if let Some(parent_id) = record.parent_snapshot_id.as_deref() {
                load_inner(connection, parent_id, visited)?
            } else {
                load_effective_scan_snapshot(connection, &record.scan_id)?
            }
        } else {
            load_effective_scan_snapshot(connection, &record.scan_id)?
        };

        if let Some(attempt_id) = &record.build_attempt_id
            && parent_record
                .as_ref()
                .and_then(|parent| parent.build_attempt_id.as_deref())
                != Some(attempt_id.as_str())
        {
            let raw = connection
                .query_row(
                    "SELECT delta_json FROM build_attempts
                      WHERE id=?1 AND base_scan_id=?2 AND status='completed'",
                    params![attempt_id, record.scan_id],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?
                .flatten()
                .with_context(|| {
                    format!("snapshot {snapshot_id} build attempt {attempt_id} has no delta")
                })?;
            let delta: BuildGraphDelta = serde_json::from_str(&raw)?;
            merge_build_delta(&mut snapshot, delta, attempt_id)?;
        }
        let parent_runtime_ids = parent_record
            .as_ref()
            .map(|parent| parent.runtime_session_ids.as_slice())
            .unwrap_or(&[]);
        let new_runtime_ids = record
            .runtime_session_ids
            .iter()
            .filter(|id| !parent_runtime_ids.contains(id))
            .cloned()
            .collect::<Vec<_>>();
        if !new_runtime_ids.is_empty() {
            runtime::merge_runtime_sessions(connection, &mut snapshot, &new_runtime_ids)?;
        }
        Ok(snapshot)
    }

    load_inner(connection, snapshot_id, &mut BTreeSet::new())
}

fn load_completed_snapshot_profiles_from_connection(
    connection: &Connection,
    snapshot_id: &str,
) -> Result<Vec<ProfileRecord>> {
    let mut current = snapshot_id.to_owned();
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(current.clone()) {
            bail!("completed snapshot parent cycle detected while loading profiles");
        }
        let record = load_completed_snapshot_record(connection, &current)?
            .with_context(|| format!("completed snapshot {current} was not found"))?;
        if record.build_attempt_id.is_none()
            && record.runtime_session_ids.is_empty()
            && incremental::scan_is_semantic_noop_overlay(connection, &record.scan_id)?
        {
            let scan_parent_snapshot_id = connection.query_row(
                "SELECT parent_snapshot_id FROM scans WHERE id=?1",
                [&record.scan_id],
                |row| row.get::<_, Option<String>>(0),
            )?;
            if record.parent_snapshot_id != scan_parent_snapshot_id {
                bail!("completed snapshot parent differs from its semantic overlay scan parent");
            }
            current = record
                .parent_snapshot_id
                .context("semantic no-op snapshot has no parent completed snapshot")?;
            continue;
        }
        let profiles =
            if record.build_attempt_id.is_some() || !record.runtime_session_ids.is_empty() {
                load_completed_snapshot_from_connection(connection, &current)?.profiles
            } else {
                load_profiles(connection, &record.scan_id)?
            };
        let observed_ids = profiles
            .iter()
            .map(|profile| profile.id.as_str())
            .collect::<Vec<_>>();
        if observed_ids
            != record
                .profile_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        {
            bail!("completed snapshot profile metadata differs from its stored profile set");
        }
        return Ok(profiles);
    }
}

/*
 * Kept near the completed-snapshot loader because both reconstruction and
 * content identity must apply precisely the same immutable overlay order.
 */
fn merge_completed_build_delta(
    connection: &Connection,
    snapshot: &mut GraphSnapshot,
    scan_id: &str,
    attempt_id: &str,
) -> Result<()> {
    let raw = connection
        .query_row(
            "SELECT delta_json FROM build_attempts
                  WHERE id=?1 AND base_scan_id=?2 AND status='completed'",
            params![attempt_id, scan_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten()
        .with_context(|| format!("completed build attempt {attempt_id} has no graph delta"))?;
    let delta: BuildGraphDelta = serde_json::from_str(&raw)?;
    merge_build_delta(snapshot, delta, attempt_id)?;
    Ok(())
}

fn load_effective_scan_snapshot(connection: &Connection, scan_id: &str) -> Result<GraphSnapshot> {
    let overlay = load_base_snapshot_from_connection(connection, scan_id)?;
    if !incremental::scan_is_semantic_noop_overlay(connection, scan_id)? {
        return Ok(overlay);
    }
    let parent_snapshot_id = overlay
        .scan
        .parent_snapshot_id
        .as_deref()
        .context("semantic no-op overlay has no parent completed snapshot")?;
    let mut snapshot = load_completed_snapshot_from_connection(connection, parent_snapshot_id)?;
    apply_semantic_noop_overlay(&mut snapshot, overlay)?;
    Ok(snapshot)
}

fn apply_semantic_noop_overlay(snapshot: &mut GraphSnapshot, overlay: GraphSnapshot) -> Result<()> {
    if overlay.nodes.len() != 1 {
        bail!("semantic no-op overlay must persist exactly one node");
    }
    for node in overlay.nodes {
        if let Some(existing) = snapshot.nodes.iter_mut().find(|item| item.id == node.id) {
            if existing.kind != node.kind
                || existing.locator != node.locator
                || existing.display_name != node.display_name
            {
                bail!("semantic no-op overlay changed node public identity fields");
            }
            *existing = node;
        } else {
            bail!(
                "semantic no-op overlay introduced an unknown node {}",
                node.id
            );
        }
    }
    for log in overlay.adapter_logs {
        if let Some(existing) = snapshot
            .adapter_logs
            .iter_mut()
            .find(|item| item.adapter == log.adapter)
        {
            *existing = log;
        } else {
            snapshot.adapter_logs.push(log);
        }
    }
    snapshot.scan = overlay.scan;
    snapshot.nodes.sort_by(|left, right| left.id.cmp(&right.id));
    snapshot
        .adapter_logs
        .sort_by(|left, right| left.adapter.cmp(&right.adapter));
    refresh_profile_matrix(snapshot, false);
    Ok(())
}

fn completed_snapshot_identity(
    connection: &Connection,
    scan_id: &str,
    build_attempt_id: Option<&str>,
    runtime_session_ids: &[String],
    parent_snapshot_id: Option<&str>,
    source_revision: Option<&str>,
) -> Result<(String, Vec<String>)> {
    if build_attempt_id.is_none()
        && runtime_session_ids.is_empty()
        && incremental::scan_is_semantic_noop_overlay(connection, scan_id)?
    {
        return incremental::semantic_noop_snapshot_identity(
            connection,
            scan_id,
            parent_snapshot_id.context("semantic no-op overlay identity has no parent")?,
            source_revision,
        );
    }
    let layered = build_attempt_id.is_some() || !runtime_session_ids.is_empty();
    let parent_record = parent_snapshot_id
        .map(|parent_id| {
            load_completed_snapshot_record(connection, parent_id)?
                .with_context(|| format!("parent completed snapshot {parent_id} was not found"))
        })
        .transpose()?;
    let mut snapshot = if layered {
        if let Some(parent_id) = parent_snapshot_id {
            load_completed_snapshot_from_connection(connection, parent_id)?
        } else {
            load_effective_scan_snapshot(connection, scan_id)?
        }
    } else {
        load_effective_scan_snapshot(connection, scan_id)?
    };
    if let Some(attempt_id) = build_attempt_id
        && parent_record
            .as_ref()
            .and_then(|parent| parent.build_attempt_id.as_deref())
            != Some(attempt_id)
    {
        merge_completed_build_delta(connection, &mut snapshot, scan_id, attempt_id)?;
    }
    let parent_runtime_ids = parent_record
        .as_ref()
        .map(|parent| parent.runtime_session_ids.as_slice())
        .unwrap_or(&[]);
    let new_runtime_ids = runtime_session_ids
        .iter()
        .filter(|id| !parent_runtime_ids.contains(id))
        .cloned()
        .collect::<Vec<_>>();
    if !new_runtime_ids.is_empty() {
        runtime::merge_runtime_sessions(connection, &mut snapshot, &new_runtime_ids)?;
    }
    let mut profile_ids = snapshot
        .profiles
        .iter()
        .map(|profile| profile.id.clone())
        .collect::<Vec<_>>();
    profile_ids.sort();
    profile_ids.dedup();
    let mut identity = json!({
        "schema": "completed-snapshot-v1",
        "parent_snapshot_id": parent_snapshot_id,
        "source_revision": source_revision,
        "profile_ids": profile_ids,
        "graph": {
            "profiles": snapshot.profiles,
            "nodes": snapshot.nodes,
            "sites": snapshot.sites,
            "edges": snapshot.edges,
            "evidence": snapshot.evidence,
            "diagnostics": snapshot.diagnostics,
            "file_coverage": snapshot.file_coverage,
            "coverage": snapshot.coverage,
        },
    });
    if !runtime_session_ids.is_empty() {
        identity["schema"] = json!("completed-snapshot-v2");
        identity["runtime_session_ids"] = json!(runtime_session_ids);
    }
    Ok((stable_id_from_value("snapshot", &identity), profile_ids))
}

fn create_completed_snapshot(
    connection: &Connection,
    source: SnapshotSource<'_>,
) -> Result<String> {
    let (snapshot_id, profile_ids) = completed_snapshot_identity(
        connection,
        source.scan_id,
        source.build_attempt_id,
        source.runtime_session_ids,
        source.parent_snapshot_id,
        source.source_revision,
    )?;
    let profile_set_json = serde_json::to_string(&profile_ids)?;
    let runtime_session_set_json = serde_json::to_string(source.runtime_session_ids)?;
    connection.execute(
        "INSERT INTO completed_snapshots(
            id, source_kind, source_attempt_id, scan_id, build_attempt_id,
            runtime_import_id, runtime_session_set_json, parent_snapshot_id,
            source_revision, profile_set_json, status, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'completed', ?11)
         ON CONFLICT(id) DO NOTHING",
        params![
            snapshot_id,
            source.source_kind,
            source.source_attempt_id,
            source.scan_id,
            source.build_attempt_id,
            source.runtime_import_id,
            runtime_session_set_json,
            source.parent_snapshot_id,
            source.source_revision,
            profile_set_json,
            source.created_at,
        ],
    )?;
    let stored = load_completed_snapshot_record(connection, &snapshot_id)?
        .context("completed snapshot insert was not visible")?;
    if stored.parent_snapshot_id.as_deref() != source.parent_snapshot_id
        || stored.source_revision.as_deref() != source.source_revision
        || stored.profile_ids != profile_ids
        || stored.runtime_import_id.as_deref() != source.runtime_import_id
        || stored.runtime_session_ids != source.runtime_session_ids
        || stored.status != "completed"
    {
        bail!("completed snapshot identity collision for {snapshot_id}");
    }
    persist_completed_snapshot_seal(connection, &snapshot_id)?;
    connection.execute(
        "INSERT INTO snapshot_sources(source_kind, source_attempt_id, snapshot_id, promoted_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            source.source_kind,
            source.source_attempt_id,
            snapshot_id,
            source.created_at
        ],
    )?;
    Ok(snapshot_id)
}

fn promote_completed_snapshot(connection: &Connection, snapshot_id: &str) -> Result<()> {
    let status = connection
        .query_row(
            "SELECT status FROM completed_snapshots WHERE id=?1",
            [snapshot_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .with_context(|| format!("completed snapshot {snapshot_id} was not found"))?;
    if status != "completed" {
        bail!("snapshot {snapshot_id} cannot be promoted from status {status}");
    }
    if completed_snapshot_seal_table_exists(connection)? {
        verify_completed_snapshot_seal(connection, snapshot_id)?;
    }
    connection.execute(
        "INSERT INTO current_completed_snapshot(singleton, snapshot_id) VALUES (1, ?1)
         ON CONFLICT(singleton) DO UPDATE SET snapshot_id=excluded.snapshot_id",
        [snapshot_id],
    )?;
    Ok(())
}

fn promote_completed_snapshot_if_current_parent(
    connection: &Connection,
    snapshot_id: &str,
    expected_parent_snapshot_id: Option<&str>,
) -> Result<bool> {
    let status = connection
        .query_row(
            "SELECT status FROM completed_snapshots WHERE id=?1",
            [snapshot_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .with_context(|| format!("completed snapshot {snapshot_id} was not found"))?;
    if status != "completed" {
        bail!("snapshot {snapshot_id} cannot be promoted from status {status}");
    }
    if completed_snapshot_seal_table_exists(connection)? {
        verify_completed_snapshot_seal(connection, snapshot_id)?;
    }
    let updated = if let Some(expected_parent_snapshot_id) = expected_parent_snapshot_id {
        connection.execute(
            "UPDATE current_completed_snapshot SET snapshot_id=?1
              WHERE singleton=1 AND snapshot_id=?2",
            params![snapshot_id, expected_parent_snapshot_id],
        )?
    } else {
        connection.execute(
            "INSERT OR IGNORE INTO current_completed_snapshot(singleton, snapshot_id)
             VALUES (1, ?1)",
            [snapshot_id],
        )?
    };
    Ok(updated == 1)
}

fn backfill_completed_snapshots(connection: &Connection) -> Result<()> {
    // Early development fixtures used a deliberately reduced v1 `scans`
    // table. Real v1 stores have these columns, but an empty reduced store can
    // still be upgraded safely because it has no graph attempts to backfill.
    if !table_has_column(connection, "scans", "status")?
        || !table_has_column(connection, "scans", "started_at")?
        || !table_has_column(connection, "scans", "completed_at")?
    {
        return Ok(());
    }
    let scans = {
        let mut statement = connection.prepare(
            "SELECT id, COALESCE(completed_at, started_at), parent_snapshot_id, source_revision
               FROM scans WHERE status='completed' ORDER BY started_at, rowid",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (scan_id, created_at, parent_snapshot_id, source_revision) in scans {
        create_completed_snapshot(
            connection,
            SnapshotSource {
                source_kind: "scan",
                source_attempt_id: &scan_id,
                scan_id: &scan_id,
                build_attempt_id: None,
                runtime_import_id: None,
                runtime_session_ids: &[],
                parent_snapshot_id: parent_snapshot_id.as_deref(),
                source_revision: source_revision.as_deref(),
                created_at: &created_at,
            },
        )?;
    }

    let build_attempts = {
        let mut statement = connection.prepare(
            "SELECT id, base_scan_id, COALESCE(completed_at, started_at)
               FROM build_attempts
              WHERE status='completed' AND delta_json IS NOT NULL
              ORDER BY started_at, rowid",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (attempt_id, scan_id, created_at) in build_attempts {
        let base_snapshot_id = connection
            .query_row(
                "SELECT snapshot_id FROM snapshot_sources
                  WHERE source_kind='scan' AND source_attempt_id=?1",
                [&scan_id],
                |row| row.get::<_, String>(0),
            )
            .with_context(|| format!("completed base scan {scan_id} has no migrated snapshot"))?;
        connection.execute(
            "UPDATE build_attempts SET base_snapshot_id=?2 WHERE id=?1",
            params![attempt_id, base_snapshot_id],
        )?;
        let source_revision = connection.query_row(
            "SELECT source_revision FROM completed_snapshots WHERE id=?1",
            [&base_snapshot_id],
            |row| row.get::<_, Option<String>>(0),
        )?;
        create_completed_snapshot(
            connection,
            SnapshotSource {
                source_kind: "build",
                source_attempt_id: &attempt_id,
                scan_id: &scan_id,
                build_attempt_id: Some(&attempt_id),
                runtime_import_id: None,
                runtime_session_ids: &[],
                parent_snapshot_id: Some(&base_snapshot_id),
                source_revision: source_revision.as_deref(),
                created_at: &created_at,
            },
        )?;
    }

    let current_scan_id = connection
        .query_row(
            "SELECT scan_id FROM current_successful WHERE singleton=1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(scan_id) = current_scan_id {
        let current_build_id = connection
            .query_row(
                "SELECT attempt_id FROM current_build_successful WHERE base_scan_id=?1",
                [&scan_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let (source_kind, source_attempt_id) = current_build_id
            .as_deref()
            .map_or(("scan", scan_id.as_str()), |attempt_id| {
                ("build", attempt_id)
            });
        let snapshot_id = connection.query_row(
            "SELECT snapshot_id FROM snapshot_sources
              WHERE source_kind=?1 AND source_attempt_id=?2",
            params![source_kind, source_attempt_id],
            |row| row.get::<_, String>(0),
        )?;
        promote_completed_snapshot(connection, &snapshot_id)?;
    }
    Ok(())
}

fn authenticate_store_schema_before_v16(connection: &Connection) -> Result<()> {
    ensure_schema_objects_absent(
        connection,
        &[
            "runtime_import_operation_owners",
            "runtime_import_operation_owners_import",
            "scan_operation_staging",
            "scan_operation_staging_scan",
            "scan_operation_staging_pending_cancelled",
            "legacy_scan_operation_candidates",
        ],
        15,
    )
}

fn authenticate_store_schema_before_v17(connection: &Connection) -> Result<()> {
    validate_runtime_import_operation_ownership_schema_and_rows(connection)?;
    ensure_schema_objects_absent(
        connection,
        &[
            "scan_operation_staging",
            "scan_operation_staging_scan",
            "scan_operation_staging_pending_cancelled",
            "legacy_scan_operation_candidates",
        ],
        16,
    )
}

fn authenticate_legacy_runtime_import_candidates(
    connection: &Connection,
) -> Result<Vec<LegacyRuntimeImportCandidate>> {
    // Minimal early-development migration fixtures can omit the runtime
    // tables entirely; every real pre-v16 runtime table is authenticated and
    // its staging rows are captured before migration DDL begins.
    if !table_exists(connection, "runtime_imports")? {
        return Ok(Vec::new());
    }
    let candidates = connection
        .prepare(
            "SELECT id, created_at, result_snapshot_id IS NULL
               FROM runtime_imports
              WHERE status='staging'
              ORDER BY id COLLATE BINARY",
        )?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    candidates
        .into_iter()
        .map(|(import_id, created_at, result_snapshot_id_is_null)| {
            if !(1..=512).contains(&import_id.len())
                || created_at.is_empty()
                || !result_snapshot_id_is_null
            {
                bail!("legacy runtime import candidate is inconsistent");
            }
            Ok(LegacyRuntimeImportCandidate {
                import_id,
                created_at,
            })
        })
        .collect()
}

fn authenticate_legacy_scan_operation_candidates(
    connection: &Connection,
) -> Result<Vec<LegacyScanOperationCandidate>> {
    if !table_exists(connection, "scans")?
        || !table_has_column(connection, "scans", "status")?
        || !table_has_column(connection, "scans", "strict")?
        || !table_has_column(connection, "scans", "parent_snapshot_id")?
        || !table_has_column(connection, "scans", "mutation_count")?
        || !table_has_column(connection, "scans", "started_at")?
    {
        return Ok(Vec::new());
    }
    let candidates = connection
        .prepare(
            "SELECT id, status, strict, parent_snapshot_id, mutation_count, started_at
               FROM scans
              WHERE status IN ('staging', 'completed')
              ORDER BY id COLLATE BINARY",
        )?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    candidates
        .into_iter()
        .map(
            |(scan_id, status, strict, parent_snapshot_id, mutation_count, started_at)| {
                if !(1..=512).contains(&scan_id.len())
                    || !matches!(strict, 0 | 1)
                    || started_at.is_empty()
                    || (status == "completed" && mutation_count < 0)
                {
                    bail!("legacy scan operation candidate is inconsistent");
                }
                let (validated_mutation_count, prospective_snapshot_id) = if status == "completed" {
                    let snapshot_id = connection
                        .query_row(
                            "SELECT snapshot_id FROM snapshot_sources
                                  WHERE source_kind='scan' AND source_attempt_id=?1",
                            [&scan_id],
                            |row| row.get::<_, String>(0),
                        )
                        .with_context(|| {
                            format!("completed legacy scan {scan_id} has no immutable snapshot")
                        })?;
                    (Some(mutation_count), Some(snapshot_id))
                } else {
                    (None, None)
                };
                Ok(LegacyScanOperationCandidate {
                    scan_id,
                    strict: strict != 0,
                    parent_snapshot_id,
                    validated_mutation_count,
                    prospective_snapshot_id,
                    started_at,
                })
            },
        )
        .collect()
}

fn ensure_schema_objects_absent(
    connection: &Connection,
    names: &[&str],
    version: i64,
) -> Result<()> {
    for name in names {
        let object_type = connection
            .query_row(
                "SELECT type FROM sqlite_schema WHERE name=?1",
                [name],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(object_type) = object_type {
            bail!("store schema {version} contains forbidden future {object_type} object {name}");
        }
    }
    Ok(())
}

fn normalized_schema_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn validate_schema_object_sql(
    connection: &Connection,
    object_type: &str,
    name: &str,
    expected_sql: &str,
) -> Result<()> {
    let actual = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type=?1 AND name=?2",
            params![object_type, name],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten()
        .with_context(|| format!("store schema is missing {object_type} {name}"))?;
    if normalized_schema_sql(&actual) != normalized_schema_sql(expected_sql) {
        bail!("store schema {object_type} {name} does not have its exact expected shape");
    }
    Ok(())
}

fn validate_named_table_indexes(
    connection: &Connection,
    table: &str,
    expected: &[(&str, &str)],
) -> Result<()> {
    let actual = connection
        .prepare(
            "SELECT name, sql FROM sqlite_schema
              WHERE type='index' AND tbl_name=?1 AND sql IS NOT NULL
              ORDER BY name COLLATE BINARY",
        )?
        .query_map([table], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let expected = expected
        .iter()
        .map(|(name, sql)| ((*name).to_owned(), normalized_schema_sql(sql)))
        .collect::<Vec<_>>();
    let normalized_actual = actual
        .into_iter()
        .map(|(name, sql)| (name, normalized_schema_sql(&sql)))
        .collect::<Vec<_>>();
    if normalized_actual != expected {
        bail!("store schema table {table} does not have its exact expected named indexes");
    }
    Ok(())
}

fn validate_single_foreign_key(
    connection: &Connection,
    table: &str,
    from: &str,
    parent_table: &str,
    to: &str,
) -> Result<()> {
    let foreign_keys = connection
        .prepare(&format!("PRAGMA foreign_key_list({table})"))?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if foreign_keys
        != [(
            parent_table.to_owned(),
            from.to_owned(),
            to.to_owned(),
            "NO ACTION".to_owned(),
            "CASCADE".to_owned(),
            "NONE".to_owned(),
        )]
    {
        bail!("store schema table {table} does not have its exact expected foreign key");
    }
    Ok(())
}

fn validate_runtime_import_operation_ownership_schema_and_rows(
    connection: &Connection,
) -> Result<()> {
    validate_schema_object_sql(
        connection,
        "table",
        "runtime_import_operation_owners",
        RUNTIME_IMPORT_OPERATION_OWNERS_TABLE_SQL,
    )?;
    validate_named_table_indexes(
        connection,
        "runtime_import_operation_owners",
        &[(
            "runtime_import_operation_owners_import",
            RUNTIME_IMPORT_OPERATION_OWNERS_INDEX_SQL,
        )],
    )?;
    validate_single_foreign_key(
        connection,
        "runtime_import_operation_owners",
        "import_id",
        "runtime_imports",
        "id",
    )?;
    if !table_exists(connection, "runtime_imports")? {
        let owner_count: u64 = connection.query_row(
            "SELECT COUNT(*) FROM runtime_import_operation_owners",
            [],
            |row| row.get(0),
        )?;
        if owner_count != 0 {
            bail!("runtime import ownership exists without the runtime import table");
        }
        return Ok(());
    }
    let invalid_rows: u64 = connection.query_row(
        "SELECT COUNT(*)
           FROM runtime_import_operation_owners AS owner
           LEFT JOIN runtime_imports AS import ON import.id=owner.import_id
          WHERE typeof(owner.import_id)!='text'
             OR length(CAST(owner.import_id AS BLOB)) NOT BETWEEN 1 AND 512
             OR typeof(owner.operation_id)!='text'
             OR length(CAST(owner.operation_id AS BLOB)) NOT BETWEEN 1 AND 512
             OR typeof(owner.created_at)!='text' OR length(owner.created_at)=0
             OR import.id IS NULL OR import.status!='staging'
             OR import.result_snapshot_id IS NOT NULL",
        [],
        |row| row.get(0),
    )?;
    let unowned_staging: u64 = connection.query_row(
        "SELECT COUNT(*) FROM runtime_imports AS import
          WHERE import.status='staging'
            AND import.result_snapshot_id IS NULL
            AND NOT EXISTS (
                SELECT 1 FROM runtime_import_operation_owners AS owner
                 WHERE owner.import_id=import.id
            )",
        [],
        |row| row.get(0),
    )?;
    if invalid_rows != 0 || unowned_staging != 0 {
        bail!(
            "runtime import operation ownership rows are inconsistent: \
             {invalid_rows} invalid owners, {unowned_staging} unowned staging imports"
        );
    }
    let mut statement = connection.prepare(
        "SELECT substr(CAST(import_id AS BLOB), 1, 513),
                substr(CAST(operation_id AS BLOB), 1, 513)
           FROM runtime_import_operation_owners
          ORDER BY import_id COLLATE BINARY, operation_id COLLATE BINARY",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let import_id = String::from_utf8(row.get::<_, Vec<u8>>(0)?)
            .context("runtime import ownership import ID is not valid UTF-8")?;
        let operation_id = String::from_utf8(row.get::<_, Vec<u8>>(1)?)
            .context("runtime import ownership operation ID is not valid UTF-8")?;
        if import_id.len() > 512
            || operation_id.len() > 512
            || (operation_id.starts_with(LEGACY_RUNTIME_IMPORT_OWNER_PREFIX)
                && operation_id != legacy_runtime_import_owner_id(&import_id))
        {
            bail!("runtime import operation ownership identity is inconsistent");
        }
    }
    Ok(())
}

fn validate_scan_operation_staging_schema_and_rows(connection: &Connection) -> Result<()> {
    validate_schema_object_sql(
        connection,
        "table",
        "scan_operation_staging",
        SCAN_OPERATION_STAGING_TABLE_SQL,
    )?;
    validate_named_table_indexes(
        connection,
        "scan_operation_staging",
        &[
            (
                "scan_operation_staging_pending_cancelled",
                SCAN_OPERATION_STAGING_PENDING_INDEX_SQL,
            ),
            (
                "scan_operation_staging_scan",
                SCAN_OPERATION_STAGING_SCAN_INDEX_SQL,
            ),
        ],
    )?;
    validate_single_foreign_key(
        connection,
        "scan_operation_staging",
        "scan_id",
        "scans",
        "id",
    )?;
    let owner_count: u64 =
        connection.query_row("SELECT COUNT(*) FROM scan_operation_staging", [], |row| {
            row.get(0)
        })?;
    let has_full_parent_schema = table_exists(connection, "snapshot_sources")?
        && table_has_column(connection, "scans", "status")?
        && table_has_column(connection, "scans", "strict")?
        && table_has_column(connection, "scans", "parent_snapshot_id")?
        && table_has_column(connection, "scans", "mutation_count")?;
    if !has_full_parent_schema {
        if owner_count != 0 {
            bail!("scan operation staging exists without its complete parent schema");
        }
        return Ok(());
    }
    let invalid_rows: u64 = connection.query_row(
        "SELECT COUNT(*)
           FROM scan_operation_staging AS owner
           LEFT JOIN scans AS scan ON scan.id=owner.scan_id
          WHERE typeof(owner.operation_id)!='text'
             OR length(CAST(owner.operation_id AS BLOB)) NOT BETWEEN 1 AND 512
             OR typeof(owner.scan_id)!='text'
             OR length(CAST(owner.scan_id AS BLOB)) NOT BETWEEN 1 AND 512
             OR typeof(owner.repository_binding_digest)!='blob'
             OR length(owner.repository_binding_digest)!=32
             OR typeof(owner.configuration_digest)!='blob'
             OR length(owner.configuration_digest)!=32
             OR owner.strict NOT IN (0, 1) OR owner.cache_enabled NOT IN (0, 1)
             OR typeof(owner.created_at)!='text' OR length(owner.created_at)=0
             OR scan.id IS NULL OR scan.status NOT IN ('staging', 'completed', 'cancelled')
             OR owner.strict!=scan.strict
             OR owner.base_snapshot_id IS NOT scan.parent_snapshot_id
             OR (owner.validated_mutation_count IS NULL
                 AND (owner.prospective_snapshot_id IS NOT NULL
                      OR owner.result_digest IS NOT NULL))
             OR (owner.validated_mutation_count IS NOT NULL
                 AND (owner.validated_mutation_count<0
                      OR owner.validated_mutation_count!=scan.mutation_count
                      OR owner.prospective_snapshot_id IS NULL))
             OR (owner.result_digest IS NOT NULL
                 AND (typeof(owner.result_digest)!='blob'
                      OR length(owner.result_digest)!=32))
             OR (owner.decision_authorization_digest IS NOT NULL
                 AND (typeof(owner.decision_authorization_digest)!='blob'
                      OR length(owner.decision_authorization_digest)!=32))",
        [],
        |row| row.get(0),
    )?;
    if invalid_rows != 0 {
        bail!("scan operation staging contains {invalid_rows} inconsistent ownership rows");
    }
    let operation_ids = connection
        .prepare(
            "SELECT substr(CAST(operation_id AS BLOB), 1, 513)
               FROM scan_operation_staging
              ORDER BY operation_id COLLATE BINARY",
        )?
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for operation_id in operation_ids {
        let operation_id = String::from_utf8(operation_id)
            .context("scan operation staging operation ID is not valid UTF-8")?;
        let binding = load_scan_operation_recovery_binding_from(connection, &operation_id)?;
        if operation_id.starts_with(LEGACY_SCAN_OPERATION_CANDIDATE_PREFIX) {
            validate_legacy_scan_operation_candidate(&binding)?;
        } else {
            validate_internal_scan_operation_binding(&binding)?;
            if binding.status == "completed" {
                let snapshot_id = connection
                    .query_row(
                        "SELECT snapshot_id FROM snapshot_sources
                          WHERE source_kind='scan' AND source_attempt_id=?1",
                        [&binding.scan_id],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?
                    .context("completed operation-owned scan has no snapshot source")?;
                if binding.validated_mutation_count.is_none()
                    || binding.result_digest.is_none()
                    || binding.prospective_snapshot_id.as_deref() != Some(snapshot_id.as_str())
                {
                    bail!("completed scan operation staging is not durably sealed");
                }
            }
        }
    }
    Ok(())
}

fn load_scan_operation_recovery_binding_from(
    connection: &Connection,
    operation_id: &str,
) -> Result<ScanOperationRecoveryBinding> {
    connection
        .query_row(
            "SELECT owner.operation_id, owner.scan_id,
                    owner.repository_binding_digest, owner.configuration_digest,
                    owner.strict, owner.cache_enabled, owner.base_snapshot_id,
                    owner.validated_mutation_count, owner.prospective_snapshot_id,
                    owner.result_digest, owner.decision_authorization_digest,
                    scan.root, scan.status, scan.strict, scan.parent_snapshot_id,
                    scan.mutation_count
               FROM scan_operation_staging AS owner
               JOIN scans AS scan ON scan.id=owner.scan_id
              WHERE owner.operation_id=?1",
            [operation_id],
            |row| {
                Ok(ScanOperationRecoveryBinding {
                    operation_id: row.get(0)?,
                    scan_id: row.get(1)?,
                    repository_binding_digest: row.get(2)?,
                    configuration_digest: row.get(3)?,
                    strict: row.get(4)?,
                    cache_enabled: row.get(5)?,
                    base_snapshot_id: row.get(6)?,
                    validated_mutation_count: row.get(7)?,
                    prospective_snapshot_id: row.get(8)?,
                    result_digest: row.get(9)?,
                    decision_authorization_digest: row.get(10)?,
                    root: row.get(11)?,
                    status: row.get(12)?,
                    scan_strict: row.get(13)?,
                    parent_snapshot_id: row.get(14)?,
                    mutation_count: row.get(15)?,
                })
            },
        )
        .optional()?
        .context("scan completion has no durable operation-owned staging binding")
}

fn validate_store_foreign_keys(connection: &Connection, version: i64) -> Result<()> {
    let violations =
        connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get::<_, u64>(0)
        })?;
    if violations != 0 {
        bail!("store schema {version} migration left {violations} foreign key violations");
    }
    Ok(())
}

fn table_has_column(connection: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    for candidate in columns {
        if candidate? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn legacy_runtime_import_owner_id(import_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"depgraph-legacy-runtime-import-owner-v1");
    digest.update((import_id.len() as u64).to_be_bytes());
    digest.update(import_id.as_bytes());
    let digest = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{LEGACY_RUNTIME_IMPORT_OWNER_PREFIX}{digest}")
}

fn legacy_scan_operation_candidate_id(scan_id: &str) -> String {
    format!(
        "{LEGACY_SCAN_OPERATION_CANDIDATE_PREFIX}{:x}",
        Sha256::digest(scan_id.as_bytes())
    )
}

fn append_scan_authorization_digest_part(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

#[allow(clippy::too_many_arguments)]
fn scan_decision_authorization_digest_from_parts(
    operation_id: &str,
    scan_id: &str,
    repository_root: &str,
    repository_binding_digest: &[u8],
    configuration_digest: &[u8],
    strict: bool,
    cache_enabled: bool,
    base_snapshot_id: Option<&str>,
    validated_mutation_count: i64,
    prospective_snapshot_id: &str,
    result_digest: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"depgraph:scan-operation-completion-decision:v1\0");
    for value in [
        operation_id.as_bytes(),
        scan_id.as_bytes(),
        repository_root.as_bytes(),
        repository_binding_digest,
        configuration_digest,
        &[u8::from(strict)],
        &[u8::from(cache_enabled)],
        base_snapshot_id.unwrap_or_default().as_bytes(),
        &validated_mutation_count.to_be_bytes(),
        prospective_snapshot_id.as_bytes(),
        result_digest,
    ] {
        append_scan_authorization_digest_part(&mut hasher, value);
    }
    hasher.finalize().into()
}

fn build_delta_from_protocol(protocol: &ValidatedProtocol) -> Result<BuildGraphDelta> {
    let profile_coverage = protocol
        .events
        .iter()
        .filter_map(|event| match event {
            ProtocolEvent::ProfileCompleted(completed) => Some((
                completed.profile_id.clone(),
                coverage_record(&completed.coverage),
            )),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let coverage = protocol
        .events
        .iter()
        .rev()
        .find_map(|event| match event {
            ProtocolEvent::ScanCompleted(completed) => Some(coverage_record(&completed.coverage)),
            _ => None,
        })
        .context("build protocol has no final coverage")?;
    let profiles = protocol
        .profiles
        .values()
        .map(|profile| ProfileRecord {
            id: profile.id.clone(),
            language: profile.language.clone(),
            toolchain: profile.toolchain.clone(),
            command: profile.command.clone(),
            target: profile.target.clone(),
            features: profile.features.clone(),
            environment: serde_json::to_value(&profile.environment).unwrap_or_else(|_| json!({})),
            source_revision: profile.source_revision.clone(),
            properties: serde_json::to_value(&profile.properties).unwrap_or_else(|_| json!({})),
            coverage: profile_coverage.get(&profile.id).cloned(),
        })
        .collect();
    let nodes = protocol
        .nodes
        .values()
        .map(|node| NodeRecord {
            id: node.id.clone(),
            kind: node.kind.clone(),
            locator: node.locator.clone(),
            display_name: node
                .display_name
                .clone()
                .unwrap_or_else(|| node.locator.clone()),
            properties: serde_json::to_value(&node.properties).unwrap_or_else(|_| json!({})),
        })
        .collect();
    let sites = protocol
        .sites
        .values()
        .map(|site| SiteRecord {
            id: site.id.clone(),
            source: site.source.clone(),
            kind: site.kind.clone(),
            specifier: Some(site.specifier.clone()),
            profile_id: site.profile_id.clone(),
            resolution_status: enum_json(&site.resolution_status),
            precision: enum_json(&site.precision),
            condition: serde_json::to_value(&site.condition).unwrap_or_else(|_| json!({})),
            target_ids: site.target_ids.clone(),
            reason: site.reason.clone(),
        })
        .collect();
    let edges = protocol
        .edges
        .values()
        .map(|edge| EdgeRecord {
            id: edge.id.clone(),
            site_id: edge.site_id.clone(),
            source: edge.source.clone(),
            target: edge.target.clone(),
            kind: edge.kind.clone(),
            phase: enum_json(&edge.phase),
            environment: edge.environment.clone().unwrap_or_else(|| "any".to_owned()),
            profile_id: edge.profile_id.clone(),
            resolution_status: enum_json(&edge.resolution_status),
            precision: enum_json(&edge.precision),
            condition: serde_json::to_value(&edge.condition).unwrap_or_else(|_| json!({})),
            generated: edge.generated,
        })
        .collect();
    let mut evidence = Vec::new();
    for site in protocol.sites.values() {
        append_evidence_records(&mut evidence, "site", &site.id, &site.evidence)?;
    }
    for edge in protocol.edges.values() {
        append_evidence_records(&mut evidence, "edge", &edge.id, &edge.evidence)?;
    }
    let mut diagnostics = Vec::new();
    for (ordinal, diagnostic) in protocol.diagnostics.values().enumerate() {
        diagnostics.push(diagnostic_record(ordinal as i64, diagnostic));
        append_evidence_records(
            &mut evidence,
            "diagnostic",
            &diagnostic.id,
            &diagnostic.evidence,
        )?;
    }
    Ok(BuildGraphDelta {
        profiles,
        nodes,
        sites,
        edges,
        evidence,
        diagnostics,
        coverage,
    })
}

fn enum_json<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_default()
}

fn coverage_record(coverage: &Coverage) -> CoverageRecord {
    CoverageRecord {
        profiles: coverage.profiles,
        files_discovered: coverage.files_discovered,
        files_analyzed: coverage.files_analyzed,
        files_skipped: coverage.files_skipped,
        dependency_sites: coverage.dependency_sites,
        resolved: coverage.resolved,
        candidates: coverage.candidates,
        external: coverage.external,
        unresolved: coverage.unresolved,
        unsupported_syntax: coverage.unsupported_syntax,
        project_code_executed: coverage.project_code_executed,
        completeness: coverage.completeness.iter().map(enum_json).collect(),
        reasons: coverage.reasons.clone(),
    }
}

fn append_evidence_records(
    output: &mut Vec<EvidenceRecord>,
    owner_type: &str,
    owner_id: &str,
    evidence: &[Evidence],
) -> Result<()> {
    for (ordinal, item) in evidence.iter().enumerate() {
        output.push(EvidenceRecord {
            owner_type: owner_type.to_owned(),
            owner_id: owner_id.to_owned(),
            ordinal: ordinal as i64,
            kind: enum_json(&item.kind),
            extractor: item.extractor.clone(),
            extractor_version: item.extractor_version.clone(),
            path: item.path.clone().unwrap_or_default(),
            start_line: item.start_line.unwrap_or(1).into(),
            start_column: item.start_column.unwrap_or(1).into(),
            end_line: item.end_line.unwrap_or(1).into(),
            end_column: item.end_column.unwrap_or(1).into(),
            detail: item.detail.clone(),
            properties: serde_json::to_value(&item.properties)?,
        });
    }
    Ok(())
}

fn diagnostic_record(ordinal: i64, diagnostic: &Diagnostic) -> DiagnosticRecord {
    DiagnosticRecord {
        ordinal,
        id: diagnostic.id.clone(),
        severity: enum_json(&diagnostic.severity),
        code: diagnostic.code.clone(),
        message: diagnostic.message.clone(),
        path: diagnostic.path.clone(),
        adapter: None,
        start_line: diagnostic.start_line.map(Into::into),
        start_column: diagnostic.start_column.map(Into::into),
        end_line: diagnostic.end_line.map(Into::into),
        end_column: diagnostic.end_column.map(Into::into),
        properties: serde_json::to_value(&diagnostic.properties).unwrap_or_else(|_| json!({})),
    }
}

fn validate_delta_attempt_metadata(
    delta: &BuildGraphDelta,
    attempt: &BuildAttemptRecord,
) -> Result<()> {
    let output_digest = attempt
        .validated_output_digest
        .as_deref()
        .context("build attempt has no validated output digest")?;
    for evidence in delta.evidence.iter().filter(|evidence| {
        matches!(evidence.owner_type.as_str(), "site" | "edge") && evidence.ordinal == 0
    }) {
        if evidence.kind != "build"
            || evidence.extractor != attempt.observer
            || evidence.extractor_version != attempt.observer_version
        {
            bail!("build evidence producer does not match its attempt audit");
        }
        for (field, expected) in [
            ("build_run_id", attempt.id.as_str()),
            ("profile_id", attempt.profile_id.as_str()),
            ("command_plan_digest", attempt.command_plan_digest.as_str()),
            (
                "toolchain_executable_digest",
                attempt.toolchain_executable_digest.as_str(),
            ),
            (
                "environment_key_set_digest",
                attempt.environment_key_set_digest.as_str(),
            ),
            ("validated_output_digest", output_digest),
        ] {
            if evidence.properties.get(field).and_then(Value::as_str) != Some(expected) {
                bail!("build evidence {field} does not match its attempt audit");
            }
        }
    }
    Ok(())
}

fn validate_build_union(
    base: &GraphSnapshot,
    delta: &BuildGraphDelta,
    attempt: &BuildAttemptRecord,
) -> Result<()> {
    if delta.profiles.len() != 1 || delta.profiles[0].id != attempt.profile_id {
        bail!("build delta must contain exactly its audited profile");
    }
    let base_profiles = base
        .profiles
        .iter()
        .map(|profile| (&profile.id, profile))
        .collect::<BTreeMap<_, _>>();
    for profile in &delta.profiles {
        if profile
            .properties
            .get("profile_phase")
            .and_then(Value::as_str)
            != Some("build")
        {
            bail!(
                "build profile {} must declare profile_phase=build",
                profile.id
            );
        }
        let parent_id = declared_parent_profile_id(profile)
            .with_context(|| format!("build profile {} has no parent profile", profile.id))?;
        let parent = base
            .profiles
            .iter()
            .find(|candidate| candidate.id == parent_id)
            .with_context(|| {
                format!(
                    "build profile {} parent {parent_id} is not in the base graph",
                    profile.id
                )
            })?;
        let declared_effective = declared_effective_input_id(profile).with_context(|| {
            format!(
                "build profile {} has no canonical effective input identity",
                profile.id
            )
        })?;
        if declared_effective != canonical_effective_input_id(parent)
            || canonical_profile_language(&profile.language)
                != canonical_profile_language(&parent.language)
        {
            bail!(
                "build profile {} effective parent contract is invalid",
                profile.id
            );
        }
        if let Some(existing) = base_profiles.get(&profile.id)
            && (existing.language != profile.language
                || existing.toolchain != profile.toolchain
                || existing.command != profile.command
                || existing.target != profile.target
                || existing.features != profile.features
                || existing.environment != profile.environment
                || existing.source_revision != profile.source_revision)
        {
            bail!("build profile {} conflicts with the base graph", profile.id);
        }
    }

    let base_nodes = base
        .nodes
        .iter()
        .map(|node| (&node.id, node))
        .collect::<BTreeMap<_, _>>();
    for node in &delta.nodes {
        if let Some(existing) = base_nodes.get(&node.id) {
            if *existing != node {
                bail!("build node {} would overwrite the base graph", node.id);
            }
        } else {
            let provenance = node
                .properties
                .get("build_provenance")
                .and_then(Value::as_object)
                .with_context(|| format!("new build node {} lacks build provenance", node.id))?;
            if node
                .properties
                .get("build_generated")
                .and_then(Value::as_bool)
                != Some(true)
                || provenance.get("build_run_id").and_then(Value::as_str)
                    != Some(attempt.id.as_str())
                || provenance.get("profile_id").and_then(Value::as_str)
                    != Some(attempt.profile_id.as_str())
                || provenance.get("observer").and_then(Value::as_str)
                    != Some(attempt.observer.as_str())
                || provenance.get("observer_version").and_then(Value::as_str)
                    != Some(attempt.observer_version.as_str())
                || provenance
                    .get("command_plan_digest")
                    .and_then(Value::as_str)
                    != Some(attempt.command_plan_digest.as_str())
                || provenance
                    .get("toolchain_executable_digest")
                    .and_then(Value::as_str)
                    != Some(attempt.toolchain_executable_digest.as_str())
                || provenance
                    .get("environment_key_set_digest")
                    .and_then(Value::as_str)
                    != Some(attempt.environment_key_set_digest.as_str())
                || provenance
                    .get("validated_output_digest")
                    .and_then(Value::as_str)
                    != attempt.validated_output_digest.as_deref()
            {
                bail!("new build node {} has unauthorized provenance", node.id);
            }
        }
    }
    let node_ids = base
        .nodes
        .iter()
        .chain(delta.nodes.iter())
        .map(|node| node.id.as_str())
        .collect::<BTreeSet<_>>();
    let profile_ids = base
        .profiles
        .iter()
        .chain(delta.profiles.iter())
        .map(|profile| profile.id.as_str())
        .collect::<BTreeSet<_>>();
    let base_site_ids = base
        .sites
        .iter()
        .map(|site| site.id.as_str())
        .collect::<BTreeSet<_>>();
    let base_edge_ids = base
        .edges
        .iter()
        .map(|edge| edge.id.as_str())
        .collect::<BTreeSet<_>>();
    for site in &delta.sites {
        if base_site_ids.contains(site.id.as_str()) {
            bail!(
                "build site {} would overwrite an existing evidence layer",
                site.id
            );
        }
        if site.precision != "observed"
            || !node_ids.contains(site.source.as_str())
            || site
                .target_ids
                .iter()
                .any(|target| !node_ids.contains(target.as_str()))
            || !profile_ids.contains(site.profile_id.as_str())
        {
            bail!("build site {} is not authorized by the base graph", site.id);
        }
    }
    let delta_site_ids = delta
        .sites
        .iter()
        .map(|site| site.id.as_str())
        .collect::<BTreeSet<_>>();
    for edge in &delta.edges {
        if base_edge_ids.contains(edge.id.as_str()) {
            bail!(
                "build edge {} would overwrite an existing evidence layer",
                edge.id
            );
        }
        if edge.phase != "build"
            || edge.precision != "observed"
            || !node_ids.contains(edge.source.as_str())
            || !node_ids.contains(edge.target.as_str())
            || !profile_ids.contains(edge.profile_id.as_str())
            || edge
                .site_id
                .as_deref()
                .is_some_and(|site_id| !delta_site_ids.contains(site_id))
        {
            bail!("build edge {} is not authorized by the base graph", edge.id);
        }
    }
    Ok(())
}

fn deduplicate_identical_build_evidence(
    base: &GraphSnapshot,
    delta: &mut BuildGraphDelta,
) -> Result<()> {
    let base_sites = base
        .sites
        .iter()
        .map(|site| (site.id.as_str(), site))
        .collect::<BTreeMap<_, _>>();
    let base_edges = base
        .edges
        .iter()
        .map(|edge| (edge.id.as_str(), edge))
        .collect::<BTreeMap<_, _>>();
    let mut removed_sites = Vec::new();
    for site in &delta.sites {
        if let Some(existing) = base_sites.get(site.id.as_str()) {
            if *existing != site {
                bail!(
                    "build site {} conflicts with an existing evidence layer",
                    site.id
                );
            }
            removed_sites.push(site.clone());
        }
    }
    let removed_site_ids = removed_sites
        .iter()
        .map(|site| site.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut removed_edge_ids = BTreeSet::new();
    for edge in &delta.edges {
        if let Some(existing) = base_edges.get(edge.id.as_str()) {
            if *existing != edge {
                bail!(
                    "build edge {} conflicts with an existing evidence layer",
                    edge.id
                );
            }
            removed_edge_ids.insert(edge.id.clone());
        } else if edge
            .site_id
            .as_deref()
            .is_some_and(|site_id| removed_site_ids.contains(site_id))
        {
            bail!(
                "build site {} is already complete but edge {} is missing from its evidence layer",
                edge.site_id.as_deref().unwrap_or_default(),
                edge.id
            );
        }
    }
    if removed_sites.is_empty() && removed_edge_ids.is_empty() {
        return Ok(());
    }
    delta
        .sites
        .retain(|site| !removed_site_ids.contains(site.id.as_str()));
    delta
        .edges
        .retain(|edge| !removed_edge_ids.contains(&edge.id));
    delta.evidence.retain(|evidence| {
        !((evidence.owner_type == "site" && removed_site_ids.contains(evidence.owner_id.as_str()))
            || (evidence.owner_type == "edge"
                && removed_edge_ids.contains(evidence.owner_id.as_str())))
    });
    subtract_site_coverage(&mut delta.coverage, &removed_sites);
    for profile in &mut delta.profiles {
        if let Some(coverage) = &mut profile.coverage {
            let removed = removed_sites
                .iter()
                .filter(|site| site.profile_id == profile.id)
                .cloned()
                .collect::<Vec<_>>();
            subtract_site_coverage(coverage, &removed);
        }
    }
    Ok(())
}

fn subtract_site_coverage(coverage: &mut CoverageRecord, sites: &[SiteRecord]) {
    coverage.dependency_sites = coverage
        .dependency_sites
        .saturating_sub(sites.len().try_into().unwrap_or(u64::MAX));
    for site in sites {
        let counter = match site.resolution_status.as_str() {
            "resolved" => &mut coverage.resolved,
            "candidates" => &mut coverage.candidates,
            "external" => &mut coverage.external,
            "unresolved" => &mut coverage.unresolved,
            _ => continue,
        };
        *counter = counter.saturating_sub(1);
    }
    if coverage.dependency_sites == 0 {
        coverage.unsupported_syntax = 0;
        coverage.reasons.clear();
    }
}

fn canonical_profile_language(language: &str) -> &str {
    match language {
        "typescript" | "javascript" | "web" => "web",
        other => other,
    }
}

fn merge_build_delta(
    snapshot: &mut GraphSnapshot,
    delta: BuildGraphDelta,
    _attempt_id: &str,
) -> Result<()> {
    for profile in delta.profiles {
        if let Some(existing) = snapshot
            .profiles
            .iter_mut()
            .find(|item| item.id == profile.id)
        {
            if let Some(build_coverage) = profile.coverage {
                let coverage = existing
                    .coverage
                    .get_or_insert_with(CoverageRecord::default);
                union_coverage(coverage, &build_coverage);
            }
        } else {
            snapshot.profiles.push(profile);
        }
    }
    for node in delta.nodes {
        if !snapshot.nodes.iter().any(|item| item.id == node.id) {
            snapshot.nodes.push(node);
        }
    }
    snapshot.sites.extend(delta.sites.iter().cloned());
    snapshot.edges.extend(delta.edges);
    snapshot.evidence.extend(delta.evidence);
    snapshot.diagnostics.extend(delta.diagnostics);
    union_coverage(&mut snapshot.coverage, &delta.coverage);
    snapshot.coverage.profiles = snapshot.profiles.len() as u64;
    snapshot.scan.project_code_executed = true;
    snapshot
        .profiles
        .sort_by(|left, right| left.id.cmp(&right.id));
    snapshot.nodes.sort_by(|left, right| left.id.cmp(&right.id));
    snapshot.sites.sort_by(|left, right| left.id.cmp(&right.id));
    snapshot.edges.sort_by(|left, right| left.id.cmp(&right.id));
    refresh_profile_matrix(snapshot, true);
    Ok(())
}

fn union_coverage(target: &mut CoverageRecord, delta: &CoverageRecord) {
    target.dependency_sites = target
        .dependency_sites
        .saturating_add(delta.dependency_sites);
    target.resolved = target.resolved.saturating_add(delta.resolved);
    target.candidates = target.candidates.saturating_add(delta.candidates);
    target.external = target.external.saturating_add(delta.external);
    target.unresolved = target.unresolved.saturating_add(delta.unresolved);
    target.unsupported_syntax = target
        .unsupported_syntax
        .saturating_add(delta.unsupported_syntax);
    target.project_code_executed |= delta.project_code_executed;
    target
        .completeness
        .extend(delta.completeness.iter().cloned());
    target.completeness.sort();
    target.completeness.dedup();
    target.reasons.extend(delta.reasons.iter().cloned());
    target.reasons.sort();
    target.reasons.dedup();
}

fn ensure_build_staging(tx: &Transaction<'_>, attempt_id: &str) -> Result<()> {
    let status = tx
        .query_row(
            "SELECT status FROM build_attempts WHERE id=?1",
            [attempt_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .with_context(|| format!("build attempt {attempt_id} was not found"))?;
    if status != "staging" {
        bail!("build attempt {attempt_id} is immutable after reaching status {status}");
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_snapshot_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("snapshot name must not be empty");
    }
    if name.len() > 64 {
        bail!("snapshot name must be at most 64 ASCII characters");
    }
    if !name.is_ascii() {
        bail!("snapshot name must contain only ASCII characters");
    }
    if name.eq_ignore_ascii_case("current") || name.eq_ignore_ascii_case("latest") {
        bail!("snapshot name {name:?} is reserved");
    }
    if name
        .get(.."snapshot:".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("snapshot:"))
    {
        bail!("snapshot name must not use the stable ID prefix \"snapshot:\"");
    }
    let mut bytes = name.bytes();
    let first = bytes.next().expect("empty snapshot names were rejected");
    if !first.is_ascii_alphanumeric()
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!(
            "snapshot name must start with an ASCII letter or digit and contain only letters, digits, '.', '_', or '-'"
        );
    }
    Ok(())
}

fn ingest_event_in_transaction(
    tx: &Transaction<'_>,
    event: &Value,
    replace_existing_evidence: bool,
    evidence_owners: &mut HashSet<(String, String)>,
) -> Result<()> {
    let scan_id = required_str(event, "scan_id")?;
    let event_type = required_str(event, "event")?;
    let adapter = event
        .get("adapter")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    match event_type {
        "scan_started" => {
            if let Some(executed) = event.get("project_code_executed").and_then(Value::as_bool) {
                tx.execute(
                    "UPDATE scans SET project_code_executed = project_code_executed OR ?2 WHERE id = ?1",
                    params![scan_id, executed],
                )?;
            }
        }
        "profile_declared" => insert_profile(tx, scan_id, required_object(event, "profile")?)?,
        "node_upsert" => insert_node(tx, scan_id, required_object(event, "node")?)?,
        "dependency_site" => insert_site(
            tx,
            scan_id,
            required_object(event, "site")?,
            replace_existing_evidence,
            evidence_owners,
        )?,
        "edge_upsert" => insert_edge(
            tx,
            scan_id,
            required_object(event, "edge")?,
            replace_existing_evidence,
            evidence_owners,
        )?,
        "diagnostic" => insert_diagnostic(
            tx,
            scan_id,
            adapter,
            required_object(event, "diagnostic")?,
            replace_existing_evidence,
            evidence_owners,
        )?,
        "file_completed" => insert_file_coverage(tx, scan_id, adapter, event)?,
        "profile_completed" => insert_profile_coverage(tx, scan_id, event)?,
        "scan_completed" => {
            let coverage = required_object(event, "coverage")?.clone();
            let existing = tx
                .query_row(
                    "SELECT json FROM coverage WHERE scan_id = ?1",
                    [scan_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|raw| serde_json::from_str::<Value>(&raw))
                .transpose()?;
            let coverage = existing
                .map(|current| merge_coverage(current, coverage.clone()))
                .unwrap_or(coverage);
            tx.execute(
                "INSERT INTO coverage(scan_id, json) VALUES (?1, ?2)
                 ON CONFLICT(scan_id) DO UPDATE SET json = excluded.json",
                params![scan_id, serde_json::to_string(&coverage)?],
            )?;
            if coverage
                .get("project_code_executed")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                tx.execute(
                    "UPDATE scans SET project_code_executed = 1 WHERE id = ?1",
                    [scan_id],
                )?;
            }
        }
        other => bail!("unknown protocol event {other}"),
    }
    Ok(())
}

fn ensure_scan_staging(tx: &Transaction<'_>, scan_id: &str) -> Result<()> {
    let status = tx
        .query_row("SELECT status FROM scans WHERE id=?1", [scan_id], |row| {
            row.get::<_, String>(0)
        })
        .optional()?
        .with_context(|| format!("scan {scan_id} was not started"))?;
    if status != "staging" {
        bail!("scan {scan_id} is immutable after reaching status {status}");
    }
    Ok(())
}

fn replace_abandoned_scan_attempt(
    tx: &Transaction<'_>,
    root: &Path,
    strict: bool,
    identity: &ScanOperationStagingIdentity<'_>,
) -> Result<()> {
    let existing = tx
        .query_row(
            "SELECT owner.scan_id, owner.repository_binding_digest,
                    owner.configuration_digest, owner.strict, owner.cache_enabled,
                    owner.base_snapshot_id, scan.root, scan.status, scan.strict,
                    scan.parent_snapshot_id
               FROM scan_operation_staging AS owner
               JOIN scans AS scan ON scan.id=owner.scan_id
              WHERE owner.operation_id=?1",
            [identity.operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, bool>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, bool>(8)?,
                    row.get::<_, Option<String>>(9)?,
                ))
            },
        )
        .optional()?;
    let Some((
        scan_id,
        repository_binding_digest,
        configuration_digest,
        owner_strict,
        cache_enabled,
        base_snapshot_id,
        stored_root,
        status,
        scan_strict,
        parent_snapshot_id,
    )) = existing
    else {
        return Ok(());
    };
    if !scan_attempt_is_bound_to_operation(&scan_id, identity.operation_id, true)
        || repository_binding_digest.as_slice() != identity.repository_binding_digest.as_slice()
        || configuration_digest.as_slice() != identity.configuration_digest.as_slice()
        || owner_strict != strict
        || scan_strict != strict
        || cache_enabled != identity.cache_enabled
        || stored_root != root.to_string_lossy()
        || base_snapshot_id != parent_snapshot_id
    {
        bail!("abandoned scan attempt does not match its durable operation owner");
    }
    let completed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    match status.as_str() {
        "staging" => {
            tx.execute(
                "UPDATE incremental_deltas
                    SET status='cancelled', completed_at=?2,
                        error='operation reclaimed abandoned scan attempt'
                  WHERE scan_id=?1 AND status='staging'",
                params![scan_id, completed_at],
            )?;
            let updated = tx.execute(
                "UPDATE scans
                    SET status='cancelled', completed_at=?2,
                        error='operation reclaimed abandoned scan attempt'
                  WHERE id=?1 AND status='staging'",
                params![scan_id, completed_at],
            )?;
            if updated != 1 {
                bail!("abandoned scan attempt changed before replacement");
            }
        }
        "cancelled" => {}
        _ => bail!("operation-owned scan attempt is not replaceable"),
    }
    let deleted = tx.execute(
        "DELETE FROM scan_operation_staging
          WHERE operation_id=?1 AND scan_id=?2",
        params![identity.operation_id, scan_id],
    )?;
    if deleted != 1 {
        bail!("abandoned scan attempt ownership changed before replacement");
    }
    Ok(())
}

fn scan_attempt_is_bound_to_operation(
    scan_id: &str,
    operation_id: &str,
    allow_legacy_identity: bool,
) -> bool {
    if allow_legacy_identity && scan_id == operation_id {
        return true;
    }
    let owner_digest = Sha256::digest(operation_id.as_bytes());
    let prefix = format!("scan-attempt:{owner_digest:x}:");
    scan_id.strip_prefix(&prefix).is_some_and(|nonce| {
        nonce.len() == 32
            && nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn validate_internal_scan_operation_binding(binding: &ScanOperationRecoveryBinding) -> Result<()> {
    let unsealed_native_identity = binding.decision_authorization_digest.is_none()
        && scan_attempt_is_bound_to_operation(&binding.scan_id, &binding.operation_id, true);
    let authorized_decision = binding
        .decision_authorization_digest
        .as_deref()
        .filter(|digest| *digest != [0_u8; 32])
        .and_then(|digest| {
            Some((
                digest,
                binding.validated_mutation_count?,
                binding.prospective_snapshot_id.as_deref()?,
                binding.result_digest.as_deref()?,
            ))
        })
        .is_some_and(
            |(digest, mutation_count, prospective_snapshot_id, result_digest)| {
                digest
                    == scan_decision_authorization_digest_from_parts(
                        &binding.operation_id,
                        &binding.scan_id,
                        &binding.root,
                        &binding.repository_binding_digest,
                        &binding.configuration_digest,
                        binding.strict,
                        binding.cache_enabled,
                        binding.base_snapshot_id.as_deref(),
                        mutation_count,
                        prospective_snapshot_id,
                        result_digest,
                    )
                    .as_slice()
            },
        );
    if (!unsealed_native_identity && !authorized_decision)
        || binding
            .operation_id
            .starts_with(LEGACY_SCAN_OPERATION_CANDIDATE_PREFIX)
        || binding.repository_binding_digest.len() != 32
        || binding.configuration_digest.len() != 32
        || binding.strict != binding.scan_strict
        || binding.base_snapshot_id != binding.parent_snapshot_id
    {
        bail!("scan staging operation ownership is inconsistent");
    }
    Ok(())
}

fn validate_legacy_scan_operation_candidate(binding: &ScanOperationRecoveryBinding) -> Result<()> {
    let zero_digest = [0_u8; 32];
    let exact_identity =
        binding.operation_id == legacy_scan_operation_candidate_id(&binding.scan_id);
    let exact_authority = binding.repository_binding_digest.as_slice() == zero_digest
        && binding.configuration_digest.as_slice() == zero_digest
        && binding.decision_authorization_digest.as_deref() == Some(zero_digest.as_slice())
        && !binding.cache_enabled;
    let exact_scan = binding.strict == binding.scan_strict
        && binding.base_snapshot_id == binding.parent_snapshot_id;
    let exact_state = match binding.status.as_str() {
        "staging" => {
            binding.validated_mutation_count.is_none()
                && binding.prospective_snapshot_id.is_none()
                && binding.result_digest.is_none()
        }
        "completed" => {
            binding.validated_mutation_count == Some(binding.mutation_count)
                && binding.prospective_snapshot_id.is_some()
                && binding.result_digest.is_none()
        }
        _ => false,
    };
    if !exact_identity || !exact_authority || !exact_scan || !exact_state {
        bail!("legacy scan operation candidate is inconsistent");
    }
    Ok(())
}

fn validate_scan_operation_recovery_binding(
    binding: &ScanOperationRecoveryBinding,
    identity: &ScanCompletionRecoveryIdentity<'_>,
) -> Result<()> {
    validate_internal_scan_operation_binding(binding)?;
    let repository_root = identity.repository_root.to_string_lossy();
    if binding.operation_id != identity.operation_id
        || binding.scan_id != identity.scan_id
        || binding.repository_binding_digest.as_slice()
            != identity.repository_binding_digest.as_slice()
        || binding
            .decision_authorization_digest
            .as_deref()
            .is_none_or(|digest| digest == [0_u8; 32])
        || binding.strict != identity.strict
        || binding.scan_strict != identity.strict
        || binding.cache_enabled != identity.cache_enabled
        || binding.base_snapshot_id != binding.parent_snapshot_id
        || binding.validated_mutation_count != Some(binding.mutation_count)
        || binding.prospective_snapshot_id.as_deref() != Some(identity.snapshot_id)
        || binding.result_digest.as_deref() != Some(identity.result_digest.as_slice())
        || binding.root != repository_root
    {
        bail!("scan completion recovery does not match durable operation staging");
    }
    Ok(())
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("event is missing string field {field}"))
}

fn is_secret_like_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "API_KEY",
        "PRIVATE_KEY",
        "CREDENTIAL",
        "AUTH",
        "COOKIE",
        "SESSION",
    ]
    .iter()
    .any(|part| upper.contains(part))
}

fn required_object<'a>(value: &'a Value, field: &str) -> Result<&'a Value> {
    let child = value
        .get(field)
        .with_context(|| format!("event is missing object field {field}"))?;
    if !child.is_object() {
        bail!("event field {field} must be an object");
    }
    Ok(child)
}

fn insert_profile(tx: &Transaction<'_>, scan_id: &str, profile: &Value) -> Result<()> {
    tx.execute(
        "INSERT INTO profiles(scan_id, id, json) VALUES (?1, ?2, ?3)
         ON CONFLICT(scan_id, id) DO UPDATE SET json = excluded.json",
        params![
            scan_id,
            required_str(profile, "id")?,
            serde_json::to_string(profile)?
        ],
    )?;
    Ok(())
}

fn insert_profile_coverage(tx: &Transaction<'_>, scan_id: &str, event: &Value) -> Result<()> {
    let profile_id = required_str(event, "profile_id")?;
    let coverage = required_object(event, "coverage")?;
    tx.execute(
        "INSERT INTO profile_coverage(scan_id, profile_id, json) VALUES (?1, ?2, ?3)
         ON CONFLICT(scan_id, profile_id) DO UPDATE SET json=excluded.json",
        params![scan_id, profile_id, serde_json::to_string(coverage)?],
    )?;
    Ok(())
}

fn insert_node(tx: &Transaction<'_>, scan_id: &str, node: &Value) -> Result<()> {
    let display_name = node
        .get("display_name")
        .and_then(Value::as_str)
        .unwrap_or_else(|| required_str(node, "locator").unwrap_or("<unknown>"));
    let properties = node.get("properties").cloned().unwrap_or_else(|| json!({}));
    tx.prepare_cached(
        "INSERT INTO nodes(scan_id, id, kind, locator, display_name, properties_json, raw_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(scan_id, id) DO UPDATE SET
           kind=excluded.kind, locator=excluded.locator, display_name=excluded.display_name,
           properties_json=excluded.properties_json, raw_json=excluded.raw_json",
    )?
    .execute(params![
        scan_id,
        required_str(node, "id")?,
        required_str(node, "kind")?,
        required_str(node, "locator")?,
        display_name,
        serde_json::to_string(&properties)?,
        serde_json::to_string(node)?
    ])?;
    Ok(())
}

fn insert_site(
    tx: &Transaction<'_>,
    scan_id: &str,
    site: &Value,
    replace_existing_evidence: bool,
    evidence_owners: &mut HashSet<(String, String)>,
) -> Result<()> {
    upsert_site_row(tx, scan_id, site)?;
    insert_evidence(
        tx,
        scan_id,
        "site",
        required_str(site, "id")?,
        site,
        replace_existing_evidence,
        evidence_owners,
    )?;
    Ok(())
}

fn upsert_site_row(tx: &Transaction<'_>, scan_id: &str, site: &Value) -> Result<()> {
    let targets = site.get("target_ids").cloned().unwrap_or_else(|| json!([]));
    let condition = site
        .get("condition")
        .cloned()
        .unwrap_or_else(|| json!({"op":"all","conditions":[]}));
    tx.prepare_cached(
        "INSERT INTO sites(scan_id, id, source, kind, specifier, profile_id,
                           resolution_status, precision, condition_json, target_ids_json,
                           reason, raw_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(scan_id, id) DO UPDATE SET
           source=excluded.source, kind=excluded.kind, specifier=excluded.specifier,
           profile_id=excluded.profile_id, resolution_status=excluded.resolution_status,
           precision=excluded.precision, condition_json=excluded.condition_json,
           target_ids_json=excluded.target_ids_json, reason=excluded.reason, raw_json=excluded.raw_json",
    )?
    .execute(params![
            scan_id,
            required_str(site, "id")?,
            required_str(site, "source")?,
            required_str(site, "kind")?,
            site.get("specifier").and_then(Value::as_str),
            required_str(site, "profile_id")?,
            required_str(site, "resolution_status")?,
            site.get("precision").and_then(Value::as_str).unwrap_or("heuristic"),
            serde_json::to_string(&condition)?,
            serde_json::to_string(&targets)?,
            site.get("reason").and_then(Value::as_str),
            serialize_graph_object_without_evidence(site)?
        ])?;
    Ok(())
}

fn insert_edge(
    tx: &Transaction<'_>,
    scan_id: &str,
    edge: &Value,
    replace_existing_evidence: bool,
    evidence_owners: &mut HashSet<(String, String)>,
) -> Result<()> {
    upsert_edge_row(tx, scan_id, edge)?;
    insert_evidence(
        tx,
        scan_id,
        "edge",
        required_str(edge, "id")?,
        edge,
        replace_existing_evidence,
        evidence_owners,
    )?;
    Ok(())
}

fn upsert_edge_row(tx: &Transaction<'_>, scan_id: &str, edge: &Value) -> Result<()> {
    let condition = edge
        .get("condition")
        .cloned()
        .unwrap_or_else(|| json!({"op":"all","conditions":[]}));
    tx.prepare_cached(
        "INSERT INTO edges(scan_id, id, site_id, source, target, kind, phase, environment,
                           profile_id, resolution_status, precision, condition_json, generated, raw_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
         ON CONFLICT(scan_id, id) DO UPDATE SET
           site_id=excluded.site_id, source=excluded.source, target=excluded.target,
           kind=excluded.kind, phase=excluded.phase, environment=excluded.environment,
           profile_id=excluded.profile_id, resolution_status=excluded.resolution_status,
           precision=excluded.precision, condition_json=excluded.condition_json,
           generated=excluded.generated, raw_json=excluded.raw_json",
    )?
    .execute(params![
            scan_id,
            required_str(edge, "id")?,
            edge.get("site_id").and_then(Value::as_str),
            required_str(edge, "source")?,
            required_str(edge, "target")?,
            required_str(edge, "kind")?,
            edge.get("phase").and_then(Value::as_str).unwrap_or("source"),
            edge.get("environment").and_then(Value::as_str).unwrap_or("any"),
            required_str(edge, "profile_id")?,
            required_str(edge, "resolution_status")?,
            required_str(edge, "precision")?,
            serde_json::to_string(&condition)?,
            edge.get("generated").and_then(Value::as_bool).unwrap_or(false),
            serialize_graph_object_without_evidence(edge)?
        ])?;
    Ok(())
}

// Evidence is authoritative in the normalized evidence table. Keeping an
// empty wire field preserves typed raw-record decoding without storing every
// multi-kilobyte payload a second time inside sites and edges.
struct GraphObjectWithoutEvidence<'a>(&'a serde_json::Map<String, Value>);

impl Serialize for GraphObjectWithoutEvidence<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let has_evidence = self.0.contains_key("evidence");
        let mut map = serializer.serialize_map(Some(self.0.len() + usize::from(!has_evidence)))?;
        for (key, value) in self.0 {
            if key == "evidence" {
                map.serialize_entry(key, &[] as &[Value])?;
            } else {
                map.serialize_entry(key, value)?;
            }
        }
        if !has_evidence {
            map.serialize_entry("evidence", &[] as &[Value])?;
        }
        map.end()
    }
}

fn serialize_graph_object_without_evidence(object: &Value) -> Result<String> {
    let object = object
        .as_object()
        .context("graph record must be a JSON object")?;
    Ok(serde_json::to_string(&GraphObjectWithoutEvidence(object))?)
}

fn insert_evidence(
    tx: &Transaction<'_>,
    scan_id: &str,
    owner_type: &str,
    owner_id: &str,
    object: &Value,
    replace_existing_evidence: bool,
    evidence_owners: &mut HashSet<(String, String)>,
) -> Result<()> {
    let duplicate_in_batch = !evidence_owners.insert((owner_type.to_owned(), owner_id.to_owned()));
    if replace_existing_evidence || duplicate_in_batch {
        tx.prepare_cached(
            "DELETE FROM evidence WHERE scan_id=?1 AND owner_type=?2 AND owner_id=?3",
        )?
        .execute(params![scan_id, owner_type, owner_id])?;
    }
    let evidence = object
        .get("evidence")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for (ordinal, item) in evidence.iter().enumerate() {
        tx.prepare_cached(
            "INSERT INTO evidence(scan_id, owner_type, owner_id, ordinal, kind, extractor,
                                  extractor_version, path, start_line, start_column,
                                  end_line, end_column, raw_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        )?
        .execute(params![
            scan_id,
            owner_type,
            owner_id,
            ordinal as i64,
            item.get("kind").and_then(Value::as_str).unwrap_or("source"),
            item.get("extractor")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            item.get("extractor_version")
                .and_then(Value::as_str)
                .unwrap_or("0.0.0"),
            item.get("path").and_then(Value::as_str).unwrap_or(""),
            item.get("start_line").and_then(Value::as_u64).unwrap_or(1),
            item.get("start_column")
                .and_then(Value::as_u64)
                .unwrap_or(1),
            item.get("end_line").and_then(Value::as_u64).unwrap_or(1),
            item.get("end_column").and_then(Value::as_u64).unwrap_or(1),
            serde_json::to_string(item)?
        ])?;
    }
    Ok(())
}

fn insert_diagnostic(
    tx: &Transaction<'_>,
    scan_id: &str,
    adapter: &str,
    diagnostic: &Value,
    replace_existing_evidence: bool,
    evidence_owners: &mut HashSet<(String, String)>,
) -> Result<()> {
    let ordinal: i64 = tx.query_row(
        "SELECT COALESCE(MAX(ordinal), -1) + 1 FROM diagnostics WHERE scan_id = ?1",
        [scan_id],
        |row| row.get(0),
    )?;
    let id = diagnostic
        .get("id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("diagnostic:{scan_id}:{ordinal}"));
    tx.execute(
        "INSERT INTO diagnostics(scan_id, ordinal, id, severity, code, message, path, adapter, raw_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(scan_id, id) DO UPDATE SET
           severity=excluded.severity, code=excluded.code, message=excluded.message,
           path=excluded.path, adapter=excluded.adapter, raw_json=excluded.raw_json",
        params![
            scan_id,
            ordinal,
            &id,
            diagnostic.get("severity").and_then(Value::as_str).unwrap_or("warning"),
            diagnostic.get("code").and_then(Value::as_str).unwrap_or("unknown"),
            diagnostic.get("message").and_then(Value::as_str).unwrap_or("unknown diagnostic"),
            diagnostic.get("path").and_then(Value::as_str),
            adapter,
            serde_json::to_string(diagnostic)?
        ],
    )?;
    insert_evidence(
        tx,
        scan_id,
        "diagnostic",
        &id,
        diagnostic,
        replace_existing_evidence,
        evidence_owners,
    )?;
    Ok(())
}

fn insert_file_coverage(
    tx: &Transaction<'_>,
    scan_id: &str,
    adapter: &str,
    event: &Value,
) -> Result<()> {
    tx.execute(
        "INSERT INTO file_coverage(scan_id, path, discovered_sites, emitted_sites, skipped_sites, skipped, reason, adapter)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(scan_id, adapter, path) DO UPDATE SET
           discovered_sites=excluded.discovered_sites, emitted_sites=excluded.emitted_sites,
           skipped_sites=excluded.skipped_sites, skipped=excluded.skipped, reason=excluded.reason",
        params![
            scan_id,
            required_str(event, "path")?,
            event.get("discovered_sites").and_then(Value::as_u64).unwrap_or(0),
            event.get("emitted_sites").and_then(Value::as_u64).unwrap_or(0),
            event.get("skipped_sites").and_then(Value::as_u64).unwrap_or(0),
            event.get("skipped").and_then(Value::as_bool).unwrap_or(false),
            event.get("reason").and_then(Value::as_str),
            adapter
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use depgraph_protocol::{
        DependencySite, GraphEdge, build_edge_stable_id, build_site_stable_id,
        validate_build_ndjson,
    };
    use std::io::Cursor;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    const RUST_SEMANTIC_GOLDEN: &str = include_str!(
        "../../depgraph-protocol/tests/fixtures/protocol-v1.rust-semantic.golden.ndjson"
    );

    #[derive(Debug, Eq, PartialEq)]
    struct StoreSemanticSnapshot {
        version: i64,
        schema: Vec<(String, String, String, Option<String>)>,
        rows: Vec<(String, Vec<Vec<String>>)>,
    }

    fn store_semantic_snapshot(path: &Path) -> Result<StoreSemanticSnapshot> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let version = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let schema = connection
            .prepare(
                "SELECT type, name, tbl_name, sql FROM sqlite_schema
                 ORDER BY type, name, tbl_name",
            )?
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let table_names = connection
            .prepare(
                "SELECT name FROM sqlite_schema
                  WHERE type='table' AND name NOT LIKE 'sqlite_%'
                  ORDER BY name",
            )?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut tables = Vec::with_capacity(table_names.len());
        for table_name in table_names {
            let escaped = table_name.replace('"', "\"\"");
            let mut statement = connection.prepare(&format!("SELECT * FROM \"{escaped}\""))?;
            let column_count = statement.column_count();
            let mut query = statement.query([])?;
            let mut rows = Vec::new();
            while let Some(row) = query.next()? {
                let mut encoded = Vec::with_capacity(column_count);
                for column in 0..column_count {
                    use rusqlite::types::ValueRef;
                    let value = match row.get_ref(column)? {
                        ValueRef::Null => "null".to_owned(),
                        ValueRef::Integer(value) => format!("integer:{value}"),
                        ValueRef::Real(value) => format!("real:{:016x}", value.to_bits()),
                        ValueRef::Text(value) => format!("text:{}", encode_hex(value)),
                        ValueRef::Blob(value) => format!("blob:{}", encode_hex(value)),
                    };
                    encoded.push(value);
                }
                rows.push(encoded);
            }
            rows.sort();
            tables.push((table_name, rows));
        }
        Ok(StoreSemanticSnapshot {
            version,
            schema,
            rows: tables,
        })
    }

    fn encode_hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
        }
        encoded
    }

    fn common(event: &str, seq: u64) -> Value {
        json!({
            "event": event,
            "protocol_version": "1.0",
            "scan_id": "scan-1",
            "adapter": "fixture",
            "adapter_version": "0.1.0",
            "seq": seq
        })
    }

    fn empty_scan_events(scan_id: &str) -> [Value; 2] {
        [
            json!({
                "event": "scan_started",
                "protocol_version": "1.0",
                "scan_id": scan_id,
                "adapter": "fixture",
                "adapter_version": "0.1.0",
                "seq": 1,
                "root": "/fixture",
                "project_code_executed": false,
                "safe_mode": true
            }),
            json!({
                "event": "scan_completed",
                "protocol_version": "1.0",
                "scan_id": scan_id,
                "adapter": "fixture",
                "adapter_version": "0.1.0",
                "seq": 2,
                "coverage": {
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
                }
            }),
        ]
    }

    fn assert_node_page_matches_snapshot(
        store: &mut Store,
        snapshot_id: &str,
        snapshot: &GraphSnapshot,
    ) -> Result<()> {
        let expected = snapshot
            .nodes
            .iter()
            .map(|node| NodeSummaryRecord {
                id: node.id.clone(),
                kind: node.kind.clone(),
                locator: node.locator.clone(),
                display_name: node.display_name.clone(),
            })
            .collect::<Vec<_>>();
        let page = store.find_completed_snapshot_nodes_page(
            snapshot_id,
            "",
            NodeTextMatch::Contains,
            &[],
            0,
            expected.len().max(1),
            || false,
        )?;
        assert_eq!(page.total_items, expected.len() as u64);
        assert_eq!(page.items, expected);
        Ok(())
    }

    #[test]
    fn read_only_open_never_creates_a_missing_store() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("missing.db");
        let error = Store::open_read_only(&path).err().expect("missing store");
        assert!(error.to_string().contains("read-only"));
        assert!(!path.exists());
    }

    fn operation_scan_attempt_id(operation_id: &str, nonce: char) -> String {
        let owner_digest = Sha256::digest(operation_id.as_bytes());
        format!(
            "scan-attempt:{owner_digest:x}:{}",
            nonce.to_string().repeat(32)
        )
    }

    #[test]
    fn operation_scan_cancellation_retains_idempotent_proof_until_acknowledged() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        let operation_id = "op_00000000000000000000000000000001";
        let scan_id = operation_scan_attempt_id(operation_id, '1');
        let identity = ScanOperationStagingIdentity {
            operation_id,
            repository_binding_digest: &[2; 32],
            configuration_digest: &[3; 32],
            cache_enabled: false,
        };
        store.start_scan_for_operation(
            &scan_id,
            Path::new("/fixture"),
            false,
            Some("revision"),
            &identity,
        )?;

        store.cancel_scan_for_operation(operation_id)?;
        store.cancel_scan_for_operation(operation_id)?;
        assert_eq!(store.scan(&scan_id)?.unwrap().status, "cancelled");
        let pending = store.pending_cancelled_scan_operations()?;
        assert_eq!(pending.operation_ids(), [operation_id]);
        assert!(!pending.more_work());
        assert_eq!(
            store.connection.query_row(
                "SELECT scan_id FROM scan_operation_staging WHERE operation_id=?1",
                [operation_id],
                |row| row.get::<_, String>(0),
            )?,
            scan_id
        );

        assert!(store.finalize_cancelled_scan_for_operation(operation_id)?);
        assert!(!store.finalize_cancelled_scan_for_operation(operation_id)?);
        assert!(
            store
                .pending_cancelled_scan_operations()?
                .operation_ids()
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn cancelled_scan_reconciliation_is_stably_bounded_across_multiple_pages() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        let query_plan = store
            .connection
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT substr(CAST(owner.operation_id AS BLOB), 1, 513)
                   FROM scan_operation_staging AS owner
                        INDEXED BY scan_operation_staging_pending_cancelled
                   JOIN scans AS scan ON scan.id=owner.scan_id
                  WHERE scan.status='cancelled'
                    AND (?1 IS NULL OR owner.operation_id COLLATE BINARY > ?1)
                  ORDER BY owner.operation_id COLLATE BINARY
                  LIMIT ?2",
            )?
            .query_map(params![Option::<String>::None, 65_i64], |row| {
                row.get::<_, String>(3)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert!(
            query_plan
                .iter()
                .any(|detail| { detail.contains("scan_operation_staging_pending_cancelled") }),
            "unexpected cancellation query plan: {query_plan:?}"
        );
        assert!(
            !query_plan
                .iter()
                .any(|detail| detail.contains("TEMP B-TREE"))
        );
        let total = MAX_PENDING_CANCELLED_SCAN_OPERATIONS + 5;
        for index in 0..total {
            let operation_id = format!("op_{index:032x}");
            let owner_digest = Sha256::digest(operation_id.as_bytes());
            let scan_id = format!("scan-attempt:{owner_digest:x}:{index:032x}");
            store.start_scan_for_operation(
                &scan_id,
                Path::new("/fixture"),
                false,
                None,
                &ScanOperationStagingIdentity {
                    operation_id: &operation_id,
                    repository_binding_digest: &[9; 32],
                    configuration_digest: &[10; 32],
                    cache_enabled: false,
                },
            )?;
            store.cancel_scan_for_operation(&operation_id)?;
        }

        let first = store.pending_cancelled_scan_operations()?;
        assert_eq!(
            first.operation_ids().len(),
            MAX_PENDING_CANCELLED_SCAN_OPERATIONS
        );
        assert!(first.more_work());
        let next_after = first
            .next_after_operation_id()
            .context("full reconciliation page cursor")?
            .to_owned();
        let second = store.pending_cancelled_scan_operations_after(Some(&next_after))?;
        assert_eq!(second.operation_ids().len(), 5);
        assert!(!second.more_work());
        for operation_id in first.into_operation_ids() {
            assert!(store.finalize_cancelled_scan_for_operation(&operation_id)?);
        }
        for operation_id in second.into_operation_ids() {
            assert!(store.finalize_cancelled_scan_for_operation(&operation_id)?);
        }
        assert!(
            store
                .pending_cancelled_scan_operations()?
                .operation_ids()
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn cancelled_scan_reconciliation_rejects_oversized_corrupt_ids_at_a_fixed_bound() -> Result<()>
    {
        let mut store = Store::open_in_memory()?;
        let operation_id = "op_00000000000000000000000000000004";
        let scan_id = operation_scan_attempt_id(operation_id, '5');
        store.start_scan_for_operation(
            &scan_id,
            Path::new("/fixture"),
            false,
            None,
            &ScanOperationStagingIdentity {
                operation_id,
                repository_binding_digest: &[11; 32],
                configuration_digest: &[12; 32],
                cache_enabled: false,
            },
        )?;
        store.cancel_scan_for_operation(operation_id)?;
        store
            .connection
            .execute_batch("PRAGMA ignore_check_constraints=ON")?;
        store.connection.execute(
            "UPDATE scan_operation_staging SET operation_id=?1 WHERE operation_id=?2",
            params!["x".repeat(4096), operation_id],
        )?;

        let error = store
            .pending_cancelled_scan_operations()
            .expect_err("oversized cancellation proof must fail closed");
        assert!(error.to_string().contains("exceeds its storage bound"));
        Ok(())
    }

    #[test]
    fn p1a_reserved_legacy_scan_sentinel_cannot_be_attached_as_operation_owner() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        let operation_id = format!("{LEGACY_SCAN_OPERATION_CANDIDATE_PREFIX}forged-owner");
        let scan_id = operation_scan_attempt_id(&operation_id, 'a');
        let identity = ScanOperationStagingIdentity {
            operation_id: &operation_id,
            repository_binding_digest: &[6; 32],
            configuration_digest: &[7; 32],
            cache_enabled: false,
        };

        let error = store
            .start_scan_for_operation(&scan_id, Path::new("/fixture"), false, None, &identity)
            .expect_err("reserved migration sentinel must not become an operation owner");
        assert!(error.to_string().contains("identity is invalid"));
        assert!(store.scan(&scan_id)?.is_none());
        assert_eq!(
            store.connection.query_row(
                "SELECT COUNT(*) FROM scan_operation_staging WHERE operation_id=?1",
                [&operation_id],
                |row| row.get::<_, u64>(0),
            )?,
            0
        );
        Ok(())
    }

    #[test]
    fn reclaimed_operation_replaces_only_its_canonically_bound_scan_attempt() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        let operation_id = "op_00000000000000000000000000000002";
        let first_scan_id = operation_scan_attempt_id(operation_id, '2');
        let second_scan_id = operation_scan_attempt_id(operation_id, '3');
        let identity = ScanOperationStagingIdentity {
            operation_id,
            repository_binding_digest: &[4; 32],
            configuration_digest: &[5; 32],
            cache_enabled: true,
        };
        store.start_scan_for_operation(
            &first_scan_id,
            Path::new("/fixture"),
            true,
            Some("revision"),
            &identity,
        )?;
        store.start_scan_for_operation(
            &second_scan_id,
            Path::new("/fixture"),
            true,
            Some("revision"),
            &identity,
        )?;
        assert_eq!(store.scan(&first_scan_id)?.unwrap().status, "cancelled");
        assert_eq!(store.scan(&second_scan_id)?.unwrap().status, "staging");
        assert_eq!(
            store.connection.query_row(
                "SELECT scan_id FROM scan_operation_staging WHERE operation_id=?1",
                [operation_id],
                |row| row.get::<_, String>(0),
            )?,
            second_scan_id
        );

        store.start_scan("foreign-scan", Path::new("/fixture"), true)?;
        store.connection.execute(
            "UPDATE scan_operation_staging SET scan_id='foreign-scan'
              WHERE operation_id=?1",
            [operation_id],
        )?;
        let error = store
            .cancel_scan_for_operation(operation_id)
            .unwrap_err()
            .to_string();
        assert!(error.contains("ownership is inconsistent"));
        assert_eq!(store.scan("foreign-scan")?.unwrap().status, "staging");
        assert_eq!(store.scan(&second_scan_id)?.unwrap().status, "staging");
        Ok(())
    }

    #[test]
    fn scan_completion_recovery_finishes_without_replacing_a_later_current_snapshot() -> Result<()>
    {
        let mut store = Store::open_in_memory()?;
        ingest_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
        )?;
        let base_snapshot_id = store.current_snapshot_id()?.context("base snapshot")?;

        let operation_id = "op_00000000000000000000000000000003";
        let scan_id = operation_scan_attempt_id(operation_id, '4');
        let repository_binding_digest = [6; 32];
        let configuration_digest = [7; 32];
        let result_digest = [8; 32];
        let identity = ScanOperationStagingIdentity {
            operation_id,
            repository_binding_digest: &repository_binding_digest,
            configuration_digest: &configuration_digest,
            cache_enabled: false,
        };
        store.start_scan_for_operation(
            &scan_id,
            Path::new("/fixture"),
            false,
            Some("older-revision"),
            &identity,
        )?;
        for event in empty_scan_events(&scan_id) {
            store.ingest_event(&event)?;
        }
        let validation = store.validate_scan_for_completion(&scan_id)?;
        let older_snapshot_id = store.prospective_scan_snapshot_id(&scan_id)?;
        store.seal_scan_operation_staging(operation_id, &validation, &older_snapshot_id)?;
        store.bind_scan_operation_result(operation_id, &result_digest)?;

        let later_scan_id = "later-current-scan";
        store.start_scan_with_revision(
            later_scan_id,
            Path::new("/fixture"),
            false,
            Some("later-revision"),
        )?;
        for event in empty_scan_events(later_scan_id) {
            store.ingest_event(&event)?;
        }
        store.finish_scan(later_scan_id, "completed", None, true)?;
        let later_snapshot_id = store.current_snapshot_id()?.context("later snapshot")?;
        assert_ne!(later_snapshot_id, base_snapshot_id);
        assert_ne!(later_snapshot_id, older_snapshot_id);

        store.recover_scan_completion_for_operation(&ScanCompletionRecoveryIdentity {
            operation_id,
            scan_id: &scan_id,
            repository_root: Path::new("/fixture"),
            repository_binding_digest: &repository_binding_digest,
            strict: false,
            cache_enabled: false,
            snapshot_id: &older_snapshot_id,
            result_digest: &result_digest,
        })?;

        assert_eq!(store.scan(&scan_id)?.unwrap().status, "completed");
        assert_eq!(
            store.snapshot_id_for_source("scan", &scan_id)?.as_deref(),
            Some(older_snapshot_id.as_str())
        );
        assert_eq!(
            store.current_snapshot_id()?.as_deref(),
            Some(later_snapshot_id.as_str())
        );
        Ok(())
    }

    #[test]
    fn bounded_node_page_can_be_cancelled_during_sql_traversal() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        store.start_scan("cancelled-read", Path::new("/tmp/project"), false)?;
        for event in [
            json!({
                "event": "scan_started",
                "protocol_version": "1.0",
                "scan_id": "cancelled-read",
                "adapter": "fixture",
                "adapter_version": "0.1.0",
                "seq": 1,
                "root": "/tmp/project",
                "project_code_executed": false,
                "safe_mode": true
            }),
            json!({
                "event": "scan_completed",
                "protocol_version": "1.0",
                "scan_id": "cancelled-read",
                "adapter": "fixture",
                "adapter_version": "0.1.0",
                "seq": 2,
                "coverage": {
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
                }
            }),
        ] {
            store.ingest_event(&event)?;
        }
        let tx = store.connection.transaction()?;
        for index in 0..10_000 {
            let id = format!("node:cancel:{index:05}");
            let locator = format!("repo://src/{index:05}.rs");
            let display_name = format!("cancel::{index:05}");
            let raw = json!({
                "id": id,
                "kind": "module",
                "locator": locator,
                "display_name": display_name,
                "properties": {}
            });
            tx.execute(
                "INSERT INTO nodes(scan_id, id, kind, locator, display_name, properties_json, raw_json)
                 VALUES ('cancelled-read', ?1, 'module', ?2, ?3, '{}', ?4)",
                params![id, locator, display_name, raw.to_string()],
            )?;
        }
        tx.commit()?;
        store.finish_scan("cancelled-read", "completed", None, true)?;
        let snapshot_id = store.current_snapshot_id()?.unwrap();
        let checks = Arc::new(AtomicUsize::new(0));

        let error = store
            .find_completed_snapshot_nodes_page(
                &snapshot_id,
                "cancel",
                NodeTextMatch::Contains,
                &[],
                0,
                10,
                {
                    let checks = Arc::clone(&checks);
                    move || checks.fetch_add(1, Ordering::AcqRel) >= 1
                },
            )
            .expect_err("the in-progress traversal must be interrupted");

        assert!(checks.load(Ordering::Acquire) >= 2);
        assert!(error.to_string().contains("cancel"));
        Ok(())
    }

    #[test]
    fn incomplete_scan_is_not_promoted() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        store.start_scan("scan-1", Path::new("/tmp/project"), false)?;
        store.finish_scan("scan-1", "failed", Some("worker crashed"), false)?;
        assert_eq!(store.latest_attempt_id()?.as_deref(), Some("scan-1"));
        assert_eq!(store.latest_successful_id()?, None);
        assert_eq!(store.current_snapshot_id()?, None);
        assert_eq!(store.snapshot_id_for_source("scan", "scan-1")?, None);
        Ok(())
    }

    #[test]
    fn validated_completion_rejects_an_intervening_scan_mutation() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        let scan_id = stage_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
            Some("fixture-revision"),
        )?;
        let validation = store.validate_scan_for_completion(&scan_id)?;
        let summary = store.load_validated_scan_summary(&validation)?;
        let snapshot = store.load_snapshot(&scan_id)?;
        assert_eq!(summary.coverage, snapshot.coverage);
        assert_eq!(summary.diagnostics, snapshot.diagnostics);
        store.save_adapter_log(&scan_id, "late-adapter", "late mutation", false)?;

        let error = store
            .load_validated_scan_summary(&validation)
            .expect_err("mutation after validation must invalidate the summary token");
        assert!(
            error
                .to_string()
                .contains("changed after completion validation")
        );
        let error = store
            .finish_validated_scan(validation, true)
            .expect_err("mutation after validation must prevent promotion");
        assert!(error.to_string().contains("changed concurrently"));
        assert_eq!(
            store.scan(&scan_id)?.map(|scan| scan.status),
            Some("staging".into())
        );
        assert_eq!(store.current_snapshot_id()?, None);
        Ok(())
    }

    #[test]
    fn validated_completion_token_populates_both_scan_cache_layers() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        let scan_id = stage_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
            Some("fixture-revision"),
        )?;
        let validation = store.validate_scan_for_completion(&scan_id)?;
        let completed = store.finish_validated_scan(validation, true)?;
        let syntax = CacheKey::new(
            CacheLayer::Syntax,
            BTreeMap::from([("input".into(), "syntax".into())]),
        );
        let semantic = CacheKey::new(
            CacheLayer::Semantic,
            BTreeMap::from([
                ("input".into(), "semantic".into()),
                ("syntax_key".into(), syntax.key.clone()),
            ]),
        );

        let results =
            store.store_completed_scan_snapshot_caches(&syntax, Some(&semantic), &completed)?;
        assert!(results.iter().all(|result| result.outcome == "stored"));
        assert_eq!(
            store.cache_entry_counts()?,
            CacheEntryCounts {
                syntax: 1,
                semantic: 1,
                build: 0,
                compiler_precise: 0,
            }
        );
        Ok(())
    }

    #[test]
    fn doctor_summary_is_bounded_and_never_reads_diagnostic_payloads() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        store.start_scan("scan-1", Path::new("/tmp/project"), false)?;
        for ordinal in 0..70_i64 {
            store.connection.execute(
                "INSERT INTO diagnostics(
                     scan_id, ordinal, id, severity, code, message, path, adapter, raw_json
                 ) VALUES (?1, ?2, ?3, 'warning', ?4, ?5, ?6, 'fixture', ?7)",
                params![
                    "scan-1",
                    ordinal,
                    format!("diagnostic:{ordinal}"),
                    format!("CODE_{ordinal:02}"),
                    format!("representative {ordinal}"),
                    format!("src/{ordinal}.rs"),
                    "not-json-and-must-never-be-read secret-value"
                ],
            )?;
        }

        let summary = store.scan_attempt_summary("scan-1")?;
        assert_eq!(summary.diagnostics.total, 70);
        assert_eq!(summary.diagnostics.groups.len(), 64);
        assert_eq!(summary.diagnostics.omitted_groups, 6);
        assert_eq!(summary.diagnostics.omitted_diagnostics, 6);
        assert_eq!(summary.diagnostics.samples.len(), 5);
        assert!(!serde_json::to_string(&summary)?.contains("not-json-and-must-never-be-read"));
        assert!(store.load_snapshot("scan-1").is_err());
        Ok(())
    }

    #[test]
    fn failed_scan_retains_the_previous_completed_snapshot() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        ingest_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
        )?;
        let completed_id = store.current_snapshot_id()?.context("current snapshot")?;
        let completed = store.load_completed_snapshot(&completed_id)?;

        store.start_scan("failed-scan", Path::new("/fixture"), false)?;
        let mut diagnostic = common("diagnostic", 1);
        diagnostic["scan_id"] = json!("failed-scan");
        diagnostic["diagnostic"] = json!({
            "id":"diagnostic:failed-scan","severity":"error",
            "code":"fixture-failure","message":"worker crashed"
        });
        store.ingest_event(&diagnostic)?;
        store.finish_scan("failed-scan", "failed", Some("worker crashed"), false)?;

        assert_eq!(
            store.current_snapshot_id()?.as_deref(),
            Some(completed_id.as_str())
        );
        assert_eq!(store.load_completed_snapshot(&completed_id)?, completed);
        assert_eq!(store.snapshot_id_for_source("scan", "failed-scan")?, None);
        assert_eq!(store.latest_attempt_id()?.as_deref(), Some("failed-scan"));
        assert_eq!(
            store.latest_successful_id()?.as_deref(),
            Some("scan-golden")
        );
        Ok(())
    }

    #[test]
    fn completed_topology_matches_the_full_scan_snapshot() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        ingest_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
        )?;
        let snapshot_id = store.current_snapshot_id()?.context("current snapshot")?;
        let snapshot = store.load_completed_snapshot(&snapshot_id)?;
        let topology = store.load_completed_topology(&snapshot_id)?;

        assert_eq!(
            topology.nodes,
            snapshot
                .nodes
                .into_iter()
                .map(|node| GraphTopologyNode {
                    id: node.id,
                    kind: node.kind,
                })
                .collect::<Vec<_>>()
        );
        assert_eq!(
            topology.edges,
            snapshot
                .edges
                .into_iter()
                .map(|edge| GraphTopologyEdge {
                    source: edge.source,
                    target: edge.target,
                })
                .collect::<Vec<_>>()
        );
        Ok(())
    }

    #[test]
    fn new_stores_use_the_large_graph_page_size() -> Result<()> {
        let store = Store::open_in_memory()?;
        let page_size: i64 = store
            .connection
            .query_row("PRAGMA page_size", [], |row| row.get(0))?;
        assert_eq!(page_size, STORE_PAGE_SIZE_BYTES);
        let cache_size: i64 = store
            .connection
            .query_row("PRAGMA cache_size", [], |row| row.get(0))?;
        assert_eq!(cache_size, -STORE_CACHE_SIZE_KIB);
        let temp_store: i64 = store
            .connection
            .query_row("PRAGMA temp_store", [], |row| row.get(0))?;
        assert_eq!(temp_store, 2);
        Ok(())
    }

    #[test]
    fn daemon_recovery_cancels_staging_attempts_without_replacing_current_snapshot() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        ingest_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
        )?;
        let current = store.current_snapshot_id()?.context("current snapshot")?;
        store.start_scan("interrupted-scan", Path::new("/fixture"), false)?;
        let audit = build_attempt_audit("interrupted-build");
        store.save_build_audit(&audit)?;
        store.start_build_attempt("scan-golden", &audit)?;

        let recovered = store.recover_interrupted_attempts(Path::new("/fixture"))?;

        assert_eq!(recovered.scan_attempt_ids, ["interrupted-scan"]);
        assert_eq!(recovered.build_attempt_ids, ["interrupted-build"]);
        assert_eq!(store.scan("interrupted-scan")?.unwrap().status, "cancelled");
        assert_eq!(
            store.build_attempt("interrupted-build")?.unwrap().status,
            "cancelled"
        );
        assert_eq!(
            store.current_snapshot_id()?.as_deref(),
            Some(current.as_str())
        );
        Ok(())
    }

    #[test]
    fn interrupted_promotion_rolls_back_attempt_and_snapshot_publication() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        stage_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
            Some("revision-rollback"),
        )?;
        store.connection.execute_batch(
            "CREATE TRIGGER reject_snapshot_source
             BEFORE INSERT ON snapshot_sources
             BEGIN SELECT RAISE(ABORT, 'simulated interruption'); END;",
        )?;

        let error = store
            .finish_scan("scan-golden", "completed", None, true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("simulated interruption"));
        assert_eq!(store.scan("scan-golden")?.unwrap().status, "staging");
        assert_eq!(store.current_snapshot_id()?, None);
        let count: i64 =
            store
                .connection
                .query_row("SELECT COUNT(*) FROM completed_snapshots", [], |row| {
                    row.get(0)
                })?;
        assert_eq!(count, 0);
        Ok(())
    }

    #[test]
    fn snapshot_integrity_detects_persisted_graph_tampering() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        ingest_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
        )?;
        let snapshot_id = store.current_snapshot_id()?.context("current snapshot")?;
        assert!(store.verify_snapshot_integrity(&snapshot_id)?.valid);

        store.connection.execute(
            r#"UPDATE nodes SET properties_json='{"tampered":true}'
              WHERE scan_id='scan-golden' AND id=(
                SELECT id FROM nodes WHERE scan_id='scan-golden' ORDER BY id LIMIT 1
              )"#,
            [],
        )?;
        let integrity = store.verify_snapshot_integrity(&snapshot_id)?;
        assert!(!integrity.valid);
        assert_eq!(integrity.reasons, ["content_digest_mismatch"]);
        assert_ne!(integrity.expected_id, integrity.observed_id);
        Ok(())
    }

    #[test]
    fn paged_node_projection_rejects_serde_invalid_completed_build_delta() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        ingest_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
        )?;
        let base = store.load_snapshot("scan-golden")?;
        let audit = build_attempt_audit("build-invalid-delta");
        store.save_build_audit(&audit)?;
        store.start_build_attempt("scan-golden", &audit)?;
        let protocol = validate_build_ndjson(Cursor::new(build_protocol(
            "build-invalid-delta",
            false,
            "production",
            &canonical_effective_input_id(&base.profiles[0]),
        )))?;
        store.save_build_delta("build-invalid-delta", &protocol)?;
        store.finish_build_attempt("build-invalid-delta", "completed", None, true)?;
        let snapshot_id = store.current_snapshot_id()?.context("build snapshot")?;

        store.connection.execute(
            "UPDATE build_attempts
                SET delta_json=json_set(delta_json, '$.coverage.profiles', 'not-an-integer')
              WHERE id='build-invalid-delta'",
            [],
        )?;

        store
            .load_completed_snapshot(&snapshot_id)
            .expect_err("canonical build delta decoding must reject the corruption");
        store
            .find_completed_snapshot_nodes_page(
                &snapshot_id,
                "",
                NodeTextMatch::Contains,
                &[],
                0,
                10,
                || false,
            )
            .expect_err("paged projection must reject the same build delta corruption");
        Ok(())
    }

    #[test]
    fn paged_node_projection_rejects_tampered_non_node_canonical_row() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        ingest_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
        )?;
        let snapshot_id = store.current_snapshot_id()?.context("scan snapshot")?;
        store.connection.execute(
            "UPDATE evidence
                SET raw_json=json_set(raw_json, '$.properties.sealed_tamper', 1)
              WHERE scan_id='scan-golden'",
            [],
        )?;

        store.load_completed_snapshot(&snapshot_id)?;
        store
            .completed_snapshot_details(&snapshot_id)
            .expect_err("completed snapshot details must reject serde-valid non-node tampering");
        store
            .find_completed_snapshot_nodes_page(
                &snapshot_id,
                "",
                NodeTextMatch::Contains,
                &[],
                0,
                10,
                || false,
            )
            .expect_err("paged projection must reject non-node snapshot tampering");
        Ok(())
    }

    #[test]
    fn snapshot_names_are_immutable_and_resolve_canonical_completed_details() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        ingest_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
        )?;
        let snapshot_id = store.current_snapshot_id()?.context("current snapshot")?;

        store.create_snapshot_name("zeta", &snapshot_id)?;
        store.create_snapshot_name("alpha-1", &snapshot_id)?;
        assert_eq!(
            store
                .snapshot_names()?
                .into_iter()
                .map(|record| record.name)
                .collect::<Vec<_>>(),
            vec!["alpha-1", "zeta"]
        );
        assert_eq!(
            store.resolve_completed_snapshot_selector("ALPHA-1")?,
            snapshot_id
        );
        assert_eq!(
            store.resolve_completed_snapshot_selector(&snapshot_id)?,
            snapshot_id
        );
        assert_eq!(
            store.resolve_completed_snapshot_selector("current")?,
            snapshot_id
        );

        let details = store.completed_snapshot_details(&snapshot_id)?;
        assert_eq!(details.snapshot.status, "completed");
        assert_eq!(
            details.snapshot.source_revision.as_deref(),
            Some("fixture-revision")
        );
        assert_eq!(details.snapshot.profile_ids, vec!["web:production:server"]);
        assert_eq!(details.names, vec!["alpha-1", "zeta"]);
        assert_eq!(details.coverage.profiles, 1);
        assert_eq!(details.coverage.completeness, vec!["syntax-complete"]);

        for invalid in [
            "",
            "current",
            "LATEST",
            "snapshot:short",
            "-leading",
            "contains space",
            "日本語",
        ] {
            let error = store
                .create_snapshot_name(invalid, &snapshot_id)
                .unwrap_err()
                .to_string();
            assert!(error.contains("snapshot name"), "{invalid:?}: {error}");
        }
        let too_long = "a".repeat(65);
        assert!(
            store
                .create_snapshot_name(&too_long, &snapshot_id)
                .unwrap_err()
                .to_string()
                .contains("snapshot name")
        );
        assert!(
            store
                .create_snapshot_name("ALPHA-1", &snapshot_id)
                .unwrap_err()
                .to_string()
                .contains("already exists")
        );
        assert!(
            store
                .resolve_completed_snapshot_selector("latest")
                .unwrap_err()
                .to_string()
                .contains("reserved")
        );
        assert!(
            store
                .resolve_completed_snapshot_selector("missing")
                .unwrap_err()
                .to_string()
                .contains("was not found")
        );

        let update_error = store
            .connection
            .execute(
                "UPDATE snapshot_names SET name='renamed' WHERE name='alpha-1'",
                [],
            )
            .unwrap_err()
            .to_string();
        assert!(update_error.contains("snapshot names are immutable"));
        let delete_error = store
            .connection
            .execute("DELETE FROM snapshot_names WHERE name='alpha-1'", [])
            .unwrap_err()
            .to_string();
        assert!(delete_error.contains("snapshot names are immutable"));

        store.start_scan("failed-scan", Path::new("/tmp/failed"), false)?;
        store.finish_scan("failed-scan", "failed", Some("worker failed"), false)?;
        assert_eq!(store.snapshot_id_for_scan_selection("failed-scan")?, None);
        assert!(
            store
                .create_snapshot_name("failed", "failed-scan")
                .unwrap_err()
                .to_string()
                .contains("completed snapshot")
        );
        Ok(())
    }

    #[test]
    fn completed_snapshot_identity_is_stable_across_attempt_timestamps_and_stores() -> Result<()> {
        let fixture =
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson");
        let mut first = Store::open_in_memory()?;
        ingest_protocol_fixture(&mut first, fixture)?;
        let first_id = first.current_snapshot_id()?.context("first snapshot")?;

        let mut second = Store::open_in_memory()?;
        ingest_protocol_fixture(&mut second, fixture)?;
        second.connection.execute(
            "UPDATE scans SET started_at='2099-01-01T00:00:00.000Z',
                              completed_at='2099-01-01T00:00:01.000Z'
              WHERE id='scan-golden'",
            [],
        )?;
        let second_id = second.current_snapshot_id()?.context("second snapshot")?;

        assert_eq!(first_id, second_id);
        assert!(first_id.starts_with("snapshot:sha256:"));
        assert!(second.verify_snapshot_integrity(&second_id)?.valid);
        Ok(())
    }

    #[test]
    fn prospective_scan_identity_matches_later_promotion() -> Result<()> {
        let fixture =
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson");
        let mut store = Store::open_in_memory()?;
        let scan_id = stage_protocol_fixture(&mut store, fixture, Some("fixture-revision"))?;
        store.validate_scan(&scan_id)?;

        let prospective = store.prospective_scan_snapshot_id(&scan_id)?;
        store.finish_scan(&scan_id, "completed", None, true)?;

        assert_eq!(
            store.snapshot_id_for_source("scan", &scan_id)?.as_deref(),
            Some(prospective.as_str())
        );
        Ok(())
    }

    #[test]
    fn invalid_staging_scan_cannot_be_promoted_by_calling_finish_directly() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        store.start_scan("scan-1", Path::new("/tmp/project"), false)?;

        let error = store
            .finish_scan("scan-1", "completed", None, true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot be promoted before validation"));
        assert_eq!(store.latest_successful_id()?, None);
        assert_eq!(store.scan("scan-1")?.unwrap().status, "staging");
        Ok(())
    }

    #[test]
    fn latest_attempt_uses_insertion_order_when_timestamps_collide() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        store.start_scan("z-earlier", Path::new("/tmp/project"), false)?;
        store.start_scan("a-later", Path::new("/tmp/project"), false)?;
        store
            .connection
            .execute("UPDATE scans SET started_at='2026-01-01T00:00:00.000Z'", [])?;

        assert_eq!(store.latest_attempt_id()?.as_deref(), Some("a-later"));
        Ok(())
    }

    #[test]
    fn merged_coverage_intersects_completeness_independent_of_worker_order() {
        let complete = json!({
            "profiles":1,"files_discovered":1,"files_analyzed":1,"files_skipped":0,
            "dependency_sites":1,"resolved":1,"candidates":0,"external":0,
            "unresolved":0,"unsupported_syntax":0,"project_code_executed":false,
            "completeness":["syntax-complete"],"reasons":[]
        });
        let incomplete = json!({
            "profiles":1,"files_discovered":1,"files_analyzed":0,"files_skipped":1,
            "dependency_sites":0,"resolved":0,"candidates":0,"external":0,
            "unresolved":0,"unsupported_syntax":1,"project_code_executed":false,
            "completeness":[],"reasons":["unsupported_syntax"]
        });

        for merged in [
            merge_coverage(complete.clone(), incomplete.clone()),
            merge_coverage(incomplete.clone(), complete.clone()),
        ] {
            assert_eq!(merged["profiles"], 2);
            assert_eq!(merged["files_skipped"], 1);
            assert_eq!(merged["unsupported_syntax"], 1);
            assert_eq!(merged["completeness"], json!([]));
            assert_eq!(merged["reasons"], json!(["unsupported_syntax"]));
        }
    }

    #[test]
    fn profile_completed_coverage_round_trips_in_deterministic_profile_order() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        store.start_scan("scan-1", Path::new("/tmp/project"), false)?;
        let empty_profile_coverage = json!({
            "profiles":1,"files_discovered":0,"files_analyzed":0,"files_skipped":0,
            "dependency_sites":0,"resolved":0,"candidates":0,"external":0,
            "unresolved":0,"unsupported_syntax":0,"project_code_executed":false,
            "completeness":["syntax-complete"],"reasons":[]
        });
        for (seq, id) in [(1, "z-profile"), (2, "a-profile")] {
            let mut declared = common("profile_declared", seq);
            declared["profile"] = json!({
                "id":id,"language":"fixture","features":[],"environment":{},"properties":{}
            });
            store.ingest_event(&declared)?;
        }
        for (seq, id) in [(3, "z-profile"), (4, "a-profile")] {
            let mut completed = common("profile_completed", seq);
            completed["profile_id"] = json!(id);
            completed["coverage"] = empty_profile_coverage.clone();
            store.ingest_event(&completed)?;
        }
        let mut completed = common("scan_completed", 5);
        completed["coverage"] = json!({
            "profiles":2,"files_discovered":0,"files_analyzed":0,"files_skipped":0,
            "dependency_sites":0,"resolved":0,"candidates":0,"external":0,
            "unresolved":0,"unsupported_syntax":0,"project_code_executed":false,
            "completeness":["syntax-complete"],"reasons":[]
        });
        store.ingest_event(&completed)?;

        store.validate_scan("scan-1")?;
        store.finish_scan("scan-1", "completed", None, true)?;
        let snapshot = store.load_snapshot("scan-1")?;
        assert_eq!(
            snapshot
                .profiles
                .iter()
                .map(|profile| profile.id.as_str())
                .collect::<Vec<_>>(),
            vec!["a-profile", "z-profile"]
        );
        assert!(snapshot.profiles.iter().all(|profile| {
            profile
                .coverage
                .as_ref()
                .is_some_and(|coverage| coverage.profiles == 1)
        }));
        assert_eq!(snapshot.coverage.profiles, 2);
        Ok(())
    }

    #[test]
    fn rust_semantic_graph_round_trips_canonical_identities_and_site_less_evidence() -> Result<()> {
        let events: Vec<Value> = RUST_SEMANTIC_GOLDEN
            .lines()
            .map(serde_json::from_str)
            .collect::<serde_json::Result<_>>()?;
        let scan_id = "scan-rust-semantic-golden";
        let mut store = Store::open_in_memory()?;
        store.start_scan(scan_id, Path::new("/fixture"), false)?;
        for event in &events {
            store.ingest_event(event)?;
        }
        store.validate_scan(scan_id)?;
        store.finish_scan(scan_id, "completed", None, true)?;

        let snapshot = store.load_snapshot(scan_id)?;
        assert_eq!(snapshot.coverage.completeness, vec!["syntax-complete"]);
        assert_eq!(snapshot.profiles.len(), 1);
        assert_eq!(
            snapshot.profiles[0]
                .coverage
                .as_ref()
                .expect("completed Rust profile coverage")
                .completeness,
            vec!["syntax-complete"]
        );
        assert!(
            !snapshot
                .coverage
                .completeness
                .iter()
                .any(|level| level == "semantic-complete")
        );
        let expected_nodes: Vec<_> = events
            .iter()
            .filter(|event| event["event"] == "node_upsert")
            .map(|event| &event["node"])
            .collect();
        assert_eq!(snapshot.nodes.len(), expected_nodes.len());
        for expected in expected_nodes {
            let id = expected["id"].as_str().expect("fixture node ID");
            let loaded = snapshot
                .nodes
                .iter()
                .find(|node| node.id == id)
                .unwrap_or_else(|| panic!("missing stored node {id}"));
            assert_eq!(loaded.kind, expected["kind"]);
            assert_eq!(loaded.locator, expected["locator"]);
            assert_eq!(loaded.display_name, expected["display_name"]);
            assert_eq!(loaded.properties, expected["properties"]);
            if matches!(loaded.kind.as_str(), "symbol" | "type") {
                assert!(
                    loaded.properties["canonical_identity"].is_object(),
                    "semantic node {id} lost its canonical identity"
                );
                assert_eq!(loaded.properties["language"], "rust");
                assert_eq!(
                    loaded.properties["crate_identity"],
                    "Cargo.toml#lib:rust_semantic_fixture:src/lib.rs"
                );
            }
        }

        assert!(snapshot.sites.is_empty());
        let expected_edges: Vec<_> = events
            .iter()
            .filter(|event| event["event"] == "edge_upsert")
            .map(|event| &event["edge"])
            .collect();
        assert_eq!(snapshot.edges.len(), expected_edges.len());
        assert_eq!(snapshot.evidence.len(), expected_edges.len());
        let relation_kinds: std::collections::BTreeSet<_> = snapshot
            .edges
            .iter()
            .map(|edge| edge.kind.as_str())
            .collect();
        assert_eq!(
            relation_kinds,
            std::collections::BTreeSet::from(["declares", "extends", "implements", "instantiates"])
        );

        for expected in expected_edges {
            let id = expected["id"].as_str().expect("fixture edge ID");
            let loaded = snapshot
                .edges
                .iter()
                .find(|edge| edge.id == id)
                .unwrap_or_else(|| panic!("missing stored edge {id}"));
            assert_eq!(
                loaded.site_id, None,
                "{} must remain site-less",
                loaded.kind
            );
            assert_eq!(loaded.source, expected["source"]);
            assert_eq!(loaded.target, expected["target"]);
            assert_eq!(loaded.kind, expected["kind"]);
            assert_eq!(loaded.phase, "semantic");
            assert_eq!(loaded.environment, "any");
            assert_eq!(loaded.profile_id, expected["profile_id"]);
            assert_eq!(loaded.resolution_status, "resolved");
            assert_eq!(loaded.precision, "exact");
            assert_eq!(loaded.condition, expected["condition"]);
            assert_eq!(loaded.generated, expected["generated"]);

            let expected_evidence = &expected["evidence"][0];
            let evidence = snapshot
                .evidence
                .iter()
                .find(|item| item.owner_type == "edge" && item.owner_id == id)
                .unwrap_or_else(|| panic!("missing stored semantic evidence for {id}"));
            assert_eq!(evidence.ordinal, 0);
            assert_eq!(evidence.kind, "semantic");
            assert_eq!(evidence.extractor, "rust-analyzer-hir");
            assert_eq!(evidence.extractor_version, "0.0.330");
            assert_eq!(evidence.path, expected_evidence["path"]);
            assert_eq!(evidence.start_line, expected_evidence["start_line"]);
            assert_eq!(evidence.start_column, expected_evidence["start_column"]);
            assert_eq!(evidence.end_line, expected_evidence["end_line"]);
            assert_eq!(evidence.end_column, expected_evidence["end_column"]);
            assert_eq!(
                evidence.detail.as_deref(),
                expected_evidence["detail"].as_str()
            );
            assert_eq!(evidence.properties, expected_evidence["properties"]);
            assert_eq!(evidence.properties["backend"], "rust-analyzer-library");
            assert_eq!(
                evidence.properties["rust_analyzer_revision"],
                "8954b66d43225e62c92e8bbcc8500191b5cceb1e"
            );
        }
        Ok(())
    }

    #[test]
    fn aggregate_and_profile_coverage_must_agree_with_stored_profiles() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        store.start_scan("scan-1", Path::new("/tmp/project"), false)?;
        let mut declared = common("profile_declared", 1);
        declared["profile"] = json!({
            "id":"profile-1","language":"fixture","features":[],"environment":{},"properties":{}
        });
        store.ingest_event(&declared)?;
        let mut profile_completed = common("profile_completed", 2);
        profile_completed["profile_id"] = json!("profile-1");
        profile_completed["coverage"] = json!({
            "profiles":1,"files_discovered":0,"files_analyzed":0,"files_skipped":0,
            "dependency_sites":1,"resolved":1,"candidates":0,"external":0,
            "unresolved":0,"unsupported_syntax":0,"project_code_executed":false,
            "completeness":["syntax-complete"],"reasons":[]
        });
        store.ingest_event(&profile_completed)?;
        let mut completed = common("scan_completed", 3);
        completed["coverage"] = json!({
            "profiles":1,"files_discovered":0,"files_analyzed":0,"files_skipped":0,
            "dependency_sites":0,"resolved":0,"candidates":0,"external":0,
            "unresolved":0,"unsupported_syntax":0,"project_code_executed":false,
            "completeness":["syntax-complete"],"reasons":[]
        });
        store.ingest_event(&completed)?;

        assert!(
            store
                .validate_scan("scan-1")
                .unwrap_err()
                .to_string()
                .contains("profile profile-1 coverage site counts")
        );
        assert!(
            store
                .finish_scan("scan-1", "completed", None, true)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn aggregate_coverage_cannot_overstate_profile_completeness_or_hide_unsupported_syntax()
    -> Result<()> {
        for (scan_id, profile_completeness, aggregate_completeness, profile_unsupported, needle) in [
            (
                "scan-completeness",
                json!([]),
                json!(["syntax-complete"]),
                0,
                "profile intersection",
            ),
            (
                "scan-unsupported",
                json!([]),
                json!([]),
                1,
                "below the profile maximum",
            ),
        ] {
            let mut store = Store::open_in_memory()?;
            store.start_scan(scan_id, Path::new("/tmp/project"), false)?;
            let mut declared = common("profile_declared", 1);
            declared["scan_id"] = json!(scan_id);
            declared["profile"] = json!({
                "id":"profile-1","language":"fixture","features":[],"environment":{},"properties":{}
            });
            store.ingest_event(&declared)?;

            let mut profile_completed = common("profile_completed", 2);
            profile_completed["scan_id"] = json!(scan_id);
            profile_completed["profile_id"] = json!("profile-1");
            profile_completed["coverage"] = json!({
                "profiles":1,"files_discovered":0,"files_analyzed":0,"files_skipped":0,
                "dependency_sites":0,"resolved":0,"candidates":0,"external":0,
                "unresolved":0,"unsupported_syntax":profile_unsupported,
                "project_code_executed":false,"completeness":profile_completeness,"reasons":[]
            });
            store.ingest_event(&profile_completed)?;

            let mut completed = common("scan_completed", 3);
            completed["scan_id"] = json!(scan_id);
            completed["coverage"] = json!({
                "profiles":1,"files_discovered":0,"files_analyzed":0,"files_skipped":0,
                "dependency_sites":0,"resolved":0,"candidates":0,"external":0,
                "unresolved":0,"unsupported_syntax":0,"project_code_executed":false,
                "completeness":aggregate_completeness,"reasons":[]
            });
            store.ingest_event(&completed)?;

            let error = store.validate_scan(scan_id).unwrap_err().to_string();
            assert!(
                error.contains(needle),
                "unexpected validation error: {error}"
            );
        }
        Ok(())
    }

    #[test]
    fn persists_and_validates_a_resolved_site() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        store.start_scan("scan-1", Path::new("/tmp/project"), false)?;
        for node in [
            json!({"id":"file:a","kind":"file","locator":"file://a","display_name":"a","properties":{}}),
            json!({"id":"file:b","kind":"file","locator":"file://b","display_name":"b","properties":{}}),
        ] {
            let mut event = common("node_upsert", 1);
            event["node"] = node;
            store.ingest_event(&event)?;
        }
        let mut site_event = common("dependency_site", 2);
        site_event["site"] = json!({
            "id":"site:1","source":"file:a","kind":"imports","specifier":"./b",
            "profile_id":"fixture:default","resolution_status":"resolved","precision":"exact",
            "condition":{"op":"all","conditions":[]},"target_ids":["file:b"],"evidence":[]
        });
        store.ingest_event(&site_event)?;
        let mut edge_event = common("edge_upsert", 3);
        edge_event["edge"] = json!({
            "id":"edge:1","site_id":"site:1","source":"file:a","target":"file:b",
            "kind":"imports","phase":"source","environment":"any","profile_id":"fixture:default",
            "resolution_status":"resolved","precision":"exact","condition":{"op":"all","conditions":[]},
            "generated":false,"evidence":[]
        });
        store.ingest_event(&edge_event)?;
        let mut completed = common("scan_completed", 4);
        completed["coverage"] = json!({
            "profiles":0,"files_discovered":0,"files_analyzed":0,"files_skipped":0,
            "dependency_sites":1,"resolved":1,"candidates":0,"external":0,
            "unresolved":0,"unsupported_syntax":0,"project_code_executed":false,
            "completeness":["syntax-complete"],"reasons":[]
        });
        store.ingest_event(&completed)?;
        store.validate_scan("scan-1")?;
        store.finish_scan("scan-1", "completed", None, true)?;
        let snapshot = store.load_snapshot("scan-1")?;
        assert_eq!(snapshot.nodes.len(), 2);
        assert_eq!(snapshot.sites.len(), 1);
        assert_eq!(snapshot.edges.len(), 1);
        assert_eq!(store.latest_successful_id()?.as_deref(), Some("scan-1"));
        Ok(())
    }

    #[test]
    fn repeated_upserts_replace_evidence_within_and_across_batches() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        store.start_scan("scan-1", Path::new("/tmp/project"), false)?;
        let mut node = common("node_upsert", 1);
        node["node"] = json!({
            "id":"file:a","kind":"file","locator":"file://a","display_name":"a","properties":{}
        });
        store.ingest_event(&node)?;

        let site = |seq, details: &[&str]| {
            let mut event = common("dependency_site", seq);
            event["site"] = json!({
                "id":"site:1","source":"file:a","kind":"imports","specifier":"./b",
                "profile_id":"fixture:default","resolution_status":"unresolved",
                "precision":"exact","condition":{"op":"all","conditions":[]},"target_ids":[],
                "evidence":details.iter().map(|detail| json!({
                    "kind":"source","extractor":"fixture","extractor_version":"1.0.0",
                    "path":"a.ts","start_line":1,"start_column":1,
                    "end_line":1,"end_column":2,"detail":detail
                })).collect::<Vec<_>>()
            });
            event
        };
        let first = site(2, &["stale-zero", "stale-one"]);
        let same_batch_replacement = site(3, &["same-batch"]);
        store.ingest_events(&[&first, &same_batch_replacement])?;
        let snapshot = store.load_snapshot("scan-1")?;
        assert_eq!(snapshot.evidence.len(), 1);
        assert_eq!(snapshot.evidence[0].ordinal, 0);
        assert_eq!(snapshot.evidence[0].detail.as_deref(), Some("same-batch"));

        let later_batch_replacement = site(4, &["later-zero", "later-one"]);
        store.ingest_event(&later_batch_replacement)?;
        let snapshot = store.load_snapshot("scan-1")?;
        assert_eq!(snapshot.evidence.len(), 2);
        assert_eq!(snapshot.evidence[0].ordinal, 0);
        assert_eq!(snapshot.evidence[0].detail.as_deref(), Some("later-zero"));
        assert_eq!(snapshot.evidence[1].ordinal, 1);
        assert_eq!(snapshot.evidence[1].detail.as_deref(), Some("later-one"));
        let raw_site: String = store.connection.query_row(
            "SELECT raw_json FROM sites WHERE scan_id='scan-1' AND id='site:1'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            serde_json::from_str::<Value>(&raw_site)?["evidence"],
            json!([])
        );
        Ok(())
    }

    #[test]
    fn skipped_occurrence_does_not_require_an_artificial_graph_site() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        store.start_scan("scan-1", Path::new("/tmp/project"), false)?;
        for node in [
            json!({"id":"file:a","kind":"file","locator":"file://a","display_name":"a","properties":{}}),
            json!({"id":"file:b","kind":"file","locator":"file://b","display_name":"b","properties":{}}),
        ] {
            let mut event = common("node_upsert", 1);
            event["node"] = node;
            store.ingest_event(&event)?;
        }
        let mut site_event = common("dependency_site", 2);
        site_event["site"] = json!({
            "id":"site:1","source":"file:a","kind":"imports","specifier":"./b",
            "profile_id":"fixture:default","resolution_status":"resolved","precision":"exact",
            "condition":{"op":"all","conditions":[]},"target_ids":["file:b"],"evidence":[]
        });
        store.ingest_event(&site_event)?;
        let mut edge_event = common("edge_upsert", 3);
        edge_event["edge"] = json!({
            "id":"edge:1","site_id":"site:1","source":"file:a","target":"file:b",
            "kind":"imports","phase":"source","environment":"any","profile_id":"fixture:default",
            "resolution_status":"resolved","precision":"exact","condition":{"op":"all","conditions":[]},
            "generated":false,"evidence":[]
        });
        store.ingest_event(&edge_event)?;
        let mut file_completed = common("file_completed", 4);
        file_completed["path"] = json!("a.ts");
        file_completed["discovered_sites"] = json!(2);
        file_completed["emitted_sites"] = json!(1);
        file_completed["skipped_sites"] = json!(1);
        file_completed["skipped"] = json!(true);
        file_completed["reason"] = json!("one occurrence could not be emitted");
        store.ingest_event(&file_completed)?;
        let mut completed = common("scan_completed", 5);
        completed["coverage"] = json!({
            "profiles":0,"files_discovered":1,"files_analyzed":0,"files_skipped":1,
            "dependency_sites":1,"resolved":1,"candidates":0,"external":0,
            "unresolved":0,"unsupported_syntax":1,"project_code_executed":false,
            "completeness":[],"reasons":["unsupported_syntax","skipped_sites"]
        });
        store.ingest_event(&completed)?;

        store.validate_scan("scan-1")?;
        let snapshot = store.load_snapshot("scan-1")?;
        assert_eq!(snapshot.sites.len(), 1);
        assert_eq!(snapshot.file_coverage.len(), 1);
        assert_eq!(snapshot.file_coverage[0].discovered_sites, 2);
        assert_eq!(snapshot.file_coverage[0].emitted_sites, 1);
        assert_eq!(snapshot.file_coverage[0].skipped_sites, 1);
        Ok(())
    }

    #[test]
    fn completed_scans_are_immutable() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        store.start_scan("scan-1", Path::new("/tmp/project"), false)?;
        store.finish_scan("scan-1", "failed", Some("fixture"), false)?;
        let mut event = common("diagnostic", 1);
        event["diagnostic"] = json!({
            "id":"diagnostic:late","severity":"warning","code":"late","message":"late"
        });
        let error = store.ingest_event(&event).unwrap_err().to_string();
        assert!(error.contains("immutable"));
        assert!(
            store
                .finish_scan("scan-1", "completed", None, true)
                .unwrap_err()
                .to_string()
                .contains("immutable")
        );
        Ok(())
    }

    #[test]
    fn migrates_v1_store_without_losing_edges() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("v1.db");
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "PRAGMA foreign_keys=OFF;
             CREATE TABLE scans(id TEXT PRIMARY KEY);
             CREATE TABLE sites(scan_id TEXT NOT NULL, id TEXT NOT NULL, PRIMARY KEY(scan_id,id));
             CREATE TABLE evidence(
                scan_id TEXT NOT NULL, owner_type TEXT NOT NULL, owner_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL, extractor TEXT NOT NULL, extractor_version TEXT NOT NULL,
                path TEXT NOT NULL, start_line INTEGER NOT NULL, start_column INTEGER NOT NULL,
                end_line INTEGER NOT NULL, end_column INTEGER NOT NULL, raw_json TEXT NOT NULL,
                PRIMARY KEY(scan_id,owner_type,owner_id,ordinal));
             CREATE TABLE diagnostics(
                scan_id TEXT NOT NULL, ordinal INTEGER NOT NULL, severity TEXT NOT NULL,
                code TEXT NOT NULL, message TEXT NOT NULL, path TEXT, adapter TEXT,
                raw_json TEXT NOT NULL, PRIMARY KEY(scan_id,ordinal));
             CREATE TABLE file_coverage(
                scan_id TEXT NOT NULL, path TEXT NOT NULL, discovered_sites INTEGER NOT NULL,
                emitted_sites INTEGER NOT NULL, skipped INTEGER NOT NULL, reason TEXT,
                adapter TEXT NOT NULL, PRIMARY KEY(scan_id,adapter,path));
             CREATE TABLE edges(
                scan_id TEXT NOT NULL, id TEXT NOT NULL, site_id TEXT NOT NULL,
                source TEXT NOT NULL, target TEXT NOT NULL, kind TEXT NOT NULL,
                phase TEXT NOT NULL, environment TEXT NOT NULL, profile_id TEXT NOT NULL,
                resolution_status TEXT NOT NULL, precision TEXT NOT NULL,
                condition_json TEXT NOT NULL, generated INTEGER NOT NULL, raw_json TEXT NOT NULL,
                PRIMARY KEY(scan_id,id));
             CREATE INDEX edges_scan_source ON edges(scan_id,source);
             CREATE INDEX edges_scan_target ON edges(scan_id,target);
             CREATE INDEX edges_scan_kind ON edges(scan_id,kind);
             PRAGMA user_version=1;",
        )?;
        drop(connection);

        let store = Store::open(&path)?;
        assert_eq!(store.schema_version()?, STORE_SCHEMA_VERSION);
        let site_not_null: i64 = store.connection.query_row(
            "SELECT [notnull] FROM pragma_table_info('edges') WHERE name='site_id'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(site_not_null, 0);
        let evidence_kind: i64 = store.connection.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('evidence') WHERE name='kind'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(evidence_kind, 1);
        let skipped_sites: i64 = store.connection.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('file_coverage') WHERE name='skipped_sites'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(skipped_sites, 1);
        let site_index: i64 = store.connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='edges_scan_site'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(site_index, 1);
        let profile_coverage_table: i64 = store.connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='profile_coverage'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(profile_coverage_table, 1);
        let build_audits_table: i64 = store.connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='build_audits'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(build_audits_table, 1);
        let build_attempts_table: i64 = store.connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='build_attempts'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(build_attempts_table, 1);
        for table in [
            "completed_snapshots",
            "snapshot_sources",
            "current_completed_snapshot",
            "syntax_cache",
            "semantic_cache",
            "build_cache",
            "cache_events",
            "incremental_deltas",
            "impact_query_cache",
        ] {
            let count: i64 = store.connection.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )?;
            assert_eq!(count, 1, "missing migrated table {table}");
        }
        assert!(table_has_column(
            &store.connection,
            "scans",
            "mutation_count"
        )?);
        assert!(table_has_column(
            &store.connection,
            "build_attempts",
            "base_snapshot_id"
        )?);
        Ok(())
    }

    #[test]
    fn migrates_v7_current_graph_into_an_immutable_completed_snapshot() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("v7.db");
        let mut expected = {
            let mut store = Store::open(&path)?;
            ingest_protocol_fixture(
                &mut store,
                include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
            )?;
            let base = store.load_snapshot("scan-golden")?;
            let audit = build_attempt_audit("migrated-build");
            store.save_build_audit(&audit)?;
            store.start_build_attempt("scan-golden", &audit)?;
            let protocol = validate_build_ndjson(Cursor::new(build_protocol(
                "migrated-build",
                false,
                "production",
                &canonical_effective_input_id(&base.profiles[0]),
            )))?;
            store.save_build_delta("migrated-build", &protocol)?;
            store.finish_build_attempt("migrated-build", "completed", None, true)?;
            store.load_snapshot("scan-golden")?
        };
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "PRAGMA foreign_keys=OFF;
             DROP TABLE scan_operation_staging;
             DROP TABLE runtime_import_operation_owners;
             DROP TABLE impact_query_cache;
             DROP TABLE cache_events;
             DROP TABLE syntax_cache;
             DROP TABLE semantic_cache;
             DROP TABLE build_cache;
             DROP TABLE incremental_deltas;
             DROP TABLE snapshot_names;
             DROP TABLE current_completed_snapshot;
             DROP TABLE snapshot_sources;
             DROP TABLE completed_snapshot_seals;
             DROP TABLE completed_snapshots;
             ALTER TABLE build_attempts DROP COLUMN base_snapshot_id;
             ALTER TABLE scans DROP COLUMN mutation_count;
             ALTER TABLE scans DROP COLUMN source_revision;
             ALTER TABLE scans DROP COLUMN parent_snapshot_id;
             PRAGMA user_version=7;",
        )?;
        drop(connection);
        expected.scan.source_revision = None;

        let store = Store::open(&path)?;
        assert_eq!(store.schema_version()?, STORE_SCHEMA_VERSION);
        let current_id = store
            .current_snapshot_id()?
            .context("migrated current snapshot")?;
        let metadata = store
            .completed_snapshot(&current_id)?
            .context("migrated snapshot metadata")?;
        assert_eq!(metadata.source_kind, "build");
        assert_eq!(metadata.source_attempt_id, "migrated-build");
        assert!(metadata.parent_snapshot_id.is_some());
        assert_eq!(store.load_completed_snapshot(&current_id)?, expected);
        assert_eq!(store.load_snapshot("scan-golden")?, expected);
        assert!(store.verify_snapshot_integrity(&current_id)?.valid);
        Ok(())
    }

    #[test]
    fn migrates_v8_completed_snapshots_without_losing_graphs() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("v8.db");
        let snapshot_id = {
            let mut store = Store::open(&path)?;
            ingest_protocol_fixture(
                &mut store,
                include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
            )?;
            store.current_snapshot_id()?.context("v8 snapshot")?
        };
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "DROP TABLE scan_operation_staging;
             DROP TABLE runtime_import_operation_owners;
             DROP TABLE impact_query_cache;
             DROP TABLE incremental_deltas;
             DROP TABLE cache_events;
             DROP TABLE syntax_cache;
             DROP TABLE semantic_cache;
             DROP TABLE build_cache;
             DROP TABLE snapshot_names;
             PRAGMA user_version=8;",
        )?;
        drop(connection);

        let mut store = Store::open(&path)?;
        assert_eq!(store.schema_version()?, STORE_SCHEMA_VERSION);
        assert_eq!(
            store.current_snapshot_id()?.as_deref(),
            Some(snapshot_id.as_str())
        );
        assert!(store.verify_snapshot_integrity(&snapshot_id)?.valid);
        assert!(store.snapshot_names()?.is_empty());
        store.create_snapshot_name("migrated", &snapshot_id)?;
        assert_eq!(
            store.resolve_completed_snapshot_selector("migrated")?,
            snapshot_id
        );
        Ok(())
    }

    #[test]
    fn migrates_v14_by_canonical_validating_and_backfilling_snapshot_seals() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("v14.db");
        let snapshot_id = {
            let mut store = Store::open(&path)?;
            ingest_protocol_fixture(
                &mut store,
                include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
            )?;
            store.current_snapshot_id()?.context("v14 snapshot")?
        };
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "DROP TABLE scan_operation_staging;
             DROP TABLE runtime_import_operation_owners;
             DROP TABLE completed_snapshot_seals;
             PRAGMA user_version=14;",
        )?;
        drop(connection);

        let read_only_error = Store::open_read_only(&path)
            .err()
            .context("old read-only store must require writable migration")?;
        assert!(read_only_error.to_string().contains("schema 14"));

        let mut store = Store::open(&path)?;
        assert_eq!(store.schema_version()?, STORE_SCHEMA_VERSION);
        let stored_seal_count: u64 = store.connection.query_row(
            "SELECT COUNT(*) FROM completed_snapshot_seals",
            [],
            |row| row.get(0),
        )?;
        let snapshot_count: u64 =
            store
                .connection
                .query_row("SELECT COUNT(*) FROM completed_snapshots", [], |row| {
                    row.get(0)
                })?;
        assert_eq!(stored_seal_count, snapshot_count);
        let snapshot = store.load_completed_snapshot(&snapshot_id)?;
        assert_node_page_matches_snapshot(&mut store, &snapshot_id, &snapshot)?;
        Ok(())
    }

    #[test]
    fn v14_snapshot_seal_backfill_rejects_corruption_transactionally() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("v14-corrupt.db");
        {
            let mut store = Store::open(&path)?;
            ingest_protocol_fixture(
                &mut store,
                include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
            )?;
            let base = store.load_snapshot("scan-golden")?;
            let audit = build_attempt_audit("v14-corrupt-build");
            store.save_build_audit(&audit)?;
            store.start_build_attempt("scan-golden", &audit)?;
            let protocol = validate_build_ndjson(Cursor::new(build_protocol(
                "v14-corrupt-build",
                false,
                "production",
                &canonical_effective_input_id(&base.profiles[0]),
            )))?;
            store.save_build_delta("v14-corrupt-build", &protocol)?;
            store.finish_build_attempt("v14-corrupt-build", "completed", None, true)?;
        }
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "DROP TABLE scan_operation_staging;
             DROP TABLE runtime_import_operation_owners;
             DROP TABLE completed_snapshot_seals;
             UPDATE build_attempts
                SET delta_json=json_set(delta_json, '$.coverage.profiles', 'invalid')
              WHERE id='v14-corrupt-build';
             PRAGMA user_version=14;",
        )?;
        drop(connection);

        let error = Store::open(&path)
            .err()
            .context("corrupt v14 store migration must fail")?;
        let error_chain = format!("{error:#}");
        assert!(error_chain.contains("failed to backfill storage seal"));
        assert!(error_chain.contains("canonical"));
        let connection = Connection::open(&path)?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        assert_eq!(version, 14);
        let seal_table_count: u64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master
              WHERE type='table' AND name='completed_snapshot_seals'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(seal_table_count, 0);
        Ok(())
    }

    #[test]
    fn v15_foreign_key_violation_rolls_back_the_entire_v16_migration() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("v15-foreign-key-violation.db");
        drop(Store::open(&path)?);
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "PRAGMA foreign_keys=OFF;
             DROP TABLE scan_operation_staging;
             DROP TABLE runtime_import_operation_owners;
             INSERT INTO snapshot_names(name, snapshot_id, named_at)
             VALUES ('orphan', 'snapshot:sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                     '2026-08-09T00:00:00.000Z');
             PRAGMA user_version=15;",
        )?;
        drop(connection);
        let before = store_semantic_snapshot(&path)?;

        let error = Store::open(&path)
            .err()
            .context("v15 foreign key violation must reject migration")?;
        assert!(
            format!("{error:#}").contains("migration left 1 foreign key violations"),
            "unexpected migration error: {error:#}"
        );
        assert_eq!(store_semantic_snapshot(&path)?, before);

        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        assert_eq!(
            connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?,
            15
        );
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                  WHERE type='table' AND name='runtime_import_operation_owners'",
                [],
                |row| row.get::<_, u64>(0),
            )?,
            0
        );
        Ok(())
    }

    #[test]
    fn genuine_v15_store_migrates_to_exact_v17_staging_schema() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("v15-genuine.db");
        let current_snapshot_id = {
            let mut store = Store::open(&path)?;
            ingest_protocol_fixture(
                &mut store,
                include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
            )?;
            store.current_snapshot_id()?.context("current snapshot")?
        };
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "DROP TABLE scan_operation_staging;
             DROP TABLE runtime_import_operation_owners;
             PRAGMA user_version=15;",
        )?;
        drop(connection);

        let store = Store::open(&path)?;
        assert_eq!(store.schema_version()?, STORE_SCHEMA_VERSION);
        validate_runtime_import_operation_ownership_schema_and_rows(&store.connection)?;
        validate_scan_operation_staging_schema_and_rows(&store.connection)?;
        validate_store_foreign_keys(&store.connection, STORE_SCHEMA_VERSION)?;
        assert_eq!(
            store.current_snapshot_id()?.as_deref(),
            Some(current_snapshot_id.as_str())
        );
        assert_eq!(
            store.connection.query_row(
                "SELECT COUNT(*) FROM scan_operation_staging
                  WHERE substr(operation_id, 1, length(?1))=?1",
                [LEGACY_SCAN_OPERATION_CANDIDATE_PREFIX],
                |row| row.get::<_, u64>(0),
            )?,
            1
        );
        Ok(())
    }

    #[test]
    fn v15_late_v17_candidate_failure_rolls_back_the_entire_migration() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("v15-late-v17-candidate-failure.db");
        {
            let mut store = Store::open(&path)?;
            ingest_protocol_fixture(
                &mut store,
                include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
            )?;
        }
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "DROP TABLE scan_operation_staging;
             DROP TABLE runtime_import_operation_owners;
             DELETE FROM snapshot_sources
              WHERE source_kind='scan' AND source_attempt_id='scan-golden';
             PRAGMA user_version=15;",
        )?;
        drop(connection);
        let before = store_semantic_snapshot(&path)?;
        assert_eq!(before.version, 15);

        let error = Store::open(&path)
            .err()
            .context("late-invalid v15 legacy candidate must reject migration")?;
        assert!(
            format!("{error:#}")
                .contains("completed legacy scan scan-golden has no immutable snapshot"),
            "unexpected migration error: {error:#}"
        );
        let after = store_semantic_snapshot(&path)?;
        assert_eq!(after.version, 15);
        assert_eq!(after, before);
        Ok(())
    }

    #[test]
    fn malformed_preexisting_v15_runtime_ownership_is_rejected_without_mutation() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("v15-malformed-runtime-ownership.db");
        drop(Store::open(&path)?);
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "DROP TABLE scan_operation_staging;
             DROP TABLE runtime_import_operation_owners;
             CREATE TABLE runtime_import_operation_owners(operation_id TEXT);
             PRAGMA user_version=15;",
        )?;
        drop(connection);
        let before = store_semantic_snapshot(&path)?;

        for _ in 0..2 {
            let error = Store::open(&path)
                .err()
                .context("malformed v15 future ownership table must reject migration")?;
            assert!(format!("{error:#}").contains("forbidden future table object"));
            assert_eq!(store_semantic_snapshot(&path)?, before);
        }
        Ok(())
    }

    #[test]
    fn malformed_preexisting_v16_scan_staging_is_rejected_without_mutation() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("v16-malformed-scan-staging.db");
        drop(Store::open(&path)?);
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "DROP TABLE scan_operation_staging;
             CREATE TABLE scan_operation_staging(operation_id TEXT PRIMARY KEY);
             PRAGMA user_version=16;",
        )?;
        drop(connection);
        let before = store_semantic_snapshot(&path)?;

        for _ in 0..2 {
            let error = Store::open(&path)
                .err()
                .context("malformed v16 future staging table must reject migration")?;
            assert!(format!("{error:#}").contains("forbidden future table object"));
            assert_eq!(store_semantic_snapshot(&path)?, before);
        }
        Ok(())
    }

    #[test]
    fn p1a_v16_legacy_candidate_state_conflicts_roll_back_without_mutation() -> Result<()> {
        for (case, future_schema) in [
            (
                "malformed",
                "CREATE TABLE legacy_scan_operation_candidates(scan_id INTEGER PRIMARY KEY);",
            ),
            (
                "conflicting",
                "CREATE TABLE legacy_scan_operation_candidates(
                    scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
                    migrated_status TEXT NOT NULL
                        CHECK(migrated_status IN ('staging', 'completed')),
                    migrated_mutation_count INTEGER NOT NULL
                        CHECK(migrated_mutation_count >= 0)
                 );",
            ),
        ] {
            let temp = tempfile::tempdir()?;
            let path = temp.path().join(format!("v16-{case}-legacy-candidates.db"));
            drop(Store::open(&path)?);
            let connection = Connection::open(&path)?;
            connection.execute_batch("DROP TABLE scan_operation_staging;")?;
            connection.execute_batch(future_schema)?;
            connection.execute_batch("PRAGMA user_version=16;")?;
            drop(connection);
            let before = store_semantic_snapshot(&path)?;

            for _ in 0..2 {
                let error = Store::open(&path).err().with_context(|| {
                    format!("{case} legacy candidate state must reject migration")
                })?;
                assert!(
                    format!("{error:#}").contains("forbidden future table object"),
                    "unexpected {case} migration error: {error:#}"
                );
                assert_eq!(store_semantic_snapshot(&path)?, before, "{case}");
            }
        }
        Ok(())
    }

    #[test]
    fn p1a_completed_historical_snapshot_is_untouched_by_sentinel_reconciliation() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("v16-completed-history.db");
        let mut store = Store::open(&path)?;
        ingest_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
        )?;
        let current_snapshot_id = store.current_snapshot_id()?.context("current snapshot")?;
        let current_snapshot = store.load_completed_snapshot(&current_snapshot_id)?;
        let completed_scan_id = current_snapshot.scan.id.clone();
        drop(store);

        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "DROP TABLE scan_operation_staging;
             PRAGMA user_version=16;",
        )?;
        drop(connection);

        let mut store = Store::open(&path)?;
        assert_eq!(
            store.connection.query_row(
                "SELECT COUNT(*) FROM scan_operation_staging
                  WHERE substr(operation_id, 1, length(?1))=?1",
                [LEGACY_SCAN_OPERATION_CANDIDATE_PREFIX],
                |row| row.get::<_, u64>(0),
            )?,
            1
        );
        assert!(!store.reconcile_legacy_scan_operation_candidates()?);
        assert_eq!(
            store.current_snapshot_id()?.as_deref(),
            Some(current_snapshot_id.as_str())
        );
        assert_eq!(
            store.load_completed_snapshot(&current_snapshot_id)?,
            current_snapshot
        );
        assert_eq!(
            store
                .scan(&completed_scan_id)?
                .context("completed scan")?
                .status,
            "completed"
        );
        assert_eq!(
            store.connection.query_row(
                "SELECT COUNT(*) FROM scan_operation_staging
                  WHERE substr(operation_id, 1, length(?1))=?1",
                [LEGACY_SCAN_OPERATION_CANDIDATE_PREFIX],
                |row| row.get::<_, u64>(0),
            )?,
            0
        );
        Ok(())
    }

    #[test]
    fn genuine_v16_store_migrates_to_exact_v17_staging_schema() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("v16-genuine.db");
        drop(Store::open(&path)?);
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "DROP TABLE scan_operation_staging;
             PRAGMA user_version=16;",
        )?;
        drop(connection);

        let store = Store::open(&path)?;
        assert_eq!(store.schema_version()?, STORE_SCHEMA_VERSION);
        validate_runtime_import_operation_ownership_schema_and_rows(&store.connection)?;
        validate_scan_operation_staging_schema_and_rows(&store.connection)?;
        validate_store_foreign_keys(&store.connection, STORE_SCHEMA_VERSION)?;
        Ok(())
    }

    #[test]
    fn explicit_garbage_collection_removes_only_unreferenced_terminal_attempts() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        ingest_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
        )?;
        let current_id = store.current_snapshot_id()?.context("current snapshot")?;
        let current = store.load_completed_snapshot(&current_id)?;

        store.start_scan("failed-scan", Path::new("/fixture"), false)?;
        store.finish_scan("failed-scan", "cancelled", Some("cancelled"), false)?;
        let mut failed_audit = build_attempt_audit("failed-build");
        failed_audit["outcome"] = json!("failed");
        failed_audit["validated_output_digest"] = Value::Null;
        store.save_build_audit(&failed_audit)?;
        store.start_build_attempt("scan-golden", &failed_audit)?;
        store.finish_build_attempt("failed-build", "failed", Some("observer failed"), false)?;

        assert!(store.scan("failed-scan")?.is_some());
        assert!(store.build_attempt("failed-build")?.is_some());
        assert!(store.build_audit("failed-build")?.is_some());
        let report = store.garbage_collect_unreferenced_attempts()?;
        assert_eq!(
            report,
            GarbageCollectionReport {
                scan_attempts_deleted: 1,
                build_attempts_deleted: 1,
                build_audits_deleted: 1,
            }
        );
        assert!(store.scan("failed-scan")?.is_none());
        assert!(store.build_attempt("failed-build")?.is_none());
        assert!(store.build_audit("failed-build")?.is_none());
        assert_eq!(
            store.current_snapshot_id()?.as_deref(),
            Some(current_id.as_str())
        );
        assert_eq!(store.load_completed_snapshot(&current_id)?, current);
        Ok(())
    }

    #[test]
    fn build_audit_round_trips_without_secret_environment_keys() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        let audit = json!({
            "run_id":"build-1",
            "outcome":"completed",
            "started_at":"2026-07-22T00:00:00.000Z",
            "finished_at":"2026-07-22T00:00:01.000Z",
            "environment_keys":["CI","PATH"],
            "redacted_secret_key_count":1
        });
        store.save_build_audit(&audit)?;
        assert_eq!(store.build_audit("build-1")?.unwrap().audit, audit);

        let unsafe_audit = json!({
            "run_id":"build-2",
            "outcome":"failed",
            "started_at":"2026-07-22T00:00:00.000Z",
            "finished_at":"2026-07-22T00:00:01.000Z",
            "environment_keys":["API_TOKEN"]
        });
        assert!(store.save_build_audit(&unsafe_audit).is_err());
        Ok(())
    }

    #[test]
    fn completed_build_delta_unions_layers_without_overwriting_base_and_failed_delta_is_discarded()
    -> Result<()> {
        let mut store = Store::open_in_memory()?;
        ingest_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
        )?;
        let base = store.load_snapshot("scan-golden")?;
        let base_snapshot_id = store.current_snapshot_id()?.context("base snapshot")?;
        let base_metadata = store
            .completed_snapshot(&base_snapshot_id)?
            .context("base snapshot metadata")?;
        assert_eq!(base_metadata.source_kind, "scan");
        assert_eq!(base_metadata.source_attempt_id, "scan-golden");
        assert_eq!(
            base_metadata.source_revision.as_deref(),
            Some("fixture-revision")
        );
        assert_eq!(base_metadata.profile_ids, ["web:production:server"]);
        assert!(store.verify_snapshot_integrity(&base_snapshot_id)?.valid);
        assert_eq!(base.profiles[0].source_revision.as_deref(), Some("fixture"));
        assert_eq!(base.edges.len(), 1);
        assert_eq!(base.edges[0].phase, "source");
        assert_node_page_matches_snapshot(&mut store, &base_snapshot_id, &base)?;

        let audit = build_attempt_audit("build-run-1");
        store.save_build_audit(&audit)?;
        store.start_build_attempt("scan-golden", &audit)?;
        let effective_input_id = canonical_effective_input_id(&base.profiles[0]);
        let protocol = validate_build_ndjson(Cursor::new(build_protocol(
            "build-run-1",
            false,
            "production",
            &effective_input_id,
        )))?;
        store.save_build_delta("build-run-1", &protocol)?;
        store.finish_build_attempt("build-run-1", "completed", None, true)?;

        let build_snapshot_id = store.current_snapshot_id()?.context("build snapshot")?;
        assert_ne!(build_snapshot_id, base_snapshot_id);
        let build_metadata = store
            .completed_snapshot(&build_snapshot_id)?
            .context("build snapshot metadata")?;
        assert_eq!(build_metadata.source_kind, "build");
        assert_eq!(build_metadata.source_attempt_id, "build-run-1");
        assert_eq!(
            build_metadata.parent_snapshot_id.as_deref(),
            Some(base_snapshot_id.as_str())
        );
        assert_eq!(
            build_metadata.profile_ids,
            ["web:build", "web:production:server"]
        );
        assert_eq!(store.load_completed_snapshot(&base_snapshot_id)?, base);
        assert!(store.verify_snapshot_integrity(&build_snapshot_id)?.valid);
        let union = store.load_snapshot("scan-golden")?;
        assert_eq!(store.load_completed_snapshot(&build_snapshot_id)?, union);
        assert_node_page_matches_snapshot(&mut store, &build_snapshot_id, &union)?;
        assert_eq!(union.edges.len(), 2);
        let doctor_summary = store.scan_attempt_summary("scan-golden")?;
        let mut expected_profiles_by_language = BTreeMap::new();
        for profile in &union.profiles {
            *expected_profiles_by_language
                .entry(profile.language.clone())
                .or_default() += 1;
        }
        assert!(doctor_summary.scan.project_code_executed);
        assert_eq!(doctor_summary.coverage, union.coverage);
        assert_eq!(
            doctor_summary.profile_count,
            u64::try_from(union.profiles.len())?
        );
        assert_eq!(
            doctor_summary.profiles_by_language,
            expected_profiles_by_language
        );
        assert_eq!(
            doctor_summary.package_instance_count,
            u64::try_from(
                union
                    .nodes
                    .iter()
                    .filter(|node| node.kind == "package_instance")
                    .count()
            )?
        );
        assert_eq!(
            doctor_summary.diagnostics.total,
            u64::try_from(union.diagnostics.len())?
        );
        assert!(
            doctor_summary
                .diagnostics
                .groups
                .iter()
                .any(|group| group.code == "build-observed" && group.count == 1)
        );
        assert!(
            !serde_json::to_string(&doctor_summary)?.contains("must-not-appear-in-doctor-summary")
        );
        assert_eq!(
            union
                .edges
                .iter()
                .map(|edge| edge.phase.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["build", "source"])
        );
        assert_eq!(union.nodes, base.nodes, "base node identity must be reused");
        assert!(
            union
                .coverage
                .completeness
                .contains(&"build-observed".to_owned())
        );
        assert!(union.scan.project_code_executed);
        assert_eq!(union.profile_matrix.entries.len(), 1);
        let matrix_entry = &union.profile_matrix.entries[0];
        assert_eq!(
            matrix_entry.profile_ids,
            ["web:build", "web:production:server"]
        );
        assert_eq!(matrix_entry.parent_profile_ids, ["web:production:server"]);
        assert_eq!(matrix_entry.phases, ["build", "static"]);
        assert_eq!(
            matrix_entry.selection_reasons,
            ["direct-effective-input", "parent-effective-input"]
        );
        assert_eq!(matrix_entry.phase_coverage["static"].sites, 1);
        assert_eq!(matrix_entry.phase_coverage["static"].edges, 1);
        assert_eq!(matrix_entry.phase_coverage["build"].sites, 1);
        assert_eq!(matrix_entry.phase_coverage["build"].edges, 1);
        assert_eq!(union.profile_matrix.correlations.len(), 1);
        let correlation = &union.profile_matrix.correlations[0];
        assert_eq!(correlation.status, "matched");
        assert!(correlation.difference_reasons.is_empty());
        assert_eq!(
            correlation.conditions_by_phase["static"], correlation.conditions_by_phase["build"],
            "canonical condition union must deduplicate reordered conditions"
        );
        assert_eq!(
            correlation.condition_union,
            correlation.conditions_by_phase["static"]
        );
        assert_eq!(union.profile_matrix.difference_counts["matched"], 1);
        assert_eq!(union.profile_matrix.difference_counts["conflict"], 0);
        assert_eq!(
            store.current_build_attempt_id("scan-golden")?.as_deref(),
            Some("build-run-1")
        );
        assert_eq!(store.load_snapshot("scan-golden")?, union);

        let failed_audit = build_attempt_audit("build-run-2");
        store.save_build_audit(&failed_audit)?;
        store.start_build_attempt("scan-golden", &failed_audit)?;
        let failed_protocol = validate_build_ndjson(Cursor::new(build_protocol(
            "build-run-2",
            true,
            "production",
            &effective_input_id,
        )))?;
        assert!(
            store
                .save_build_delta("build-run-2", &failed_protocol)
                .is_err(),
            "a conflicting later build layer must fail before staging"
        );
        store.finish_build_attempt(
            "build-run-2",
            "security_failed",
            Some("build-evidence-conflicts-with-existing-layer"),
            false,
        )?;
        let retained = store.load_snapshot("scan-golden")?;
        assert_eq!(
            retained, union,
            "failed attempt must not replace current union"
        );
        let retained_delta: Option<String> = store.connection.query_row(
            "SELECT delta_json FROM build_attempts WHERE id='build-run-2'",
            [],
            |row| row.get(0),
        )?;
        assert!(retained_delta.is_none());
        assert_eq!(
            store.current_snapshot_id()?.as_deref(),
            Some(build_snapshot_id.as_str())
        );
        assert_eq!(store.snapshot_id_for_source("build", "build-run-2")?, None);

        let mut supervisor_failure = build_attempt_audit("build-run-supervisor-failed");
        supervisor_failure["outcome"] = json!("timed_out");
        supervisor_failure["validated_output_digest"] = Value::Null;
        store.save_build_audit(&supervisor_failure)?;
        store.start_build_attempt("scan-golden", &supervisor_failure)?;
        store.finish_build_attempt(
            "build-run-supervisor-failed",
            "timed_out",
            Some("build-timeout"),
            false,
        )?;
        assert_eq!(
            store
                .build_attempt("build-run-supervisor-failed")?
                .unwrap()
                .status,
            "timed_out"
        );
        assert_eq!(
            store.current_build_attempt_id("scan-golden")?.as_deref(),
            Some("build-run-1")
        );
        Ok(())
    }

    #[test]
    fn build_cache_hit_validates_base_audit_and_payload_and_replaces_corrupt_entries() -> Result<()>
    {
        let mut store = Store::open_in_memory()?;
        ingest_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
        )?;
        let base_snapshot_id = store.current_snapshot_id()?.context("base snapshot")?;
        let audit = build_attempt_audit("build-cache-run");
        store.save_build_audit(&audit)?;
        store.start_build_attempt("scan-golden", &audit)?;
        let effective_input_id =
            canonical_effective_input_id(&store.load_snapshot("scan-golden")?.profiles[0]);
        let protocol = validate_build_ndjson(Cursor::new(build_protocol(
            "build-cache-run",
            false,
            "production",
            &effective_input_id,
        )))?;
        store.save_build_delta("build-cache-run", &protocol)?;
        store.finish_build_attempt("build-cache-run", "completed", None, true)?;
        let build_snapshot_id = store.current_snapshot_id()?.context("build snapshot")?;
        let key = CacheKey::new(
            CacheLayer::Build,
            BTreeMap::from([
                ("base_snapshot".to_owned(), base_snapshot_id),
                ("source".to_owned(), "sha256:source".to_owned()),
            ]),
        );
        assert_eq!(
            store
                .store_snapshot_cache(&key, &build_snapshot_id, None, Some("build-cache-run"),)?
                .outcome,
            "stored"
        );
        let hit = store.lookup_build_cache(&key)?;
        assert_eq!(hit.result.outcome, "hit");
        assert_eq!(hit.result.reason, "validated");
        assert_eq!(
            hit.audit.as_ref().context("cached audit")?["run_id"],
            "build-cache-run"
        );
        let publish_error = store
            .publish_validated_build_cache_hit_with_precommit(&hit, || {
                anyhow::bail!("source changed")
            })
            .unwrap_err();
        assert!(
            publish_error
                .to_string()
                .contains("pre-commit validation failed")
        );
        assert!(
            !store
                .recent_cache_events(20)?
                .iter()
                .any(|event| event.layer == CacheLayer::Build && event.outcome == "hit")
        );
        store.publish_validated_build_cache_hit_with_precommit(&hit, || Ok(()))?;
        assert!(
            store
                .recent_cache_events(20)?
                .iter()
                .any(|event| event.layer == CacheLayer::Build
                    && event.outcome == "hit"
                    && event.reason == "validated")
        );

        store.connection.execute(
            "UPDATE build_cache SET payload_digest='cache-payload-reference:sha256:broken' WHERE key=?1",
            [&key.key],
        )?;
        let rejected = store.lookup_build_cache(&key)?;
        assert_eq!(rejected.result.outcome, "reject");
        assert_eq!(rejected.result.reason, "payload-integrity-failed");

        assert_eq!(
            store
                .store_snapshot_cache(&key, &build_snapshot_id, None, Some("build-cache-run"),)?
                .outcome,
            "stored"
        );
        assert_eq!(store.lookup_build_cache(&key)?.result.outcome, "hit");

        let mut stale_dimensions = key.dimensions.clone();
        stale_dimensions.insert("source".to_owned(), "sha256:changed".to_owned());
        let stale = CacheKey::new(CacheLayer::Build, stale_dimensions);
        let miss = store.lookup_build_cache(&stale)?;
        assert_eq!(miss.result.outcome, "miss");
        assert_eq!(miss.result.reason, "not-found");
        Ok(())
    }

    #[test]
    fn compiler_precise_cache_promotes_a_new_attempt_atomically_and_rejects_tampering() -> Result<()>
    {
        let mut store = Store::open_in_memory()?;
        ingest_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
        )?;
        let base_snapshot_id = store.current_snapshot_id()?.context("safe snapshot")?;
        let effective_input_id =
            canonical_effective_input_id(&store.load_snapshot("scan-golden")?.profiles[0]);
        let mut cold_audit = build_attempt_audit("compiler-cold");
        cold_audit["command_program"] = json!("cargo");
        cold_audit["logical_cwd"] = json!(".");
        cold_audit["source_root_digest"] = json!("e".repeat(64));
        cold_audit["network_policy"] = json!("deny");
        store.save_build_audit(&cold_audit)?;
        store.start_build_attempt_at_base_snapshot(
            "scan-golden",
            &base_snapshot_id,
            &cold_audit,
        )?;
        let protocol = validate_build_ndjson(Cursor::new(build_protocol(
            "compiler-cold",
            false,
            "production",
            &effective_input_id,
        )))?;
        store.save_build_delta("compiler-cold", &protocol)?;
        store.finish_build_attempt("compiler-cold", "completed", None, true)?;
        let cold_snapshot_id = store.current_snapshot_id()?.context("cold snapshot")?;
        let key = CacheKey::new(
            CacheLayer::CompilerPrecise,
            BTreeMap::from([
                ("base_snapshot".to_owned(), base_snapshot_id.clone()),
                ("source".to_owned(), "sha256:compiler-input".to_owned()),
            ]),
        );
        let evidence = json!({
            "effective_input_identity":key.key,
            "base_snapshot_id":base_snapshot_id,
            "validated_output_digest":"d".repeat(64),
        });
        assert_eq!(
            store
                .store_compiler_precise_cache(&key, "compiler-cold", &evidence)?
                .outcome,
            "stored"
        );
        let hit = store.lookup_compiler_precise_cache(&key)?;
        assert_eq!(hit.result.outcome, "hit");

        let mut warm_audit = cold_audit.clone();
        warm_audit["run_id"] = json!("compiler-warm");
        warm_audit["started_at"] = json!("2026-07-22T00:00:02.000Z");
        warm_audit["finished_at"] = json!("2026-07-22T00:00:02.000Z");
        assert!(
            store
                .promote_validated_compiler_precise_cache_hit_with_precommit(
                    &hit,
                    "scan-golden",
                    &warm_audit,
                    || anyhow::bail!("input changed"),
                )
                .is_err()
        );
        assert_eq!(
            store.current_snapshot_id()?.as_deref(),
            Some(cold_snapshot_id.as_str())
        );
        assert!(store.build_attempt("compiler-warm")?.is_none());

        let warm_snapshot_id = store.promote_validated_compiler_precise_cache_hit_with_precommit(
            &hit,
            "scan-golden",
            &warm_audit,
            || Ok(()),
        )?;
        assert_ne!(warm_snapshot_id, cold_snapshot_id);
        assert_eq!(
            store.current_build_attempt_id("scan-golden")?.as_deref(),
            Some("compiler-warm")
        );
        assert!(
            store
                .recent_cache_events(20)?
                .iter()
                .any(|event| event.layer == CacheLayer::CompilerPrecise
                    && event.outcome == "hit"
                    && event.reason == "validated")
        );

        store.connection.execute(
            "UPDATE compiler_precise_cache SET payload_digest='tampered' WHERE key=?1",
            [&key.key],
        )?;
        let rejected = store.lookup_compiler_precise_cache(&key)?;
        assert_eq!(rejected.result.outcome, "reject");
        assert_eq!(rejected.result.reason, "corrupt");
        assert_eq!(
            store
                .store_compiler_precise_cache(&key, "compiler-cold", &evidence)?
                .outcome,
            "stored"
        );
        assert_eq!(
            store.lookup_compiler_precise_cache(&key)?.result.outcome,
            "hit"
        );
        store.connection.execute(
            "UPDATE compiler_precise_cache SET payload_json='{' WHERE key=?1",
            [&key.key],
        )?;
        let malformed = store.lookup_compiler_precise_cache(&key)?;
        assert_eq!(malformed.result.outcome, "reject");
        assert_eq!(malformed.result.reason, "corrupt");
        assert_eq!(
            store
                .store_compiler_precise_cache(&key, "compiler-cold", &evidence)?
                .outcome,
            "stored"
        );
        assert_eq!(
            store.lookup_compiler_precise_cache(&key)?.result.outcome,
            "hit"
        );

        for ordinal in 0..=COMPILER_PRECISE_CACHE_MAX_ENTRIES {
            let bounded = CacheKey::new(
                CacheLayer::CompilerPrecise,
                BTreeMap::from([
                    ("base_snapshot".to_owned(), base_snapshot_id.clone()),
                    (
                        "source".to_owned(),
                        format!("sha256:compiler-input-{ordinal:02}"),
                    ),
                ]),
            );
            store.store_compiler_precise_cache(
                &bounded,
                "compiler-cold",
                &json!({
                    "effective_input_identity":bounded.key,
                    "base_snapshot_id":base_snapshot_id,
                    "validated_output_digest":"d".repeat(64),
                }),
            )?;
        }
        assert_eq!(
            store.cache_entry_counts()?.compiler_precise,
            COMPILER_PRECISE_CACHE_MAX_ENTRIES as u64
        );
        assert!(store.verify_snapshot_integrity(&cold_snapshot_id)?.valid);
        assert!(store.verify_snapshot_integrity(&warm_snapshot_id)?.valid);
        Ok(())
    }

    #[test]
    fn build_target_conflict_keeps_both_layers_and_emits_provenance_diagnostic() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        ingest_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
        )?;
        let audit = build_attempt_audit("build-run-conflict");
        store.save_build_audit(&audit)?;
        store.start_build_attempt("scan-golden", &audit)?;
        let protocol = validate_build_ndjson(Cursor::new(build_protocol(
            "build-run-conflict",
            true,
            "production",
            &canonical_effective_input_id(&store.load_snapshot("scan-golden")?.profiles[0]),
        )))?;
        store.save_build_delta("build-run-conflict", &protocol)?;
        store.finish_build_attempt("build-run-conflict", "completed", None, true)?;

        let snapshot = store.load_snapshot("scan-golden")?;
        assert_eq!(snapshot.edges.len(), 2);
        let conflict = snapshot
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "BUILD_EVIDENCE_CONFLICT")
            .expect("conflict diagnostic");
        assert_eq!(conflict.properties["build_run_id"], "build-run-conflict");
        assert_eq!(
            conflict.properties["profile_matrix_schema"],
            "profile-matrix-v1"
        );
        let correlation = snapshot
            .profile_matrix
            .correlations
            .iter()
            .find(|correlation| correlation.status == "conflict")
            .expect("conflicting correlation");
        assert_eq!(correlation.difference_reasons, ["target_mismatch"]);
        assert_eq!(
            correlation.targets_by_phase["static"],
            ["file:sha256:target"]
        );
        assert_eq!(
            correlation.targets_by_phase["build"],
            ["file:sha256:source"]
        );
        let kinds = snapshot
            .evidence
            .iter()
            .filter(|evidence| {
                evidence.owner_type == "diagnostic" && evidence.owner_id == conflict.id
            })
            .map(|evidence| evidence.kind.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(kinds, BTreeSet::from(["build", "source"]));
        Ok(())
    }

    #[test]
    fn build_condition_conflict_preserves_both_conditions_and_evidence() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        ingest_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
        )?;
        let effective_input_id =
            canonical_effective_input_id(&store.load_snapshot("scan-golden")?.profiles[0]);
        let audit = build_attempt_audit("build-run-condition-conflict");
        store.save_build_audit(&audit)?;
        store.start_build_attempt("scan-golden", &audit)?;
        let protocol = validate_build_ndjson(Cursor::new(build_protocol(
            "build-run-condition-conflict",
            false,
            "development",
            &effective_input_id,
        )))?;
        store.save_build_delta("build-run-condition-conflict", &protocol)?;
        store.finish_build_attempt("build-run-condition-conflict", "completed", None, true)?;

        let snapshot = store.load_snapshot("scan-golden")?;
        let correlation = snapshot
            .profile_matrix
            .correlations
            .iter()
            .find(|correlation| correlation.status == "conflict")
            .context("condition conflict correlation")?;
        assert_eq!(correlation.difference_reasons, ["condition_mismatch"]);
        assert_ne!(
            correlation.conditions_by_phase["static"],
            correlation.conditions_by_phase["build"]
        );
        assert_eq!(
            correlation.condition_union["op"], "any",
            "both canonical conditions must remain queryable"
        );
        let diagnostic_id = correlation
            .diagnostic_id
            .as_deref()
            .context("condition conflict diagnostic")?;
        let kinds = snapshot
            .evidence
            .iter()
            .filter(|evidence| {
                evidence.owner_type == "diagnostic" && evidence.owner_id == diagnostic_id
            })
            .map(|evidence| evidence.kind.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(kinds, BTreeSet::from(["build", "source"]));
        Ok(())
    }

    #[test]
    fn repeated_build_of_same_effective_input_keeps_profile_and_graph_identity() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        ingest_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
        )?;
        let effective_input_id =
            canonical_effective_input_id(&store.load_snapshot("scan-golden")?.profiles[0]);
        let mut first_identity = None;

        for run_id in ["build-run-repeat-1", "build-run-repeat-2"] {
            let audit = build_attempt_audit(run_id);
            store.save_build_audit(&audit)?;
            store.start_build_attempt("scan-golden", &audit)?;
            let protocol = validate_build_ndjson(Cursor::new(build_protocol(
                run_id,
                false,
                "production",
                &effective_input_id,
            )))?;
            store.save_build_delta(run_id, &protocol)?;
            store.finish_build_attempt(run_id, "completed", None, true)?;

            let snapshot = store.load_snapshot("scan-golden")?;
            let identity = json!({
                "profiles": snapshot.profiles.iter().map(|item| &item.id).collect::<Vec<_>>(),
                "nodes": snapshot.nodes.iter().map(|item| &item.id).collect::<Vec<_>>(),
                "sites": snapshot.sites.iter().map(|item| &item.id).collect::<Vec<_>>(),
                "edges": snapshot.edges.iter().map(|item| &item.id).collect::<Vec<_>>(),
                "effective_profiles": snapshot.profile_matrix.entries.iter().map(|item| &item.id).collect::<Vec<_>>(),
                "correlations": snapshot.profile_matrix.correlations.iter().map(|item| &item.id).collect::<Vec<_>>(),
            });
            if let Some(first_identity) = &first_identity {
                assert_eq!(&identity, first_identity);
            } else {
                first_identity = Some(identity);
            }
        }
        Ok(())
    }

    #[test]
    fn build_delta_rejects_forged_effective_input_identity() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        ingest_protocol_fixture(
            &mut store,
            include_str!("../../depgraph-protocol/tests/fixtures/protocol-v1.golden.ndjson"),
        )?;
        let mut root = store.load_snapshot("scan-golden")?.profiles[0].clone();
        let canonical = canonical_effective_input_id(&root);
        root.properties["effective_input_id"] =
            json!(format!("effective-input:sha256:{}", "f".repeat(64)));
        assert_eq!(
            canonical_effective_input_id(&root),
            canonical,
            "a root profile cannot self-declare a different effective identity"
        );

        let run_id = "build-run-forged-effective-input";
        let audit = build_attempt_audit(run_id);
        store.save_build_audit(&audit)?;
        store.start_build_attempt("scan-golden", &audit)?;
        let forged = format!("effective-input:sha256:{}", "f".repeat(64));
        let protocol = validate_build_ndjson(Cursor::new(build_protocol(
            run_id,
            false,
            "production",
            &forged,
        )))?;
        let error = store
            .save_build_delta(run_id, &protocol)
            .unwrap_err()
            .to_string();
        assert!(error.contains("effective parent contract is invalid"));
        let delta: Option<String> = store.connection.query_row(
            "SELECT delta_json FROM build_attempts WHERE id=?1",
            [run_id],
            |row| row.get(0),
        )?;
        assert!(delta.is_none());
        Ok(())
    }

    fn ingest_protocol_fixture(store: &mut Store, fixture: &str) -> Result<()> {
        let scan_id = stage_protocol_fixture(store, fixture, Some("fixture-revision"))?;
        store.finish_scan(&scan_id, "completed", None, true)?;
        Ok(())
    }

    fn stage_protocol_fixture(
        store: &mut Store,
        fixture: &str,
        source_revision: Option<&str>,
    ) -> Result<String> {
        let first: Value = serde_json::from_str(fixture.lines().next().context("fixture")?)?;
        let scan_id = required_str(&first, "scan_id")?.to_owned();
        store.start_scan_with_revision(&scan_id, Path::new("/fixture"), false, source_revision)?;
        let mut events = fixture
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        events.sort_by_key(|event| (event["event"] == "edge_upsert") as u8);
        for event in events {
            store.ingest_event(&event)?;
        }
        Ok(scan_id)
    }

    fn build_attempt_audit(run_id: &str) -> Value {
        json!({
            "schema_version":"1.0",
            "run_id":run_id,
            "adapter":"build-observer",
            "adapter_version":"0.1.0",
            "profile_id":"web:build",
            "command_plan_digest":"a".repeat(64),
            "toolchain_executable_digest":"b".repeat(64),
            "environment_key_set_digest":"c".repeat(64),
            "validated_output_digest":"d".repeat(64),
            "outcome":"completed",
            "started_at":"2026-07-22T00:00:00.000Z",
            "finished_at":"2026-07-22T00:00:01.000Z",
            "environment_keys":["CI","PATH"]
        })
    }

    fn build_protocol(
        run_id: &str,
        conflicting_target: bool,
        mode: &str,
        effective_input_id: &str,
    ) -> String {
        let provenance = json!({
            "build_run_id":run_id,
            "profile_id":"web:build",
            "command_plan_digest":"a".repeat(64),
            "toolchain_executable_digest":"b".repeat(64),
            "environment_key_set_digest":"c".repeat(64),
            "validated_output_digest":"d".repeat(64),
            "logical_artifact_path":"dist/manifest.json",
            "artifact_digest":"e".repeat(64)
        });
        let common = |event: &str, seq: u64| {
            json!({
                "event":event,"protocol_version":"1.0","scan_id":run_id,
                "adapter":"build-observer","adapter_version":"0.1.0","seq":seq
            })
        };
        let target = if conflicting_target {
            "file:sha256:source"
        } else {
            "file:sha256:target"
        };
        let mut events = Vec::new();
        let mut started = common("scan_started", 1);
        started["root"] = json!("/fixture");
        started["safe_mode"] = json!(false);
        started["project_code_executed"] = json!(true);
        events.push(started);
        let mut profile = common("profile_declared", 2);
        profile["profile"] = json!({
            "id":"web:build","language":"typescript",
            "toolchain":"typescript 7.0.2","command":"scan","target":"server",
            "features":[],"environment":{"mode":"production"},
            "source_revision":"fixture","properties":{
                "profile_contract":"phase-parent-effective-v1",
                "profile_phase":"build",
                "parent_profile_id":"web:production:server",
                "effective_input_id":effective_input_id
            }
        });
        events.push(profile);
        for (seq, id, locator) in [
            (3, "file:sha256:source", "src/index.ts"),
            (4, "file:sha256:target", "src/lib.ts"),
        ] {
            let mut node = common("node_upsert", seq);
            node["node"] = json!({
                "id":id,"kind":"file","locator":locator,"display_name":locator,
                "properties":{"language":"typescript"}
            });
            events.push(node);
        }
        let mut edge = common("edge_upsert", 5);
        edge["edge"] = json!({
            "id":format!("edge:build:{run_id}"),"source":"file:sha256:source",
            "target":target,"kind":"imports","site_id":format!("site:build:{run_id}"),
            "phase":"build","environment":"server","profile_id":"web:build",
            "condition":{"op":"all","conditions":[
                {"op":"eq","key":"runtime","value":"server"},
                {"op":"eq","key":"mode","value":mode}
            ]},"resolution_status":"resolved","precision":"observed","generated":true,
            "evidence":[{"kind":"build","extractor":"build-observer",
                "extractor_version":"0.1.0","properties":provenance.clone()}]
        });
        events.push(edge);
        let mut site = common("dependency_site", 6);
        site["site"] = json!({
            "id":format!("site:build:{run_id}"),"source":"file:sha256:source",
            "kind":"import","specifier":"./lib","resolution_status":"resolved",
            "target_ids":[target],"profile_id":"web:build",
            "condition":{"op":"all","conditions":[
                {"op":"eq","key":"mode","value":mode},
                {"op":"eq","key":"runtime","value":"server"}
            ]},"precision":"observed","evidence":[{"kind":"build",
                "extractor":"build-observer","extractor_version":"0.1.0",
                "properties":provenance}]
        });
        events.push(site);
        let typed_site: DependencySite = serde_json::from_value(events[5]["site"].clone()).unwrap();
        let site_id = build_site_stable_id(&typed_site).unwrap();
        events[5]["site"]["id"] = json!(site_id);
        events[4]["edge"]["site_id"] = events[5]["site"]["id"].clone();
        let typed_edge: GraphEdge = serde_json::from_value(events[4]["edge"].clone()).unwrap();
        events[4]["edge"]["id"] = json!(build_edge_stable_id(&typed_edge).unwrap());
        let mut diagnostic = common("diagnostic", 7);
        diagnostic["diagnostic"] = json!({
            "id":format!("diagnostic:build:{run_id}"),
            "severity":"warning",
            "code":"build-observed",
            "message":"build observation retained",
            "properties":{"private_payload":"must-not-appear-in-doctor-summary"}
        });
        events.push(diagnostic);
        let coverage = json!({
            "profiles":1,"files_discovered":0,"files_analyzed":0,"files_skipped":0,
            "dependency_sites":1,"resolved":1,"candidates":0,"external":0,
            "unresolved":0,"unsupported_syntax":0,"project_code_executed":true,
            "completeness":["build-observed"],"reasons":[]
        });
        let mut profile_completed = common("profile_completed", 8);
        profile_completed["profile_id"] = json!("web:build");
        profile_completed["coverage"] = coverage.clone();
        events.push(profile_completed);
        let mut completed = common("scan_completed", 9);
        completed["coverage"] = coverage;
        events.push(completed);
        events
            .into_iter()
            .map(|event| serde_json::to_string(&event).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    }
}
