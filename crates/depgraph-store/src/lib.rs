use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use depgraph_protocol::{
    Coverage, Diagnostic, Evidence, ProtocolEvent, ValidatedProtocol, stable_id_from_value,
    validate_build_contract,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod cache;
mod diff;
mod impact_cache;
mod incremental;
mod profile_matrix;
mod runtime;

pub use cache::{
    CACHE_CONTRACT_VERSION, CacheEntryCounts, CacheEventRecord, CacheKey, CacheLayer,
    CacheLookupResult, ValidatedScanCacheHit,
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
pub use runtime::{
    RuntimeEdgeContext, RuntimeImportResult, RuntimeSessionDelta, RuntimeSessionRecord,
    runtime_context_for_edge,
};

pub const STORE_SCHEMA_VERSION: i64 = 13;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanRecord {
    pub id: String,
    pub root: String,
    pub status: String,
    pub strict: bool,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub project_code_executed: bool,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_snapshot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
}

pub type ScanAttemptRecord = ScanRecord;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompletedSnapshotRecord {
    pub id: String,
    pub source_kind: String,
    pub source_attempt_id: String,
    pub scan_id: String,
    pub build_attempt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_import_id: Option<String>,
    #[serde(default)]
    pub runtime_session_ids: Vec<String>,
    pub parent_snapshot_id: Option<String>,
    pub source_revision: Option<String>,
    pub profile_ids: Vec<String>,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotIntegrityRecord {
    pub snapshot_id: String,
    pub valid: bool,
    pub expected_id: String,
    pub observed_id: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotNameRecord {
    pub name: String,
    pub snapshot_id: String,
    pub named_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompletedSnapshotDetails {
    pub snapshot: CompletedSnapshotRecord,
    pub names: Vec<String>,
    pub coverage: CoverageRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct GarbageCollectionReport {
    pub scan_attempts_deleted: u64,
    pub build_attempts_deleted: u64,
    pub build_audits_deleted: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct InterruptedAttemptRecovery {
    pub scan_attempt_ids: Vec<String>,
    pub build_attempt_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeRecord {
    pub id: String,
    pub kind: String,
    pub locator: String,
    pub display_name: String,
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProfileRecord {
    pub id: String,
    pub language: String,
    pub toolchain: Option<Value>,
    pub command: Option<String>,
    pub target: Option<String>,
    pub features: Vec<String>,
    pub environment: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    pub properties: Value,
    pub coverage: Option<CoverageRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SiteRecord {
    pub id: String,
    pub source: String,
    pub kind: String,
    pub specifier: Option<String>,
    pub profile_id: String,
    pub resolution_status: String,
    pub precision: String,
    pub condition: Value,
    pub target_ids: Vec<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EdgeRecord {
    pub id: String,
    pub site_id: Option<String>,
    pub source: String,
    pub target: String,
    pub kind: String,
    pub phase: String,
    pub environment: String,
    pub profile_id: String,
    pub resolution_status: String,
    pub precision: String,
    pub condition: Value,
    pub generated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CoverageRecord {
    pub profiles: u64,
    pub files_discovered: u64,
    pub files_analyzed: u64,
    pub files_skipped: u64,
    pub dependency_sites: u64,
    pub resolved: u64,
    pub candidates: u64,
    pub external: u64,
    pub unresolved: u64,
    pub unsupported_syntax: u64,
    pub project_code_executed: bool,
    pub completeness: Vec<String>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiagnosticRecord {
    pub ordinal: i64,
    pub id: String,
    pub severity: String,
    pub code: String,
    pub message: String,
    pub path: Option<String>,
    pub adapter: Option<String>,
    pub start_line: Option<u64>,
    pub start_column: Option<u64>,
    pub end_line: Option<u64>,
    pub end_column: Option<u64>,
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceRecord {
    pub owner_type: String,
    pub owner_id: String,
    pub ordinal: i64,
    pub kind: String,
    pub extractor: String,
    pub extractor_version: String,
    pub path: String,
    pub start_line: u64,
    pub start_column: u64,
    pub end_line: u64,
    pub end_column: u64,
    pub detail: Option<String>,
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileCoverageRecord {
    pub adapter: String,
    pub path: String,
    pub discovered_sites: u64,
    pub emitted_sites: u64,
    pub skipped_sites: u64,
    pub skipped: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterLogRecord {
    pub adapter: String,
    pub stderr: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BuildAuditRecord {
    pub run_id: String,
    pub outcome: String,
    pub started_at: String,
    pub finished_at: String,
    pub audit: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildAttemptRecord {
    pub id: String,
    pub base_scan_id: String,
    pub base_snapshot_id: Option<String>,
    pub audit_run_id: String,
    pub status: String,
    pub observer: String,
    pub observer_version: String,
    pub profile_id: String,
    pub command_plan_digest: String,
    pub toolchain_executable_digest: String,
    pub environment_key_set_digest: String,
    pub validated_output_digest: Option<String>,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
struct BuildGraphDelta {
    profiles: Vec<ProfileRecord>,
    nodes: Vec<NodeRecord>,
    sites: Vec<SiteRecord>,
    edges: Vec<EdgeRecord>,
    evidence: Vec<EvidenceRecord>,
    diagnostics: Vec<DiagnosticRecord>,
    coverage: CoverageRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphSnapshot {
    pub scan: ScanRecord,
    pub profiles: Vec<ProfileRecord>,
    pub nodes: Vec<NodeRecord>,
    pub sites: Vec<SiteRecord>,
    pub edges: Vec<EdgeRecord>,
    pub evidence: Vec<EvidenceRecord>,
    pub diagnostics: Vec<DiagnosticRecord>,
    pub file_coverage: Vec<FileCoverageRecord>,
    pub adapter_logs: Vec<AdapterLogRecord>,
    pub coverage: CoverageRecord,
    pub profile_matrix: ProfileMatrixRecord,
}

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
        if current != STORE_SCHEMA_VERSION {
            bail!(
                "store schema {current} does not match supported read-only schema {STORE_SCHEMA_VERSION}"
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

    pub fn schema_version(&self) -> Result<i64> {
        self.connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .context("failed to read schema version")
    }

    fn migrate(&mut self) -> Result<()> {
        self.connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;
        let current = self.schema_version()?;
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
        let base_snapshot_id = self
            .snapshot_id_for_scan_selection(base_scan_id)?
            .with_context(|| format!("base scan {base_scan_id} has no completed snapshot"))?;
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
        let by_name = self
            .connection
            .query_row(
                "SELECT snapshot_id FROM snapshot_names WHERE name=?1 COLLATE NOCASE",
                [selector],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
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
        if source_revision.is_some_and(|revision| revision.trim().is_empty()) {
            bail!("source revision must not be empty");
        }
        let parent_snapshot_id = self.current_snapshot_id()?;
        let tx = self.connection.transaction()?;
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
        for event in events {
            if required_str(event, "scan_id")? != scan_id {
                bail!("event batch contains multiple scan IDs");
            }
            ingest_event_in_transaction(&tx, event)?;
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
        let mut statement = self.connection.prepare(
            "SELECT s.id, s.resolution_status, s.target_ids_json,
                    COUNT(e.id), MIN(CASE WHEN e.resolution_status = s.resolution_status THEN 1 ELSE 0 END)
             FROM sites s LEFT JOIN edges e ON e.scan_id = s.scan_id AND e.site_id = s.id
             WHERE s.scan_id = ?1
             GROUP BY s.id, s.resolution_status, s.target_ids_json
             ORDER BY s.id",
        )?;
        let rows = statement.query_map([scan_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })?;
        for row in rows {
            let (id, status, targets_json, edge_count, statuses_match) = row?;
            let targets: Vec<String> = serde_json::from_str(&targets_json)
                .with_context(|| format!("site {id} has invalid target_ids"))?;
            match status.as_str() {
                "resolved" if targets.len() == 1 && edge_count == 1 => {}
                "candidates" if !targets.is_empty() && edge_count == targets.len() as i64 => {}
                "external" if targets.len() == 1 && edge_count == 1 => {}
                "unresolved" if targets.len() == 1 && edge_count == 1 => {}
                "resolved" | "candidates" | "external" | "unresolved" => bail!(
                    "site {id} violates {status} cardinality: {} targets, {edge_count} edges",
                    targets.len()
                ),
                _ => bail!("site {id} has unknown resolution status {status}"),
            }
            if statuses_match == Some(0) {
                bail!("site {id} and one or more edges disagree on resolution_status");
            }
        }

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

        let sites = load_sites(&self.connection, scan_id)?;
        let edges = load_edges(&self.connection, scan_id)?;
        let mut edges_by_site = BTreeMap::<String, Vec<&EdgeRecord>>::new();
        for edge in &edges {
            if let Some(site_id) = &edge.site_id {
                edges_by_site.entry(site_id.clone()).or_default().push(edge);
            }
        }
        for site in &sites {
            let expected = site.target_ids.iter().cloned().collect::<BTreeSet<_>>();
            if expected.len() != site.target_ids.len() {
                bail!("site {} contains duplicate target IDs", site.id);
            }
            let site_edges = edges_by_site.get(&site.id).cloned().unwrap_or_default();
            let observed = site_edges
                .iter()
                .map(|edge| edge.target.clone())
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
            Some(mutation_count)
        } else {
            None
        };
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
        if promote {
            let snapshot_id = completed_snapshot_id
                .as_deref()
                .context("completed scan did not create a snapshot")?;
            tx.execute(
                "INSERT INTO current_successful(singleton, scan_id) VALUES (1, ?1)
                 ON CONFLICT(singleton) DO UPDATE SET scan_id = excluded.scan_id",
                [scan_id],
            )?;
            promote_completed_snapshot(&tx, snapshot_id)?;
        }
        tx.commit()?;
        Ok(())
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
            let parent_id = record
                .parent_snapshot_id
                .as_deref()
                .or(overlay.scan.parent_snapshot_id.as_deref())
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
    for node in overlay.nodes {
        if let Some(existing) = snapshot.nodes.iter_mut().find(|item| item.id == node.id) {
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
    connection.execute(
        "INSERT INTO current_completed_snapshot(singleton, snapshot_id) VALUES (1, ?1)
         ON CONFLICT(singleton) DO UPDATE SET snapshot_id=excluded.snapshot_id",
        [snapshot_id],
    )?;
    Ok(())
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

fn ingest_event_in_transaction(tx: &Transaction<'_>, event: &Value) -> Result<()> {
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
        "dependency_site" => insert_site(tx, scan_id, required_object(event, "site")?)?,
        "edge_upsert" => insert_edge(tx, scan_id, required_object(event, "edge")?)?,
        "diagnostic" => {
            insert_diagnostic(tx, scan_id, adapter, required_object(event, "diagnostic")?)?
        }
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
    tx.execute(
        "INSERT INTO nodes(scan_id, id, kind, locator, display_name, properties_json, raw_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(scan_id, id) DO UPDATE SET
           kind=excluded.kind, locator=excluded.locator, display_name=excluded.display_name,
           properties_json=excluded.properties_json, raw_json=excluded.raw_json",
        params![
            scan_id,
            required_str(node, "id")?,
            required_str(node, "kind")?,
            required_str(node, "locator")?,
            display_name,
            serde_json::to_string(&properties)?,
            serde_json::to_string(node)?
        ],
    )?;
    Ok(())
}

fn insert_site(tx: &Transaction<'_>, scan_id: &str, site: &Value) -> Result<()> {
    upsert_site_row(tx, scan_id, site)?;
    insert_evidence(tx, scan_id, "site", required_str(site, "id")?, site)?;
    Ok(())
}

fn upsert_site_row(tx: &Transaction<'_>, scan_id: &str, site: &Value) -> Result<()> {
    let targets = site.get("target_ids").cloned().unwrap_or_else(|| json!([]));
    let condition = site
        .get("condition")
        .cloned()
        .unwrap_or_else(|| json!({"op":"all","conditions":[]}));
    tx.execute(
        "INSERT INTO sites(scan_id, id, source, kind, specifier, profile_id,
                           resolution_status, precision, condition_json, target_ids_json,
                           reason, raw_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(scan_id, id) DO UPDATE SET
           source=excluded.source, kind=excluded.kind, specifier=excluded.specifier,
           profile_id=excluded.profile_id, resolution_status=excluded.resolution_status,
           precision=excluded.precision, condition_json=excluded.condition_json,
           target_ids_json=excluded.target_ids_json, reason=excluded.reason, raw_json=excluded.raw_json",
        params![
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
            serde_json::to_string(site)?
        ],
    )?;
    Ok(())
}

fn insert_edge(tx: &Transaction<'_>, scan_id: &str, edge: &Value) -> Result<()> {
    upsert_edge_row(tx, scan_id, edge)?;
    insert_evidence(tx, scan_id, "edge", required_str(edge, "id")?, edge)?;
    Ok(())
}

fn upsert_edge_row(tx: &Transaction<'_>, scan_id: &str, edge: &Value) -> Result<()> {
    let condition = edge
        .get("condition")
        .cloned()
        .unwrap_or_else(|| json!({"op":"all","conditions":[]}));
    tx.execute(
        "INSERT INTO edges(scan_id, id, site_id, source, target, kind, phase, environment,
                           profile_id, resolution_status, precision, condition_json, generated, raw_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
         ON CONFLICT(scan_id, id) DO UPDATE SET
           site_id=excluded.site_id, source=excluded.source, target=excluded.target,
           kind=excluded.kind, phase=excluded.phase, environment=excluded.environment,
           profile_id=excluded.profile_id, resolution_status=excluded.resolution_status,
           precision=excluded.precision, condition_json=excluded.condition_json,
           generated=excluded.generated, raw_json=excluded.raw_json",
        params![
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
            serde_json::to_string(edge)?
        ],
    )?;
    Ok(())
}

fn insert_evidence(
    tx: &Transaction<'_>,
    scan_id: &str,
    owner_type: &str,
    owner_id: &str,
    object: &Value,
) -> Result<()> {
    tx.execute(
        "DELETE FROM evidence WHERE scan_id=?1 AND owner_type=?2 AND owner_id=?3",
        params![scan_id, owner_type, owner_id],
    )?;
    let evidence = object
        .get("evidence")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for (ordinal, item) in evidence.iter().enumerate() {
        tx.execute(
            "INSERT INTO evidence(scan_id, owner_type, owner_id, ordinal, kind, extractor,
                                  extractor_version, path, start_line, start_column,
                                  end_line, end_column, raw_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
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
            ],
        )?;
    }
    Ok(())
}

fn insert_diagnostic(
    tx: &Transaction<'_>,
    scan_id: &str,
    adapter: &str,
    diagnostic: &Value,
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
    insert_evidence(tx, scan_id, "diagnostic", &id, diagnostic)?;
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

fn load_profiles(connection: &Connection, scan_id: &str) -> Result<Vec<ProfileRecord>> {
    let mut statement = connection.prepare(
        "SELECT p.json, pc.json
           FROM profiles p
           LEFT JOIN profile_coverage pc
             ON pc.scan_id=p.scan_id AND pc.profile_id=p.id
          WHERE p.scan_id=?1 ORDER BY p.id",
    )?;
    let rows = statement.query_map([scan_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
    })?;
    rows.map(|row| {
        let (raw, raw_coverage) = row?;
        let value: Value = serde_json::from_str(&raw)?;
        Ok(ProfileRecord {
            id: required_str(&value, "id")?.to_owned(),
            language: required_str(&value, "language")?.to_owned(),
            toolchain: value.get("toolchain").cloned(),
            command: value
                .get("command")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            target: value
                .get("target")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            features: value
                .get("features")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect(),
            environment: value
                .get("environment")
                .cloned()
                .unwrap_or_else(|| json!({})),
            source_revision: value
                .get("source_revision")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            properties: value
                .get("properties")
                .cloned()
                .unwrap_or_else(|| json!({})),
            coverage: raw_coverage
                .map(|coverage| serde_json::from_str(&coverage))
                .transpose()?,
        })
    })
    .collect()
}

fn load_nodes(connection: &Connection, scan_id: &str) -> Result<Vec<NodeRecord>> {
    let mut statement = connection.prepare(
        "SELECT id, kind, locator, display_name, properties_json FROM nodes
         WHERE scan_id=?1 ORDER BY id",
    )?;
    let rows = statement.query_map([scan_id], |row| {
        let properties: String = row.get(4)?;
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            properties,
        ))
    })?;
    rows.map(|row| {
        let (id, kind, locator, display_name, properties) = row?;
        Ok(NodeRecord {
            id,
            kind,
            locator,
            display_name,
            properties: serde_json::from_str(&properties)?,
        })
    })
    .collect()
}

fn load_sites(connection: &Connection, scan_id: &str) -> Result<Vec<SiteRecord>> {
    let mut statement = connection.prepare(
        "SELECT id, source, kind, specifier, profile_id, resolution_status, precision,
                condition_json, target_ids_json, reason
         FROM sites WHERE scan_id=?1 ORDER BY id",
    )?;
    let rows = statement.query_map([scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, Option<String>>(9)?,
        ))
    })?;
    rows.map(|row| {
        let (
            id,
            source,
            kind,
            specifier,
            profile_id,
            status,
            precision,
            condition,
            targets,
            reason,
        ) = row?;
        Ok(SiteRecord {
            id,
            source,
            kind,
            specifier,
            profile_id,
            resolution_status: status,
            precision,
            condition: serde_json::from_str(&condition)?,
            target_ids: serde_json::from_str(&targets)?,
            reason,
        })
    })
    .collect()
}

fn load_edges(connection: &Connection, scan_id: &str) -> Result<Vec<EdgeRecord>> {
    let mut statement = connection.prepare(
        "SELECT id, site_id, source, target, kind, phase, environment, profile_id,
                resolution_status, precision, condition_json, generated
         FROM edges WHERE scan_id=?1 ORDER BY id",
    )?;
    let rows = statement.query_map([scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, String>(9)?,
            row.get::<_, String>(10)?,
            row.get::<_, bool>(11)?,
        ))
    })?;
    rows.map(|row| {
        let (
            id,
            site_id,
            source,
            target,
            kind,
            phase,
            environment,
            profile_id,
            status,
            precision,
            condition,
            generated,
        ) = row?;
        Ok(EdgeRecord {
            id,
            site_id,
            source,
            target,
            kind,
            phase,
            environment,
            profile_id,
            resolution_status: status,
            precision,
            condition: serde_json::from_str(&condition)?,
            generated,
        })
    })
    .collect()
}

fn load_evidence(connection: &Connection, scan_id: &str) -> Result<Vec<EvidenceRecord>> {
    let mut statement = connection.prepare(
        "SELECT owner_type, owner_id, ordinal, kind, extractor, extractor_version, path,
                start_line, start_column, end_line, end_column, raw_json
         FROM evidence WHERE scan_id=?1 ORDER BY owner_type, owner_id, ordinal",
    )?;
    let rows = statement.query_map([scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, u64>(7)?,
            row.get::<_, u64>(8)?,
            row.get::<_, u64>(9)?,
            row.get::<_, u64>(10)?,
            row.get::<_, String>(11)?,
        ))
    })?;
    rows.map(|row| {
        let (
            owner_type,
            owner_id,
            ordinal,
            kind,
            extractor,
            extractor_version,
            path,
            start_line,
            start_column,
            end_line,
            end_column,
            raw,
        ) = row?;
        let value: Value = serde_json::from_str(&raw)?;
        Ok(EvidenceRecord {
            owner_type,
            owner_id,
            ordinal,
            kind,
            extractor,
            extractor_version,
            path,
            start_line,
            start_column,
            end_line,
            end_column,
            detail: value
                .get("detail")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            properties: value
                .get("properties")
                .cloned()
                .unwrap_or_else(|| json!({})),
        })
    })
    .collect()
}

fn load_diagnostics(connection: &Connection, scan_id: &str) -> Result<Vec<DiagnosticRecord>> {
    let mut statement = connection.prepare(
        "SELECT ordinal, id, severity, code, message, path, adapter, raw_json
         FROM diagnostics WHERE scan_id=?1 ORDER BY ordinal",
    )?;
    let rows = statement.query_map([scan_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, String>(7)?,
        ))
    })?;
    rows.map(|row| {
        let (ordinal, id, severity, code, message, path, adapter, raw) = row?;
        let value: Value = serde_json::from_str(&raw)?;
        Ok(DiagnosticRecord {
            ordinal,
            id,
            severity,
            code,
            message,
            path,
            adapter,
            start_line: value.get("start_line").and_then(Value::as_u64),
            start_column: value.get("start_column").and_then(Value::as_u64),
            end_line: value.get("end_line").and_then(Value::as_u64),
            end_column: value.get("end_column").and_then(Value::as_u64),
            properties: value
                .get("properties")
                .cloned()
                .unwrap_or_else(|| json!({})),
        })
    })
    .collect()
}

fn load_file_coverage(connection: &Connection, scan_id: &str) -> Result<Vec<FileCoverageRecord>> {
    let mut statement = connection.prepare(
        "SELECT adapter, path, discovered_sites, emitted_sites, skipped_sites, skipped, reason
           FROM file_coverage WHERE scan_id=?1 ORDER BY adapter, path",
    )?;
    let rows = statement.query_map([scan_id], |row| {
        Ok(FileCoverageRecord {
            adapter: row.get(0)?,
            path: row.get(1)?,
            discovered_sites: row.get(2)?,
            emitted_sites: row.get(3)?,
            skipped_sites: row.get(4)?,
            skipped: row.get(5)?,
            reason: row.get(6)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn load_adapter_logs(connection: &Connection, scan_id: &str) -> Result<Vec<AdapterLogRecord>> {
    let mut statement = connection.prepare(
        "SELECT adapter, stderr, truncated FROM adapter_logs WHERE scan_id=?1 ORDER BY adapter",
    )?;
    let rows = statement.query_map([scan_id], |row| {
        Ok(AdapterLogRecord {
            adapter: row.get(0)?,
            stderr: row.get(1)?,
            truncated: row.get(2)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn observed_coverage(
    connection: &Connection,
    scan_id: &str,
    sites: &[SiteRecord],
    project_code_executed: bool,
    stored: Option<CoverageRecord>,
) -> Result<CoverageRecord> {
    let had_final_coverage = stored.is_some();
    let mut coverage = stored.unwrap_or_else(|| CoverageRecord {
        reasons: vec!["final worker coverage unavailable".to_owned()],
        ..CoverageRecord::default()
    });
    coverage.dependency_sites = sites.len() as u64;
    coverage.resolved = 0;
    coverage.candidates = 0;
    coverage.external = 0;
    coverage.unresolved = 0;
    for site in sites {
        match site.resolution_status.as_str() {
            "resolved" => coverage.resolved += 1,
            "candidates" => coverage.candidates += 1,
            "external" => coverage.external += 1,
            "unresolved" => coverage.unresolved += 1,
            _ => {}
        }
    }
    let (profiles, files, skipped): (i64, i64, i64) = connection.query_row(
        "SELECT
            (SELECT COUNT(*) FROM profiles WHERE scan_id=?1),
            (SELECT COUNT(*) FROM file_coverage WHERE scan_id=?1),
            (SELECT COALESCE(SUM(CASE WHEN skipped THEN 1 ELSE 0 END), 0)
               FROM file_coverage WHERE scan_id=?1)",
        [scan_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    coverage.profiles = profiles as u64;
    coverage.files_discovered = files as u64;
    coverage.files_skipped = skipped as u64;
    coverage.files_analyzed = (files - skipped) as u64;
    coverage.project_code_executed |= project_code_executed;
    if !had_final_coverage {
        coverage.completeness.clear();
    }
    Ok(coverage)
}

fn merge_coverage(mut left: Value, right: Value) -> Value {
    const COUNTERS: &[&str] = &[
        "profiles",
        "files_discovered",
        "files_analyzed",
        "files_skipped",
        "dependency_sites",
        "resolved",
        "candidates",
        "external",
        "unresolved",
        "unsupported_syntax",
    ];
    if !left.is_object() {
        left = json!({});
    }
    for field in COUNTERS {
        let total = left.get(*field).and_then(Value::as_u64).unwrap_or(0)
            + right.get(*field).and_then(Value::as_u64).unwrap_or(0);
        left[*field] = json!(total);
    }
    left["project_code_executed"] = json!(
        left.get("project_code_executed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || right
                .get("project_code_executed")
                .and_then(Value::as_bool)
                .unwrap_or(false)
    );
    let mut completeness = left
        .get("completeness")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let right_completeness = right
        .get("completeness")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    // Aggregate completeness is a guarantee about the entire scan. A level
    // is therefore retained only when every contributing worker reported it.
    completeness.retain(|level| right_completeness.contains(level));
    completeness.sort_by_key(Value::to_string);
    completeness.dedup();
    left["completeness"] = Value::Array(completeness);
    let mut reasons = left
        .get("reasons")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    reasons.extend(
        right
            .get("reasons")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    );
    reasons.sort_by_key(Value::to_string);
    reasons.dedup();
    left["reasons"] = Value::Array(reasons);
    left
}

#[cfg(test)]
mod tests {
    use super::*;
    use depgraph_protocol::{
        DependencySite, GraphEdge, build_edge_stable_id, build_site_stable_id,
        validate_build_ndjson,
    };
    use std::io::Cursor;

    const RUST_SEMANTIC_GOLDEN: &str = include_str!(
        "../../depgraph-protocol/tests/fixtures/protocol-v1.rust-semantic.golden.ndjson"
    );

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

    #[test]
    fn read_only_open_never_creates_a_missing_store() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("missing.db");
        let error = Store::open_read_only(&path).err().expect("missing store");
        assert!(error.to_string().contains("read-only"));
        assert!(!path.exists());
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
             DROP TABLE impact_query_cache;
             DROP TABLE cache_events;
             DROP TABLE syntax_cache;
             DROP TABLE semantic_cache;
             DROP TABLE build_cache;
             DROP TABLE incremental_deltas;
             DROP TABLE snapshot_names;
             DROP TABLE current_completed_snapshot;
             DROP TABLE snapshot_sources;
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
            "DROP TABLE impact_query_cache;
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
        assert_eq!(union.edges.len(), 2);
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
        let coverage = json!({
            "profiles":1,"files_discovered":0,"files_analyzed":0,"files_skipped":0,
            "dependency_sites":1,"resolved":1,"candidates":0,"external":0,
            "unresolved":0,"unsupported_syntax":0,"project_code_executed":true,
            "completeness":["build-observed"],"reasons":[]
        });
        let mut profile_completed = common("profile_completed", 7);
        profile_completed["profile_id"] = json!("web:build");
        profile_completed["coverage"] = coverage.clone();
        events.push(profile_completed);
        let mut completed = common("scan_completed", 8);
        completed["coverage"] = coverage;
        events.push(completed);
        events
            .into_iter()
            .map(|event| serde_json::to_string(&event).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    }
}
