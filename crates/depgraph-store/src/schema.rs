//! Schema migrations and schema/row validation for the SQLite store.
//!
//! `Store::migrate` owns every `PRAGMA user_version` transition (v1 through
//! v17) and the DDL statements each step applies. The free functions
//! alongside it authenticate a pre-migration store's shape and validate that
//! a migrated schema -- and, where a migration also captures existing rows,
//! those rows -- exactly match the expected shape. Extracted from `lib.rs`
//! (REFACTOR-001-TASK-005) as a pure move -- no logic changes. Functions and
//! constants used only within this module stay private; the ones lib.rs and
//! the crate's test module call across the module boundary are
//! `pub(crate)`.

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};

use crate::{
    LEGACY_RUNTIME_IMPORT_OWNER_PREFIX, LEGACY_SCAN_OPERATION_CANDIDATE_PREFIX,
    LegacyRuntimeImportCandidate, LegacyScanOperationCandidate, STORE_CACHE_SIZE_KIB,
    STORE_PAGE_SIZE_BYTES, STORE_SCHEMA_VERSION, Store, backfill_completed_snapshot_seals,
    backfill_completed_snapshots, legacy_runtime_import_owner_id,
    legacy_scan_operation_candidate_id, load_scan_operation_recovery_binding_from,
    validate_internal_scan_operation_binding, validate_legacy_scan_operation_candidate,
};

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

impl Store {
    pub(crate) fn migrate(&mut self) -> Result<()> {
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

pub(crate) fn validate_runtime_import_operation_ownership_schema_and_rows(
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

pub(crate) fn validate_scan_operation_staging_schema_and_rows(
    connection: &Connection,
) -> Result<()> {
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

pub(crate) fn validate_store_foreign_keys(connection: &Connection, version: i64) -> Result<()> {
    let violations =
        connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get::<_, u64>(0)
        })?;
    if violations != 0 {
        bail!("store schema {version} migration left {violations} foreign key violations");
    }
    Ok(())
}

pub(crate) fn table_has_column(connection: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    for candidate in columns {
        if candidate? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn table_exists(connection: &Connection, table: &str) -> Result<bool> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}
