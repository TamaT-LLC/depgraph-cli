//! Completed-snapshot storage seals and completed-snapshot creation,
//! loading, and promotion for the SQLite store.
//!
//! `SnapshotSealHasher` and the free functions built on it hash every row a
//! completed snapshot's closure can reach, so `create_completed_snapshot`,
//! `promote_completed_snapshot`, and friends can detect silent corruption of
//! immutable history. The remaining free functions load, reconstruct, and
//! promote `completed_snapshots` rows. Extracted from `lib.rs`
//! (REFACTOR-001-TASK-006) as a pure move -- no logic changes; the seal hash
//! computation is byte-for-byte unchanged. Functions and the CTE/hasher
//! helpers used only within this module stay private; the ones lib.rs and
//! sibling modules (`runtime`, `cache`, `incremental`, `schema`) call across
//! the module boundary are `pub(crate)`.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use depgraph_protocol::stable_id_from_value;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    BuildGraphDelta, COMPLETED_SNAPSHOT_SEAL_VERSION, CompletedSnapshotRecord, GraphSnapshot,
    LEGACY_COMPLETED_SNAPSHOT_SEAL_VERSION, ProfileMatrixRecord, ProfileRecord, ScanRecord,
    incremental, load_adapter_logs, load_diagnostics, load_edges, load_evidence,
    load_file_coverage, load_nodes, load_profiles, load_sites, merge_build_delta,
    observed_coverage, profile_matrix::refresh_profile_matrix, runtime, table_has_column,
};

#[derive(Clone, Copy)]
pub(crate) struct SnapshotSource<'a> {
    pub(crate) source_kind: &'a str,
    pub(crate) source_attempt_id: &'a str,
    pub(crate) scan_id: &'a str,
    pub(crate) build_attempt_id: Option<&'a str>,
    pub(crate) runtime_import_id: Option<&'a str>,
    pub(crate) runtime_session_ids: &'a [String],
    pub(crate) parent_snapshot_id: Option<&'a str>,
    pub(crate) source_revision: Option<&'a str>,
    pub(crate) created_at: &'a str,
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
    fn new(snapshot_id: &str, version: i64) -> Self {
        let mut hasher = Self(Sha256::new());
        hasher
            .write_bytes(format!("depgraph-completed-snapshot-storage-seal-v{version}").as_bytes());
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

fn completed_snapshot_storage_seal_with_version(
    connection: &Connection,
    snapshot_id: &str,
    version: i64,
    include_health_provenance: bool,
) -> Result<String> {
    let mut hasher = SnapshotSealHasher::new(snapshot_id, version);
    let scan_suffix = if include_health_provenance {
        "
SELECT scan.id, scan.root, scan.status, scan.strict, scan.started_at,
       scan.completed_at, scan.project_code_executed, scan.protocol_version,
       scan.error, scan.parent_snapshot_id, scan.source_revision,
       scan.mutation_count, scan.health_policy_config_digest,
       scan.health_analyzer_version, scan.health_finding_contract_version
  FROM scans AS scan
 WHERE scan.id IN (
       SELECT snapshot.scan_id
         FROM completed_snapshots AS snapshot
         JOIN snapshot_closure AS closure ON closure.id=snapshot.id
 )
 ORDER BY scan.id COLLATE BINARY"
    } else {
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
 ORDER BY scan.id COLLATE BINARY"
    };
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
        ("scans", scan_suffix),
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

fn completed_snapshot_storage_seal(connection: &Connection, snapshot_id: &str) -> Result<String> {
    completed_snapshot_storage_seal_with_version(
        connection,
        snapshot_id,
        COMPLETED_SNAPSHOT_SEAL_VERSION,
        true,
    )
}

pub(crate) fn verify_completed_snapshot_seal_v1(
    connection: &Connection,
    snapshot_id: &str,
) -> Result<()> {
    let expected = connection
        .query_row(
            "SELECT seal_sha256 FROM completed_snapshot_seals
              WHERE snapshot_id=?1 AND seal_version=?2",
            params![snapshot_id, LEGACY_COMPLETED_SNAPSHOT_SEAL_VERSION],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .with_context(|| format!("completed snapshot {snapshot_id} has no v1 storage seal"))?;
    let Some(expected) = expected else {
        bail!("completed snapshot {snapshot_id} has no v1 storage seal");
    };
    let observed = completed_snapshot_storage_seal_with_version(
        connection,
        snapshot_id,
        LEGACY_COMPLETED_SNAPSHOT_SEAL_VERSION,
        false,
    )?;
    if observed != expected {
        bail!("completed snapshot {snapshot_id} legacy storage seal mismatch");
    }
    Ok(())
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

pub(crate) fn persist_completed_snapshot_seal(
    connection: &Connection,
    snapshot_id: &str,
) -> Result<()> {
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

pub(crate) fn verify_completed_snapshot_seal(
    connection: &Connection,
    snapshot_id: &str,
) -> Result<()> {
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

fn backfill_completed_snapshot_seals_with_version(
    connection: &Connection,
    version: i64,
    include_health_provenance: bool,
) -> Result<()> {
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
        validate_completed_snapshot_for_seal(connection, &snapshot_id)
            .with_context(|| format!("failed to backfill storage seal for {snapshot_id}"))?;
        let observed = completed_snapshot_storage_seal_with_version(
            connection,
            &snapshot_id,
            version,
            include_health_provenance,
        )?;
        connection.execute(
            "INSERT INTO completed_snapshot_seals(snapshot_id, seal_version, seal_sha256)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(snapshot_id) DO NOTHING",
            params![snapshot_id, version, observed],
        )?;
    }
    Ok(())
}

pub(crate) fn backfill_completed_snapshot_seals(connection: &Connection) -> Result<()> {
    backfill_completed_snapshot_seals_with_version(
        connection,
        COMPLETED_SNAPSHOT_SEAL_VERSION,
        true,
    )
}

pub(crate) fn backfill_completed_snapshot_seals_v1(connection: &Connection) -> Result<()> {
    let existing_version = connection
        .query_row(
            "SELECT MIN(seal_version) FROM completed_snapshot_seals",
            [],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()?
        .flatten();
    if existing_version == Some(COMPLETED_SNAPSHOT_SEAL_VERSION) {
        // A test or an interrupted upgrade can reopen a database whose rows
        // already use the v2 seal while its user_version still advertises an
        // older schema.  Do not attempt to insert v1 rows into the v2 CHECK
        // constraint; the v18 step will authenticate them in place.
        return Ok(());
    }
    if existing_version.is_some_and(|version| version != LEGACY_COMPLETED_SNAPSHOT_SEAL_VERSION) {
        bail!("completed snapshot seals contain an unsupported version");
    }
    backfill_completed_snapshot_seals_with_version(
        connection,
        LEGACY_COMPLETED_SNAPSHOT_SEAL_VERSION,
        false,
    )
}

pub(crate) fn load_completed_snapshot_record(
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

pub(crate) fn load_base_snapshot_from_connection(
    connection: &Connection,
    scan_id: &str,
) -> Result<GraphSnapshot> {
    let health_columns_available =
        table_has_column(connection, "scans", "health_policy_config_digest")?;
    let health_projection = if health_columns_available {
        "health_policy_config_digest, health_analyzer_version,
                    health_finding_contract_version"
    } else {
        "NULL AS health_policy_config_digest, NULL AS health_analyzer_version,
                    NULL AS health_finding_contract_version"
    };
    let scan_query = format!(
        "SELECT id, root, status, strict, started_at, completed_at,
                    project_code_executed, error, parent_snapshot_id, source_revision,
                    {health_projection}
               FROM scans WHERE id=?1"
    );
    let scan = connection
        .query_row(&scan_query, [scan_id], |row| {
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
                health_policy_config_digest: row.get(10)?,
                health_analyzer_version: row.get(11)?,
                health_finding_contract_version: row.get(12)?,
            })
        })
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

pub(crate) fn load_completed_snapshot_from_connection(
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

pub(crate) fn load_completed_snapshot_profiles_from_connection(
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
                let mut snapshot = load_completed_snapshot_from_connection(connection, &current)?;
                std::mem::take(&mut snapshot.profiles)
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

fn apply_semantic_noop_overlay(
    snapshot: &mut GraphSnapshot,
    mut overlay: GraphSnapshot,
) -> Result<()> {
    if overlay.nodes.len() != 1 {
        bail!("semantic no-op overlay must persist exactly one node");
    }
    for node in std::mem::take(&mut overlay.nodes) {
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
    for log in std::mem::take(&mut overlay.adapter_logs) {
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
    snapshot.scan = overlay.scan.clone();
    snapshot.nodes.sort_by(|left, right| left.id.cmp(&right.id));
    snapshot
        .adapter_logs
        .sort_by(|left, right| left.adapter.cmp(&right.adapter));
    refresh_profile_matrix(snapshot, false);
    Ok(())
}

pub(crate) fn completed_snapshot_identity(
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

pub(crate) fn create_completed_snapshot(
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

pub(crate) fn promote_completed_snapshot(connection: &Connection, snapshot_id: &str) -> Result<()> {
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

pub(crate) fn promote_completed_snapshot_if_current_parent(
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

pub(crate) fn backfill_completed_snapshots(connection: &Connection) -> Result<()> {
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
