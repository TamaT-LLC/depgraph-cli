//! Bounded, range-oriented read access for snapshot-scoped health analysis.
//!
//! The whole-snapshot health path materializes every node, edge, site, and
//! evidence record before a single subject is analyzed. This module lets the
//! core health analyzer plan a partition of the subject id space from SQL
//! aggregates only, then load the inbound side of each range directly by
//! target. Range boundaries are an execution partition, not a semantic one:
//! every subject still sees all of its inbound edges and sites regardless of
//! which range the sources belong to, so a target used only from a later range
//! is never mistaken for an unused subject.
//!
//! All loaders charge one budget step per materialized row through
//! [`HealthWorkBudget`], so a caller can bound each phase independently and
//! fail fast before a range is fully resident.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    CoverageRecord, EdgeRecord, GraphSnapshot, NodeRecord, ProfileMatrixRecord, ProfileRecord,
    ScanRecord, SiteRecord, Store, incremental, profile_matrix::refresh_profile_matrix,
    read::load_profiles, snapshot::load_completed_snapshot_record,
};

/// Contract version of [`HealthRangePlan`] and of the digests derived from it.
pub const HEALTH_RANGE_PLAN_CONTRACT_VERSION: &str = "depgraph-health-range-plan-v1";

/// Node kinds that become health subjects.
const SUBJECT_KINDS_SQL: &str = "('file', 'symbol', 'type')";

/// Estimated work per subject, inbound edge, inbound site, and Go profile.
///
/// The constants deliberately over-approximate the analyzer's per-row steps
/// so a planned range normally finishes inside its budget; an overrun is
/// recovered by re-splitting the range, never by raising a limit.
pub const HEALTH_RANGE_ESTIMATE_PER_SUBJECT: u64 = 6;
pub const HEALTH_RANGE_ESTIMATE_PER_EDGE: u64 = 6;
pub const HEALTH_RANGE_ESTIMATE_PER_SITE: u64 = 3;
pub const HEALTH_RANGE_ESTIMATE_PER_GO_PROFILE: u64 = 3;

/// A range is closed once its estimate reaches `per_range_work / SAFETY`.
const HEALTH_RANGE_ESTIMATE_SAFETY_DIVISOR: u64 = 2;

const SQL_BATCH_SIZE: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HealthWorkError {
    #[error("health range work was cancelled")]
    Cancelled,
    #[error("health range work exhausted its bounded budget")]
    ResourceExhausted,
}

/// Per-phase work accounting supplied by the caller.
///
/// Every materialized row costs one step. Implementations decide the budget
/// and the cancellation source; the store only reports the outcome.
pub trait HealthWorkBudget {
    fn step(&mut self) -> std::result::Result<(), HealthWorkError>;
}

/// Simple counting budget without an external cancellation source.
#[derive(Clone, Debug)]
pub struct CountingHealthWorkBudget {
    used: u64,
    maximum: u64,
}

impl CountingHealthWorkBudget {
    #[must_use]
    pub const fn new(maximum: u64) -> Self {
        Self { used: 0, maximum }
    }

    #[must_use]
    pub const fn used(&self) -> u64 {
        self.used
    }
}

impl HealthWorkBudget for CountingHealthWorkBudget {
    fn step(&mut self) -> std::result::Result<(), HealthWorkError> {
        if self.used >= self.maximum {
            return Err(HealthWorkError::ResourceExhausted);
        }
        self.used += 1;
        Ok(())
    }
}

/// Find the typed budget outcome inside an `anyhow` error chain.
#[must_use]
pub fn health_work_error(error: &anyhow::Error) -> Option<HealthWorkError> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<HealthWorkError>().copied())
}

fn charge(budget: &mut dyn HealthWorkBudget) -> Result<()> {
    budget.step().map_err(anyhow::Error::from)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthRangeLimits {
    /// Work budget of each phase and each range (unchanged production constant).
    pub per_range_work: u64,
    /// Maximum number of planned ranges, including re-splits.
    pub max_ranges: u32,
    /// Maximum rows the planner may read before failing closed.
    pub planner_rows: u64,
    /// Maximum times a range that overran its budget may be split in half.
    pub max_resplit_depth: u8,
}

/// Which snapshot input a health request addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthInputSelector<'a> {
    CompletedSnapshot(&'a str),
    Attempt(&'a str),
}

/// One layer of a completed snapshot's reconstruction chain, top-down.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HealthLayer {
    Scan {
        scan_id: String,
    },
    SemanticNoop {
        scan_id: String,
        parent_snapshot_id: String,
    },
    BuildDelta {
        attempt_id: String,
        base_scan_id: String,
    },
    RuntimeSessions {
        session_ids: Vec<String>,
    },
}

/// Resolved identity of one health input, fixed before any heavy read.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthInputIdentity {
    pub snapshot_id: Option<String>,
    pub attempt_id: Option<String>,
    /// Scan whose normalized tables hold the base graph.
    pub base_scan_id: String,
    /// Reconstruction layers, top-down. A plain snapshot has exactly one
    /// `Scan` layer.
    pub layers: Vec<HealthLayer>,
    pub layer_digest: String,
    /// Bound for `attempt:` inputs so a staging scan that progressed never
    /// reuses stale range results.
    pub staging_fingerprint: Option<String>,
    pub analysis_plan_id: Option<String>,
    pub analysis_input_digest: Option<String>,
}

impl HealthInputIdentity {
    /// A plain input reads one scan's normalized tables without overlays and
    /// can therefore be planned and loaded by target-keyed ranges.
    #[must_use]
    pub fn is_plain(&self) -> bool {
        matches!(self.layers.as_slice(), [HealthLayer::Scan { .. }])
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthTargetStats {
    pub nodes_by_kind: BTreeMap<String, u64>,
    pub subjects: u64,
    pub edges: u64,
    pub sites: u64,
    pub site_targets: u64,
    pub targetless_sites: u64,
    pub evidence: u64,
    pub profiles: u64,
    pub go_profiles: u64,
    pub go_module_nodes: u64,
    pub manifest_sites: u64,
    pub ledger_incomplete_units: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RangeSplitReason {
    BudgetReached,
    Tail,
    ResplitAfterOverrun { parent: u32, depth: u8 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthRange {
    pub index: u32,
    /// Inclusive lower bound of the sorted subject id interval.
    pub first_subject_id: String,
    /// Inclusive upper bound of the sorted subject id interval.
    pub last_subject_id: String,
    pub subject_count: u64,
    pub inbound_edge_count: u64,
    pub inbound_site_count: u64,
    pub estimated_work: u64,
    pub split_reason: RangeSplitReason,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthRangePlan {
    pub contract_version: String,
    pub identity: HealthInputIdentity,
    pub limits: HealthRangeLimits,
    pub stats: HealthTargetStats,
    pub ranges: Vec<HealthRange>,
    pub plan_digest: String,
    pub planner_work_used: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthTargetlessSiteFlags {
    pub candidate: bool,
    pub unresolved: bool,
    pub dynamic: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthLedgerUnit {
    pub unit_id: String,
    pub stage: String,
    pub chunk_id: String,
    pub status: String,
}

/// Snapshot-wide health inputs that every range shares.
///
/// Everything here is O(profiles + Go packages + skipped files); the graph
/// itself is never loaded through this projection.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct HealthGlobalInput {
    pub scan: ScanRecord,
    pub profiles: Vec<ProfileRecord>,
    pub profile_matrix: ProfileMatrixRecord,
    pub coverage: CoverageRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_dependency_coverage: Option<crate::AnalysisDependencyCoverage>,
    /// `file_coverage` paths that were skipped or unsupported.
    pub coverage_omitted_paths: Vec<String>,
    /// Distinct `language` values of subject nodes; `None` marks subjects
    /// without a string language.
    pub subject_languages: Vec<Option<String>>,
    /// Go module/package nodes (identity source for package scopes).
    pub go_module_nodes: Vec<NodeRecord>,
    /// Every edge whose target is a Go module node (package projection input).
    pub go_package_edges: Vec<EdgeRecord>,
    /// `candidates` sites with at least one Go module node target.
    pub go_candidate_sites: Vec<SiteRecord>,
    pub targetless_sites: HealthTargetlessSiteFlags,
    pub ledger_incomplete_units: Vec<HealthLedgerUnit>,
    pub ledger_incomplete_unit_count: u64,
    pub work_used: u64,
}

impl HealthGlobalInput {
    /// Stable digest of the shared context; range checkpoints are bound to it.
    #[must_use]
    pub fn digest(&self) -> String {
        let payload = json!({
            "analysis_dependency_coverage": self.analysis_dependency_coverage,
            "coverage": self.coverage,
            "coverage_omitted_paths": self.coverage_omitted_paths,
            "go_candidate_sites": self.go_candidate_sites,
            "go_module_nodes": self.go_module_nodes,
            "go_package_edges": self.go_package_edges,
            "ledger_incomplete_unit_count": self.ledger_incomplete_unit_count,
            "ledger_incomplete_units": self.ledger_incomplete_units,
            "profile_matrix_entries": self
                .profile_matrix
                .entries
                .iter()
                .map(|entry| json!({
                    "id": entry.id,
                    "language": entry.language,
                    "profile_ids": entry.profile_ids,
                }))
                .collect::<Vec<_>>(),
            "profiles": self.profiles,
            "scan_status": self.scan.status,
            "subject_languages": self.subject_languages,
            "targetless_sites": self.targetless_sites,
        });
        sha256_hex(depgraph_protocol::canonical_json(&payload).as_bytes())
    }
}

/// The subjects of one range and their complete inbound side.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct HealthRangeInput {
    pub range: HealthRange,
    pub subjects: Vec<NodeRecord>,
    /// Edges whose target is in the range, ordered by edge id.
    pub inbound_edges: Vec<EdgeRecord>,
    /// Sites with at least one target in the range, ordered by site id.
    pub inbound_sites: Vec<SiteRecord>,
    /// Sites in `inbound_sites` that carry dynamic-import evidence.
    pub dynamic_site_ids: BTreeSet<String>,
    pub work_used: u64,
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(bytes)))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn load_scan_record(connection: &Connection, scan_id: &str) -> Result<ScanRecord> {
    connection
        .query_row(
            "SELECT id, root, status, strict, started_at, completed_at,
                    project_code_executed, error, parent_snapshot_id, source_revision,
                    health_policy_config_digest, health_analyzer_version,
                    health_finding_contract_version
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
                    health_policy_config_digest: row.get(10)?,
                    health_analyzer_version: row.get(11)?,
                    health_finding_contract_version: row.get(12)?,
                })
            },
        )
        .optional()?
        .with_context(|| format!("scan {scan_id} was not found"))
}

/// The coverage record a whole-snapshot load derives (`read::observed_coverage`),
/// computed from SQL counts instead of materialized sites.
fn observed_coverage_sql(
    connection: &Connection,
    scan_id: &str,
    project_code_executed: bool,
) -> Result<CoverageRecord> {
    let stored = connection
        .query_row(
            "SELECT json FROM coverage WHERE scan_id=?1",
            [scan_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|raw| serde_json::from_str::<CoverageRecord>(&raw))
        .transpose()?;
    let had_final_coverage = stored.is_some();
    let mut coverage = stored.unwrap_or_else(|| CoverageRecord {
        reasons: vec!["final worker coverage unavailable".to_owned()],
        ..CoverageRecord::default()
    });
    (
        coverage.dependency_sites,
        coverage.resolved,
        coverage.candidates,
        coverage.external,
        coverage.unresolved,
    ) = connection.query_row(
        "SELECT COUNT(*),
                COALESCE(SUM(resolution_status='resolved'), 0),
                COALESCE(SUM(resolution_status='candidates'), 0),
                COALESCE(SUM(resolution_status='external'), 0),
                COALESCE(SUM(resolution_status='unresolved'), 0)
           FROM sites WHERE scan_id=?1",
        [scan_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    let (profiles, files, skipped): (u64, u64, u64) = connection.query_row(
        "SELECT
            (SELECT COUNT(*) FROM profiles WHERE scan_id=?1),
            (SELECT COUNT(*) FROM file_coverage WHERE scan_id=?1),
            (SELECT COALESCE(SUM(CASE WHEN skipped THEN 1 ELSE 0 END), 0)
               FROM file_coverage WHERE scan_id=?1)",
        [scan_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    coverage.profiles = profiles;
    coverage.files_discovered = files;
    coverage.files_skipped = skipped;
    coverage.files_analyzed = files.saturating_sub(skipped);
    coverage.project_code_executed |= project_code_executed;
    if !had_final_coverage {
        coverage.completeness.clear();
    }
    Ok(coverage)
}

fn analysis_plan_identity(
    connection: &Connection,
    scan_id: &str,
) -> Result<(Option<String>, Option<String>)> {
    Ok(connection
        .query_row(
            "SELECT plan_id, input_digest FROM analysis_scan_metadata WHERE scan_id=?1",
            [scan_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .optional()?
        .unwrap_or((None, None)))
}

fn staging_fingerprint(connection: &Connection, scan: &ScanRecord) -> Result<String> {
    let (nodes, edges, sites, evidence): (u64, u64, u64, u64) = connection.query_row(
        "SELECT (SELECT COUNT(*) FROM nodes WHERE scan_id=?1),
                (SELECT COUNT(*) FROM edges WHERE scan_id=?1),
                (SELECT COUNT(*) FROM sites WHERE scan_id=?1),
                (SELECT COUNT(*) FROM evidence WHERE scan_id=?1)",
        [&scan.id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let mut ledger = connection.prepare(
        "SELECT unit_id, unit_root, stage, chunk_id, status, reused
           FROM analysis_unit_ledger WHERE scan_id=?1
          ORDER BY unit_id COLLATE BINARY, unit_root COLLATE BINARY,
                   stage COLLATE BINARY, chunk_id COLLATE BINARY",
    )?;
    let ledger_rows = ledger
        .query_map([&scan.id], |row| {
            Ok(json!([
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, bool>(5)?,
            ]))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let payload = json!({
        "completed_at": scan.completed_at,
        "counts": [nodes, edges, sites, evidence],
        "error": scan.error,
        "ledger": ledger_rows,
        "status": scan.status,
    });
    Ok(sha256_hex(
        depgraph_protocol::canonical_json(&payload).as_bytes(),
    ))
}

fn resolve_completed_layers(
    connection: &Connection,
    snapshot_id: &str,
    layers: &mut Vec<HealthLayer>,
    visited: &mut BTreeSet<String>,
) -> Result<String> {
    if !visited.insert(snapshot_id.to_owned()) {
        bail!("completed snapshot parent cycle detected while resolving health input");
    }
    let record = load_completed_snapshot_record(connection, snapshot_id)?
        .with_context(|| format!("completed snapshot {snapshot_id} was not found"))?;
    let semantic_noop = record.build_attempt_id.is_none()
        && record.runtime_session_ids.is_empty()
        && incremental::scan_is_semantic_noop_overlay(connection, &record.scan_id)?;
    if semantic_noop {
        let parent_id = record
            .parent_snapshot_id
            .clone()
            .context("semantic no-op overlay has no parent completed snapshot")?;
        layers.push(HealthLayer::SemanticNoop {
            scan_id: record.scan_id.clone(),
            parent_snapshot_id: parent_id.clone(),
        });
        return resolve_completed_layers(connection, &parent_id, layers, visited);
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
        layers.push(HealthLayer::RuntimeSessions {
            session_ids: new_runtime_ids,
        });
    }
    if let Some(attempt_id) = &record.build_attempt_id
        && parent_record
            .as_ref()
            .and_then(|parent| parent.build_attempt_id.as_deref())
            != Some(attempt_id.as_str())
    {
        layers.push(HealthLayer::BuildDelta {
            attempt_id: attempt_id.clone(),
            base_scan_id: record.scan_id.clone(),
        });
    }
    if layered && let Some(parent_id) = record.parent_snapshot_id.as_deref() {
        return resolve_completed_layers(connection, parent_id, layers, visited);
    }
    if incremental::scan_is_semantic_noop_overlay(connection, &record.scan_id)? {
        let parent_id = connection
            .query_row(
                "SELECT parent_snapshot_id FROM scans WHERE id=?1",
                [&record.scan_id],
                |row| row.get::<_, Option<String>>(0),
            )?
            .context("semantic no-op overlay has no parent completed snapshot")?;
        layers.push(HealthLayer::SemanticNoop {
            scan_id: record.scan_id.clone(),
            parent_snapshot_id: parent_id.clone(),
        });
        return resolve_completed_layers(connection, &parent_id, layers, visited);
    }
    layers.push(HealthLayer::Scan {
        scan_id: record.scan_id.clone(),
    });
    Ok(record.scan_id)
}

fn layer_digest(layers: &[HealthLayer]) -> String {
    sha256_hex(depgraph_protocol::canonical_json(&json!(layers)).as_bytes())
}

/// Sorted cursor over `(key, count)` rows.
struct CountCursor<'conn> {
    rows: rusqlite::Rows<'conn>,
    current: Option<(String, u64)>,
}

impl CountCursor<'_> {
    fn advance(&mut self) -> Result<()> {
        self.current = match self.rows.next()? {
            Some(row) => Some((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
            None => None,
        };
        Ok(())
    }

    /// Return the count for `key`, consuming every row with a smaller key.
    fn count_for(&mut self, key: &str, rows_read: &mut u64) -> Result<u64> {
        loop {
            match &self.current {
                Some((current, count)) if current.as_str() == key => {
                    let count = *count;
                    *rows_read += 1;
                    self.advance()?;
                    return Ok(count);
                }
                Some((current, _)) if current.as_str() < key => {
                    *rows_read += 1;
                    self.advance()?;
                }
                _ => return Ok(0),
            }
        }
    }
}

const SITE_TARGETS_TABLE: &str = "temp.health_site_targets";

/// Sites projected per batch. Each batch charges its target rows to the
/// budget before inserting them, so the projection never grows past the
/// budget and cancellation is observed between batches.
const SITE_TARGET_PROJECTION_BATCH: i64 = 2_048;

/// Build (or reuse) the temporary `site_id -> target_id` projection for one
/// scan. Sites store their targets as a JSON array without an index, so the
/// projection turns per-range site fetches into index range scans.
///
/// Every projected row is one step of `budget`; a budget failure drops the
/// partial projection before the error is returned. A projection that already
/// exists for `scan_id` is reused without charging; callers that must account
/// for its rows (the planner) do so from the reported row count.
fn ensure_site_target_projection(
    connection: &Connection,
    scan_id: &str,
    budget: &mut dyn HealthWorkBudget,
) -> Result<SiteTargetProjection> {
    let existing = connection
        .query_row(
            "SELECT name FROM sqlite_temp_master WHERE type='table' AND name='health_site_targets_scan'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if existing.is_some() {
        let current = connection
            .query_row(
                "SELECT scan_id, row_count FROM temp.health_site_targets_scan",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)),
            )
            .optional()?;
        if let Some((current_scan, rows)) = current
            && current_scan == scan_id
        {
            return Ok(SiteTargetProjection { rows, reused: true });
        }
    }
    connection.execute_batch(&format!(
        "DROP TABLE IF EXISTS {SITE_TARGETS_TABLE};
         DROP TABLE IF EXISTS temp.health_site_targets_scan;
         CREATE TEMP TABLE health_site_targets (target_id TEXT NOT NULL, site_id TEXT NOT NULL);
         CREATE TEMP TABLE health_site_targets_scan (scan_id TEXT NOT NULL, row_count INTEGER NOT NULL);"
    ))?;
    let inserted = match project_site_targets(connection, scan_id, budget) {
        Ok(inserted) => inserted,
        Err(error) => {
            // Never leave a half-built projection behind; a later request
            // would otherwise trust its row count.
            let _ = release_site_target_projection(connection);
            return Err(error);
        }
    };
    connection.execute_batch(
        "CREATE INDEX temp.health_site_targets_target ON health_site_targets(target_id, site_id);",
    )?;
    connection.execute(
        "INSERT INTO temp.health_site_targets_scan(scan_id, row_count) VALUES (?1, ?2)",
        params![scan_id, inserted],
    )?;
    Ok(SiteTargetProjection {
        rows: inserted,
        reused: false,
    })
}

struct SiteTargetProjection {
    rows: u64,
    /// The table already existed for this scan, so no row was charged.
    reused: bool,
}

/// Fill the projection in primary-key order, one bounded batch of sites at a
/// time. The batch's target count is charged before its rows are inserted so
/// an exhausted budget stops the projection without materializing the batch.
fn project_site_targets(
    connection: &Connection,
    scan_id: &str,
    budget: &mut dyn HealthWorkBudget,
) -> Result<u64> {
    let mut batch_statement = connection.prepare(
        "SELECT id, json_array_length(target_ids_json) FROM sites
          WHERE scan_id=?1 AND id>?2 ORDER BY id LIMIT ?3",
    )?;
    let mut insert_statement = connection.prepare(&format!(
        "INSERT INTO {SITE_TARGETS_TABLE}(target_id, site_id)
         SELECT CAST(target.value AS TEXT), site.id
           FROM sites AS site, json_each(site.target_ids_json) AS target
          WHERE site.scan_id=?1 AND site.id>?2 AND site.id<=?3"
    ))?;
    let mut inserted = 0_u64;
    let mut cursor = String::new();
    loop {
        let mut last: Option<String> = None;
        let mut targets = 0_u64;
        let mut sites = 0_i64;
        let mut rows = batch_statement.query(params![
            scan_id,
            cursor.as_str(),
            SITE_TARGET_PROJECTION_BATCH
        ])?;
        while let Some(row) = rows.next()? {
            last = Some(row.get::<_, String>(0)?);
            targets += row.get::<_, Option<u64>>(1)?.unwrap_or(0);
            sites += 1;
        }
        drop(rows);
        let Some(last) = last else {
            break;
        };
        for _ in 0..targets {
            charge(budget)?;
        }
        inserted +=
            insert_statement.execute(params![scan_id, cursor.as_str(), last.as_str()])? as u64;
        cursor = last;
        if sites < SITE_TARGET_PROJECTION_BATCH {
            break;
        }
    }
    Ok(inserted)
}

/// Planner-side budget: counts projected rows toward `planner_rows` and polls
/// cancellation at the same 4,096-row cadence as the rest of the planner.
struct PlannerRowBudget<'a> {
    rows_read: &'a mut u64,
    limit: u64,
    cancelled: &'a mut dyn FnMut() -> bool,
}

impl HealthWorkBudget for PlannerRowBudget<'_> {
    fn step(&mut self) -> std::result::Result<(), HealthWorkError> {
        *self.rows_read += 1;
        if *self.rows_read > self.limit {
            return Err(HealthWorkError::ResourceExhausted);
        }
        if self.rows_read.is_multiple_of(4096) && (self.cancelled)() {
            return Err(HealthWorkError::Cancelled);
        }
        Ok(())
    }
}

fn release_site_target_projection(connection: &Connection) -> Result<()> {
    connection.execute_batch(&format!(
        "DROP TABLE IF EXISTS {SITE_TARGETS_TABLE};
         DROP TABLE IF EXISTS temp.health_site_targets_scan;"
    ))?;
    Ok(())
}

fn node_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(String, String, String, String, String)> {
    Ok((
        row.get::<_, String>(0)?,
        row.get::<_, String>(1)?,
        row.get::<_, String>(2)?,
        row.get::<_, String>(3)?,
        row.get::<_, String>(4)?,
    ))
}

fn finish_node(
    (id, kind, locator, display_name, properties): (String, String, String, String, String),
) -> Result<NodeRecord> {
    Ok(NodeRecord {
        id,
        kind,
        locator,
        display_name,
        properties: serde_json::from_str(&properties)?,
    })
}

const NODE_COLUMNS: &str = "id, kind, locator, display_name, properties_json";
const EDGE_COLUMNS: &str = "id, site_id, source, target, kind, phase, environment, profile_id,
                resolution_status, precision, condition_json, generated";
const SITE_COLUMNS: &str = "id, source, kind, specifier, profile_id, resolution_status, precision,
                condition_json, target_ids_json, reason";

const DEPENDENCY_SITE_KINDS_SQL: &str = "('cargo_dependency', 'module_requirement',
    'package_dependency', 'package_peer_dependency', 'package_optional_dependency')";

fn dependency_string_property(key: &str) -> String {
    format!(
        "CASE WHEN json_type(properties_json, '$.{key}')='text'
              THEN json_extract(properties_json, '$.{key}') END"
    )
}

/// Mirrors the dependency analyzer's string-only package-name precedence.
/// Differential core tests exercise this SQL path against the full analyzer.
fn dependency_package_name_sql() -> String {
    let go = ["import_path", "package_path", "module_path"]
        .map(dependency_string_property)
        .join(",");
    let fallback = [
        "name",
        "package",
        "package_name",
        "module_path",
        "import_path",
    ]
    .map(dependency_string_property)
    .join(",");
    format!(
        "COALESCE(CASE WHEN json_extract(properties_json, '$.language')='go'
                            OR json_extract(properties_json, '$.ecosystem')='go'
                       THEN COALESCE({go}) END, {fallback})"
    )
}

/// Manifest discovery observes every manifest_path; drift only consults
/// hashes attached to those paths or the three default manifest names.
/// Keep real representatives of distinct relevant observations, plus every
/// declaration source/target, without materializing unrelated graph nodes.
fn dependency_metadata_nodes_sql() -> String {
    let manifest = dependency_string_property("manifest_path");
    let path = dependency_string_property("path");
    let hash = format!(
        "COALESCE({}, {})",
        dependency_string_property("content_hash"),
        dependency_string_property("content_digest")
    );
    format!(
        "WITH observations AS NOT MATERIALIZED (
             SELECT id, {manifest} AS manifest_path, {path} AS path, {hash} AS content_hash
               FROM nodes WHERE scan_id=?1
         ), manifest_paths(path) AS (
             SELECT manifest_path FROM observations WHERE manifest_path IS NOT NULL
             UNION SELECT 'Cargo.toml' UNION SELECT 'go.mod' UNION SELECT 'package.json'
         ), relevant AS NOT MATERIALIZED (
             SELECT id, manifest_path, content_hash,
                    CASE WHEN content_hash IS NOT NULL AND path IN (SELECT path FROM manifest_paths)
                         THEN path END AS hash_path
               FROM observations
         )
         SELECT {NODE_COLUMNS} FROM nodes WHERE scan_id=?1 AND id IN (
             SELECT MIN(id) FROM relevant WHERE manifest_path IS NOT NULL OR hash_path IS NOT NULL
               GROUP BY manifest_path, content_hash, hash_path
             UNION SELECT source FROM sites WHERE scan_id=?1 AND kind IN {DEPENDENCY_SITE_KINDS_SQL}
             UNION SELECT CAST(target.value AS TEXT) FROM sites, json_each(target_ids_json) AS target
               WHERE scan_id=?1 AND kind IN {DEPENDENCY_SITE_KINDS_SQL}
         ) ORDER BY id"
    )
}

type EdgeRow = (
    String,
    Option<String>,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    bool,
);

fn edge_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EdgeRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
    ))
}

fn finish_edge(row: EdgeRow) -> Result<EdgeRecord> {
    let (
        id,
        site_id,
        source,
        target,
        kind,
        phase,
        environment,
        profile_id,
        resolution_status,
        precision,
        condition,
        generated,
    ) = row;
    Ok(EdgeRecord {
        id,
        site_id,
        source,
        target,
        kind,
        phase,
        environment,
        profile_id,
        resolution_status,
        precision,
        condition: serde_json::from_str(&condition)?,
        generated,
    })
}

type SiteRow = (
    String,
    String,
    String,
    Option<String>,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
);

fn site_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SiteRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
    ))
}

fn finish_site(row: SiteRow) -> Result<SiteRecord> {
    let (
        id,
        source,
        kind,
        specifier,
        profile_id,
        resolution_status,
        precision,
        condition,
        target_ids,
        reason,
    ) = row;
    Ok(SiteRecord {
        id,
        source,
        kind,
        specifier,
        profile_id,
        resolution_status,
        precision,
        condition: serde_json::from_str(&condition)?,
        target_ids: serde_json::from_str(&target_ids)?,
        reason,
    })
}

fn query_nodes_charged(
    connection: &Connection,
    sql: &str,
    parameters: &[&dyn rusqlite::ToSql],
    budget: &mut dyn HealthWorkBudget,
    out: &mut Vec<NodeRecord>,
) -> Result<()> {
    let mut statement = connection.prepare(sql)?;
    let mut rows = statement.query(parameters)?;
    while let Some(row) = rows.next()? {
        charge(budget)?;
        out.push(finish_node(node_from_row(row)?)?);
    }
    Ok(())
}

fn query_edges_charged(
    connection: &Connection,
    sql: &str,
    parameters: &[&dyn rusqlite::ToSql],
    budget: &mut dyn HealthWorkBudget,
    out: &mut Vec<EdgeRecord>,
) -> Result<()> {
    let mut statement = connection.prepare(sql)?;
    let mut rows = statement.query(parameters)?;
    while let Some(row) = rows.next()? {
        charge(budget)?;
        out.push(finish_edge(edge_from_row(row)?)?);
    }
    Ok(())
}

fn query_sites_charged(
    connection: &Connection,
    sql: &str,
    parameters: &[&dyn rusqlite::ToSql],
    budget: &mut dyn HealthWorkBudget,
    out: &mut Vec<SiteRecord>,
) -> Result<()> {
    let mut statement = connection.prepare(sql)?;
    let mut rows = statement.query(parameters)?;
    while let Some(row) = rows.next()? {
        charge(budget)?;
        out.push(finish_site(site_from_row(row)?)?);
    }
    Ok(())
}

fn placeholders(count: usize) -> String {
    let mut out = String::with_capacity(count * 3);
    for index in 0..count {
        if index > 0 {
            out.push(',');
        }
        out.push('?');
    }
    out
}

/// Planner bound: `rows_read` aggregate/index rows may not exceed
/// `planner_rows`, and cancellation is honoured at every checkpoint.
fn planner_check(
    cancelled: &mut dyn FnMut() -> bool,
    rows_read: u64,
    planner_rows: u64,
) -> Result<()> {
    if cancelled() {
        return Err(HealthWorkError::Cancelled.into());
    }
    if rows_read > planner_rows {
        return Err(HealthWorkError::ResourceExhausted.into());
    }
    Ok(())
}

impl Store {
    /// Resolve which scan tables and overlay layers a health request reads,
    /// without loading any graph row.
    pub fn resolve_health_input(
        &self,
        selector: HealthInputSelector<'_>,
    ) -> Result<HealthInputIdentity> {
        let connection = &self.connection;
        match selector {
            HealthInputSelector::CompletedSnapshot(snapshot_id) => {
                let mut layers = Vec::new();
                let base_scan_id = resolve_completed_layers(
                    connection,
                    snapshot_id,
                    &mut layers,
                    &mut BTreeSet::new(),
                )?;
                let (analysis_plan_id, analysis_input_digest) =
                    analysis_plan_identity(connection, &base_scan_id)?;
                Ok(HealthInputIdentity {
                    snapshot_id: Some(snapshot_id.to_owned()),
                    attempt_id: None,
                    base_scan_id,
                    layer_digest: layer_digest(&layers),
                    layers,
                    staging_fingerprint: None,
                    analysis_plan_id,
                    analysis_input_digest,
                })
            }
            HealthInputSelector::Attempt(attempt_id) => {
                // Mirror `Store::load_snapshot`: a promoted or completed scan
                // is addressed through its completed snapshot instead.
                if self.completed_snapshot(attempt_id)?.is_some() {
                    return self
                        .resolve_health_input(HealthInputSelector::CompletedSnapshot(attempt_id));
                }
                let scan = load_scan_record(connection, attempt_id)?;
                if scan.status == "completed"
                    && let Some(snapshot_id) = self.snapshot_id_for_scan_selection(attempt_id)?
                {
                    return self.resolve_health_input(HealthInputSelector::CompletedSnapshot(
                        &snapshot_id,
                    ));
                }
                let mut layers = Vec::new();
                if let Some(build_attempt_id) = self.current_build_attempt_id(attempt_id)? {
                    layers.push(HealthLayer::BuildDelta {
                        attempt_id: build_attempt_id,
                        base_scan_id: attempt_id.to_owned(),
                    });
                }
                layers.push(HealthLayer::Scan {
                    scan_id: attempt_id.to_owned(),
                });
                let (analysis_plan_id, analysis_input_digest) =
                    analysis_plan_identity(connection, attempt_id)?;
                Ok(HealthInputIdentity {
                    snapshot_id: None,
                    attempt_id: Some(attempt_id.to_owned()),
                    base_scan_id: attempt_id.to_owned(),
                    layer_digest: layer_digest(&layers),
                    layers,
                    staging_fingerprint: Some(staging_fingerprint(connection, &scan)?),
                    analysis_plan_id,
                    analysis_input_digest,
                })
            }
        }
    }

    /// Plan health execution ranges from SQL aggregates and sorted index
    /// scans only. No node, edge, site, or evidence record is materialized.
    pub fn health_range_plan(
        &self,
        identity: &HealthInputIdentity,
        limits: &HealthRangeLimits,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<HealthRangePlan> {
        if !identity.is_plain() {
            bail!("health ranges can only be planned for a plain scan input");
        }
        if limits.per_range_work == 0 || limits.max_ranges == 0 || limits.planner_rows == 0 {
            bail!("health range limits must be positive");
        }
        let connection = &self.connection;
        let scan_id = identity.base_scan_id.as_str();
        let mut rows_read = 0_u64;
        let planner_rows = limits.planner_rows;

        let mut stats = HealthTargetStats::default();
        let mut kinds = connection.prepare(
            "SELECT kind, COUNT(*) FROM nodes WHERE scan_id=?1 GROUP BY kind ORDER BY kind",
        )?;
        for row in kinds.query_map([scan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
        })? {
            let (kind, count) = row?;
            rows_read += 1;
            if matches!(kind.as_str(), "file" | "symbol" | "type") {
                stats.subjects += count;
            }
            stats.nodes_by_kind.insert(kind, count);
        }
        planner_check(cancelled, rows_read, planner_rows)?;
        (
            stats.edges,
            stats.sites,
            stats.targetless_sites,
            stats.evidence,
            stats.profiles,
        ) = connection.query_row(
            "SELECT (SELECT COUNT(*) FROM edges WHERE scan_id=?1),
                        (SELECT COUNT(*) FROM sites WHERE scan_id=?1),
                        (SELECT COUNT(*) FROM sites
                          WHERE scan_id=?1 AND json_array_length(target_ids_json)=0),
                        (SELECT COUNT(*) FROM evidence WHERE scan_id=?1),
                        (SELECT COUNT(*) FROM profiles WHERE scan_id=?1)",
            [scan_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
        rows_read += 1;
        stats.go_profiles = connection.query_row(
            "SELECT COUNT(*) FROM profiles
              WHERE scan_id=?1 AND json_extract(json, '$.language')='go'",
            [scan_id],
            |row| row.get(0),
        )?;
        stats.go_module_nodes = connection.query_row(
            "SELECT COUNT(*) FROM nodes
              WHERE scan_id=?1 AND kind='module'
                AND json_extract(properties_json, '$.language')='go'",
            [scan_id],
            |row| row.get(0),
        )?;
        stats.manifest_sites = connection.query_row(
            "SELECT COUNT(*) FROM sites
              WHERE scan_id=?1 AND kind IN ('cargo_dependency', 'module_requirement',
                    'package_dependency', 'package_peer_dependency',
                    'package_optional_dependency')",
            [scan_id],
            |row| row.get(0),
        )?;
        stats.ledger_incomplete_units = connection.query_row(
            "SELECT COUNT(*) FROM analysis_unit_ledger
              WHERE scan_id=?1 AND status<>'completed'",
            [scan_id],
            |row| row.get(0),
        )?;
        rows_read += 4;
        planner_check(cancelled, rows_read, planner_rows)?;

        // Site targets are a JSON array without an index; project them once so
        // both the planner and the range loader can seek by target id. The
        // projection charges the planner budget row by row, so an input with
        // more targets than the budget fails before the table is built.
        let projection = {
            let mut projection_budget = PlannerRowBudget {
                rows_read: &mut rows_read,
                limit: planner_rows,
                cancelled,
            };
            ensure_site_target_projection(connection, scan_id, &mut projection_budget)?
        };
        stats.site_targets = projection.rows;
        if projection.reused {
            // Account for the reused rows so a repeated plan on the same
            // connection reports the same work and digest as the first one.
            rows_read += projection.rows;
        }
        planner_check(cancelled, rows_read, planner_rows)?;

        let go_profile_cost = HEALTH_RANGE_ESTIMATE_PER_GO_PROFILE * stats.go_profiles;
        let cut_at = (limits.per_range_work / HEALTH_RANGE_ESTIMATE_SAFETY_DIVISOR).max(1);

        let mut subject_statement = connection.prepare(&format!(
            "SELECT id,
                    CASE WHEN kind='file'
                          AND json_extract(properties_json, '$.language')='go'
                         THEN 1 ELSE 0 END
               FROM nodes
              WHERE scan_id=?1 AND kind IN {SUBJECT_KINDS_SQL}
              ORDER BY id"
        ))?;
        let mut edge_statement = connection.prepare(
            "SELECT target, COUNT(*) FROM edges WHERE scan_id=?1
              GROUP BY target ORDER BY target",
        )?;
        let mut site_statement = connection.prepare(&format!(
            "SELECT target_id, COUNT(*) FROM {SITE_TARGETS_TABLE}
              GROUP BY target_id ORDER BY target_id"
        ))?;
        let mut edges = CountCursor {
            rows: edge_statement.query([scan_id])?,
            current: None,
        };
        edges.advance()?;
        let mut sites = CountCursor {
            rows: site_statement.query([])?,
            current: None,
        };
        sites.advance()?;

        let mut ranges = Vec::<HealthRange>::new();
        let mut open: Option<HealthRange> = None;
        let mut subjects = subject_statement.query([scan_id])?;
        while let Some(row) = subjects.next()? {
            let id = row.get::<_, String>(0)?;
            let is_go_file = row.get::<_, i64>(1)? == 1;
            rows_read += 1;
            if rows_read.is_multiple_of(4096) {
                planner_check(cancelled, rows_read, planner_rows)?;
            }
            let inbound_edges = edges.count_for(&id, &mut rows_read)?;
            let inbound_sites = sites.count_for(&id, &mut rows_read)?;
            let estimate = HEALTH_RANGE_ESTIMATE_PER_SUBJECT
                + HEALTH_RANGE_ESTIMATE_PER_EDGE * inbound_edges
                + HEALTH_RANGE_ESTIMATE_PER_SITE * inbound_sites
                + if is_go_file { go_profile_cost } else { 0 };
            let range = open.get_or_insert_with(|| HealthRange {
                index: ranges.len() as u32,
                first_subject_id: id.clone(),
                last_subject_id: id.clone(),
                subject_count: 0,
                inbound_edge_count: 0,
                inbound_site_count: 0,
                estimated_work: 0,
                split_reason: RangeSplitReason::Tail,
            });
            range.last_subject_id = id;
            range.subject_count += 1;
            range.inbound_edge_count += inbound_edges;
            range.inbound_site_count += inbound_sites;
            range.estimated_work += estimate;
            if range.estimated_work >= cut_at {
                let mut closed = open.take().expect("open range");
                closed.split_reason = RangeSplitReason::BudgetReached;
                ranges.push(closed);
                if ranges.len() > limits.max_ranges as usize {
                    return Err(HealthWorkError::ResourceExhausted.into());
                }
            }
        }
        if let Some(tail) = open.take() {
            ranges.push(tail);
            if ranges.len() > limits.max_ranges as usize {
                return Err(HealthWorkError::ResourceExhausted.into());
            }
        }
        planner_check(cancelled, rows_read, planner_rows)?;

        let mut plan = HealthRangePlan {
            contract_version: HEALTH_RANGE_PLAN_CONTRACT_VERSION.to_owned(),
            identity: identity.clone(),
            limits: *limits,
            stats,
            ranges,
            plan_digest: String::new(),
            planner_work_used: rows_read,
        };
        plan.plan_digest = health_range_plan_digest(&plan);
        Ok(plan)
    }

    /// Load the snapshot-wide context every range shares. Only profiles,
    /// coverage metadata, Go module identities, and the edges/sites that
    /// target Go modules are materialized.
    pub fn load_health_global_context(
        &self,
        plan: &HealthRangePlan,
        budget: &mut dyn HealthWorkBudget,
    ) -> Result<HealthGlobalInput> {
        let connection = &self.connection;
        let scan_id = plan.identity.base_scan_id.as_str();
        let mut work = WorkCounter::new(budget);
        let scan = load_scan_record(connection, scan_id)?;
        work.charge()?;
        let profiles = load_profiles(connection, scan_id)?;
        for _ in &profiles {
            work.charge()?;
        }
        let coverage = observed_coverage_sql(connection, scan_id, scan.project_code_executed)?;
        work.charge()?;
        let mut profile_snapshot = GraphSnapshot {
            scan: scan.clone(),
            profiles: profiles.clone(),
            nodes: Vec::new(),
            sites: Vec::new(),
            edges: Vec::new(),
            evidence: Vec::new(),
            diagnostics: Vec::new(),
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: coverage.clone(),
            profile_matrix: ProfileMatrixRecord::default(),
            analysis_dependency_coverage: None,
        };
        // Matrix entries (ids, languages, member profile ids) are a function of
        // the profile records alone; sites and edges only contribute phase
        // coverage that health never reads.
        refresh_profile_matrix(&mut profile_snapshot, false);
        let profile_matrix = profile_snapshot.profile_matrix;
        for entry in &profile_matrix.entries {
            work.charge()?;
            for _ in &entry.profile_ids {
                work.charge()?;
            }
        }

        let mut coverage_omitted_paths = Vec::new();
        let mut statement = connection.prepare(
            "SELECT path FROM file_coverage
              WHERE scan_id=?1 AND (skipped OR reason='unsupported_syntax')
              ORDER BY adapter, path",
        )?;
        let mut rows = statement.query([scan_id])?;
        while let Some(row) = rows.next()? {
            work.charge()?;
            coverage_omitted_paths.push(row.get::<_, String>(0)?);
        }
        drop(rows);

        let mut subject_languages = Vec::new();
        let mut statement = connection.prepare(&format!(
            "SELECT DISTINCT CASE WHEN json_type(properties_json, '$.language')='text'
                                  THEN json_extract(properties_json, '$.language')
                                  ELSE NULL END AS language
               FROM nodes WHERE scan_id=?1 AND kind IN {SUBJECT_KINDS_SQL}
              ORDER BY language"
        ))?;
        let mut rows = statement.query([scan_id])?;
        while let Some(row) = rows.next()? {
            work.charge()?;
            subject_languages.push(row.get::<_, Option<String>>(0)?);
        }
        drop(rows);

        let mut go_module_nodes = Vec::new();
        query_nodes_charged(
            connection,
            &format!(
                "SELECT {NODE_COLUMNS} FROM nodes
                  WHERE scan_id=?1 AND kind='module'
                    AND json_extract(properties_json, '$.language')='go'
                  ORDER BY id"
            ),
            &[&scan_id],
            &mut work,
            &mut go_module_nodes,
        )?;
        let module_ids = go_module_nodes
            .iter()
            .map(|node| node.id.clone())
            .collect::<Vec<_>>();
        let mut go_package_edges = Vec::new();
        let mut go_candidate_sites = BTreeMap::<String, SiteRecord>::new();
        for batch in module_ids.chunks(SQL_BATCH_SIZE) {
            let marks = placeholders(batch.len());
            let mut parameters: Vec<&dyn rusqlite::ToSql> = vec![&scan_id];
            parameters.extend(batch.iter().map(|id| id as &dyn rusqlite::ToSql));
            query_edges_charged(
                connection,
                &format!(
                    "SELECT {EDGE_COLUMNS} FROM edges
                      WHERE scan_id=?1 AND target IN ({marks}) ORDER BY id"
                ),
                &parameters,
                &mut work,
                &mut go_package_edges,
            )?;
            let mut sites = Vec::new();
            query_sites_charged(
                connection,
                &format!(
                    "SELECT {SITE_COLUMNS} FROM sites AS site
                      WHERE site.scan_id=?1 AND site.resolution_status='candidates'
                        AND EXISTS (SELECT 1 FROM json_each(site.target_ids_json) AS target
                                     WHERE CAST(target.value AS TEXT) IN ({marks}))
                      ORDER BY site.id"
                ),
                &parameters,
                &mut work,
                &mut sites,
            )?;
            for site in sites {
                go_candidate_sites.insert(site.id.clone(), site);
            }
        }
        go_package_edges.sort_by(|left, right| left.id.cmp(&right.id));

        let (candidate, unresolved, dynamic_kind): (u64, u64, u64) = connection.query_row(
            "SELECT COALESCE(SUM(resolution_status='candidates'), 0),
                    COALESCE(SUM(resolution_status='unresolved'), 0),
                    COALESCE(SUM(kind IN ('dynamic_import', 'dynamic-load')), 0)
               FROM sites WHERE scan_id=?1 AND json_array_length(target_ids_json)=0",
            [scan_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        work.charge()?;
        let dynamic_evidence: bool = connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sites AS site
                  JOIN evidence AS item
                    ON item.scan_id=site.scan_id AND item.owner_type='site'
                   AND item.owner_id=site.id
                 WHERE site.scan_id=?1 AND json_array_length(site.target_ids_json)=0
                   AND json_extract(item.raw_json, '$.properties.occurrence_kind')='dynamic_import')",
            [scan_id],
            |row| row.get(0),
        )?;
        work.charge()?;
        let targetless_sites = HealthTargetlessSiteFlags {
            candidate: candidate > 0,
            unresolved: unresolved > 0,
            dynamic: dynamic_kind > 0 || dynamic_evidence,
        };

        let ledger_incomplete_unit_count: u64 = connection.query_row(
            "SELECT COUNT(*) FROM analysis_unit_ledger WHERE scan_id=?1 AND status<>'completed'",
            [scan_id],
            |row| row.get(0),
        )?;
        let mut ledger_incomplete_units = Vec::new();
        let mut statement = connection.prepare(
            "SELECT unit_id, stage, chunk_id, status FROM analysis_unit_ledger
              WHERE scan_id=?1 AND status<>'completed'
              ORDER BY unit_id COLLATE BINARY, stage COLLATE BINARY, chunk_id COLLATE BINARY
              LIMIT 1024",
        )?;
        let mut rows = statement.query([scan_id])?;
        while let Some(row) = rows.next()? {
            work.charge()?;
            ledger_incomplete_units.push(HealthLedgerUnit {
                unit_id: row.get(0)?,
                stage: row.get(1)?,
                chunk_id: row.get(2)?,
                status: row.get(3)?,
            });
        }
        drop(rows);
        let analysis_dependency_coverage = if plan.identity.is_plain() {
            super::analysis_dependency_coverage::load_analysis_dependency_coverage(
                connection,
                scan_id,
                || work.charge(),
            )?
        } else {
            None
        };
        let work_used = work.used;
        Ok(HealthGlobalInput {
            scan,
            profiles,
            profile_matrix,
            coverage,
            coverage_omitted_paths,
            subject_languages,
            go_module_nodes,
            go_package_edges,
            go_candidate_sites: go_candidate_sites.into_values().collect(),
            targetless_sites,
            ledger_incomplete_units,
            ledger_incomplete_unit_count,
            analysis_dependency_coverage,
            work_used,
        })
    }

    /// Load one range: its subjects plus every edge and site that targets a
    /// subject in the range, whichever range the sources belong to.
    pub fn load_health_range(
        &self,
        plan: &HealthRangePlan,
        range: &HealthRange,
        budget: &mut dyn HealthWorkBudget,
    ) -> Result<HealthRangeInput> {
        let connection = &self.connection;
        let scan_id = plan.identity.base_scan_id.as_str();
        let mut work = WorkCounter::new(budget);
        // Normally reused from planning on this connection; rebuilding it on a
        // fresh connection is charged to this range like any other row load.
        ensure_site_target_projection(connection, scan_id, &mut work)?;
        let lo = range.first_subject_id.as_str();
        let hi = range.last_subject_id.as_str();
        let mut subjects = Vec::new();
        query_nodes_charged(
            connection,
            &format!(
                "SELECT {NODE_COLUMNS} FROM nodes
                  WHERE scan_id=?1 AND kind IN {SUBJECT_KINDS_SQL}
                    AND id BETWEEN ?2 AND ?3
                  ORDER BY id"
            ),
            &[&scan_id, &lo, &hi],
            &mut work,
            &mut subjects,
        )?;
        // Non-subject node ids (modules, packages) can sort inside the
        // interval; only edges and sites that target a subject are part of the
        // range, exactly as the planner counted them.
        let mut inbound_edges = Vec::new();
        query_edges_charged(
            connection,
            &format!(
                "SELECT {EDGE_COLUMNS} FROM edges AS edge
                  WHERE edge.scan_id=?1 AND edge.target BETWEEN ?2 AND ?3
                    AND EXISTS (SELECT 1 FROM nodes AS subject
                                 WHERE subject.scan_id=edge.scan_id AND subject.id=edge.target
                                   AND subject.kind IN {SUBJECT_KINDS_SQL})
                  ORDER BY edge.id"
            ),
            &[&scan_id, &lo, &hi],
            &mut work,
            &mut inbound_edges,
        )?;
        let range_site_ids = format!(
            "SELECT DISTINCT projection.site_id FROM {SITE_TARGETS_TABLE} AS projection
              WHERE projection.target_id BETWEEN ?2 AND ?3
                AND EXISTS (SELECT 1 FROM nodes AS subject
                             WHERE subject.scan_id=?1 AND subject.id=projection.target_id
                               AND subject.kind IN {SUBJECT_KINDS_SQL})"
        );
        let mut inbound_sites = Vec::new();
        query_sites_charged(
            connection,
            &format!(
                "SELECT {SITE_COLUMNS} FROM sites AS site
                  WHERE site.scan_id=?1 AND site.id IN ({range_site_ids})
                  ORDER BY site.id"
            ),
            &[&scan_id, &lo, &hi],
            &mut work,
            &mut inbound_sites,
        )?;
        let mut dynamic_site_ids = BTreeSet::new();
        let mut statement = connection.prepare(&format!(
            "SELECT DISTINCT item.owner_id FROM evidence AS item
              WHERE item.scan_id=?1 AND item.owner_type='site'
                AND item.owner_id IN ({range_site_ids})
                AND json_extract(item.raw_json, '$.properties.occurrence_kind')='dynamic_import'
              ORDER BY item.owner_id"
        ))?;
        let mut rows = statement.query(params![scan_id, lo, hi])?;
        while let Some(row) = rows.next()? {
            work.charge()?;
            dynamic_site_ids.insert(row.get::<_, String>(0)?);
        }
        drop(rows);
        let work_used = work.used;
        Ok(HealthRangeInput {
            range: range.clone(),
            subjects,
            inbound_edges,
            inbound_sites,
            dynamic_site_ids,
            work_used,
        })
    }

    /// Load the projection the dependency analyzer needs: every node, edge,
    /// and site (manifest scopes are resolved over the structural forest), but
    /// no evidence, diagnostics, file coverage, or adapter logs.
    pub fn load_health_dependency_input(
        &self,
        identity: &HealthInputIdentity,
        budget: &mut dyn HealthWorkBudget,
    ) -> Result<(GraphSnapshot, u64)> {
        self.load_health_dependency_rows(identity, budget, true)
    }

    /// Load dependency declarations and relevant manifest observations before
    /// selecting usage. Unrelated node and edge records are not materialized.
    pub fn load_health_dependency_metadata(
        &self,
        identity: &HealthInputIdentity,
        budget: &mut dyn HealthWorkBudget,
    ) -> Result<(GraphSnapshot, u64)> {
        self.load_health_dependency_rows(identity, budget, false)
    }

    fn load_health_dependency_rows(
        &self,
        identity: &HealthInputIdentity,
        budget: &mut dyn HealthWorkBudget,
        full: bool,
    ) -> Result<(GraphSnapshot, u64)> {
        if !identity.is_plain() {
            bail!("health dependency input can only be loaded for a plain scan input");
        }
        let connection = &self.connection;
        let scan_id = identity.base_scan_id.as_str();
        let mut work = WorkCounter::new(budget);
        let scan = load_scan_record(connection, scan_id)?;
        let profiles = load_profiles(connection, scan_id)?;
        for _ in &profiles {
            work.charge()?;
        }
        let coverage = observed_coverage_sql(connection, scan_id, scan.project_code_executed)?;
        let mut nodes = Vec::new();
        let node_sql = if full {
            format!("SELECT {NODE_COLUMNS} FROM nodes WHERE scan_id=?1 ORDER BY id")
        } else {
            dependency_metadata_nodes_sql()
        };
        query_nodes_charged(connection, &node_sql, &[&scan_id], &mut work, &mut nodes)?;
        let mut sites = Vec::new();
        let site_filter = if full {
            String::new()
        } else {
            format!(" AND kind IN {DEPENDENCY_SITE_KINDS_SQL}")
        };
        query_sites_charged(
            connection,
            &format!("SELECT {SITE_COLUMNS} FROM sites WHERE scan_id=?1{site_filter} ORDER BY id"),
            &[&scan_id],
            &mut work,
            &mut sites,
        )?;
        let mut edges = Vec::new();
        if full {
            query_edges_charged(
                connection,
                &format!("SELECT {EDGE_COLUMNS} FROM edges WHERE scan_id=?1 ORDER BY id"),
                &[&scan_id],
                &mut work,
                &mut edges,
            )?;
        }
        let work_used = work.used;
        Ok((
            GraphSnapshot {
                scan,
                profiles,
                nodes,
                sites,
                edges,
                evidence: Vec::new(),
                diagnostics: Vec::new(),
                file_coverage: Vec::new(),
                adapter_logs: Vec::new(),
                coverage,
                profile_matrix: ProfileMatrixRecord::default(),
                analysis_dependency_coverage: None,
            },
            work_used,
        ))
    }

    /// Target nodes whose package identity can satisfy a declaration and
    /// which have a usage edge. OFFSET 0 prevents flattening the subquery:
    /// SQLite streams one computed package name at a time instead of repeating
    /// JSON extraction for every possible module prefix or buffering all nodes.
    pub fn load_health_dependency_target_nodes(
        &self,
        identity: &HealthInputIdentity,
        exact: &BTreeSet<String>,
        modules: &BTreeSet<String>,
        budget: &mut dyn HealthWorkBudget,
    ) -> Result<Vec<NodeRecord>> {
        if !identity.is_plain() {
            bail!("health dependency targets require a plain scan input");
        }
        let mut nodes = Vec::new();
        if exact.is_empty() && modules.is_empty() {
            return Ok(nodes);
        }
        let exact_json = serde_json::to_string(exact)?;
        let modules_json = serde_json::to_string(modules)?;
        query_nodes_charged(
            &self.connection,
            &format!(
                "SELECT {NODE_COLUMNS} FROM (
                     SELECT {NODE_COLUMNS}, {} AS dependency_package FROM nodes
                       WHERE scan_id=?1 LIMIT -1 OFFSET 0
                 ) AS candidate
                 WHERE (dependency_package IN (SELECT value FROM json_each(?2))
                    OR EXISTS (SELECT 1 FROM json_each(?3) AS module
                         WHERE substr(CAST(dependency_package AS BLOB), 1, length(CAST(module.value AS BLOB))+1)
                               =CAST(module.value || '/' AS BLOB)))
                   AND EXISTS (SELECT 1 FROM edges INDEXED BY edges_scan_target
                         WHERE scan_id=?1 AND target=candidate.id
                           AND kind NOT IN ('depends_on', 'build_depends_on', 'contains', 'declares'))",
                dependency_package_name_sql()
            ),
            &[&identity.base_scan_id, &exact_json, &modules_json],
            budget,
            &mut nodes,
        )?;
        Ok(nodes)
    }

    /// Load only the known IDs needed by one ownership-traversal batch.
    pub fn load_health_dependency_nodes(
        &self,
        identity: &HealthInputIdentity,
        ids: &[String],
        budget: &mut dyn HealthWorkBudget,
    ) -> Result<Vec<NodeRecord>> {
        if !identity.is_plain() || ids.len() > SQL_BATCH_SIZE {
            bail!("invalid health dependency node batch");
        }
        let mut nodes = Vec::new();
        if ids.is_empty() {
            return Ok(nodes);
        }
        let mut parameters: Vec<&dyn rusqlite::ToSql> = vec![&identity.base_scan_id];
        parameters.extend(ids.iter().map(|id| id as &dyn rusqlite::ToSql));
        query_nodes_charged(
            &self.connection,
            &format!(
                "SELECT {NODE_COLUMNS} FROM nodes WHERE scan_id=? AND id IN ({}) ORDER BY id",
                placeholders(ids.len())
            ),
            &parameters,
            budget,
            &mut nodes,
        )?;
        Ok(nodes)
    }

    /// Import sites whose specifiers can contribute requested Go module usage.
    /// Exact keys include non-Go declarations because a Go usage may still
    /// satisfy an unscoped dependency declaration in a mixed-language graph.
    pub fn load_health_dependency_import_sites(
        &self,
        identity: &HealthInputIdentity,
        exact: &BTreeSet<String>,
        modules: &BTreeSet<String>,
        budget: &mut dyn HealthWorkBudget,
    ) -> Result<Vec<SiteRecord>> {
        if !identity.is_plain() {
            bail!("health dependency imports require a plain scan input");
        }
        let mut sites = Vec::new();
        if exact.is_empty() && modules.is_empty() {
            return Ok(sites);
        }
        let exact_json = serde_json::to_string(exact)?;
        let modules_json = serde_json::to_string(modules)?;
        query_sites_charged(
            &self.connection,
            &format!(
                "SELECT {SITE_COLUMNS} FROM sites
                  WHERE scan_id=?1 AND kind IN ('import', 'side_effect_import')
                    AND (specifier IN (SELECT value FROM json_each(?2))
                         OR EXISTS (SELECT 1 FROM json_each(?3) AS module
                                     WHERE substr(CAST(specifier AS BLOB), 1, length(CAST(module.value AS BLOB))+1)
                                           =CAST(module.value || '/' AS BLOB)))
                  ORDER BY id"
            ),
            &[&identity.base_scan_id, &exact_json, &modules_json],
            budget,
            &mut sites,
        )?;
        Ok(sites)
    }

    /// Read a bounded batch of usage edges by target (or Go alias site), or
    /// structural parents by child. Callers maintain the traversal frontier;
    /// the indexed queries never load unrelated edge records.
    pub fn load_health_dependency_edges(
        &self,
        identity: &HealthInputIdentity,
        ids: &[String],
        by_site: bool,
        structural: bool,
        budget: &mut dyn HealthWorkBudget,
    ) -> Result<Vec<EdgeRecord>> {
        if !identity.is_plain() || ids.len() > SQL_BATCH_SIZE || (by_site && structural) {
            bail!("invalid health dependency edge batch");
        }
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let column = if by_site { "site_id" } else { "target" };
        let index = if by_site {
            "edges_scan_site"
        } else {
            "edges_scan_target"
        };
        let kinds = if structural {
            "kind IN ('contains', 'declares')"
        } else {
            "kind NOT IN ('depends_on', 'build_depends_on', 'contains', 'declares')"
        };
        let mut parameters: Vec<&dyn rusqlite::ToSql> = vec![&identity.base_scan_id];
        parameters.extend(ids.iter().map(|id| id as &dyn rusqlite::ToSql));
        let mut edges = Vec::new();
        query_edges_charged(
            &self.connection,
            &format!(
                "SELECT {EDGE_COLUMNS} FROM edges INDEXED BY {index} WHERE scan_id=? AND {kinds}
                   AND {column} IN ({}) ORDER BY id",
                placeholders(ids.len())
            ),
            &parameters,
            budget,
            &mut edges,
        )?;
        Ok(edges)
    }

    /// Drop the temporary site-target projection created by range planning.
    pub fn release_health_range_projection(&self) -> Result<()> {
        release_site_target_projection(&self.connection)
    }
}

struct WorkCounter<'b> {
    budget: &'b mut dyn HealthWorkBudget,
    used: u64,
}

impl<'b> WorkCounter<'b> {
    fn new(budget: &'b mut dyn HealthWorkBudget) -> Self {
        Self { budget, used: 0 }
    }

    fn charge(&mut self) -> Result<()> {
        charge(self)
    }
}

/// Every step of a loader goes through the counter so the reported
/// `work_used` equals what the caller's budget was charged.
impl HealthWorkBudget for WorkCounter<'_> {
    fn step(&mut self) -> std::result::Result<(), HealthWorkError> {
        self.budget.step()?;
        self.used += 1;
        Ok(())
    }
}

/// Digest binding the plan to its input identity, limits, statistics, and
/// range boundaries.
#[must_use]
pub fn health_range_plan_digest(plan: &HealthRangePlan) -> String {
    let payload = json!({
        "contract_version": plan.contract_version,
        "identity": plan.identity,
        "limits": plan.limits,
        "ranges": plan.ranges,
        "stats": plan.stats,
    });
    sha256_hex(depgraph_protocol::canonical_json(&payload).as_bytes())
}

/// Split a range in half by its loaded subject ids after an overrun.
///
/// The split is deterministic (median of the sorted subject ids) so an
/// interrupted run and a fresh run converge on identical range boundaries.
#[must_use]
pub fn resplit_health_range(
    range: &HealthRange,
    subject_ids: &[String],
    next_index: u32,
    depth: u8,
) -> Option<(HealthRange, HealthRange)> {
    if subject_ids.len() < 2 {
        return None;
    }
    let middle = subject_ids.len() / 2;
    let reason = RangeSplitReason::ResplitAfterOverrun {
        parent: range.index,
        depth,
    };
    let left = HealthRange {
        index: next_index,
        first_subject_id: subject_ids[0].clone(),
        last_subject_id: subject_ids[middle - 1].clone(),
        subject_count: middle as u64,
        inbound_edge_count: 0,
        inbound_site_count: 0,
        estimated_work: range.estimated_work / 2,
        split_reason: reason,
    };
    let right = HealthRange {
        index: next_index + 1,
        first_subject_id: subject_ids[middle].clone(),
        last_subject_id: subject_ids[subject_ids.len() - 1].clone(),
        subject_count: (subject_ids.len() - middle) as u64,
        inbound_edge_count: 0,
        inbound_site_count: 0,
        estimated_work: range.estimated_work / 2,
        split_reason: reason,
    };
    Some((left, right))
}

/// Subject ids of one range without loading properties; used to re-split a
/// range that overran its budget before any of its rows were retained.
pub fn health_range_subject_ids(
    store: &Store,
    plan: &HealthRangePlan,
    range: &HealthRange,
) -> Result<Vec<String>> {
    let mut statement = store.connection.prepare(&format!(
        "SELECT id FROM nodes
          WHERE scan_id=?1 AND kind IN {SUBJECT_KINDS_SQL} AND id BETWEEN ?2 AND ?3
          ORDER BY id"
    ))?;
    statement
        .query_map(
            params![
                plan.identity.base_scan_id,
                range.first_subject_id,
                range.last_subject_id
            ],
            |row| row.get::<_, String>(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}
