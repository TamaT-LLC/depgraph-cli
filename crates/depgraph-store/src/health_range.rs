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
    ScanRecord, SiteRecord, Store, incremental,
    profile_matrix::refresh_profile_matrix,
    read::{load_profiles, load_staging_coverage},
    snapshot::load_completed_snapshot_record,
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

/// Build (or reuse) the temporary `site_id -> target_id` projection for one
/// scan. Sites store their targets as a JSON array without an index, so the
/// projection turns per-range site fetches into index range scans.
fn ensure_site_target_projection(connection: &Connection, scan_id: &str) -> Result<u64> {
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
            return Ok(rows);
        }
    }
    connection.execute_batch(&format!(
        "DROP TABLE IF EXISTS {SITE_TARGETS_TABLE};
         DROP TABLE IF EXISTS temp.health_site_targets_scan;
         CREATE TEMP TABLE health_site_targets (target_id TEXT NOT NULL, site_id TEXT NOT NULL);
         CREATE TEMP TABLE health_site_targets_scan (scan_id TEXT NOT NULL, row_count INTEGER NOT NULL);"
    ))?;
    let inserted = connection.execute(
        &format!(
            "INSERT INTO {SITE_TARGETS_TABLE}(target_id, site_id)
             SELECT CAST(target.value AS TEXT), site.id
               FROM sites AS site, json_each(site.target_ids_json) AS target
              WHERE site.scan_id=?1"
        ),
        [scan_id],
    )?;
    connection.execute_batch(&format!(
        "CREATE INDEX temp.health_site_targets_target ON health_site_targets(target_id, site_id);"
    ))?;
    connection.execute(
        "INSERT INTO temp.health_site_targets_scan(scan_id, row_count) VALUES (?1, ?2)",
        params![scan_id, inserted as u64],
    )?;
    Ok(inserted as u64)
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
        let mut check = |rows_read: u64| -> Result<()> {
            if cancelled() {
                return Err(HealthWorkError::Cancelled.into());
            }
            if rows_read > limits.planner_rows {
                return Err(HealthWorkError::ResourceExhausted.into());
            }
            Ok(())
        };

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
        check(rows_read)?;
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
        check(rows_read)?;

        // Site targets are a JSON array without an index; project them once so
        // both the planner and the range loader can seek by target id.
        stats.site_targets = ensure_site_target_projection(connection, scan_id)?;
        rows_read += stats.site_targets;
        check(rows_read)?;

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
            if rows_read % 4096 == 0 {
                check(rows_read)?;
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
        check(rows_read)?;

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
        let coverage = load_staging_coverage(connection, scan_id)?;
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
            work.budget,
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
                work.budget,
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
                work.budget,
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
        ensure_site_target_projection(connection, scan_id)?;
        let mut work = WorkCounter::new(budget);
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
            work.budget,
            &mut subjects,
        )?;
        let mut inbound_edges = Vec::new();
        query_edges_charged(
            connection,
            &format!(
                "SELECT {EDGE_COLUMNS} FROM edges
                  WHERE scan_id=?1 AND target BETWEEN ?2 AND ?3
                  ORDER BY id"
            ),
            &[&scan_id, &lo, &hi],
            work.budget,
            &mut inbound_edges,
        )?;
        let mut inbound_sites = Vec::new();
        query_sites_charged(
            connection,
            &format!(
                "SELECT {SITE_COLUMNS} FROM sites AS site
                  WHERE site.scan_id=?1 AND site.id IN (
                        SELECT DISTINCT site_id FROM {SITE_TARGETS_TABLE}
                         WHERE target_id BETWEEN ?2 AND ?3)
                  ORDER BY site.id"
            ),
            &[&scan_id, &lo, &hi],
            work.budget,
            &mut inbound_sites,
        )?;
        let mut dynamic_site_ids = BTreeSet::new();
        let mut statement = connection.prepare(&format!(
            "SELECT DISTINCT item.owner_id FROM evidence AS item
              WHERE item.scan_id=?1 AND item.owner_type='site'
                AND item.owner_id IN (
                    SELECT DISTINCT site_id FROM {SITE_TARGETS_TABLE}
                     WHERE target_id BETWEEN ?2 AND ?3)
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
        plan: &HealthRangePlan,
        budget: &mut dyn HealthWorkBudget,
    ) -> Result<(GraphSnapshot, u64)> {
        let connection = &self.connection;
        let scan_id = plan.identity.base_scan_id.as_str();
        let mut work = WorkCounter::new(budget);
        let scan = load_scan_record(connection, scan_id)?;
        let profiles = load_profiles(connection, scan_id)?;
        for _ in &profiles {
            work.charge()?;
        }
        let coverage = load_staging_coverage(connection, scan_id)?;
        let mut nodes = Vec::new();
        query_nodes_charged(
            connection,
            &format!("SELECT {NODE_COLUMNS} FROM nodes WHERE scan_id=?1 ORDER BY id"),
            &[&scan_id],
            work.budget,
            &mut nodes,
        )?;
        let mut sites = Vec::new();
        query_sites_charged(
            connection,
            &format!("SELECT {SITE_COLUMNS} FROM sites WHERE scan_id=?1 ORDER BY id"),
            &[&scan_id],
            work.budget,
            &mut sites,
        )?;
        let mut edges = Vec::new();
        query_edges_charged(
            connection,
            &format!("SELECT {EDGE_COLUMNS} FROM edges WHERE scan_id=?1 ORDER BY id"),
            &[&scan_id],
            work.budget,
            &mut edges,
        )?;
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
            },
            work_used,
        ))
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
        charge(self.budget)?;
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
