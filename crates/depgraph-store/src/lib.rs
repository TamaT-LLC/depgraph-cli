use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const SCHEMA_VERSION: i64 = 5;

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    pub id: String,
    pub kind: String,
    pub locator: String,
    pub display_name: String,
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileRecord {
    pub id: String,
    pub language: String,
    pub toolchain: Option<Value>,
    pub command: Option<String>,
    pub target: Option<String>,
    pub features: Vec<String>,
    pub environment: Value,
    pub properties: Value,
    pub coverage: Option<CoverageRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCoverageRecord {
    pub adapter: String,
    pub path: String,
    pub discovered_sites: u64,
    pub emitted_sites: u64,
    pub skipped_sites: u64,
    pub skipped: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterLogRecord {
    pub adapter: String,
    pub stderr: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        if current > SCHEMA_VERSION {
            bail!("store schema {current} is newer than supported schema {SCHEMA_VERSION}");
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
        Ok(())
    }

    pub fn start_scan(&mut self, scan_id: &str, root: &Path, strict: bool) -> Result<()> {
        let tx = self.connection.transaction()?;
        tx.execute(
            "INSERT INTO scans(id, root, status, strict, started_at, protocol_version)
             VALUES (?1, ?2, 'staging', ?3, ?4, '1.0')",
            params![
                scan_id,
                root.to_string_lossy(),
                strict,
                Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
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
            "completed" | "partial" | "failed" | "policy_failed" | "security_failed"
        ) {
            bail!("invalid terminal scan status {status}");
        }
        if promote && status != "completed" {
            bail!("only completed scans can become the current successful scan");
        }
        if promote {
            let current = self
                .connection
                .query_row("SELECT status FROM scans WHERE id=?1", [scan_id], |row| {
                    row.get::<_, String>(0)
                })
                .optional()?
                .with_context(|| format!("scan {scan_id} was not started"))?;
            if current != "staging" {
                bail!("scan {scan_id} is immutable after reaching status {current}");
            }
            self.validate_scan(scan_id)
                .with_context(|| format!("scan {scan_id} cannot be promoted before validation"))?;
        }
        let tx = self.connection.transaction()?;
        ensure_scan_staging(&tx, scan_id)?;
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
        tx.execute(
            "UPDATE scans SET status = ?2, completed_at = ?3, error = ?4 WHERE id = ?1",
            params![
                scan_id,
                status,
                Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                error
            ],
        )?;
        if promote {
            tx.execute(
                "INSERT INTO current_successful(singleton, scan_id) VALUES (1, ?1)
                 ON CONFLICT(singleton) DO UPDATE SET scan_id = excluded.scan_id",
                [scan_id],
            )?;
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
                        project_code_executed, error
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
                    })
                },
            )
            .optional()
            .context("failed to load scan")
    }

    pub fn load_snapshot(&self, scan_id: &str) -> Result<GraphSnapshot> {
        let scan = self
            .scan(scan_id)?
            .with_context(|| format!("scan {scan_id} was not found"))?;
        let profiles = load_profiles(&self.connection, scan_id)?;
        let nodes = load_nodes(&self.connection, scan_id)?;
        let sites = load_sites(&self.connection, scan_id)?;
        let edges = load_edges(&self.connection, scan_id)?;
        let evidence = load_evidence(&self.connection, scan_id)?;
        let diagnostics = load_diagnostics(&self.connection, scan_id)?;
        let file_coverage = load_file_coverage(&self.connection, scan_id)?;
        let adapter_logs = load_adapter_logs(&self.connection, scan_id)?;
        let stored_coverage = self
            .connection
            .query_row(
                "SELECT json FROM coverage WHERE scan_id = ?1",
                [scan_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|raw| serde_json::from_str(&raw))
            .transpose()?;
        let coverage = observed_coverage(
            &self.connection,
            scan_id,
            &sites,
            scan.project_code_executed,
            stored_coverage,
        )?;
        Ok(GraphSnapshot {
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
        })
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
        tx.commit()?;
        Ok(())
    }
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
    insert_evidence(tx, scan_id, "site", required_str(site, "id")?, site)?;
    Ok(())
}

fn insert_edge(tx: &Transaction<'_>, scan_id: &str, edge: &Value) -> Result<()> {
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
    insert_evidence(tx, scan_id, "edge", required_str(edge, "id")?, edge)?;
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
    fn incomplete_scan_is_not_promoted() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        store.start_scan("scan-1", Path::new("/tmp/project"), false)?;
        store.finish_scan("scan-1", "failed", Some("worker crashed"), false)?;
        assert_eq!(store.latest_attempt_id()?.as_deref(), Some("scan-1"));
        assert_eq!(store.latest_successful_id()?, None);
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
        assert_eq!(store.schema_version()?, 5);
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
        Ok(())
    }
}
