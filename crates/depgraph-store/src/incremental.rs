use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use depgraph_protocol::{
    Coverage, DeltaBaseGraph, DeltaCoverage, DeltaCoverageKey, DeltaEvidenceKey,
    DeltaEvidenceOwner, DeltaFileCoverage, DeltaValidator, Evidence, GraphNode, ValidatedDelta,
    delta_graph_digest, stable_id_from_value,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    AdapterLogRecord, Store, completed_snapshot_identity, ensure_scan_staging,
    ingest_event_in_transaction, insert_node, load_completed_snapshot_record,
    promote_completed_snapshot, required_str, upsert_edge_row, upsert_site_row,
};

const MAX_SCOPE_VALUES: usize = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncrementalDeltaRecord {
    pub scan_id: String,
    pub delta_id: String,
    pub adapter: String,
    pub base_snapshot_id: String,
    pub base_graph_digest: String,
    pub result_graph_digest: String,
    pub mutation_count: u64,
    pub status: String,
    pub prospective_snapshot_id: Option<String>,
    pub staged_at: String,
    pub completed_at: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncrementalReplacementScope {
    pub paths: Vec<String>,
    pub package_locators: Vec<String>,
    pub profile_ids: Vec<String>,
    pub replanned_profile_ids: Vec<String>,
    pub artifact_node_ids: Vec<String>,
    pub adapters: Vec<String>,
}

impl IncrementalReplacementScope {
    pub fn new(
        paths: impl IntoIterator<Item = String>,
        package_locators: impl IntoIterator<Item = String>,
        profile_ids: impl IntoIterator<Item = String>,
        replanned_profile_ids: impl IntoIterator<Item = String>,
        artifact_node_ids: impl IntoIterator<Item = String>,
        adapters: impl IntoIterator<Item = String>,
    ) -> Result<Self> {
        let scope = Self {
            paths: normalize_values("path", paths, true)?,
            package_locators: normalize_values("package locator", package_locators, false)?,
            profile_ids: normalize_values("profile ID", profile_ids, false)?,
            replanned_profile_ids: normalize_values(
                "replanned profile ID",
                replanned_profile_ids,
                false,
            )?,
            artifact_node_ids: normalize_values("artifact node ID", artifact_node_ids, false)?,
            adapters: normalize_values("adapter", adapters, false)?,
        };
        scope.validate()?;
        Ok(scope)
    }

    fn validate(&self) -> Result<()> {
        if self.paths.is_empty()
            && self.package_locators.is_empty()
            && self.profile_ids.is_empty()
            && self.artifact_node_ids.is_empty()
        {
            bail!("incremental replacement scope must invalidate graph ownership");
        }
        validate_normalized("path", &self.paths, true)?;
        validate_normalized("package locator", &self.package_locators, false)?;
        validate_normalized("profile ID", &self.profile_ids, false)?;
        validate_normalized("replanned profile ID", &self.replanned_profile_ids, false)?;
        if self
            .replanned_profile_ids
            .iter()
            .any(|id| self.profile_ids.binary_search(id).is_err())
        {
            bail!("every replanned profile must also be an affected profile");
        }
        validate_normalized("artifact node ID", &self.artifact_node_ids, false)?;
        validate_normalized("adapter", &self.adapters, false)?;
        Ok(())
    }
}

impl Store {
    pub fn delta_base_graph(&self, snapshot_id: &str) -> Result<DeltaBaseGraph> {
        load_delta_base_graph(&self.connection, snapshot_id)
    }

    /// Builds the bounded validation projection for a one-file semantic no-op.
    ///
    /// The projection intentionally contains only the changed file node and a
    /// synthetic, internally consistent coverage ledger. Its digest is bound
    /// to the exact current snapshot ID, while the eventual store transaction
    /// separately proves that the projected node still matches that snapshot.
    pub fn semantic_noop_delta_base(
        &self,
        snapshot_id: &str,
        path: &str,
    ) -> Result<Option<DeltaBaseGraph>> {
        semantic_noop_delta_base(&self.connection, snapshot_id, path)
    }

    /// Atomically persists and promotes a proven content-fingerprint-only
    /// mutation without cloning or digesting the repository-complete graph.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_semantic_noop_delta(
        &mut self,
        scan_id: &str,
        root: &Path,
        strict: bool,
        base_snapshot_id: &str,
        source_revision: Option<&str>,
        delta: &ValidatedDelta,
        stderr: &str,
        stderr_truncated: bool,
    ) -> Result<String> {
        if source_revision.is_some_and(|revision| revision.trim().is_empty()) {
            bail!("source revision must not be empty");
        }
        let tx = self.connection.transaction()?;
        ensure_current_base(&tx, base_snapshot_id)?;
        if delta.base_snapshot_id != base_snapshot_id {
            bail!("semantic no-op delta base does not match the current snapshot");
        }
        if delta.scope.paths.len() != 1
            || delta.scope.adapters.as_slice() != ["web"]
            || !delta.node_deletes.is_empty()
            || delta.node_upserts.len() != 1
            || !delta.site_deletes.is_empty()
            || !delta.site_upserts.is_empty()
            || !delta.edge_deletes.is_empty()
            || !delta.edge_upserts.is_empty()
            || !delta.evidence_deletes.is_empty()
            || !delta.evidence_upserts.is_empty()
            || !delta.coverage_deletes.is_empty()
            || !delta.coverage_upserts.is_empty()
        {
            bail!("semantic no-op delta must contain exactly one Web file-node upsert");
        }
        let path = &delta.scope.paths[0];
        let base = semantic_noop_delta_base(&tx, base_snapshot_id, path)?
            .context("semantic no-op base file is unavailable")?;
        let canonical = revalidate_delta(scan_id, base.clone(), &delta.events)?;
        ensure_staged_metadata_for_delta(delta, &canonical)?;
        let projected_result = apply_delta_to_graph(base.clone(), &canonical)?;
        if delta_graph_digest(&projected_result) != canonical.result_graph_digest {
            bail!("semantic no-op result digest does not match the projected graph");
        }
        let previous = base
            .nodes
            .values()
            .next()
            .context("semantic no-op projection has no file node")?;
        let next = canonical
            .node_upserts
            .values()
            .next()
            .context("semantic no-op delta has no file-node upsert")?;
        validate_semantic_noop_node(previous, next, path)?;

        let started_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        tx.execute(
            "INSERT INTO scans(
                id, root, status, strict, started_at, protocol_version,
                parent_snapshot_id, source_revision, mutation_count
             ) VALUES (?1, ?2, 'staging', ?3, ?4, '1.0', ?5, ?6, 1)",
            params![
                scan_id,
                root.to_string_lossy(),
                strict,
                started_at,
                base_snapshot_id,
                source_revision,
            ],
        )?;
        insert_node(&tx, scan_id, &serde_json::to_value(next)?)?;
        tx.execute(
            "INSERT INTO adapter_logs(scan_id, adapter, stderr, truncated)
             VALUES (?1, 'web', ?2, ?3)",
            params![scan_id, stderr, stderr_truncated],
        )?;

        let completed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let mutation_count = delta_mutation_count(&canonical);
        let (snapshot_id, profile_ids) =
            semantic_noop_snapshot_identity(&tx, scan_id, base_snapshot_id, source_revision)?;
        tx.execute(
            "INSERT INTO incremental_deltas(
                scan_id, delta_id, adapter, base_snapshot_id, base_graph_digest,
                result_graph_digest, scope_json, events_json, mutation_count,
                status, prospective_snapshot_id, staged_at, completed_at
             ) VALUES (?1, ?2, 'web', ?3, ?4, ?5, ?6, ?7, ?8,
                       'applied', ?9, ?10, ?11)",
            params![
                scan_id,
                canonical.delta_id,
                base_snapshot_id,
                canonical.base_graph_digest,
                canonical.result_graph_digest,
                serde_json::to_string(&canonical.scope)?,
                serde_json::to_string(&canonical.events)?,
                mutation_count,
                snapshot_id,
                started_at,
                completed_at,
            ],
        )?;
        tx.execute(
            "UPDATE scans SET status='completed', completed_at=?2 WHERE id=?1",
            params![scan_id, completed_at],
        )?;
        insert_semantic_noop_completed_snapshot(
            &tx,
            &snapshot_id,
            scan_id,
            base_snapshot_id,
            source_revision,
            &profile_ids,
            &completed_at,
        )?;
        tx.execute(
            "INSERT INTO current_successful(singleton, scan_id) VALUES (1, ?1)
             ON CONFLICT(singleton) DO UPDATE SET scan_id=excluded.scan_id",
            [scan_id],
        )?;
        promote_completed_snapshot(&tx, &snapshot_id)?;
        tx.commit()?;
        Ok(snapshot_id)
    }

    pub fn stage_incremental_delta(
        &mut self,
        scan_id: &str,
        delta: &ValidatedDelta,
    ) -> Result<IncrementalDeltaRecord> {
        let tx = self.connection.transaction()?;
        ensure_scan_staging(&tx, scan_id)?;
        let parent = incremental_parent(&tx, scan_id)?;
        if parent != delta.base_snapshot_id {
            bail!("incremental delta base does not match the staging scan parent");
        }
        ensure_current_base(&tx, &parent)?;
        let base = load_delta_base_graph(&tx, &parent)?;
        let canonical = revalidate_delta(scan_id, base.clone(), &delta.events)?;
        if canonical.delta_id != delta.delta_id
            || canonical.base_snapshot_id != delta.base_snapshot_id
            || canonical.base_graph_digest != delta.base_graph_digest
            || canonical.result_graph_digest != delta.result_graph_digest
        {
            bail!("validated delta metadata does not match its canonical event stream");
        }
        let result = apply_delta_to_graph(base, &canonical)?;
        let observed_result_digest = delta_graph_digest(&result);
        if observed_result_digest != canonical.result_graph_digest {
            bail!("delta result graph digest does not match the canonical graph after mutation");
        }
        let mutation_count = delta_mutation_count(&canonical);
        let adapter = canonical
            .events
            .first()
            .map(|event| event.common().adapter.clone())
            .context("validated delta has no start event")?;
        let staged_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        tx.execute(
            "INSERT INTO incremental_deltas(
                scan_id, delta_id, adapter, base_snapshot_id, base_graph_digest,
                result_graph_digest, scope_json, events_json, mutation_count,
                status, staged_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'staging', ?10)",
            params![
                scan_id,
                canonical.delta_id,
                adapter,
                canonical.base_snapshot_id,
                canonical.base_graph_digest,
                canonical.result_graph_digest,
                serde_json::to_string(&canonical.scope)?,
                serde_json::to_string(&canonical.events)?,
                mutation_count,
                staged_at,
            ],
        )?;
        tx.commit()?;
        self.incremental_delta(scan_id, &canonical.delta_id)?
            .context("staged incremental delta was not visible after commit")
    }

    pub fn apply_staged_incremental_delta(
        &mut self,
        scan_id: &str,
        delta_id: &str,
    ) -> Result<IncrementalDeltaRecord> {
        let result = (|| -> Result<()> {
            let tx = self.connection.transaction()?;
            ensure_scan_staging(&tx, scan_id)?;
            let staged = load_staged_delta(&tx, scan_id, delta_id)?;
            if staged.record.status != "staging" {
                bail!(
                    "incremental delta {delta_id} is immutable after reaching status {}",
                    staged.record.status
                );
            }
            let parent = incremental_parent(&tx, scan_id)?;
            if parent != staged.record.base_snapshot_id {
                bail!("staged delta base does not match the incremental scan parent");
            }
            ensure_current_base(&tx, &parent)?;
            let base = load_delta_base_graph(&tx, &parent)?;
            if delta_graph_digest(&base) != staged.record.base_graph_digest {
                bail!("staged delta base graph digest no longer matches the completed snapshot");
            }
            let canonical = revalidate_delta(scan_id, base.clone(), &staged.events)?;
            ensure_staged_metadata(&staged.record, &canonical)?;
            let expected_result = apply_delta_to_graph(base, &canonical)?;
            if delta_graph_digest(&expected_result) != staged.record.result_graph_digest {
                bail!("staged delta result graph digest failed canonical recomputation");
            }

            apply_delta_mutations(&tx, scan_id, &canonical)?;
            let stored_result = load_scan_delta_graph(&tx, scan_id, &parent)?;
            if delta_graph_digest(&stored_result) != staged.record.result_graph_digest {
                bail!("transactional graph mutation produced an unexpected graph digest");
            }
            let (source_revision,): (Option<String>,) = tx.query_row(
                "SELECT source_revision FROM scans WHERE id=?1",
                [scan_id],
                |row| Ok((row.get(0)?,)),
            )?;
            let (prospective_snapshot_id, _) = completed_snapshot_identity(
                &tx,
                scan_id,
                None,
                &[],
                Some(&parent),
                source_revision.as_deref(),
            )?;
            tx.execute(
                "UPDATE scans SET mutation_count=mutation_count+?2 WHERE id=?1",
                params![scan_id, staged.record.mutation_count],
            )?;
            tx.execute(
                "UPDATE incremental_deltas
                    SET status='applied', prospective_snapshot_id=?3,
                        completed_at=?4, error=NULL
                  WHERE scan_id=?1 AND delta_id=?2 AND status='staging'",
                params![
                    scan_id,
                    delta_id,
                    prospective_snapshot_id,
                    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                ],
            )?;
            tx.commit()?;
            Ok(())
        })();

        if let Err(error) = result {
            self.connection.execute(
                "UPDATE incremental_deltas
                    SET status='failed', completed_at=?3,
                        error='transactional incremental delta apply failed'
                  WHERE scan_id=?1 AND delta_id=?2 AND status='staging'",
                params![
                    scan_id,
                    delta_id,
                    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
                ],
            )?;
            return Err(error);
        }
        self.incremental_delta(scan_id, delta_id)?
            .context("applied incremental delta was not visible after commit")
    }

    pub fn cancel_staged_incremental_delta(
        &mut self,
        scan_id: &str,
        delta_id: &str,
    ) -> Result<IncrementalDeltaRecord> {
        let tx = self.connection.transaction()?;
        ensure_scan_staging(&tx, scan_id)?;
        let changed = tx.execute(
            "UPDATE incremental_deltas
                SET status='cancelled', completed_at=?3,
                    error='incremental delta apply cancelled'
              WHERE scan_id=?1 AND delta_id=?2 AND status='staging'",
            params![
                scan_id,
                delta_id,
                Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
            ],
        )?;
        if changed != 1 {
            bail!("staged incremental delta {delta_id} was not found");
        }
        tx.commit()?;
        self.incremental_delta(scan_id, delta_id)?
            .context("cancelled incremental delta was not visible after commit")
    }

    pub fn incremental_delta(
        &self,
        scan_id: &str,
        delta_id: &str,
    ) -> Result<Option<IncrementalDeltaRecord>> {
        load_incremental_delta_record(&self.connection, scan_id, delta_id)
    }

    pub fn start_incremental_scan_with_revision(
        &mut self,
        scan_id: &str,
        root: &Path,
        strict: bool,
        base_snapshot_id: &str,
        source_revision: Option<&str>,
    ) -> Result<()> {
        if source_revision.is_some_and(|revision| revision.trim().is_empty()) {
            bail!("source revision must not be empty");
        }
        let base = self
            .completed_snapshot(base_snapshot_id)?
            .with_context(|| {
                format!("incremental base snapshot {base_snapshot_id} was not found")
            })?;
        if base.source_kind != "scan" {
            bail!("incremental replacement requires a completed scan snapshot base");
        }
        if self.current_snapshot_id()?.as_deref() != Some(base_snapshot_id) {
            bail!("incremental base snapshot is not the current completed snapshot");
        }
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
                base_snapshot_id,
                source_revision,
            ],
        )?;
        tx.commit()?;
        self.clone_completed_scan_into_staging(base_snapshot_id, scan_id)
    }

    pub fn replace_incremental_graph(
        &mut self,
        scan_id: &str,
        base_snapshot_id: &str,
        scope: &IncrementalReplacementScope,
        replacement_events: &[Value],
        adapter_logs: &[AdapterLogRecord],
    ) -> Result<()> {
        scope.validate()?;
        if replacement_events.is_empty() {
            bail!("incremental replacement must include a complete replacement event batch");
        }
        let tx = self.connection.transaction()?;
        ensure_scan_staging(&tx, scan_id)?;
        let parent: Option<String> = tx.query_row(
            "SELECT parent_snapshot_id FROM scans WHERE id=?1",
            [scan_id],
            |row| row.get(0),
        )?;
        if parent.as_deref() != Some(base_snapshot_id) {
            bail!("incremental scan parent does not match its replacement base");
        }
        let current: Option<String> = tx
            .query_row(
                "SELECT snapshot_id FROM current_completed_snapshot WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if current.as_deref() != Some(base_snapshot_id) {
            bail!("incremental replacement base changed before the transaction started");
        }

        let ownership = load_owned_records(&tx, scan_id, scope)?;
        delete_owned_records(&tx, scan_id, scope, &ownership)?;
        let mut completed_events = 0_usize;
        for event in replacement_events {
            if required_str(event, "scan_id")? != scan_id {
                bail!("incremental replacement event targets another scan");
            }
            let event_type = required_str(event, "event")?;
            if event_type == "scan_completed" {
                completed_events += 1;
            }
            ensure_event_is_scoped(&tx, scan_id, scope, event)?;
            ingest_event_in_transaction(&tx, event)?;
        }
        if completed_events != 1 {
            bail!("incremental replacement requires exactly one scan_completed event");
        }
        for log in adapter_logs {
            if scope.adapters.binary_search(&log.adapter).is_err() {
                bail!("incremental adapter log is outside the replacement scope");
            }
            tx.execute(
                "INSERT INTO adapter_logs(scan_id, adapter, stderr, truncated)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(scan_id, adapter) DO UPDATE SET
                    stderr=excluded.stderr, truncated=excluded.truncated",
                params![scan_id, log.adapter, log.stderr, log.truncated],
            )?;
        }
        let coverage_count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM coverage WHERE scan_id=?1",
            [scan_id],
            |row| row.get(0),
        )?;
        if coverage_count != 1 {
            bail!("incremental replacement did not produce aggregate coverage");
        }
        tx.execute(
            "UPDATE scans SET mutation_count=mutation_count+1 WHERE id=?1",
            [scan_id],
        )?;
        tx.commit()?;
        Ok(())
    }
}

#[derive(Debug)]
struct StagedDelta {
    record: IncrementalDeltaRecord,
    events: Vec<depgraph_protocol::DeltaEvent>,
}

fn incremental_parent(connection: &Connection, scan_id: &str) -> Result<String> {
    connection
        .query_row(
            "SELECT parent_snapshot_id FROM scans WHERE id=?1",
            [scan_id],
            |row| row.get::<_, Option<String>>(0),
        )?
        .with_context(|| format!("incremental scan {scan_id} has no parent snapshot"))
}

fn ensure_current_base(connection: &Connection, base_snapshot_id: &str) -> Result<()> {
    let current = connection
        .query_row(
            "SELECT snapshot_id FROM current_completed_snapshot WHERE singleton=1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if current.as_deref() != Some(base_snapshot_id) {
        bail!("incremental delta base is not the current completed snapshot");
    }
    Ok(())
}

fn load_incremental_delta_record(
    connection: &Connection,
    scan_id: &str,
    delta_id: &str,
) -> Result<Option<IncrementalDeltaRecord>> {
    connection
        .query_row(
            "SELECT scan_id, delta_id, adapter, base_snapshot_id, base_graph_digest,
                    result_graph_digest, mutation_count, status, prospective_snapshot_id,
                    staged_at, completed_at, error
               FROM incremental_deltas
              WHERE scan_id=?1 AND delta_id=?2",
            params![scan_id, delta_id],
            |row| {
                Ok(IncrementalDeltaRecord {
                    scan_id: row.get(0)?,
                    delta_id: row.get(1)?,
                    adapter: row.get(2)?,
                    base_snapshot_id: row.get(3)?,
                    base_graph_digest: row.get(4)?,
                    result_graph_digest: row.get(5)?,
                    mutation_count: row.get(6)?,
                    status: row.get(7)?,
                    prospective_snapshot_id: row.get(8)?,
                    staged_at: row.get(9)?,
                    completed_at: row.get(10)?,
                    error: row.get(11)?,
                })
            },
        )
        .optional()
        .context("failed to load incremental delta")
}

fn load_staged_delta(
    connection: &Connection,
    scan_id: &str,
    delta_id: &str,
) -> Result<StagedDelta> {
    let record = load_incremental_delta_record(connection, scan_id, delta_id)?
        .with_context(|| format!("incremental delta {delta_id} was not staged for {scan_id}"))?;
    let raw = connection.query_row(
        "SELECT events_json FROM incremental_deltas WHERE scan_id=?1 AND delta_id=?2",
        params![scan_id, delta_id],
        |row| row.get::<_, String>(0),
    )?;
    Ok(StagedDelta {
        record,
        events: serde_json::from_str(&raw).context("staged delta event JSON is invalid")?,
    })
}

fn load_delta_base_graph(connection: &Connection, snapshot_id: &str) -> Result<DeltaBaseGraph> {
    let mut current = snapshot_id.to_owned();
    let mut visited = BTreeSet::new();
    let mut overlays = Vec::new();
    let mut graph = loop {
        if !visited.insert(current.clone()) {
            bail!("completed snapshot parent cycle detected while loading delta base");
        }
        let (source_kind, scan_id) = connection
            .query_row(
                "SELECT source_kind, scan_id FROM completed_snapshots
                  WHERE id=?1 AND status='completed'",
                [&current],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .with_context(|| format!("completed delta base snapshot {current} was not found"))?;
        if source_kind != "scan" {
            bail!("worker delta requires a completed scan snapshot base");
        }
        if !scan_is_semantic_noop_overlay(connection, &scan_id)? {
            break load_scan_delta_graph(connection, &scan_id, &current)?;
        }
        overlays.push(scan_id.clone());
        current = incremental_parent(connection, &scan_id)?;
    };
    if overlays.is_empty() {
        return Ok(graph);
    }
    for scan_id in overlays.into_iter().rev() {
        for raw in load_raw_records(connection, "nodes", &scan_id)? {
            let node: GraphNode = serde_json::from_str(&raw)?;
            graph.nodes.insert(node.id.clone(), node);
        }
    }
    graph.snapshot_id = snapshot_id.to_owned();
    graph.graph_digest = delta_graph_digest(&graph);
    Ok(graph)
}

fn semantic_noop_delta_base(
    connection: &Connection,
    snapshot_id: &str,
    path: &str,
) -> Result<Option<DeltaBaseGraph>> {
    let record = load_completed_snapshot_record(connection, snapshot_id)?
        .with_context(|| format!("completed delta base snapshot {snapshot_id} was not found"))?;
    if record.source_kind != "scan" {
        return Ok(None);
    }
    let Some(node) = load_effective_file_node(connection, snapshot_id, path)? else {
        return Ok(None);
    };
    if node.kind != "file"
        || node.properties.get("path").and_then(Value::as_str) != Some(path)
        || node
            .properties
            .get("analysis_hash")
            .and_then(Value::as_str)
            .is_none()
    {
        return Ok(None);
    }

    let mut graph = DeltaBaseGraph {
        snapshot_id: snapshot_id.to_owned(),
        profiles: record.profile_ids.iter().cloned().collect(),
        nodes: BTreeMap::from([(node.id.clone(), node)]),
        ..DeltaBaseGraph::default()
    };
    let aggregate = Coverage {
        profiles: graph.profiles.len() as u64,
        files_discovered: 1,
        files_analyzed: 1,
        ..Coverage::default()
    };
    graph.coverage.insert(
        DeltaCoverageKey::Aggregate,
        DeltaCoverage::Aggregate {
            value: aggregate.clone(),
        },
    );
    for profile_id in &graph.profiles {
        let coverage = DeltaCoverage::Profile {
            profile_id: profile_id.clone(),
            value: Coverage {
                profiles: 1,
                files_discovered: 1,
                files_analyzed: 1,
                ..Coverage::default()
            },
        };
        graph.coverage.insert(coverage.key(), coverage);
    }
    let file = DeltaCoverage::File {
        adapter: "web".to_owned(),
        path: path.to_owned(),
        value: DeltaFileCoverage {
            discovered_sites: 0,
            emitted_sites: 0,
            skipped_sites: 0,
            skipped: false,
            reason: None,
        },
    };
    graph.coverage.insert(file.key(), file);
    graph.graph_digest = delta_graph_digest(&graph);
    Ok(Some(graph))
}

fn load_effective_file_node(
    connection: &Connection,
    snapshot_id: &str,
    path: &str,
) -> Result<Option<GraphNode>> {
    let mut current = snapshot_id.to_owned();
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(current.clone()) {
            bail!("completed snapshot parent cycle detected while resolving {path}");
        }
        let record = load_completed_snapshot_record(connection, &current)?
            .with_context(|| format!("completed snapshot {current} was not found"))?;
        if record.source_kind != "scan" {
            return Ok(None);
        }
        let mut statement = connection.prepare(
            "SELECT raw_json FROM nodes
              WHERE scan_id=?1 AND kind='file'
                AND json_extract(properties_json, '$.path')=?2
              ORDER BY id",
        )?;
        let rows = statement
            .query_map(params![record.scan_id, path], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        match rows.as_slice() {
            [raw] => return Ok(Some(serde_json::from_str(raw)?)),
            [] if scan_is_semantic_noop_overlay(connection, &record.scan_id)? => {
                current = record
                    .parent_snapshot_id
                    .context("semantic no-op overlay has no parent snapshot")?;
            }
            [] => return Ok(None),
            _ => bail!("snapshot {current} has multiple file nodes for path {path}"),
        }
    }
}

pub(super) fn scan_is_semantic_noop_overlay(
    connection: &Connection,
    scan_id: &str,
) -> Result<bool> {
    let has_incremental_deltas = connection
        .query_row(
            "SELECT 1 FROM sqlite_master
              WHERE type='table' AND name='incremental_deltas'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !has_incremental_deltas {
        return Ok(false);
    }
    let (parent, profiles, deltas): (Option<String>, i64, i64) = connection.query_row(
        "SELECT s.parent_snapshot_id,
                (SELECT COUNT(*) FROM profiles p WHERE p.scan_id=s.id),
                (SELECT COUNT(*) FROM incremental_deltas d
                  WHERE d.scan_id=s.id AND d.status='applied')
           FROM scans s WHERE s.id=?1",
        [scan_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    Ok(parent.is_some() && profiles == 0 && deltas == 1)
}

fn validate_semantic_noop_node(previous: &GraphNode, next: &GraphNode, path: &str) -> Result<()> {
    if previous.id != next.id
        || previous.kind != next.kind
        || previous.locator != next.locator
        || previous.display_name != next.display_name
        || next.kind != "file"
        || next.properties.get("path").and_then(Value::as_str) != Some(path)
    {
        bail!("semantic no-op delta changed file-node identity or routing metadata");
    }
    let previous_analysis = required_sha256_property(previous, "analysis_hash")?;
    let next_analysis = required_sha256_property(next, "analysis_hash")?;
    if previous_analysis != next_analysis {
        bail!("semantic no-op delta changed the dependency-analysis fingerprint");
    }
    let previous_content = required_sha256_property(previous, "content_hash")?;
    let next_content = required_sha256_property(next, "content_hash")?;
    if previous_content == next_content {
        bail!("semantic no-op delta did not change the content fingerprint");
    }
    let mut expected = previous.clone();
    expected
        .properties
        .insert("content_hash".to_owned(), json!(next_content));
    if &expected != next {
        bail!("semantic no-op delta changed properties beyond the content fingerprint");
    }
    Ok(())
}

fn required_sha256_property<'a>(node: &'a GraphNode, property: &str) -> Result<&'a str> {
    let value = node
        .properties
        .get(property)
        .and_then(Value::as_str)
        .with_context(|| format!("file node has no {property}"))?;
    if value.len() != "sha256:".len() + 64
        || !value.starts_with("sha256:")
        || !value["sha256:".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("file node {property} is not a canonical SHA-256 digest");
    }
    Ok(value)
}

fn ensure_staged_metadata_for_delta(
    supplied: &ValidatedDelta,
    canonical: &ValidatedDelta,
) -> Result<()> {
    if canonical.delta_id != supplied.delta_id
        || canonical.base_snapshot_id != supplied.base_snapshot_id
        || canonical.base_graph_digest != supplied.base_graph_digest
        || canonical.result_graph_digest != supplied.result_graph_digest
        || canonical.scope != supplied.scope
    {
        bail!("validated delta metadata does not match its canonical event stream");
    }
    Ok(())
}

pub(super) fn semantic_noop_snapshot_identity(
    connection: &Connection,
    scan_id: &str,
    parent_snapshot_id: &str,
    source_revision: Option<&str>,
) -> Result<(String, Vec<String>)> {
    let parent = load_completed_snapshot_record(connection, parent_snapshot_id)?
        .with_context(|| format!("semantic no-op parent {parent_snapshot_id} was not found"))?;
    let mut nodes = load_raw_records(connection, "nodes", scan_id)?
        .into_iter()
        .map(|raw| serde_json::from_str::<GraphNode>(&raw))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if nodes.len() != 1 {
        bail!("semantic no-op overlay must persist exactly one node");
    }
    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    let identity = json!({
        "schema": "completed-snapshot-v3-semantic-noop",
        "parent_snapshot_id": parent_snapshot_id,
        "source_revision": source_revision,
        "profile_ids": parent.profile_ids,
        "node_upserts": nodes,
    });
    Ok((
        stable_id_from_value("snapshot", &identity),
        parent.profile_ids,
    ))
}

fn insert_semantic_noop_completed_snapshot(
    connection: &Connection,
    snapshot_id: &str,
    scan_id: &str,
    parent_snapshot_id: &str,
    source_revision: Option<&str>,
    profile_ids: &[String],
    completed_at: &str,
) -> Result<()> {
    connection.execute(
        "INSERT INTO completed_snapshots(
            id, source_kind, source_attempt_id, scan_id, build_attempt_id,
            runtime_import_id, runtime_session_set_json, parent_snapshot_id,
            source_revision, profile_set_json, status, created_at
         ) VALUES (?1, 'scan', ?2, ?2, NULL, NULL, '[]', ?3, ?4, ?5,
                   'completed', ?6)
         ON CONFLICT(id) DO NOTHING",
        params![
            snapshot_id,
            scan_id,
            parent_snapshot_id,
            source_revision,
            serde_json::to_string(profile_ids)?,
            completed_at,
        ],
    )?;
    let stored = load_completed_snapshot_record(connection, snapshot_id)?
        .context("semantic no-op completed snapshot insert was not visible")?;
    if stored.parent_snapshot_id.as_deref() != Some(parent_snapshot_id)
        || stored.source_revision.as_deref() != source_revision
        || stored.profile_ids != profile_ids
        || stored.status != "completed"
    {
        bail!("completed semantic no-op snapshot identity collision for {snapshot_id}");
    }
    connection.execute(
        "INSERT INTO snapshot_sources(source_kind, source_attempt_id, snapshot_id, promoted_at)
         VALUES ('scan', ?1, ?2, ?3)",
        params![scan_id, snapshot_id, completed_at],
    )?;
    Ok(())
}

fn load_scan_delta_graph(
    connection: &Connection,
    scan_id: &str,
    snapshot_id: &str,
) -> Result<DeltaBaseGraph> {
    let profiles = {
        let mut statement =
            connection.prepare("SELECT id FROM profiles WHERE scan_id=?1 ORDER BY id")?;
        statement
            .query_map([scan_id], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<BTreeSet<_>, _>>()?
    };
    let nodes = load_raw_records(connection, "nodes", scan_id)?
        .into_iter()
        .map(|raw| {
            let node: depgraph_protocol::GraphNode = serde_json::from_str(&raw)?;
            Ok((node.id.clone(), node))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let sites = load_raw_records(connection, "sites", scan_id)?
        .into_iter()
        .map(|raw| {
            let mut site: depgraph_protocol::DependencySite = serde_json::from_str(&raw)?;
            site.evidence.clear();
            Ok((site.id.clone(), site))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let edges = load_raw_records(connection, "edges", scan_id)?
        .into_iter()
        .map(|raw| {
            let mut edge: depgraph_protocol::GraphEdge = serde_json::from_str(&raw)?;
            edge.evidence.clear();
            Ok((edge.id.clone(), edge))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    let evidence = {
        let mut statement = connection.prepare(
            "SELECT owner_type, owner_id, ordinal, raw_json
               FROM evidence WHERE scan_id=?1
              ORDER BY owner_type, owner_id, ordinal",
        )?;
        let rows = statement.query_map([scan_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut records = BTreeMap::new();
        for row in rows {
            let (owner_type, owner_id, ordinal, raw) = row?;
            let owner_type = match owner_type.as_str() {
                "node" => DeltaEvidenceOwner::Node,
                "site" => DeltaEvidenceOwner::Site,
                "edge" => DeltaEvidenceOwner::Edge,
                other => bail!("unsupported delta evidence owner type {other}"),
            };
            records.insert(
                DeltaEvidenceKey {
                    owner_type,
                    owner_id,
                    ordinal,
                },
                serde_json::from_str::<Evidence>(&raw)?,
            );
        }
        records
    };

    let mut coverage = BTreeMap::new();
    {
        let mut statement = connection.prepare(
            "SELECT profile_id, json FROM profile_coverage
              WHERE scan_id=?1 ORDER BY profile_id",
        )?;
        for row in statement.query_map([scan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })? {
            let (profile_id, raw) = row?;
            let item = DeltaCoverage::Profile {
                profile_id,
                value: serde_json::from_str::<Coverage>(&raw)?,
            };
            coverage.insert(item.key(), item);
        }
    }
    {
        let mut statement = connection.prepare(
            "SELECT adapter, path, discovered_sites, emitted_sites, skipped_sites,
                    skipped, reason
               FROM file_coverage WHERE scan_id=?1 ORDER BY adapter, path",
        )?;
        for row in statement.query_map([scan_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u64>(2)?,
                row.get::<_, u64>(3)?,
                row.get::<_, u64>(4)?,
                row.get::<_, bool>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })? {
            let (adapter, path, discovered_sites, emitted_sites, skipped_sites, skipped, reason) =
                row?;
            let item = DeltaCoverage::File {
                adapter,
                path,
                value: DeltaFileCoverage {
                    discovered_sites,
                    emitted_sites,
                    skipped_sites,
                    skipped,
                    reason,
                },
            };
            coverage.insert(item.key(), item);
        }
    }
    let aggregate = connection
        .query_row(
            "SELECT json FROM coverage WHERE scan_id=?1",
            [scan_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .with_context(|| format!("scan {scan_id} has no aggregate coverage"))?;
    let aggregate = DeltaCoverage::Aggregate {
        value: serde_json::from_str::<Coverage>(&aggregate)?,
    };
    coverage.insert(aggregate.key(), aggregate);

    let mut graph = DeltaBaseGraph {
        snapshot_id: snapshot_id.to_owned(),
        graph_digest: String::new(),
        profiles,
        nodes,
        sites,
        edges,
        evidence,
        coverage,
    };
    graph.graph_digest = delta_graph_digest(&graph);
    Ok(graph)
}

fn load_raw_records(connection: &Connection, table: &str, scan_id: &str) -> Result<Vec<String>> {
    let sql = match table {
        "nodes" => "SELECT raw_json FROM nodes WHERE scan_id=?1 ORDER BY id",
        "sites" => "SELECT raw_json FROM sites WHERE scan_id=?1 ORDER BY id",
        "edges" => "SELECT raw_json FROM edges WHERE scan_id=?1 ORDER BY id",
        _ => unreachable!("delta graph loading uses fixed record tables"),
    };
    let mut statement = connection.prepare(sql)?;
    Ok(statement
        .query_map([scan_id], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?)
}

fn revalidate_delta(
    scan_id: &str,
    base: DeltaBaseGraph,
    events: &[depgraph_protocol::DeltaEvent],
) -> Result<ValidatedDelta> {
    let mut validator = DeltaValidator::new(base)?;
    for event in events {
        if event.common().scan_id != scan_id {
            bail!("incremental delta event targets another staging scan");
        }
        validator.push(event.clone())?;
    }
    Ok(validator.finish()?)
}

fn ensure_staged_metadata(record: &IncrementalDeltaRecord, delta: &ValidatedDelta) -> Result<()> {
    if record.delta_id != delta.delta_id
        || record.base_snapshot_id != delta.base_snapshot_id
        || record.base_graph_digest != delta.base_graph_digest
        || record.result_graph_digest != delta.result_graph_digest
        || record.mutation_count != delta_mutation_count(delta)
    {
        bail!("staged delta metadata does not match its revalidated event stream");
    }
    Ok(())
}

fn delta_mutation_count(delta: &ValidatedDelta) -> u64 {
    delta.events.len().saturating_sub(2) as u64
}

fn apply_delta_to_graph(
    mut graph: DeltaBaseGraph,
    delta: &ValidatedDelta,
) -> Result<DeltaBaseGraph> {
    if graph.snapshot_id != delta.base_snapshot_id || graph.graph_digest != delta.base_graph_digest
    {
        bail!("delta cannot be applied to a different base graph");
    }
    for key in &delta.evidence_deletes {
        graph.evidence.remove(key);
    }
    for id in &delta.edge_deletes {
        graph.edges.remove(id);
    }
    for id in &delta.site_deletes {
        graph.sites.remove(id);
    }
    for id in &delta.node_deletes {
        graph.nodes.remove(id);
    }
    graph.nodes.extend(delta.node_upserts.clone());
    graph.sites.extend(delta.site_upserts.clone());
    graph.edges.extend(delta.edge_upserts.clone());
    graph.evidence.extend(delta.evidence_upserts.clone());
    for key in &delta.coverage_deletes {
        graph.coverage.remove(key);
    }
    graph.coverage.extend(delta.coverage_upserts.clone());
    graph.graph_digest = delta_graph_digest(&graph);
    Ok(graph)
}

fn apply_delta_mutations(
    tx: &Transaction<'_>,
    scan_id: &str,
    delta: &ValidatedDelta,
) -> Result<()> {
    for key in &delta.evidence_deletes {
        let changed = tx.execute(
            "DELETE FROM evidence
              WHERE scan_id=?1 AND owner_type=?2 AND owner_id=?3 AND ordinal=?4",
            params![
                scan_id,
                evidence_owner_name(key.owner_type),
                key.owner_id,
                key.ordinal
            ],
        )?;
        if changed != 1 {
            bail!("delta evidence delete did not match its validated base record");
        }
    }
    delete_delta_ids(tx, "edges", scan_id, &delta.edge_deletes)?;
    delete_delta_ids(tx, "sites", scan_id, &delta.site_deletes)?;
    delete_delta_ids(tx, "nodes", scan_id, &delta.node_deletes)?;

    for node in delta.node_upserts.values() {
        insert_node(tx, scan_id, &serde_json::to_value(node)?)?;
    }
    for site in delta.site_upserts.values() {
        upsert_site_row(tx, scan_id, &serde_json::to_value(site)?)?;
    }
    for edge in delta.edge_upserts.values() {
        upsert_edge_row(tx, scan_id, &serde_json::to_value(edge)?)?;
    }
    for (key, evidence) in &delta.evidence_upserts {
        upsert_delta_evidence(tx, scan_id, key, evidence)?;
    }
    for key in &delta.coverage_deletes {
        delete_delta_coverage(tx, scan_id, key)?;
    }
    for coverage in delta.coverage_upserts.values() {
        upsert_delta_coverage(tx, scan_id, coverage)?;
    }
    if let Some(DeltaCoverage::Aggregate { value }) =
        delta.coverage_upserts.get(&DeltaCoverageKey::Aggregate)
    {
        tx.execute(
            "UPDATE scans SET project_code_executed=?2 WHERE id=?1",
            params![scan_id, value.project_code_executed],
        )?;
    }
    Ok(())
}

fn delete_delta_ids(
    tx: &Transaction<'_>,
    table: &str,
    scan_id: &str,
    ids: &BTreeSet<String>,
) -> Result<()> {
    let sql = match table {
        "nodes" => "DELETE FROM nodes WHERE scan_id=?1 AND id=?2",
        "sites" => "DELETE FROM sites WHERE scan_id=?1 AND id=?2",
        "edges" => "DELETE FROM edges WHERE scan_id=?1 AND id=?2",
        _ => unreachable!("delta deletion uses fixed graph tables"),
    };
    for id in ids {
        if tx.execute(sql, params![scan_id, id])? != 1 {
            bail!("delta {table} delete did not match its validated base record");
        }
    }
    Ok(())
}

fn evidence_owner_name(owner: DeltaEvidenceOwner) -> &'static str {
    match owner {
        DeltaEvidenceOwner::Node => "node",
        DeltaEvidenceOwner::Site => "site",
        DeltaEvidenceOwner::Edge => "edge",
    }
}

fn upsert_delta_evidence(
    tx: &Transaction<'_>,
    scan_id: &str,
    key: &DeltaEvidenceKey,
    evidence: &Evidence,
) -> Result<()> {
    let raw = serde_json::to_value(evidence)?;
    tx.execute(
        "INSERT INTO evidence(
            scan_id, owner_type, owner_id, ordinal, kind, extractor,
            extractor_version, path, start_line, start_column, end_line,
            end_column, raw_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
         ON CONFLICT(scan_id, owner_type, owner_id, ordinal) DO UPDATE SET
            kind=excluded.kind, extractor=excluded.extractor,
            extractor_version=excluded.extractor_version, path=excluded.path,
            start_line=excluded.start_line, start_column=excluded.start_column,
            end_line=excluded.end_line, end_column=excluded.end_column,
            raw_json=excluded.raw_json",
        params![
            scan_id,
            evidence_owner_name(key.owner_type),
            key.owner_id,
            key.ordinal,
            raw.get("kind").and_then(Value::as_str).unwrap_or("source"),
            evidence.extractor,
            evidence.extractor_version,
            evidence.path.as_deref().unwrap_or(""),
            evidence.start_line.unwrap_or(1),
            evidence.start_column.unwrap_or(1),
            evidence.end_line.unwrap_or(1),
            evidence.end_column.unwrap_or(1),
            serde_json::to_string(evidence)?,
        ],
    )?;
    Ok(())
}

fn delete_delta_coverage(
    tx: &Transaction<'_>,
    scan_id: &str,
    key: &DeltaCoverageKey,
) -> Result<()> {
    let changed = match key {
        DeltaCoverageKey::Aggregate => {
            tx.execute("DELETE FROM coverage WHERE scan_id=?1", [scan_id])?
        }
        DeltaCoverageKey::Profile { profile_id } => tx.execute(
            "DELETE FROM profile_coverage WHERE scan_id=?1 AND profile_id=?2",
            params![scan_id, profile_id],
        )?,
        DeltaCoverageKey::File { adapter, path } => tx.execute(
            "DELETE FROM file_coverage WHERE scan_id=?1 AND adapter=?2 AND path=?3",
            params![scan_id, adapter, path],
        )?,
    };
    if changed != 1 {
        bail!("delta coverage delete did not match its validated base record");
    }
    Ok(())
}

fn upsert_delta_coverage(
    tx: &Transaction<'_>,
    scan_id: &str,
    coverage: &DeltaCoverage,
) -> Result<()> {
    match coverage {
        DeltaCoverage::Aggregate { value } => {
            tx.execute(
                "INSERT INTO coverage(scan_id, json) VALUES (?1, ?2)
                 ON CONFLICT(scan_id) DO UPDATE SET json=excluded.json",
                params![scan_id, serde_json::to_string(value)?],
            )?;
        }
        DeltaCoverage::Profile { profile_id, value } => {
            tx.execute(
                "INSERT INTO profile_coverage(scan_id, profile_id, json)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(scan_id, profile_id) DO UPDATE SET json=excluded.json",
                params![scan_id, profile_id, serde_json::to_string(value)?],
            )?;
        }
        DeltaCoverage::File {
            adapter,
            path,
            value,
        } => {
            tx.execute(
                "INSERT INTO file_coverage(
                    scan_id, path, discovered_sites, emitted_sites, skipped_sites,
                    skipped, reason, adapter
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(scan_id, adapter, path) DO UPDATE SET
                    discovered_sites=excluded.discovered_sites,
                    emitted_sites=excluded.emitted_sites,
                    skipped_sites=excluded.skipped_sites,
                    skipped=excluded.skipped, reason=excluded.reason",
                params![
                    scan_id,
                    path,
                    value.discovered_sites,
                    value.emitted_sites,
                    value.skipped_sites,
                    value.skipped,
                    value.reason,
                    adapter,
                ],
            )?;
        }
    }
    Ok(())
}

#[derive(Default)]
struct OwnedRecords {
    nodes: BTreeSet<String>,
    sites: BTreeSet<String>,
    edges: BTreeSet<String>,
    diagnostics: BTreeSet<String>,
}

fn load_owned_records(
    tx: &Transaction<'_>,
    scan_id: &str,
    scope: &IncrementalReplacementScope,
) -> Result<OwnedRecords> {
    let mut owned = OwnedRecords::default();
    let mut nodes = tx.prepare(
        "SELECT id, kind, locator, properties_json FROM nodes WHERE scan_id=?1 ORDER BY id",
    )?;
    for row in nodes.query_map([scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })? {
        let (id, kind, locator, raw) = row?;
        let properties: Value = serde_json::from_str(&raw)?;
        if scope.artifact_node_ids.binary_search(&id).is_ok()
            || (kind == "package_instance"
                && scope.package_locators.binary_search(&locator).is_ok())
            || scope.paths.binary_search(&locator).is_ok()
            || has_named_value(
                &properties,
                &[
                    "path",
                    "source_path",
                    "manifest_path",
                    "relative_path",
                    "logical_path",
                ],
                &scope.paths,
            )
            || has_named_value(&properties, &["package_locator"], &scope.package_locators)
            || has_named_value(&properties, &["profile_id"], &scope.replanned_profile_ids)
        {
            owned.nodes.insert(id);
        }
    }

    let mut evidence = tx.prepare(
        "SELECT owner_type, owner_id, path FROM evidence WHERE scan_id=?1
         ORDER BY owner_type, owner_id, ordinal",
    )?;
    for row in evidence.query_map([scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })? {
        let (owner_type, owner_id, path) = row?;
        if scope.paths.binary_search(&path).is_ok() {
            match owner_type.as_str() {
                "node" => {
                    owned.nodes.insert(owner_id);
                }
                "site" => {
                    owned.sites.insert(owner_id);
                }
                "edge" => {
                    owned.edges.insert(owner_id);
                }
                "diagnostic" => {
                    owned.diagnostics.insert(owner_id);
                }
                _ => {}
            }
        }
    }

    let mut sites =
        tx.prepare("SELECT id, source, profile_id FROM sites WHERE scan_id=?1 ORDER BY id")?;
    for row in sites.query_map([scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })? {
        let (id, source, profile_id) = row?;
        if owned.nodes.contains(&source)
            || scope
                .replanned_profile_ids
                .binary_search(&profile_id)
                .is_ok()
        {
            owned.sites.insert(id);
        }
    }

    let mut edges = tx.prepare(
        "SELECT id, site_id, source, target, profile_id FROM edges WHERE scan_id=?1 ORDER BY id",
    )?;
    for row in edges.query_map([scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })? {
        let (id, site_id, source, target, profile_id) = row?;
        if owned.nodes.contains(&source)
            || owned.nodes.contains(&target)
            || site_id.is_some_and(|site_id| owned.sites.contains(&site_id))
            || scope
                .replanned_profile_ids
                .binary_search(&profile_id)
                .is_ok()
        {
            owned.edges.insert(id);
        }
    }

    let mut diagnostics =
        tx.prepare("SELECT id, path, raw_json FROM diagnostics WHERE scan_id=?1 ORDER BY id")?;
    for row in diagnostics.query_map([scan_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, String>(2)?,
        ))
    })? {
        let (id, path, raw) = row?;
        let diagnostic: Value = serde_json::from_str(&raw)?;
        if path.is_some_and(|path| scope.paths.binary_search(&path).is_ok())
            || has_named_value(&diagnostic, &["profile_id"], &scope.replanned_profile_ids)
        {
            owned.diagnostics.insert(id);
        }
    }
    Ok(owned)
}

fn delete_owned_records(
    tx: &Transaction<'_>,
    scan_id: &str,
    scope: &IncrementalReplacementScope,
    owned: &OwnedRecords,
) -> Result<()> {
    for (owner_type, ids) in [
        ("node", &owned.nodes),
        ("edge", &owned.edges),
        ("site", &owned.sites),
        ("diagnostic", &owned.diagnostics),
    ] {
        for id in ids {
            tx.execute(
                "DELETE FROM evidence WHERE scan_id=?1 AND owner_type=?2 AND owner_id=?3",
                params![scan_id, owner_type, id],
            )?;
        }
    }
    delete_ids(tx, "edges", scan_id, &owned.edges)?;
    delete_ids(tx, "sites", scan_id, &owned.sites)?;
    delete_ids(tx, "diagnostics", scan_id, &owned.diagnostics)?;
    delete_ids(tx, "nodes", scan_id, &owned.nodes)?;
    for path in &scope.paths {
        tx.execute(
            "DELETE FROM file_coverage WHERE scan_id=?1 AND path=?2",
            params![scan_id, path],
        )?;
    }
    for profile_id in &scope.profile_ids {
        tx.execute(
            "DELETE FROM profile_coverage WHERE scan_id=?1 AND profile_id=?2",
            params![scan_id, profile_id],
        )?;
    }
    for profile_id in &scope.replanned_profile_ids {
        tx.execute(
            "DELETE FROM profiles WHERE scan_id=?1 AND id=?2",
            params![scan_id, profile_id],
        )?;
    }
    for adapter in &scope.adapters {
        tx.execute(
            "DELETE FROM adapter_logs WHERE scan_id=?1 AND adapter=?2",
            params![scan_id, adapter],
        )?;
    }
    tx.execute("DELETE FROM coverage WHERE scan_id=?1", [scan_id])?;
    Ok(())
}

fn delete_ids(
    tx: &Transaction<'_>,
    table: &str,
    scan_id: &str,
    ids: &BTreeSet<String>,
) -> Result<()> {
    let sql = match table {
        "nodes" => "DELETE FROM nodes WHERE scan_id=?1 AND id=?2",
        "sites" => "DELETE FROM sites WHERE scan_id=?1 AND id=?2",
        "edges" => "DELETE FROM edges WHERE scan_id=?1 AND id=?2",
        "diagnostics" => "DELETE FROM diagnostics WHERE scan_id=?1 AND id=?2",
        _ => unreachable!("incremental deletion uses fixed table names"),
    };
    for id in ids {
        tx.execute(sql, params![scan_id, id])?;
    }
    Ok(())
}

fn ensure_event_is_scoped(
    tx: &Transaction<'_>,
    scan_id: &str,
    scope: &IncrementalReplacementScope,
    event: &Value,
) -> Result<()> {
    let event_type = required_str(event, "event")?;
    let adapter = event
        .get("adapter")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if !matches!(event_type, "scan_started" | "scan_completed")
        && adapter != "core"
        && scope.adapters.binary_search(&adapter.to_owned()).is_err()
    {
        bail!("incremental replacement event adapter is outside the replacement scope");
    }
    match event_type {
        "profile_declared" => {
            let profile = event
                .get("profile")
                .context("profile_declared is missing profile")?;
            let id = required_str(profile, "id")?;
            if scope
                .replanned_profile_ids
                .binary_search(&id.to_owned())
                .is_err()
            {
                let existing = ensure_existing_value_is_unchanged(
                    tx, "profiles", "json", scan_id, id, profile,
                )?;
                if !existing {
                    bail!("incremental replacement introduced an out-of-scope profile");
                }
            }
        }
        "node_upsert" => {
            let node = event.get("node").context("node_upsert is missing node")?;
            let existing = ensure_existing_value_is_unchanged(
                tx,
                "nodes",
                "raw_json",
                scan_id,
                required_str(node, "id")?,
                node,
            )?;
            if !existing && !node_is_scoped(scope, node)? {
                bail!("incremental replacement introduced an out-of-scope node");
            }
        }
        "dependency_site" => {
            let site = event
                .get("site")
                .context("dependency_site is missing site")?;
            let existing = ensure_existing_value_is_unchanged(
                tx,
                "sites",
                "raw_json",
                scan_id,
                required_str(site, "id")?,
                site,
            )?;
            if !existing && !site_is_scoped(tx, scan_id, scope, site)? {
                bail!("incremental replacement introduced an out-of-scope dependency site");
            }
        }
        "edge_upsert" => {
            let edge = event.get("edge").context("edge_upsert is missing edge")?;
            let existing = ensure_existing_value_is_unchanged(
                tx,
                "edges",
                "raw_json",
                scan_id,
                required_str(edge, "id")?,
                edge,
            )?;
            if !existing && !edge_is_scoped(tx, scan_id, scope, edge)? {
                bail!("incremental replacement introduced an out-of-scope edge");
            }
        }
        "diagnostic" => {
            let diagnostic = event
                .get("diagnostic")
                .context("diagnostic is missing payload")?;
            let existing = diagnostic
                .get("id")
                .and_then(Value::as_str)
                .map(|id| {
                    ensure_existing_value_is_unchanged(
                        tx,
                        "diagnostics",
                        "raw_json",
                        scan_id,
                        id,
                        diagnostic,
                    )
                })
                .transpose()?
                .unwrap_or(false);
            if !existing && !diagnostic_is_scoped(scope, diagnostic) {
                bail!("incremental replacement introduced an out-of-scope diagnostic");
            }
        }
        "file_completed" => {
            let path = required_str(event, "path")?;
            if scope.paths.binary_search(&path.to_owned()).is_err() {
                bail!("incremental file coverage is outside the replacement scope");
            }
        }
        "profile_completed" => {
            let profile_id = required_str(event, "profile_id")?;
            if scope
                .profile_ids
                .binary_search(&profile_id.to_owned())
                .is_err()
            {
                bail!("incremental profile coverage is outside the replacement scope");
            }
        }
        "scan_started" | "scan_completed" => {}
        other => bail!("unknown incremental replacement event {other}"),
    }
    Ok(())
}

fn ensure_existing_value_is_unchanged(
    tx: &Transaction<'_>,
    table: &str,
    column: &str,
    scan_id: &str,
    id: &str,
    replacement: &Value,
) -> Result<bool> {
    let sql = match (table, column) {
        ("profiles", "json") => "SELECT json FROM profiles WHERE scan_id=?1 AND id=?2",
        ("nodes", "raw_json") => "SELECT raw_json FROM nodes WHERE scan_id=?1 AND id=?2",
        ("sites", "raw_json") => "SELECT raw_json FROM sites WHERE scan_id=?1 AND id=?2",
        ("edges", "raw_json") => "SELECT raw_json FROM edges WHERE scan_id=?1 AND id=?2",
        ("diagnostics", "raw_json") => {
            "SELECT raw_json FROM diagnostics WHERE scan_id=?1 AND id=?2"
        }
        _ => unreachable!("incremental upsert checks use fixed table and column names"),
    };
    let existing = tx
        .query_row(sql, params![scan_id, id], |row| row.get::<_, String>(0))
        .optional()?;
    if let Some(existing) = existing {
        let existing: Value = serde_json::from_str(&existing)?;
        if existing != *replacement {
            bail!("incremental replacement attempted to mutate an out-of-scope record");
        }
        return Ok(true);
    }
    Ok(false)
}

fn node_is_scoped(scope: &IncrementalReplacementScope, node: &Value) -> Result<bool> {
    let id = required_str(node, "id")?;
    let kind = required_str(node, "kind")?;
    let locator = required_str(node, "locator")?;
    let properties = node.get("properties").unwrap_or(&Value::Null);
    Ok(scope
        .artifact_node_ids
        .binary_search(&id.to_owned())
        .is_ok()
        || (kind == "package_instance"
            && scope
                .package_locators
                .binary_search(&locator.to_owned())
                .is_ok())
        || has_named_value(
            properties,
            &[
                "path",
                "source_path",
                "manifest_path",
                "relative_path",
                "logical_path",
            ],
            &scope.paths,
        )
        || has_named_value(properties, &["package_locator"], &scope.package_locators)
        || has_named_value(properties, &["profile_id"], &scope.replanned_profile_ids))
}

fn site_is_scoped(
    tx: &Transaction<'_>,
    scan_id: &str,
    scope: &IncrementalReplacementScope,
    site: &Value,
) -> Result<bool> {
    let profile_id = required_str(site, "profile_id")?;
    if scope
        .replanned_profile_ids
        .binary_search(&profile_id.to_owned())
        .is_ok()
    {
        return Ok(true);
    }
    stored_node_is_scoped(tx, scan_id, scope, required_str(site, "source")?)
}

fn edge_is_scoped(
    tx: &Transaction<'_>,
    scan_id: &str,
    scope: &IncrementalReplacementScope,
    edge: &Value,
) -> Result<bool> {
    let profile_id = required_str(edge, "profile_id")?;
    if scope
        .replanned_profile_ids
        .binary_search(&profile_id.to_owned())
        .is_ok()
        || stored_node_is_scoped(tx, scan_id, scope, required_str(edge, "source")?)?
        || stored_node_is_scoped(tx, scan_id, scope, required_str(edge, "target")?)?
    {
        return Ok(true);
    }
    let Some(site_id) = edge.get("site_id").and_then(Value::as_str) else {
        return Ok(false);
    };
    let raw = tx
        .query_row(
            "SELECT raw_json FROM sites WHERE scan_id=?1 AND id=?2",
            params![scan_id, site_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    raw.map(|raw| serde_json::from_str::<Value>(&raw))
        .transpose()?
        .map(|site| site_is_scoped(tx, scan_id, scope, &site))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn stored_node_is_scoped(
    tx: &Transaction<'_>,
    scan_id: &str,
    scope: &IncrementalReplacementScope,
    node_id: &str,
) -> Result<bool> {
    let raw = tx
        .query_row(
            "SELECT raw_json FROM nodes WHERE scan_id=?1 AND id=?2",
            params![scan_id, node_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    raw.map(|raw| serde_json::from_str::<Value>(&raw))
        .transpose()?
        .map(|node| node_is_scoped(scope, &node))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn diagnostic_is_scoped(scope: &IncrementalReplacementScope, diagnostic: &Value) -> bool {
    diagnostic
        .get("path")
        .and_then(Value::as_str)
        .is_some_and(|path| scope.paths.binary_search(&path.to_owned()).is_ok())
        || has_named_value(diagnostic, &["profile_id"], &scope.replanned_profile_ids)
}

fn has_named_value(value: &Value, keys: &[&str], candidates: &[String]) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            (keys.contains(&key.as_str())
                && value
                    .as_str()
                    .is_some_and(|value| candidates.binary_search(&value.to_owned()).is_ok()))
                || has_named_value(value, keys, candidates)
        }),
        Value::Array(values) => values
            .iter()
            .any(|value| has_named_value(value, keys, candidates)),
        _ => false,
    }
}

fn normalize_values(
    name: &str,
    values: impl IntoIterator<Item = String>,
    paths: bool,
) -> Result<Vec<String>> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    if values.len() > MAX_SCOPE_VALUES {
        bail!("incremental {name} scope exceeds {MAX_SCOPE_VALUES} values");
    }
    for value in &mut values {
        *value = if paths {
            normalize_path(value)?
        } else {
            validate_value(name, value)?;
            value.clone()
        };
    }
    values.sort();
    values.dedup();
    Ok(values)
}

fn validate_normalized(name: &str, values: &[String], paths: bool) -> Result<()> {
    if values.len() > MAX_SCOPE_VALUES || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        bail!("incremental {name} scope is not canonical");
    }
    for value in values {
        if paths {
            if normalize_path(value)? != *value {
                bail!("incremental path scope is not canonical");
            }
        } else {
            validate_value(name, value)?;
        }
    }
    Ok(())
}

fn validate_value(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 2_048 || value.chars().any(char::is_control) {
        bail!("incremental {name} must be a bounded printable value");
    }
    Ok(())
}

fn normalize_path(value: &str) -> Result<String> {
    let normalized = value.replace('\\', "/");
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.ends_with('/')
        || normalized
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || normalized.contains(':')
        || normalized.chars().any(char::is_control)
        || normalized.len() > 4_096
    {
        bail!("incremental path must be a canonical repository-relative path");
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use depgraph_protocol::{
        CommonFields, DELTA_CONTRACT_VERSION, DeltaCompleted, DeltaEvent, DeltaNodeUpsert,
        DeltaScope, DeltaStarted, build_delta_stable_id, stable_id_from_value,
    };
    use serde_json::json;

    fn common(scan_id: &str, event: &str, seq: u64) -> Value {
        json!({
            "event":event,"protocol_version":"1.0","scan_id":scan_id,
            "adapter":"web","adapter_version":"1.0.0","seq":seq
        })
    }

    fn graph_events(scan_id: &str, renamed: bool) -> Vec<Value> {
        let a_path = if renamed {
            "a/src/renamed.ts"
        } else {
            "a/src/index.ts"
        };
        let a_target = if renamed {
            "file:a:new-target"
        } else {
            "file:a:target"
        };
        let mut seq = 1_u64;
        let mut events = Vec::new();
        for (profile_id, package, path, source, target) in [
            ("web:a", "package:a", a_path, "file:a:source", a_target),
            (
                "web:b",
                "package:b",
                "b/src/index.ts",
                "file:b:source",
                "file:b:target",
            ),
        ] {
            let revision = if profile_id == "web:a" && renamed {
                2
            } else {
                1
            };
            let mut profile = common(scan_id, "profile_declared", seq);
            seq += 1;
            profile["profile"] = json!({
                "id":profile_id,"language":"typescript","features":[],"environment":{},
                "properties":{"package_locator":package}
            });
            events.push(profile);
            for (id, node_path) in [(source, path), (target, path)] {
                let mut node = common(scan_id, "node_upsert", seq);
                seq += 1;
                node["node"] = json!({
                    "id":id,"kind":"file","locator":node_path,"display_name":node_path,
                    "properties":{"path":node_path,"package_locator":package,
                        "profile_id":profile_id,"revision":revision}
                });
                events.push(node);
            }
            let mut site = common(scan_id, "dependency_site", seq);
            seq += 1;
            site["site"] = json!({
                "id":format!("site:{profile_id}"),"source":source,"kind":"import",
                "specifier":"./target","profile_id":profile_id,"resolution_status":"resolved",
                "precision":"exact","condition":{"op":"all","conditions":[]},
                "target_ids":[target],"evidence":[{"kind":"source","extractor":"fixture",
                    "extractor_version":"1.0.0","path":path,"start_line":1,"start_column":1,
                    "end_line":1,"end_column":2,"properties":{}}]
            });
            events.push(site);
            let mut edge = common(scan_id, "edge_upsert", seq);
            seq += 1;
            edge["edge"] = json!({
                "id":format!("edge:{profile_id}"),"site_id":format!("site:{profile_id}"),
                "source":source,"target":target,"kind":"imports","phase":"source",
                "environment":"any","profile_id":profile_id,"resolution_status":"resolved",
                "precision":"exact","condition":{"op":"all","conditions":[]},"generated":false,
                "evidence":[{"kind":"source","extractor":"fixture","extractor_version":"1.0.0",
                    "path":path,"start_line":1,"start_column":1,"end_line":1,"end_column":2,
                    "properties":{}}]
            });
            events.push(edge);
            let mut file = common(scan_id, "file_completed", seq);
            seq += 1;
            file["path"] = json!(path);
            file["discovered_sites"] = json!(1);
            file["emitted_sites"] = json!(1);
            file["skipped_sites"] = json!(0);
            file["skipped"] = json!(false);
            events.push(file);
            let coverage = json!({
                "profiles":1,"files_discovered":1,"files_analyzed":1,"files_skipped":0,
                "dependency_sites":1,"resolved":1,"candidates":0,"external":0,"unresolved":0,
                "unsupported_syntax":0,"project_code_executed":false,
                "completeness":["syntax-complete"],"reasons":[]
            });
            let mut completed = common(scan_id, "profile_completed", seq);
            seq += 1;
            completed["profile_id"] = json!(profile_id);
            completed["coverage"] = coverage;
            events.push(completed);
        }
        let mut completed = common(scan_id, "scan_completed", seq);
        completed["coverage"] = json!({
            "profiles":2,"files_discovered":2,"files_analyzed":2,"files_skipped":0,
            "dependency_sites":2,"resolved":2,"candidates":0,"external":0,"unresolved":0,
            "unsupported_syntax":0,"project_code_executed":false,
            "completeness":["syntax-complete"],"reasons":[]
        });
        events.push(completed);
        events
    }

    #[derive(Debug)]
    struct StableGraphIds {
        source: String,
        target: String,
        site: String,
        edge: String,
    }

    fn stable_graph_events(scan_id: &str) -> (Vec<Value>, StableGraphIds) {
        let profile_id = "web:delta";
        let source =
            stable_id_from_value("file", &json!({"path":"src/index.ts","profile":profile_id}));
        let target =
            stable_id_from_value("file", &json!({"path":"src/lib.ts","profile":profile_id}));
        let site = stable_id_from_value(
            "site",
            &json!({
                "kind":"import","path":"src/index.ts","profile_id":profile_id,
                "source":source,"span":{"start_line":1,"start_column":1,
                    "end_line":1,"end_column":16}
            }),
        );
        let edge = stable_id_from_value(
            "edge",
            &json!({"kind":"imports","site_id":site,"target":target}),
        );
        let ids = StableGraphIds {
            source: source.clone(),
            target: target.clone(),
            site: site.clone(),
            edge: edge.clone(),
        };
        let coverage = json!({
            "profiles":1,"files_discovered":2,"files_analyzed":2,"files_skipped":0,
            "dependency_sites":1,"resolved":1,"candidates":0,"external":0,"unresolved":0,
            "unsupported_syntax":0,"project_code_executed":false,
            "completeness":["syntax-complete"],"reasons":[]
        });
        let mut profile = common(scan_id, "profile_declared", 1);
        profile["profile"] = json!({
            "id":profile_id,"language":"typescript","features":[],"environment":{},
            "properties":{"package_locator":"npm:fixture@1.0.0"}
        });
        let mut source_node = common(scan_id, "node_upsert", 2);
        source_node["node"] = json!({
            "id":source,"kind":"file","locator":"src/index.ts",
            "display_name":"src/index.ts","properties":{
                "path":"src/index.ts","package_locator":"npm:fixture@1.0.0",
                "profile_id":profile_id,
                "content_hash":format!("sha256:{}", "1".repeat(64)),
                "analysis_hash":format!("sha256:{}", "a".repeat(64))}
        });
        let mut target_node = common(scan_id, "node_upsert", 3);
        target_node["node"] = json!({
            "id":target,"kind":"file","locator":"src/lib.ts",
            "display_name":"src/lib.ts","properties":{
                "path":"src/lib.ts","package_locator":"npm:fixture@1.0.0",
                "profile_id":profile_id,"content_hash":"unchanged"}
        });
        let evidence = json!([{
            "kind":"source","extractor":"fixture","extractor_version":"1.0.0",
            "path":"src/index.ts","start_line":1,"start_column":1,
            "end_line":1,"end_column":16,"properties":{}
        }]);
        let mut site_event = common(scan_id, "dependency_site", 4);
        site_event["site"] = json!({
            "id":site,"source":source,"kind":"import","specifier":"./lib",
            "profile_id":profile_id,"resolution_status":"resolved","precision":"exact",
            "condition":{"op":"all","conditions":[]},"target_ids":[target],
            "evidence":evidence
        });
        let mut edge_event = common(scan_id, "edge_upsert", 5);
        edge_event["edge"] = json!({
            "id":edge,"site_id":site,"source":source,"target":target,
            "kind":"imports","phase":"source","environment":"any",
            "profile_id":profile_id,"resolution_status":"resolved","precision":"exact",
            "condition":{"op":"all","conditions":[]},"generated":false,
            "evidence":evidence
        });
        let mut source_file = common(scan_id, "file_completed", 6);
        source_file["path"] = json!("src/index.ts");
        source_file["discovered_sites"] = json!(1);
        source_file["emitted_sites"] = json!(1);
        source_file["skipped_sites"] = json!(0);
        source_file["skipped"] = json!(false);
        let mut target_file = common(scan_id, "file_completed", 7);
        target_file["path"] = json!("src/lib.ts");
        target_file["discovered_sites"] = json!(0);
        target_file["emitted_sites"] = json!(0);
        target_file["skipped_sites"] = json!(0);
        target_file["skipped"] = json!(false);
        let mut profile_completed = common(scan_id, "profile_completed", 8);
        profile_completed["profile_id"] = json!(profile_id);
        profile_completed["coverage"] = coverage.clone();
        let mut scan_completed = common(scan_id, "scan_completed", 9);
        scan_completed["coverage"] = coverage;
        (
            vec![
                profile,
                source_node,
                target_node,
                site_event,
                edge_event,
                source_file,
                target_file,
                profile_completed,
                scan_completed,
            ],
            ids,
        )
    }

    fn validated_node_delta(
        scan_id: &str,
        base: &DeltaBaseGraph,
        source_id: &str,
        content_hash: &str,
    ) -> ValidatedDelta {
        let mut node = base.nodes.get(source_id).unwrap().clone();
        node.properties
            .insert("content_hash".into(), json!(content_hash));
        let scope = DeltaScope {
            paths: vec!["src/index.ts".into()],
            package_locators: Vec::new(),
            profile_ids: Vec::new(),
            artifact_node_ids: Vec::new(),
            adapters: vec!["web".into()],
        };
        let common = |seq| CommonFields {
            protocol_version: "1.0".into(),
            scan_id: scan_id.into(),
            adapter: "web".into(),
            adapter_version: "1.0.0".into(),
            seq,
        };
        let mutation = DeltaEvent::NodeUpsert(DeltaNodeUpsert {
            common: common(2),
            node: node.clone(),
        });
        let delta_id =
            build_delta_stable_id(&base.snapshot_id, &base.graph_digest, &scope, [&mutation])
                .unwrap();
        let mut result = base.clone();
        result.nodes.insert(node.id.clone(), node);
        let result_graph_digest = delta_graph_digest(&result);
        let events = vec![
            DeltaEvent::DeltaStarted(DeltaStarted {
                common: common(1),
                delta_contract_version: DELTA_CONTRACT_VERSION.into(),
                delta_id: delta_id.clone(),
                base_snapshot_id: base.snapshot_id.clone(),
                base_graph_digest: base.graph_digest.clone(),
                scope,
            }),
            mutation,
            DeltaEvent::DeltaCompleted(DeltaCompleted {
                common: common(3),
                delta_contract_version: DELTA_CONTRACT_VERSION.into(),
                delta_id,
                mutation_count: 1,
                result_graph_digest,
            }),
        ];
        let mut validator = DeltaValidator::new(base.clone()).unwrap();
        for event in events {
            validator.push(event).unwrap();
        }
        validator.finish().unwrap()
    }

    fn complete(store: &mut Store, scan_id: &str, events: &[Value]) -> String {
        store
            .start_scan(scan_id, Path::new("/fixture"), false)
            .unwrap();
        let refs = events.iter().collect::<Vec<_>>();
        store.ingest_events(&refs).unwrap();
        store.validate_scan(scan_id).unwrap();
        store.finish_scan(scan_id, "completed", None, true).unwrap();
        store
            .snapshot_id_for_source("scan", scan_id)
            .unwrap()
            .unwrap()
    }

    fn replacement_events(scan_id: &str) -> Vec<Value> {
        graph_events(scan_id, true)
            .into_iter()
            .filter(|event| {
                event["event"] == "scan_completed"
                    || event["profile"]["id"] == "web:a"
                    || event["node"]["properties"]["profile_id"] == "web:a"
                    || event["site"]["profile_id"] == "web:a"
                    || event["edge"]["profile_id"] == "web:a"
                    || event["profile_id"] == "web:a"
                    || event["path"] == "a/src/renamed.ts"
            })
            .collect()
    }

    fn scope() -> IncrementalReplacementScope {
        IncrementalReplacementScope::new(
            ["a/src/index.ts".to_owned(), "a/src/renamed.ts".to_owned()],
            ["package:a".to_owned()],
            ["web:a".to_owned()],
            std::iter::empty(),
            std::iter::empty(),
            ["web".to_owned()],
        )
        .unwrap()
    }

    #[test]
    fn transactional_replacement_matches_a_full_scan_and_removes_renamed_ownership() {
        let mut incremental = Store::open_in_memory().unwrap();
        let base_id = complete(&mut incremental, "base", &graph_events("base", false));
        incremental
            .start_incremental_scan_with_revision(
                "incremental",
                Path::new("/fixture"),
                false,
                &base_id,
                Some("revision-2"),
            )
            .unwrap();
        incremental
            .replace_incremental_graph(
                "incremental",
                &base_id,
                &scope(),
                &replacement_events("incremental"),
                &[AdapterLogRecord {
                    adapter: "web".to_owned(),
                    stderr: String::new(),
                    truncated: false,
                }],
            )
            .unwrap();
        incremental.validate_scan("incremental").unwrap();
        incremental
            .finish_scan("incremental", "completed", None, true)
            .unwrap();

        let mut full = Store::open_in_memory().unwrap();
        complete(&mut full, "full", &graph_events("full", true));
        let incremental_graph = incremental.load_snapshot("incremental").unwrap();
        let full_graph = full.load_snapshot("full").unwrap();
        assert_eq!(incremental_graph.profiles, full_graph.profiles);
        assert_eq!(incremental_graph.nodes, full_graph.nodes);
        assert_eq!(incremental_graph.sites, full_graph.sites);
        assert_eq!(incremental_graph.edges, full_graph.edges);
        assert_eq!(incremental_graph.evidence, full_graph.evidence);
        assert_eq!(incremental_graph.file_coverage, full_graph.file_coverage);
        assert_eq!(incremental_graph.coverage, full_graph.coverage);
        assert!(
            incremental_graph
                .nodes
                .iter()
                .all(|node| node.locator != "a/src/index.ts")
        );
    }

    #[test]
    fn failed_replacement_rolls_back_and_keeps_the_completed_snapshot_current() {
        let mut store = Store::open_in_memory().unwrap();
        let base_id = complete(&mut store, "base", &graph_events("base", false));
        let base = store.load_completed_snapshot(&base_id).unwrap();
        store
            .start_incremental_scan_with_revision(
                "failed",
                Path::new("/fixture"),
                false,
                &base_id,
                None,
            )
            .unwrap();
        let mut events = replacement_events("failed");
        events.insert(
            1,
            json!({"event":"node_upsert","protocol_version":"1.0","scan_id":"failed",
                "adapter":"web","adapter_version":"1.0.0","seq":999,"node":{
                    "id":"file:rogue","kind":"file","locator":"rogue/src/index.ts",
                    "display_name":"rogue/src/index.ts","properties":{
                        "path":"rogue/src/index.ts","package_locator":"package:rogue",
                        "profile_id":"web:rogue"}}}),
        );
        assert!(
            store
                .replace_incremental_graph("failed", &base_id, &scope(), &events, &[])
                .is_err()
        );
        let staging = store.load_snapshot("failed").unwrap();
        assert_eq!(staging.nodes, base.nodes);
        assert_eq!(staging.sites, base.sites);
        assert_eq!(staging.edges, base.edges);
        store
            .finish_scan(
                "failed",
                "failed",
                Some("incremental replacement failed"),
                false,
            )
            .unwrap();
        assert_eq!(
            store.current_snapshot_id().unwrap().as_deref(),
            Some(base_id.as_str())
        );
        assert_eq!(store.load_completed_snapshot(&base_id).unwrap(), base);
    }

    #[test]
    fn idless_out_of_scope_diagnostic_is_rejected_and_rolled_back() {
        let mut store = Store::open_in_memory().unwrap();
        let base_id = complete(&mut store, "base", &graph_events("base", false));
        let base = store.load_completed_snapshot(&base_id).unwrap();
        store
            .start_incremental_scan_with_revision(
                "failed-diagnostic",
                Path::new("/fixture"),
                false,
                &base_id,
                None,
            )
            .unwrap();
        let mut events = replacement_events("failed-diagnostic");
        events.insert(
            1,
            json!({"event":"diagnostic","protocol_version":"1.0",
                "scan_id":"failed-diagnostic","adapter":"web","adapter_version":"1.0.0",
                "seq":999,"diagnostic":{"severity":"warning","code":"ROGUE",
                    "message":"outside replacement scope","path":"b/src/index.ts",
                    "recoverable":true,"properties":{}}}),
        );
        assert!(
            store
                .replace_incremental_graph("failed-diagnostic", &base_id, &scope(), &events, &[],)
                .is_err()
        );
        let staging = store.load_snapshot("failed-diagnostic").unwrap();
        assert_eq!(staging.nodes, base.nodes);
        assert_eq!(staging.diagnostics, base.diagnostics);
        assert_eq!(
            store.current_snapshot_id().unwrap().as_deref(),
            Some(base_id.as_str())
        );
    }

    #[test]
    fn validated_delta_updates_one_file_and_preserves_unaffected_payloads() {
        let mut store = Store::open_in_memory().unwrap();
        let (events, ids) = stable_graph_events("base-delta");
        let base_id = complete(&mut store, "base-delta", &events);
        let base_snapshot = store.load_completed_snapshot(&base_id).unwrap();
        let base = store.delta_base_graph(&base_id).unwrap();
        let delta = validated_node_delta("incremental-delta", &base, &ids.source, "after");

        store
            .start_incremental_scan_with_revision(
                "incremental-delta",
                Path::new("/fixture"),
                false,
                &base_id,
                Some("revision-2"),
            )
            .unwrap();
        let staged = store
            .stage_incremental_delta("incremental-delta", &delta)
            .unwrap();
        assert_eq!(staged.status, "staging");
        let applied = store
            .apply_staged_incremental_delta("incremental-delta", &delta.delta_id)
            .unwrap();
        assert_eq!(applied.status, "applied");
        store.validate_scan("incremental-delta").unwrap();
        store
            .finish_scan("incremental-delta", "completed", None, true)
            .unwrap();

        let current = store.current_snapshot_id().unwrap().unwrap();
        assert_ne!(current, base_id);
        assert_eq!(
            applied.prospective_snapshot_id.as_deref(),
            Some(current.as_str())
        );
        let result = store.load_completed_snapshot(&current).unwrap();
        let base_target = base_snapshot
            .nodes
            .iter()
            .find(|node| node.id == ids.target)
            .unwrap();
        assert_eq!(
            result
                .nodes
                .iter()
                .find(|node| node.id == ids.target)
                .unwrap(),
            base_target
        );
        assert_eq!(result.sites, base_snapshot.sites);
        assert_eq!(result.edges, base_snapshot.edges);
        assert_eq!(result.evidence, base_snapshot.evidence);
        assert_eq!(result.file_coverage, base_snapshot.file_coverage);
        assert_eq!(result.coverage, base_snapshot.coverage);
        assert_eq!(
            result
                .nodes
                .iter()
                .find(|node| node.id == ids.source)
                .unwrap()
                .properties["content_hash"],
            json!("after")
        );
        assert!(result.sites.iter().any(|site| site.id == ids.site));
        assert!(result.edges.iter().any(|edge| edge.id == ids.edge));
        assert_eq!(
            store.load_completed_snapshot(&base_id).unwrap(),
            base_snapshot
        );
    }

    #[test]
    fn semantic_noop_overlay_promotes_without_copying_the_complete_graph() {
        let mut store = Store::open_in_memory().unwrap();
        let (events, ids) = stable_graph_events("semantic-noop-base");
        let base_id = complete(&mut store, "semantic-noop-base", &events);
        let base_snapshot = store.load_completed_snapshot(&base_id).unwrap();
        let projection = store
            .semantic_noop_delta_base(&base_id, "src/index.ts")
            .unwrap()
            .unwrap();
        assert_eq!(projection.nodes.len(), 1);
        assert_eq!(projection.sites.len(), 0);
        let delta = validated_node_delta(
            "semantic-noop-1",
            &projection,
            &ids.source,
            &format!("sha256:{}", "2".repeat(64)),
        );
        let first_id = store
            .commit_semantic_noop_delta(
                "semantic-noop-1",
                Path::new("/fixture"),
                false,
                &base_id,
                Some("revision-2"),
                &delta,
                "semantic no-op",
                false,
            )
            .unwrap();

        let sparse_counts: (i64, i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM profiles WHERE scan_id='semantic-noop-1'),
                    (SELECT COUNT(*) FROM nodes WHERE scan_id='semantic-noop-1'),
                    (SELECT COUNT(*) FROM sites WHERE scan_id='semantic-noop-1'),
                    (SELECT COUNT(*) FROM edges WHERE scan_id='semantic-noop-1')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(sparse_counts, (0, 1, 0, 0));
        assert_eq!(
            store.current_snapshot_id().unwrap().as_deref(),
            Some(first_id.as_str())
        );
        assert!(store.verify_snapshot_integrity(&first_id).unwrap().valid);
        let first = store.load_completed_snapshot(&first_id).unwrap();
        assert_eq!(first.sites, base_snapshot.sites);
        assert_eq!(first.edges, base_snapshot.edges);
        assert_eq!(first.evidence, base_snapshot.evidence);
        assert_eq!(first.file_coverage, base_snapshot.file_coverage);
        assert_eq!(first.coverage, base_snapshot.coverage);
        assert_eq!(
            first
                .nodes
                .iter()
                .find(|node| node.id == ids.source)
                .unwrap()
                .properties["content_hash"],
            json!(format!("sha256:{}", "2".repeat(64)))
        );

        let next_projection = store
            .semantic_noop_delta_base(&first_id, "src/index.ts")
            .unwrap()
            .unwrap();
        let next_delta = validated_node_delta(
            "semantic-noop-2",
            &next_projection,
            &ids.source,
            &format!("sha256:{}", "3".repeat(64)),
        );
        let second_id = store
            .commit_semantic_noop_delta(
                "semantic-noop-2",
                Path::new("/fixture"),
                false,
                &first_id,
                Some("revision-3"),
                &next_delta,
                "",
                false,
            )
            .unwrap();
        assert_ne!(second_id, first_id);
        assert!(store.verify_snapshot_integrity(&second_id).unwrap().valid);
        assert_eq!(
            store.load_completed_snapshot_profiles(&second_id).unwrap(),
            base_snapshot.profiles
        );
        let second = store.load_completed_snapshot(&second_id).unwrap();
        assert_eq!(second.sites, base_snapshot.sites);
        assert_eq!(
            second
                .nodes
                .iter()
                .find(|node| node.id == ids.source)
                .unwrap()
                .properties["content_hash"],
            json!(format!("sha256:{}", "3".repeat(64)))
        );
        let complete_base = store.delta_base_graph(&second_id).unwrap();
        assert_eq!(complete_base.nodes.len(), base_snapshot.nodes.len());
        assert_eq!(complete_base.sites.len(), base_snapshot.sites.len());
        assert_eq!(complete_base.edges.len(), base_snapshot.edges.len());
        assert_eq!(
            complete_base.nodes[&ids.source].properties["content_hash"],
            json!(format!("sha256:{}", "3".repeat(64)))
        );
        let complete_delta = validated_node_delta(
            "complete-after-overlay",
            &complete_base,
            &ids.source,
            &format!("sha256:{}", "4".repeat(64)),
        );
        store
            .start_incremental_scan_with_revision(
                "complete-after-overlay",
                Path::new("/fixture"),
                false,
                &second_id,
                Some("revision-4"),
            )
            .unwrap();
        let staging_counts: (i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM nodes
                      WHERE scan_id='complete-after-overlay'),
                    (SELECT COUNT(*) FROM sites
                      WHERE scan_id='complete-after-overlay'),
                    (SELECT COUNT(*) FROM edges
                      WHERE scan_id='complete-after-overlay')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            staging_counts,
            (
                base_snapshot.nodes.len() as i64,
                base_snapshot.sites.len() as i64,
                base_snapshot.edges.len() as i64,
            )
        );
        store
            .stage_incremental_delta("complete-after-overlay", &complete_delta)
            .unwrap();
        store
            .apply_staged_incremental_delta("complete-after-overlay", &complete_delta.delta_id)
            .unwrap();
        store.validate_scan("complete-after-overlay").unwrap();
        store
            .finish_scan("complete-after-overlay", "completed", None, true)
            .unwrap();
        let complete_id = store.current_snapshot_id().unwrap().unwrap();
        let complete = store.load_completed_snapshot(&complete_id).unwrap();
        assert_eq!(complete.sites, base_snapshot.sites);
        assert_eq!(complete.edges, base_snapshot.edges);
        assert_eq!(
            complete
                .nodes
                .iter()
                .find(|node| node.id == ids.source)
                .unwrap()
                .properties["content_hash"],
            json!(format!("sha256:{}", "4".repeat(64)))
        );

        store
            .connection
            .execute(
                "UPDATE nodes SET properties_json='{\"tampered\":true}'
                  WHERE scan_id='semantic-noop-base' AND id=?1",
                [&ids.source],
            )
            .unwrap();
        let integrity = store.verify_snapshot_integrity(&second_id).unwrap();
        assert!(!integrity.valid);
        assert_eq!(integrity.reasons, ["parent_integrity_mismatch"]);
    }

    #[test]
    fn corrupted_staged_delta_rolls_back_and_keeps_current_snapshot() {
        let mut store = Store::open_in_memory().unwrap();
        let (events, ids) = stable_graph_events("base-failed-delta");
        let base_id = complete(&mut store, "base-failed-delta", &events);
        let base_snapshot = store.load_completed_snapshot(&base_id).unwrap();
        let base = store.delta_base_graph(&base_id).unwrap();
        let delta = validated_node_delta("failed-delta", &base, &ids.source, "after");
        store
            .start_incremental_scan_with_revision(
                "failed-delta",
                Path::new("/fixture"),
                false,
                &base_id,
                None,
            )
            .unwrap();
        store
            .stage_incremental_delta("failed-delta", &delta)
            .unwrap();
        let raw: String = store
            .connection
            .query_row(
                "SELECT events_json FROM incremental_deltas
                  WHERE scan_id='failed-delta' AND delta_id=?1",
                [&delta.delta_id],
                |row| row.get(0),
            )
            .unwrap();
        let mut staged_events: Value = serde_json::from_str(&raw).unwrap();
        staged_events[1]["node"]["id"] = json!("file:not-a-stable-id");
        store
            .connection
            .execute(
                "UPDATE incremental_deltas SET events_json=?2
                  WHERE scan_id='failed-delta' AND delta_id=?1",
                params![
                    delta.delta_id,
                    serde_json::to_string(&staged_events).unwrap()
                ],
            )
            .unwrap();

        assert!(
            store
                .apply_staged_incremental_delta("failed-delta", &delta.delta_id)
                .is_err()
        );
        assert_eq!(
            store
                .incremental_delta("failed-delta", &delta.delta_id)
                .unwrap()
                .unwrap()
                .status,
            "failed"
        );
        let staging = store.load_snapshot("failed-delta").unwrap();
        assert_eq!(staging.nodes, base_snapshot.nodes);
        assert_eq!(staging.sites, base_snapshot.sites);
        assert_eq!(staging.edges, base_snapshot.edges);
        assert!(
            store
                .finish_scan("failed-delta", "completed", None, true)
                .unwrap_err()
                .to_string()
                .contains("were not applied successfully")
        );
        assert_eq!(
            store.current_snapshot_id().unwrap().as_deref(),
            Some(base_id.as_str())
        );
        assert_eq!(
            store.load_completed_snapshot(&base_id).unwrap(),
            base_snapshot
        );
    }

    #[test]
    fn cancelled_and_crash_recovered_deltas_are_gc_eligible() {
        for (scan_id, recover) in [("cancelled-delta", false), ("crashed-delta", true)] {
            let mut store = Store::open_in_memory().unwrap();
            let (events, ids) = stable_graph_events("base-cancel-delta");
            let base_id = complete(&mut store, "base-cancel-delta", &events);
            let base = store.delta_base_graph(&base_id).unwrap();
            let delta = validated_node_delta(scan_id, &base, &ids.source, "after");
            store
                .start_incremental_scan_with_revision(
                    scan_id,
                    Path::new("/fixture"),
                    false,
                    &base_id,
                    None,
                )
                .unwrap();
            store.stage_incremental_delta(scan_id, &delta).unwrap();
            if recover {
                let recovery = store
                    .recover_interrupted_attempts(Path::new("/fixture"))
                    .unwrap();
                assert!(recovery.scan_attempt_ids.contains(&scan_id.to_owned()));
            } else {
                store
                    .cancel_staged_incremental_delta(scan_id, &delta.delta_id)
                    .unwrap();
                store
                    .finish_scan(scan_id, "cancelled", Some("cancelled"), false)
                    .unwrap();
            }
            assert_eq!(
                store
                    .incremental_delta(scan_id, &delta.delta_id)
                    .unwrap()
                    .unwrap()
                    .status,
                "cancelled"
            );
            assert_eq!(
                store.current_snapshot_id().unwrap().as_deref(),
                Some(base_id.as_str())
            );
            let report = store.garbage_collect_unreferenced_attempts().unwrap();
            assert_eq!(report.scan_attempts_deleted, 1);
            assert!(
                store
                    .incremental_delta(scan_id, &delta.delta_id)
                    .unwrap()
                    .is_none()
            );
        }
    }
}
