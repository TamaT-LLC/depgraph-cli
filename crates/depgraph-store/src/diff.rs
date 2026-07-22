use std::{cmp::Ordering, collections::BTreeSet};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    CoverageRecord, EdgeRecord, EvidenceRecord, GraphSnapshot, NodeRecord, ProfileRecord,
    SiteRecord, Store,
};

pub const SNAPSHOT_DIFF_SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChangedRecord<T> {
    pub id: String,
    pub changed_fields: Vec<String>,
    pub before: T,
    pub after: T,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecordDiff<T> {
    pub added: Vec<T>,
    pub removed: Vec<T>,
    pub changed: Vec<ChangedRecord<T>>,
}

impl<T> Default for RecordDiff<T> {
    fn default() -> Self {
        Self {
            added: Vec::new(),
            removed: Vec::new(),
            changed: Vec::new(),
        }
    }
}

impl<T> RecordDiff<T> {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphSnapshotDiff {
    pub schema_version: String,
    pub from_snapshot_id: String,
    pub to_snapshot_id: String,
    pub nodes: RecordDiff<NodeRecord>,
    pub sites: RecordDiff<SiteRecord>,
    pub edges: RecordDiff<EdgeRecord>,
    pub evidence: RecordDiff<EvidenceRecord>,
    pub profiles: RecordDiff<ProfileRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<ChangedRecord<CoverageRecord>>,
}

impl GraphSnapshotDiff {
    pub fn empty(from_snapshot_id: &str, to_snapshot_id: &str) -> Self {
        Self {
            schema_version: SNAPSHOT_DIFF_SCHEMA_VERSION.to_owned(),
            from_snapshot_id: from_snapshot_id.to_owned(),
            to_snapshot_id: to_snapshot_id.to_owned(),
            nodes: RecordDiff::default(),
            sites: RecordDiff::default(),
            edges: RecordDiff::default(),
            evidence: RecordDiff::default(),
            profiles: RecordDiff::default(),
            coverage: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
            && self.sites.is_empty()
            && self.edges.is_empty()
            && self.evidence.is_empty()
            && self.profiles.is_empty()
            && self.coverage.is_none()
    }
}

impl Store {
    pub fn diff_completed_snapshots(
        &self,
        from_snapshot_id: &str,
        to_snapshot_id: &str,
    ) -> Result<GraphSnapshotDiff> {
        self.completed_snapshot(from_snapshot_id)?
            .with_context(|| format!("completed snapshot {from_snapshot_id} was not found"))?;
        self.completed_snapshot(to_snapshot_id)?
            .with_context(|| format!("completed snapshot {to_snapshot_id} was not found"))?;
        if from_snapshot_id == to_snapshot_id {
            return Ok(GraphSnapshotDiff::empty(from_snapshot_id, to_snapshot_id));
        }
        let from = self.load_completed_snapshot(from_snapshot_id)?;
        let to = self.load_completed_snapshot(to_snapshot_id)?;
        diff_graph_snapshots(from_snapshot_id, to_snapshot_id, from, to)
    }
}

pub fn diff_graph_snapshots(
    from_snapshot_id: &str,
    to_snapshot_id: &str,
    from: GraphSnapshot,
    to: GraphSnapshot,
) -> Result<GraphSnapshotDiff> {
    let nodes = diff_records(from.nodes, to.nodes, |record| record.id.clone())?;
    let sites = diff_records(from.sites, to.sites, |record| record.id.clone())?;
    let edges = diff_records(from.edges, to.edges, |record| record.id.clone())?;
    let evidence = diff_records(from.evidence, to.evidence, evidence_identity)?;
    let profiles = diff_records(from.profiles, to.profiles, |record| record.id.clone())?;
    let coverage = if from.coverage == to.coverage {
        None
    } else {
        Some(ChangedRecord {
            id: "coverage".to_owned(),
            changed_fields: changed_fields(&from.coverage, &to.coverage)?,
            before: from.coverage,
            after: to.coverage,
        })
    };
    Ok(GraphSnapshotDiff {
        schema_version: SNAPSHOT_DIFF_SCHEMA_VERSION.to_owned(),
        from_snapshot_id: from_snapshot_id.to_owned(),
        to_snapshot_id: to_snapshot_id.to_owned(),
        nodes,
        sites,
        edges,
        evidence,
        profiles,
        coverage,
    })
}

fn diff_records<T, F>(from: Vec<T>, to: Vec<T>, identity: F) -> Result<RecordDiff<T>>
where
    T: PartialEq + Serialize,
    F: Fn(&T) -> String,
{
    let mut from = keyed_records(from, &identity);
    let mut to = keyed_records(to, &identity);
    from.sort_by(|left, right| left.0.cmp(&right.0));
    to.sort_by(|left, right| left.0.cmp(&right.0));
    ensure_unique_keys(&from)?;
    ensure_unique_keys(&to)?;

    let mut from = from.into_iter().peekable();
    let mut to = to.into_iter().peekable();
    let mut output = RecordDiff::default();
    loop {
        match (from.peek(), to.peek()) {
            (Some((from_id, _)), Some((to_id, _))) => match from_id.cmp(to_id) {
                Ordering::Less => {
                    let (_, record) = from.next().expect("peeked source record");
                    output.removed.push(record);
                }
                Ordering::Greater => {
                    let (_, record) = to.next().expect("peeked target record");
                    output.added.push(record);
                }
                Ordering::Equal => {
                    let (id, before) = from.next().expect("peeked source record");
                    let (_, after) = to.next().expect("peeked target record");
                    if before != after {
                        output.changed.push(ChangedRecord {
                            id,
                            changed_fields: changed_fields(&before, &after)?,
                            before,
                            after,
                        });
                    }
                }
            },
            (Some(_), None) => {
                output.removed.extend(from.map(|(_, record)| record));
                break;
            }
            (None, Some(_)) => {
                output.added.extend(to.map(|(_, record)| record));
                break;
            }
            (None, None) => break,
        }
    }
    Ok(output)
}

fn keyed_records<T, F>(records: Vec<T>, identity: &F) -> Vec<(String, T)>
where
    F: Fn(&T) -> String,
{
    records
        .into_iter()
        .map(|record| (identity(&record), record))
        .collect()
}

fn ensure_unique_keys<T>(records: &[(String, T)]) -> Result<()> {
    for pair in records.windows(2) {
        if pair[0].0 == pair[1].0 {
            anyhow::bail!(
                "snapshot diff input contains duplicate identity {:?}",
                pair[0].0
            );
        }
    }
    Ok(())
}

fn evidence_identity(record: &EvidenceRecord) -> String {
    format!(
        "{}:{}:{}",
        record.owner_type, record.owner_id, record.ordinal
    )
}

fn changed_fields<T: Serialize>(before: &T, after: &T) -> Result<Vec<String>> {
    let before = serde_json::to_value(before)?;
    let after = serde_json::to_value(after)?;
    let before = before
        .as_object()
        .context("snapshot diff record must serialize as an object")?;
    let after = after
        .as_object()
        .context("snapshot diff record must serialize as an object")?;
    let fields = before
        .keys()
        .chain(after.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|field| before.get(*field) != after.get(*field))
        .cloned()
        .collect();
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProfileMatrixRecord, ScanRecord};
    use serde_json::json;
    use std::path::Path;

    fn empty_snapshot(root: &str) -> GraphSnapshot {
        GraphSnapshot {
            scan: ScanRecord {
                id: "attempt".to_owned(),
                root: root.to_owned(),
                status: "completed".to_owned(),
                strict: false,
                started_at: "2026-07-23T00:00:00.000Z".to_owned(),
                completed_at: Some("2026-07-23T00:00:01.000Z".to_owned()),
                project_code_executed: false,
                error: None,
                parent_snapshot_id: None,
                source_revision: Some("revision".to_owned()),
            },
            profiles: Vec::new(),
            nodes: Vec::new(),
            sites: Vec::new(),
            edges: Vec::new(),
            evidence: Vec::new(),
            diagnostics: Vec::new(),
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: CoverageRecord::default(),
            profile_matrix: ProfileMatrixRecord::default(),
        }
    }

    fn node(id: &str, version: u64) -> NodeRecord {
        NodeRecord {
            id: id.to_owned(),
            kind: "file".to_owned(),
            locator: format!("src/{id}.ts"),
            display_name: id.to_owned(),
            properties: json!({"version": version}),
        }
    }

    fn profile(id: &str, mode: &str) -> ProfileRecord {
        ProfileRecord {
            id: id.to_owned(),
            language: "typescript".to_owned(),
            toolchain: Some(json!("typescript 7.0.2")),
            command: Some("scan".to_owned()),
            target: Some("server".to_owned()),
            features: Vec::new(),
            environment: json!({"mode": mode}),
            source_revision: Some("revision".to_owned()),
            properties: json!({}),
            coverage: None,
        }
    }

    fn site(status: &str, precision: &str, mode: &str) -> SiteRecord {
        SiteRecord {
            id: "site:shared".to_owned(),
            source: "node:shared".to_owned(),
            kind: "import".to_owned(),
            specifier: Some("./target".to_owned()),
            profile_id: "profile:shared".to_owned(),
            resolution_status: status.to_owned(),
            precision: precision.to_owned(),
            condition: json!({"op":"eq","key":"mode","value":mode}),
            target_ids: vec!["node:target".to_owned()],
            reason: None,
        }
    }

    fn edge(status: &str, precision: &str, mode: &str) -> EdgeRecord {
        EdgeRecord {
            id: "edge:shared".to_owned(),
            site_id: Some("site:shared".to_owned()),
            source: "node:shared".to_owned(),
            target: "node:target".to_owned(),
            kind: "imports".to_owned(),
            phase: "source".to_owned(),
            environment: "server".to_owned(),
            profile_id: "profile:shared".to_owned(),
            resolution_status: status.to_owned(),
            precision: precision.to_owned(),
            condition: json!({"op":"eq","key":"mode","value":mode}),
            generated: false,
        }
    }

    fn evidence(owner_id: &str, ordinal: i64, kind: &str, detail: &str) -> EvidenceRecord {
        EvidenceRecord {
            owner_type: "edge".to_owned(),
            owner_id: owner_id.to_owned(),
            ordinal,
            kind: kind.to_owned(),
            extractor: "fixture".to_owned(),
            extractor_version: "1.0".to_owned(),
            path: "src/shared.ts".to_owned(),
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 10,
            detail: Some(detail.to_owned()),
            properties: json!({}),
        }
    }

    fn persist_snapshot(store: &mut Store, scan_id: &str, version: u64) -> Result<String> {
        store.start_scan_with_revision(
            scan_id,
            Path::new("/portable/project"),
            false,
            Some(&format!("revision-{version}")),
        )?;
        let common = |event: &str, seq: u64| {
            json!({
                "event": event,
                "protocol_version": "1.0",
                "scan_id": scan_id,
                "adapter": "fixture",
                "adapter_version": "1.0",
                "seq": seq
            })
        };
        let coverage = json!({
            "profiles": 1,
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
        });
        let mut started = common("scan_started", 1);
        started["root"] = json!("/portable/project");
        started["safe_mode"] = json!(true);
        started["project_code_executed"] = json!(false);
        let mut profile = common("profile_declared", 2);
        profile["profile"] = json!({
            "id": "fixture:safe",
            "language": "typescript",
            "features": [],
            "environment": {},
            "properties": {}
        });
        let mut node = common("node_upsert", 3);
        node["node"] = json!({
            "id": "node:shared",
            "kind": "file",
            "locator": "src/shared.ts",
            "display_name": "shared",
            "properties": {"version": version}
        });
        let mut profile_completed = common("profile_completed", 4);
        profile_completed["profile_id"] = json!("fixture:safe");
        profile_completed["coverage"] = coverage.clone();
        let mut completed = common("scan_completed", 5);
        completed["coverage"] = coverage;
        for event in [started, profile, node, profile_completed, completed] {
            store.ingest_event(&event)?;
        }
        store.finish_scan(scan_id, "completed", None, true)?;
        store
            .snapshot_id_for_source("scan", scan_id)?
            .context("completed fixture snapshot")
    }

    #[test]
    fn identical_snapshots_have_an_empty_path_independent_diff() -> Result<()> {
        let from = empty_snapshot("/checkout/one");
        let mut to = from.clone();
        to.scan.root = "C:\\checkout\\two".to_owned();
        to.scan.id = "another-attempt".to_owned();
        let diff = diff_graph_snapshots("snapshot:from", "snapshot:to", from, to)?;
        assert!(diff.is_empty());
        assert_eq!(diff.schema_version, SNAPSHOT_DIFF_SCHEMA_VERSION);
        Ok(())
    }

    #[test]
    fn classifies_added_removed_and_structured_property_changes_canonically() -> Result<()> {
        let mut from = empty_snapshot("/checkout/one");
        from.nodes = vec![node("removed", 1), node("shared", 1)];
        from.profiles = vec![
            profile("profile:removed", "dev"),
            profile("profile:shared", "dev"),
        ];
        from.sites = vec![site("resolved", "exact", "dev")];
        from.edges = vec![edge("resolved", "exact", "dev")];
        from.evidence = vec![
            evidence("edge:removed", 0, "source", "removed"),
            evidence("edge:shared", 0, "source", "before"),
        ];
        from.coverage = CoverageRecord {
            profiles: 2,
            dependency_sites: 1,
            resolved: 1,
            completeness: vec!["syntax-complete".to_owned()],
            ..CoverageRecord::default()
        };

        let mut to = empty_snapshot("/checkout/two");
        to.nodes = vec![node("shared", 2), node("added", 1)];
        to.profiles = vec![
            profile("profile:shared", "production"),
            profile("profile:added", "production"),
        ];
        to.sites = vec![site("candidates", "overapprox", "production")];
        to.edges = vec![edge("candidates", "overapprox", "production")];
        to.evidence = vec![
            evidence("edge:added", 0, "build", "added"),
            evidence("edge:shared", 0, "build", "after"),
        ];
        to.coverage = CoverageRecord {
            profiles: 2,
            dependency_sites: 1,
            candidates: 1,
            project_code_executed: true,
            completeness: vec!["build-observed".to_owned(), "syntax-complete".to_owned()],
            ..CoverageRecord::default()
        };

        let diff = diff_graph_snapshots("snapshot:from", "snapshot:to", from, to)?;
        assert_eq!(diff.nodes.added[0].id, "added");
        assert_eq!(diff.nodes.removed[0].id, "removed");
        assert_eq!(diff.nodes.changed[0].id, "shared");
        assert_eq!(diff.nodes.changed[0].changed_fields, ["properties"]);
        assert_eq!(
            diff.sites.changed[0].changed_fields,
            ["condition", "precision", "resolution_status"]
        );
        assert_eq!(
            diff.edges.changed[0].changed_fields,
            ["condition", "precision", "resolution_status"]
        );
        assert_eq!(diff.evidence.changed[0].changed_fields, ["detail", "kind"]);
        assert_eq!(diff.profiles.changed[0].changed_fields, ["environment"]);
        assert_eq!(
            diff.coverage.as_ref().unwrap().changed_fields,
            [
                "candidates",
                "completeness",
                "project_code_executed",
                "resolved"
            ]
        );
        let mut golden_from = empty_snapshot("/checkout/one");
        golden_from.nodes = vec![node("shared", 1)];
        let mut golden_to = empty_snapshot("/checkout/two");
        golden_to.nodes = vec![node("shared", 2)];
        let golden = diff_graph_snapshots("snapshot:from", "snapshot:to", golden_from, golden_to)?;
        assert_eq!(
            serde_json::to_string(&golden)?,
            include_str!("../tests/fixtures/snapshot-diff.golden.json").trim()
        );
        Ok(())
    }

    #[test]
    fn completed_store_snapshots_diff_without_selecting_failed_attempts() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        let first_id = persist_snapshot(&mut store, "first-attempt", 1)?;
        let second_id = persist_snapshot(&mut store, "second-attempt", 2)?;

        let empty = store.diff_completed_snapshots(&first_id, &first_id)?;
        assert!(empty.is_empty());
        let changed = store.diff_completed_snapshots(&first_id, &second_id)?;
        assert_eq!(changed.nodes.changed.len(), 1);
        assert_eq!(changed.nodes.changed[0].id, "node:shared");
        assert_eq!(changed.nodes.changed[0].changed_fields, ["properties"]);

        store.start_scan("failed-attempt", Path::new("/portable/project"), false)?;
        store.finish_scan("failed-attempt", "failed", Some("worker failed"), false)?;
        let error = store
            .diff_completed_snapshots("failed-attempt", &second_id)
            .unwrap_err()
            .to_string();
        assert!(error.contains("completed snapshot failed-attempt was not found"));
        Ok(())
    }

    #[test]
    fn large_reordered_inputs_use_canonical_merge_order() -> Result<()> {
        let mut from = empty_snapshot("/checkout/one");
        from.nodes = (0..10_000)
            .rev()
            .map(|index| node(&format!("node:{index:05}"), 1))
            .collect();
        let mut to = empty_snapshot("/checkout/two");
        to.nodes = (0..10_000)
            .map(|index| node(&format!("node:{index:05}"), 1))
            .collect();
        assert!(diff_graph_snapshots("snapshot:from", "snapshot:to", from, to)?.is_empty());
        Ok(())
    }
}
