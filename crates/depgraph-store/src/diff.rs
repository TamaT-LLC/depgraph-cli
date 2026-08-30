use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use anyhow::{Context, Result};
use depgraph_protocol::canonical_json;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RenameConfidence {
    Ambiguous,
    Medium,
    High,
    Exact,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeRenameEvidence {
    pub node_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_content_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_identity: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_span: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<EvidenceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeRename {
    pub kind: String,
    pub old_id: String,
    pub new_id: String,
    pub confidence: RenameConfidence,
    pub reasons: Vec<String>,
    pub changed_fields: Vec<String>,
    pub before: NodeRecord,
    pub after: NodeRecord,
    pub old_evidence: NodeRenameEvidence,
    pub new_evidence: NodeRenameEvidence,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub renames: Vec<NodeRename>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rename_candidates: Vec<NodeRename>,
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
            renames: Vec::new(),
            rename_candidates: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
            && self.sites.is_empty()
            && self.edges.is_empty()
            && self.evidence.is_empty()
            && self.profiles.is_empty()
            && self.coverage.is_none()
            && self.renames.is_empty()
            && self.rename_candidates.is_empty()
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
    let from_node_evidence = node_source_evidence(&from);
    let to_node_evidence = node_source_evidence(&to);
    let from_source_hashes = source_file_content_hashes(&from);
    let to_source_hashes = source_file_content_hashes(&to);
    let mut nodes = diff_records(from.nodes, to.nodes, |record| record.id.clone())?;
    let (renames, rename_candidates) = detect_node_renames(
        &mut nodes,
        &from_node_evidence,
        &to_node_evidence,
        &from_source_hashes,
        &to_source_hashes,
    )?;
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
        renames,
        rename_candidates,
    })
}

const MAX_RENAME_CANDIDATE_PAIRS_PER_KEY: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MatchStrength {
    Medium,
    High,
    Exact,
}

#[derive(Debug, Default)]
struct MatchSignals {
    strength: Option<MatchStrength>,
    reasons: BTreeSet<String>,
}

struct RenameSides<'a> {
    removed: &'a [NodeRecord],
    removed_evidence: &'a [NodeRenameEvidence],
    added: &'a [NodeRecord],
    added_evidence: &'a [NodeRenameEvidence],
}

impl MatchSignals {
    fn add(&mut self, strength: MatchStrength, reason: &str) {
        self.strength = Some(
            self.strength
                .map_or(strength, |current| current.max(strength)),
        );
        self.reasons.insert(reason.to_owned());
    }
}

fn detect_node_renames(
    nodes: &mut RecordDiff<NodeRecord>,
    from_records: &BTreeMap<String, Vec<EvidenceRecord>>,
    to_records: &BTreeMap<String, Vec<EvidenceRecord>>,
    from_source_hashes: &BTreeMap<String, String>,
    to_source_hashes: &BTreeMap<String, String>,
) -> Result<(Vec<NodeRename>, Vec<NodeRename>)> {
    let removed_evidence = nodes
        .removed
        .iter()
        .map(|node| rename_evidence(node, from_records.get(&node.id), from_source_hashes))
        .collect::<Vec<_>>();
    let added_evidence = nodes
        .added
        .iter()
        .map(|node| rename_evidence(node, to_records.get(&node.id), to_source_hashes))
        .collect::<Vec<_>>();
    let sides = RenameSides {
        removed: &nodes.removed,
        removed_evidence: &removed_evidence,
        added: &nodes.added,
        added_evidence: &added_evidence,
    };
    let mut signals = BTreeMap::<(usize, usize), MatchSignals>::new();

    add_match_signal(
        &sides,
        &mut signals,
        file_content_key,
        MatchStrength::Exact,
        "same_file_content_hash_and_package",
    );
    add_match_signal(
        &sides,
        &mut signals,
        semantic_fingerprint_key,
        MatchStrength::Exact,
        "same_semantic_fingerprint_identity_shape_and_package",
    );
    add_match_signal(
        &sides,
        &mut signals,
        semantic_source_content_key,
        MatchStrength::Exact,
        "same_source_content_semantic_identity_shape_name_and_package",
    );
    add_match_signal(
        &sides,
        &mut signals,
        semantic_source_anchor_key,
        MatchStrength::High,
        "same_source_anchor_semantic_identity_shape_and_package",
    );
    add_match_signal(
        &sides,
        &mut signals,
        local_or_anonymous_span_key,
        MatchStrength::Medium,
        "same_local_or_anonymous_origin_source_and_package",
    );

    let mut removed_degree = vec![0_usize; nodes.removed.len()];
    let mut added_degree = vec![0_usize; nodes.added.len()];
    for &(removed_index, added_index) in signals.keys() {
        removed_degree[removed_index] += 1;
        added_degree[added_index] += 1;
    }

    let mut renamed_removed = BTreeSet::new();
    let mut renamed_added = BTreeSet::new();
    let mut renames = Vec::new();
    let mut candidates = Vec::new();
    for ((removed_index, added_index), signal) in signals {
        let before = &nodes.removed[removed_index];
        let after = &nodes.added[added_index];
        let unique = removed_degree[removed_index] == 1 && added_degree[added_index] == 1;
        let strength = signal
            .strength
            .expect("a rename match always contains a signal");
        let promoted = unique && strength >= MatchStrength::High;
        let mut reasons = signal.reasons;
        if removed_evidence[removed_index].source_span != added_evidence[added_index].source_span
            && is_local_or_anonymous(before)
            && is_local_or_anonymous(after)
        {
            reasons.insert("local_or_anonymous_source_span_changed".to_owned());
        }
        if !unique {
            reasons.insert(
                match (
                    removed_degree[removed_index] > 1,
                    added_degree[added_index] > 1,
                ) {
                    (true, true) => "ambiguous_many_to_many",
                    (true, false) => "ambiguous_one_to_many",
                    (false, true) => "ambiguous_many_to_one",
                    (false, false) => unreachable!("non-unique match must have a branching side"),
                }
                .to_owned(),
            );
        }
        let confidence = if unique {
            match strength {
                MatchStrength::Medium => RenameConfidence::Medium,
                MatchStrength::High => RenameConfidence::High,
                MatchStrength::Exact => RenameConfidence::Exact,
            }
        } else {
            RenameConfidence::Ambiguous
        };
        let record = NodeRename {
            kind: before.kind.clone(),
            old_id: before.id.clone(),
            new_id: after.id.clone(),
            confidence,
            reasons: reasons.into_iter().collect(),
            changed_fields: changed_fields(before, after)?,
            before: before.clone(),
            after: after.clone(),
            old_evidence: removed_evidence[removed_index].clone(),
            new_evidence: added_evidence[added_index].clone(),
        };
        if promoted {
            renamed_removed.insert(before.id.clone());
            renamed_added.insert(after.id.clone());
            renames.push(record);
        } else {
            candidates.push(record);
        }
    }
    nodes
        .removed
        .retain(|node| !renamed_removed.contains(&node.id));
    nodes.added.retain(|node| !renamed_added.contains(&node.id));
    Ok((renames, candidates))
}

fn add_match_signal<F>(
    sides: &RenameSides<'_>,
    signals: &mut BTreeMap<(usize, usize), MatchSignals>,
    key: F,
    strength: MatchStrength,
    reason: &str,
) where
    F: Fn(&NodeRecord, &NodeRenameEvidence) -> Option<String>,
{
    let mut removed_by_key = BTreeMap::<String, Vec<usize>>::new();
    let mut added_by_key = BTreeMap::<String, Vec<usize>>::new();
    for (index, node) in sides.removed.iter().enumerate() {
        if let Some(key) = key(node, &sides.removed_evidence[index]) {
            removed_by_key.entry(key).or_default().push(index);
        }
    }
    for (index, node) in sides.added.iter().enumerate() {
        if let Some(key) = key(node, &sides.added_evidence[index]) {
            added_by_key.entry(key).or_default().push(index);
        }
    }
    for (key, removed_indices) in removed_by_key {
        let Some(added_indices) = added_by_key.get(&key) else {
            continue;
        };
        if removed_indices
            .len()
            .checked_mul(added_indices.len())
            .is_none_or(|pairs| pairs > MAX_RENAME_CANDIDATE_PAIRS_PER_KEY)
        {
            continue;
        }
        for removed_index in &removed_indices {
            for added_index in added_indices {
                signals
                    .entry((*removed_index, *added_index))
                    .or_default()
                    .add(strength, reason);
            }
        }
    }
}

fn file_content_key(node: &NodeRecord, evidence: &NodeRenameEvidence) -> Option<String> {
    if node.kind != "file" {
        return None;
    }
    Some(canonical_json(&json!({
        "kind": node.kind,
        "package_owner": evidence.package_owner.as_ref()?,
        "content_hash": evidence.content_hash.as_ref()?,
    })))
}

fn semantic_fingerprint_key(node: &NodeRecord, evidence: &NodeRenameEvidence) -> Option<String> {
    if !is_semantic_rename_kind(node) {
        return None;
    }
    Some(canonical_json(&json!({
        "kind": node.kind,
        "package_owner": evidence.package_owner.as_ref()?,
        "semantic_fingerprint": evidence.semantic_fingerprint.as_ref()?,
        "identity_shape": semantic_identity_shape(evidence.canonical_identity.as_ref()?)?,
    })))
}

fn semantic_source_content_key(node: &NodeRecord, evidence: &NodeRenameEvidence) -> Option<String> {
    if !is_semantic_rename_kind(node) {
        return None;
    }
    let display_name = (node.kind != "route").then_some(node.display_name.as_str());
    Some(canonical_json(&json!({
        "kind": node.kind,
        "display_name": display_name,
        "package_owner": evidence.package_owner.as_ref()?,
        "source_content_hash": evidence.source_content_hash.as_ref()?,
        "identity_shape": semantic_identity_shape(evidence.canonical_identity.as_ref()?)?,
    })))
}

fn semantic_source_anchor_key(node: &NodeRecord, evidence: &NodeRenameEvidence) -> Option<String> {
    if !is_semantic_rename_kind(node) || is_local_or_anonymous(node) {
        return None;
    }
    let span = evidence.source_span.as_ref()?.as_object()?;
    Some(canonical_json(&json!({
        "kind": node.kind,
        "package_owner": evidence.package_owner.as_ref()?,
        "identity_shape": semantic_identity_shape(evidence.canonical_identity.as_ref()?)?,
        "source_path": evidence.source_path.as_ref()?,
        "start_line": span.get("start_line")?,
        "start_column": span.get("start_column")?,
    })))
}

fn local_or_anonymous_span_key(node: &NodeRecord, evidence: &NodeRenameEvidence) -> Option<String> {
    if !is_local_or_anonymous(node) {
        return None;
    }
    Some(canonical_json(&json!({
        "kind": node.kind,
        "display_name": node.display_name,
        "package_owner": evidence.package_owner.as_ref()?,
        "identity_shape": semantic_identity_shape(evidence.canonical_identity.as_ref()?)?,
        "source_path": evidence.source_path.as_ref()?,
    })))
}

fn is_semantic_rename_kind(node: &NodeRecord) -> bool {
    matches!(node.kind.as_str(), "symbol" | "type" | "route")
}

fn is_local_or_anonymous(node: &NodeRecord) -> bool {
    node.kind == "symbol"
        && node
            .properties
            .get("canonical_identity")
            .and_then(|identity| identity.get("identity_kind"))
            .and_then(Value::as_str)
            .is_some_and(|kind| matches!(kind, "local" | "anonymous"))
}

fn semantic_identity_shape(identity: &Value) -> Option<Value> {
    let mut shape = identity.as_object()?.clone();
    for volatile in [
        "resolver_identity",
        "relative_path",
        "route_pattern",
        "span",
    ] {
        shape.remove(volatile);
    }
    Some(Value::Object(shape))
}

fn node_source_evidence(snapshot: &GraphSnapshot) -> BTreeMap<String, Vec<EvidenceRecord>> {
    let mut owner_targets = BTreeMap::<(&str, &str), &str>::new();
    for edge in &snapshot.edges {
        if matches!(edge.kind.as_str(), "declares" | "contains") {
            owner_targets.insert(("edge", edge.id.as_str()), edge.target.as_str());
        }
    }
    let mut output = BTreeMap::<String, Vec<EvidenceRecord>>::new();
    for record in &snapshot.evidence {
        if let Some(target) =
            owner_targets.get(&(record.owner_type.as_str(), record.owner_id.as_str()))
        {
            output
                .entry((*target).to_owned())
                .or_default()
                .push(record.clone());
        }
    }
    for records in output.values_mut() {
        records.sort_by_key(evidence_identity);
    }
    output
}

fn source_file_content_hashes(snapshot: &GraphSnapshot) -> BTreeMap<String, String> {
    let mut by_path = BTreeMap::<String, Option<String>>::new();
    for node in snapshot.nodes.iter().filter(|node| node.kind == "file") {
        let candidate = (|| {
            let path = string_property(&node.properties, &["source_path", "path"])
                .or_else(|| node.locator.strip_prefix("file://").map(str::to_owned))
                .or_else(|| node.locator.strip_prefix("file:").map(str::to_owned))?;
            let hash = fingerprint_property(&node.properties, &["content_hash", "content_digest"])?;
            Some((path, hash))
        })();
        let Some((path, hash)) = candidate else {
            continue;
        };
        match by_path.get_mut(&path) {
            None => {
                by_path.insert(path, Some(hash));
            }
            Some(existing) if existing.as_ref() == Some(&hash) => {}
            Some(existing) => *existing = None,
        }
    }
    by_path
        .into_iter()
        .filter_map(|(path, hash)| hash.map(|hash| (path, hash)))
        .collect()
}

fn rename_evidence(
    node: &NodeRecord,
    records: Option<&Vec<EvidenceRecord>>,
    source_hashes: &BTreeMap<String, String>,
) -> NodeRenameEvidence {
    let records = records.cloned().unwrap_or_default();
    let canonical_identity = node.properties.get("canonical_identity").cloned();
    let source_record = records.first();
    let source_path = string_property(&node.properties, &["source_path", "path"])
        .or_else(|| {
            canonical_identity
                .as_ref()
                .and_then(|identity| string_property(identity, &["relative_path"]))
        })
        .or_else(|| source_record.map(|record| record.path.clone()));
    let source_span = node
        .properties
        .get("source_span")
        .cloned()
        .or_else(|| {
            canonical_identity
                .as_ref()
                .and_then(|identity| identity.get("span"))
                .cloned()
        })
        .or_else(|| {
            source_record.map(|record| {
                json!({
                    "start_line": record.start_line,
                    "start_column": record.start_column,
                    "end_line": record.end_line,
                    "end_column": record.end_column,
                })
            })
        });
    NodeRenameEvidence {
        node_id: node.id.clone(),
        package_owner: package_owner(node),
        content_hash: fingerprint_property(&node.properties, &["content_hash", "content_digest"]),
        source_content_hash: source_path
            .as_ref()
            .and_then(|path| source_hashes.get(path))
            .cloned(),
        semantic_fingerprint: fingerprint_property(
            &node.properties,
            &["semantic_hash", "declaration_hash"],
        ),
        canonical_identity,
        source_path,
        source_span,
        records,
    }
}

fn fingerprint_property(value: &Value, fields: &[&str]) -> Option<String> {
    string_property(value, fields).filter(|value| is_sha256_fingerprint(value))
}

fn is_sha256_fingerprint(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn package_owner(node: &NodeRecord) -> Option<String> {
    for field in ["package_locator", "package_id", "package_path", "package"] {
        if let Some(value) = node.properties.get(field).and_then(Value::as_str)
            && !value.is_empty()
        {
            return Some(format!("{field}:{value}"));
        }
    }
    node.properties
        .get("canonical_identity")
        .and_then(|identity| identity.get("package_locator"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(|value| format!("package_locator:{value}"))
}

fn string_property(value: &Value, fields: &[&str]) -> Option<String> {
    fields.iter().find_map(|field| {
        value
            .get(*field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
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

    const HASH_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const HASH_C: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const HASH_D: &str = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

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
                health_policy_config_digest: None,
                health_analyzer_version: None,
                health_finding_contract_version: None,
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

    fn file_node(id: &str, path: &str, package: &str, content_hash: &str) -> NodeRecord {
        NodeRecord {
            id: id.to_owned(),
            kind: "file".to_owned(),
            locator: format!("file:{path}"),
            display_name: path.to_owned(),
            properties: json!({
                "path": path,
                "package_locator": package,
                "content_hash": content_hash,
            }),
        }
    }

    fn semantic_node(
        id: &str,
        kind: &str,
        display_name: &str,
        canonical_identity: Value,
        source_path: &str,
        source_span: Value,
        semantic_hash: Option<&str>,
    ) -> NodeRecord {
        let package_locator = canonical_identity["package_locator"].clone();
        let mut properties = json!({
            "package_locator": package_locator,
            "canonical_identity": canonical_identity,
            "source_path": source_path,
            "source_span": source_span,
        });
        if let Some(semantic_hash) = semantic_hash {
            properties["semantic_hash"] = json!(semantic_hash);
        }
        NodeRecord {
            id: id.to_owned(),
            kind: kind.to_owned(),
            locator: format!("{kind}:{id}"),
            display_name: display_name.to_owned(),
            properties,
        }
    }

    fn declaration_edge(id: &str, target: &str) -> EdgeRecord {
        EdgeRecord {
            id: id.to_owned(),
            site_id: None,
            source: "package:fixture".to_owned(),
            target: target.to_owned(),
            kind: "declares".to_owned(),
            phase: "semantic".to_owned(),
            environment: "any".to_owned(),
            profile_id: "fixture:safe".to_owned(),
            resolution_status: "resolved".to_owned(),
            precision: "exact".to_owned(),
            condition: json!({"op":"all","conditions":[]}),
            generated: false,
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
    fn rename_fingerprints_require_prefixed_lowercase_sha256() {
        assert!(is_sha256_fingerprint(HASH_A));
        assert!(!is_sha256_fingerprint(&HASH_A.to_uppercase()));
        assert!(!is_sha256_fingerprint("sha256:short"));
        assert!(!is_sha256_fingerprint(&"a".repeat(64)));
    }

    #[test]
    fn conflicting_file_hashes_for_one_source_path_fail_closed_independent_of_order() {
        let first = file_node("file:first", "src/shared.ts", "npm:fixture", HASH_A);
        let second = file_node("file:second", "src/shared.ts", "npm:fixture", HASH_B);
        let mut forward = empty_snapshot("/checkout/one");
        forward.nodes = vec![first.clone(), second.clone()];
        let mut reverse = empty_snapshot("/checkout/two");
        reverse.nodes = vec![second, first];
        assert!(source_file_content_hashes(&forward).is_empty());
        assert!(source_file_content_hashes(&reverse).is_empty());
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
    fn promotes_a_unique_file_move_and_preserves_old_and_new_evidence() -> Result<()> {
        let mut from = empty_snapshot("/checkout/one");
        from.nodes = vec![file_node("file:old", "src/old.ts", "npm:fixture", HASH_A)];
        from.edges = vec![declaration_edge("edge:old", "file:old")];
        from.evidence = vec![evidence("edge:old", 0, "source", "old declaration")];
        from.evidence[0].path = "src/old.ts".to_owned();

        let mut to = empty_snapshot("/checkout/two");
        to.nodes = vec![file_node("file:new", "src/new.ts", "npm:fixture", HASH_A)];
        to.edges = vec![declaration_edge("edge:new", "file:new")];
        to.evidence = vec![evidence("edge:new", 0, "source", "new declaration")];
        to.evidence[0].path = "src/new.ts".to_owned();

        let diff = diff_graph_snapshots("snapshot:from", "snapshot:to", from, to)?;
        assert!(diff.nodes.added.is_empty());
        assert!(diff.nodes.removed.is_empty());
        assert_eq!(diff.renames.len(), 1);
        assert_eq!(diff.renames[0].old_id, "file:old");
        assert_eq!(diff.renames[0].new_id, "file:new");
        assert_eq!(diff.renames[0].confidence, RenameConfidence::Exact);
        assert_eq!(
            diff.renames[0].reasons,
            ["same_file_content_hash_and_package"]
        );
        assert_eq!(diff.renames[0].old_evidence.records[0].path, "src/old.ts");
        assert_eq!(diff.renames[0].new_evidence.records[0].path, "src/new.ts");
        Ok(())
    }

    #[test]
    fn detects_symbol_type_and_route_renames_with_canonical_confidence() -> Result<()> {
        let package = "npm:fixture";
        let symbol = |id: &str, name: &str| {
            semantic_node(
                id,
                "symbol",
                name,
                json!({
                    "language":"typescript",
                    "package_locator":package,
                    "symbol_kind":"function",
                    "identity_kind":"named",
                    "resolver_identity":format!("{package}#{name}"),
                }),
                "src/service.ts",
                json!({"start_line":10,"start_column":1,"end_line":12,"end_column":2}),
                None,
            )
        };
        let type_node = |id: &str, name: &str, path: &str| {
            semantic_node(
                id,
                "type",
                name,
                json!({
                    "language":"typescript",
                    "package_locator":package,
                    "type_kind":"interface",
                    "resolver_identity":format!("{package}#{name}"),
                }),
                path,
                json!({"start_line":1,"start_column":1,"end_line":3,"end_column":2}),
                Some(HASH_B),
            )
        };
        let route = |id: &str, pattern: &str| {
            semantic_node(
                id,
                "route",
                pattern,
                json!({
                    "framework":"next",
                    "package_locator":package,
                    "route_kind":"page",
                    "environment":"server",
                    "router_instance":"app",
                    "route_pattern":pattern,
                }),
                "src/app/page.tsx",
                json!({"start_line":1,"start_column":1,"end_line":20,"end_column":2}),
                None,
            )
        };
        let mut from = empty_snapshot("/checkout/one");
        from.nodes = vec![
            type_node("old:type", "Before", "src/types.ts"),
            route("old:route", "/before"),
            symbol("old:symbol", "before"),
        ];
        let mut to = empty_snapshot("/checkout/two");
        to.nodes = vec![
            symbol("new:symbol", "after"),
            route("new:route", "/after"),
            type_node("new:type", "After", "src/moved/types.ts"),
        ];

        let first = diff_graph_snapshots("snapshot:from", "snapshot:to", from.clone(), to.clone())?;
        let second = diff_graph_snapshots("snapshot:from", "snapshot:to", from, to)?;
        assert_eq!(first, second);
        assert!(first.nodes.added.is_empty());
        assert!(first.nodes.removed.is_empty());
        assert_eq!(
            first
                .renames
                .iter()
                .map(|rename| (rename.kind.as_str(), rename.confidence))
                .collect::<Vec<_>>(),
            [
                ("route", RenameConfidence::High),
                ("symbol", RenameConfidence::High),
                ("type", RenameConfidence::Exact),
            ]
        );
        assert_eq!(
            first.renames[2].reasons,
            ["same_semantic_fingerprint_identity_shape_and_package"]
        );
        Ok(())
    }

    #[test]
    fn detects_semantic_moves_from_their_snapshot_source_file_hash() -> Result<()> {
        let symbol = |id: &str, path: &str| {
            semantic_node(
                id,
                "symbol",
                "service",
                json!({
                    "language":"typescript",
                    "package_locator":"npm:fixture",
                    "symbol_kind":"function",
                    "identity_kind":"named",
                    "resolver_identity":format!("npm:fixture::{path}#service"),
                }),
                path,
                json!({"start_line":1,"start_column":1,"end_line":3,"end_column":2}),
                None,
            )
        };
        let route = |id: &str, path: &str, pattern: &str| {
            semantic_node(
                id,
                "route",
                pattern,
                json!({
                    "framework":"next",
                    "package_locator":"npm:fixture",
                    "route_kind":"page",
                    "environment":"server",
                    "router_instance":"app",
                    "route_pattern":pattern,
                }),
                path,
                json!({"start_line":1,"start_column":1,"end_line":3,"end_column":2}),
                None,
            )
        };
        let mut from = empty_snapshot("/checkout/one");
        from.nodes = vec![
            file_node("file:old", "src/old.ts", "npm:fixture", HASH_A),
            route("route:old", "src/old.ts", "/old"),
            symbol("symbol:old", "src/old.ts"),
        ];
        let mut to = empty_snapshot("/checkout/two");
        to.nodes = vec![
            file_node("file:new", "src/new.ts", "npm:fixture", HASH_A),
            route("route:new", "src/new.ts", "/new"),
            symbol("symbol:new", "src/new.ts"),
        ];

        let diff = diff_graph_snapshots("snapshot:from", "snapshot:to", from, to)?;
        assert!(diff.nodes.added.is_empty());
        assert!(diff.nodes.removed.is_empty());
        assert_eq!(diff.renames.len(), 3);
        assert_eq!(diff.renames[1].kind, "route");
        assert_eq!(diff.renames[2].kind, "symbol");
        assert_eq!(diff.renames[2].confidence, RenameConfidence::Exact);
        assert_eq!(
            diff.renames[2].reasons,
            ["same_source_content_semantic_identity_shape_name_and_package"]
        );
        assert_eq!(
            diff.renames[2].old_evidence.source_content_hash.as_deref(),
            Some(HASH_A)
        );
        assert_eq!(
            diff.renames[2].new_evidence.source_content_hash.as_deref(),
            Some(HASH_A)
        );
        Ok(())
    }

    #[test]
    fn keeps_local_span_changes_as_reasoned_candidates() -> Result<()> {
        let local = |id: &str, line: u64| {
            semantic_node(
                id,
                "symbol",
                "handler",
                json!({
                    "language":"typescript",
                    "package_locator":"npm:fixture",
                    "symbol_kind":"local_function",
                    "identity_kind":"local",
                    "enclosing_symbol":"symbol:owner",
                    "relative_path":"src/service.ts",
                    "span":{
                        "start_line":line,"start_column":3,"end_line":line + 2,"end_column":4
                    },
                }),
                "src/service.ts",
                json!({"start_line":line,"start_column":3,"end_line":line + 2,"end_column":4}),
                None,
            )
        };
        let mut from = empty_snapshot("/checkout/one");
        from.nodes = vec![local("local:old", 10)];
        let mut to = empty_snapshot("/checkout/two");
        to.nodes = vec![local("local:new", 20)];

        let diff = diff_graph_snapshots("snapshot:from", "snapshot:to", from, to)?;
        assert_eq!(diff.nodes.removed.len(), 1);
        assert_eq!(diff.nodes.added.len(), 1);
        assert!(diff.renames.is_empty());
        assert_eq!(diff.rename_candidates.len(), 1);
        assert_eq!(
            diff.rename_candidates[0].confidence,
            RenameConfidence::Medium
        );
        assert_eq!(
            diff.rename_candidates[0].reasons,
            [
                "local_or_anonymous_source_span_changed",
                "same_local_or_anonymous_origin_source_and_package",
            ]
        );
        Ok(())
    }

    #[test]
    fn copy_delete_add_and_ambiguous_fixtures_fail_closed() -> Result<()> {
        let old = file_node("file:old", "old.ts", "npm:fixture", HASH_A);
        let copy = file_node("file:copy", "copy.ts", "npm:fixture", HASH_A);
        let mut copy_from = empty_snapshot("/checkout/one");
        copy_from.nodes = vec![old.clone()];
        let mut copy_to = empty_snapshot("/checkout/two");
        copy_to.nodes = vec![old.clone(), copy];
        let copy_diff =
            diff_graph_snapshots("snapshot:copy-from", "snapshot:copy-to", copy_from, copy_to)?;
        assert_eq!(copy_diff.nodes.added[0].id, "file:copy");
        assert!(copy_diff.renames.is_empty());
        assert!(copy_diff.rename_candidates.is_empty());

        let mut delete_add_from = empty_snapshot("/checkout/one");
        delete_add_from.nodes = vec![file_node(
            "file:deleted",
            "deleted.ts",
            "npm:fixture",
            HASH_B,
        )];
        let mut delete_add_to = empty_snapshot("/checkout/two");
        delete_add_to.nodes = vec![file_node("file:added", "added.ts", "npm:fixture", HASH_C)];
        let delete_add = diff_graph_snapshots(
            "snapshot:delete",
            "snapshot:add",
            delete_add_from,
            delete_add_to,
        )?;
        assert_eq!(delete_add.nodes.removed.len(), 1);
        assert_eq!(delete_add.nodes.added.len(), 1);
        assert!(delete_add.renames.is_empty());
        assert!(delete_add.rename_candidates.is_empty());

        let mut ambiguous_from = empty_snapshot("/checkout/one");
        ambiguous_from.nodes = vec![
            file_node("old:a", "a.ts", "npm:fixture", HASH_C),
            file_node("old:b", "b.ts", "npm:fixture", HASH_D),
            file_node("old:c", "c.ts", "npm:fixture", HASH_D),
        ];
        let mut ambiguous_to = empty_snapshot("/checkout/two");
        ambiguous_to.nodes = vec![
            file_node("new:a", "a1.ts", "npm:fixture", HASH_C),
            file_node("new:b", "a2.ts", "npm:fixture", HASH_C),
            file_node("new:c", "c.ts", "npm:fixture", HASH_D),
        ];
        let ambiguous = diff_graph_snapshots(
            "snapshot:ambiguous-from",
            "snapshot:ambiguous-to",
            ambiguous_from,
            ambiguous_to,
        )?;
        assert!(ambiguous.renames.is_empty());
        assert_eq!(ambiguous.nodes.removed.len(), 3);
        assert_eq!(ambiguous.nodes.added.len(), 3);
        assert_eq!(ambiguous.rename_candidates.len(), 4);
        assert!(
            ambiguous
                .rename_candidates
                .iter()
                .all(|candidate| candidate.confidence == RenameConfidence::Ambiguous)
        );
        assert!(ambiguous.rename_candidates.iter().any(|candidate| {
            candidate
                .reasons
                .contains(&"ambiguous_one_to_many".to_owned())
        }));
        assert!(ambiguous.rename_candidates.iter().any(|candidate| {
            candidate
                .reasons
                .contains(&"ambiguous_many_to_one".to_owned())
        }));
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
