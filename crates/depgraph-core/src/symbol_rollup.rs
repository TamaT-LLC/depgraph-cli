//! File-level rollup of the symbol dependencies of one file (Issue #623).
//!
//! Rust HIR and the web semantic workers attach their `calls`, `type_uses`,
//! `imports` and other semantic edges to symbols, types and modules, never to
//! file nodes, so a file's `dependents` / `deps` list only its file-level
//! edges. The rollup answers the file-level question with those semantic
//! edges: it groups the semantic edges of the nodes the file owns by the other
//! file at their far end. It never creates an edge; every file it reports
//! carries the IDs and the per-kind counts of the edges behind it.
//!
//! A node belongs to a file when it is that file node, when its `source_path`
//! property names the file, or when the file node `declares` it. The near end
//! of an edge is the file its edge evidence records, which is where the
//! dependency is written; an edge without evidence falls back to the file that
//! owns its source node. A Rust module declared with `mod name;` belongs to the
//! declaring file, while the `use` items inside the module file record that
//! file as their evidence, so `deps` of the module file lists them and `deps`
//! of the declaring file does not.
//!
//! The rollup visits every node, edge, and evidence record of the snapshot a
//! bounded number of times. Like the path-step scans of Issue #620, those
//! visits count against the fixed snapshot scan ceiling, and the work that
//! grows with the matched edges counts against the request budget.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use depgraph_store::{EdgeRecord, GraphSnapshot, NodeRecord};
use serde::Serialize;

use crate::edge_kind_selection::{EdgeKindFilter, is_structural_edge_kind};
use crate::query::{GraphQueryFilter, postprocessing_cancelled, postprocessing_work_exhausted};

/// Phase of the edges the rollup groups.
pub const SYMBOL_ROLLUP_PHASE: &str = "semantic";

/// Most files one rollup lists; `total_files` counts every file.
pub const MAX_SYMBOL_ROLLUP_FILES: usize = 4096;

/// Most edge IDs listed for one file, in ID order; `edge_count` counts every edge.
pub const MAX_SYMBOL_ROLLUP_EDGE_IDS: usize = 16;

/// How the dependency list rolls up the dependencies of nodes below the selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyRollup {
    /// Group the semantic edges of the nodes a file owns by the other file.
    Symbols,
}

impl DependencyRollup {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Symbols => "symbols",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        (value == "symbols").then_some(Self::Symbols)
    }
}

/// Whether the rollup could group anything.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolRollupStatus {
    /// The semantic edges were grouped; `files` can still be empty.
    RolledUp,
    /// The snapshot has no semantic edge at all, for example a Store scanned
    /// with Rust in syntax-only mode (see `analysis_degradations`).
    NoSemanticEdges,
    /// The selector is not a file node with a path, so it owns no nodes.
    RootNotFile,
}

impl SymbolRollupStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RolledUp => "rolled_up",
            Self::NoSemanticEdges => "no_semantic_edges",
            Self::RootNotFile => "root_not_file",
        }
    }
}

/// Edges of one kind behind one file of a rollup.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SymbolRollupEdgeKind {
    pub kind: String,
    pub edge_count: u64,
}

/// One other file and the semantic edges that connect it with the selector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SymbolRollupFile {
    pub node_id: String,
    pub path: String,
    /// Edges behind this file; one edge counts once per file it connects.
    pub edge_count: u64,
    /// `edge_count` by edge kind, in kind order.
    pub edge_kinds: Vec<SymbolRollupEdgeKind>,
    /// The first [`MAX_SYMBOL_ROLLUP_EDGE_IDS`] edge IDs in ID order.
    pub edge_ids: Vec<String>,
    /// Whether the dependency list already has a direct edge with this file node.
    pub file_edge: bool,
}

/// File-level rollup of the semantic edges of the nodes the selector file owns.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SymbolRollup {
    pub rollup: DependencyRollup,
    pub status: SymbolRollupStatus,
    /// Nodes the selector file owns, the file node itself excluded.
    pub owned_nodes: u64,
    /// Matched semantic edges that reach at least one other file.
    pub attributed_edges: u64,
    /// Matched semantic edges whose far end has no file node, such as an
    /// external crate or an unresolved target.
    pub unattributed_edges: u64,
    /// Every other file reached; `files` lists at most [`MAX_SYMBOL_ROLLUP_FILES`].
    pub total_files: u64,
    /// Files in path order.
    pub files: Vec<SymbolRollupFile>,
}

impl SymbolRollup {
    fn empty(status: SymbolRollupStatus) -> Self {
        Self {
            rollup: DependencyRollup::Symbols,
            status,
            owned_nodes: 0,
            attributed_edges: 0,
            unattributed_edges: 0,
            total_files: 0,
            files: Vec::new(),
        }
    }
}

/// Work of one rollup, counted against two budgets: the snapshot-wide scans
/// against `scan_maximum` and the work that grows with the matched edges
/// against `maximum`.
pub(crate) struct SymbolRollupWork {
    used: usize,
    maximum: usize,
    scanned: usize,
    scan_maximum: usize,
}

impl SymbolRollupWork {
    pub(crate) const fn new(maximum: usize, scan_maximum: usize) -> Self {
        Self {
            used: 0,
            maximum,
            scanned: 0,
            scan_maximum,
        }
    }

    fn scan(&mut self, is_cancelled: &mut impl FnMut() -> bool) -> Result<()> {
        if is_cancelled() {
            return Err(postprocessing_cancelled());
        }
        if self.scanned >= self.scan_maximum {
            return Err(postprocessing_work_exhausted(self.scan_maximum));
        }
        self.scanned += 1;
        Ok(())
    }

    fn step(&mut self, is_cancelled: &mut impl FnMut() -> bool) -> Result<()> {
        if is_cancelled() {
            return Err(postprocessing_cancelled());
        }
        if self.used >= self.maximum {
            return Err(postprocessing_work_exhausted(self.maximum));
        }
        self.used += 1;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) const fn used(&self) -> usize {
        self.used
    }

    #[cfg(test)]
    pub(crate) const fn scanned(&self) -> usize {
        self.scanned
    }
}

fn string_property<'a>(node: &'a NodeRecord, key: &str) -> Option<&'a str> {
    node.properties
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
}

/// Repository path of a file node: its `path` property, or the path of its
/// `file:<path>` locator when the worker recorded no property, as the Agent
/// node projection reads it (Issue #566).
fn file_path(node: &NodeRecord) -> Option<&str> {
    if node.kind != "file" {
        return None;
    }
    string_property(node, "path").or_else(|| {
        node.locator
            .strip_prefix("file:")
            .filter(|path| !path.is_empty() && !path.starts_with("//"))
    })
}

#[derive(Default)]
struct FileAggregate<'a> {
    edge_ids: BTreeSet<&'a str>,
    edge_kinds: BTreeMap<&'a str, u64>,
}

/// Rolls up the semantic edges of the nodes `root` owns by the other file.
///
/// `reverse` selects incoming edges (`dependents`); otherwise the outgoing
/// edges written in the file (`deps`). `filter` and `edge_kinds` select edges
/// as they do for the traversal; structural edges are never grouped.
/// `file_neighbors` are the node IDs the dependency list reached directly.
#[allow(clippy::too_many_arguments)]
pub(crate) fn symbol_rollup_cancellable(
    snapshot: &GraphSnapshot,
    root: &NodeRecord,
    reverse: bool,
    filter: &GraphQueryFilter,
    edge_kinds: &EdgeKindFilter,
    file_neighbors: &BTreeSet<&str>,
    work: &mut SymbolRollupWork,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<SymbolRollup> {
    let Some(root_path) = file_path(root) else {
        return Ok(SymbolRollup::empty(SymbolRollupStatus::RootNotFile));
    };

    // Owner of every node and the file node of every path. A duplicate file
    // path keeps its smallest node ID so the result does not depend on order.
    let mut file_ids = BTreeMap::<&str, &str>::new();
    let mut file_nodes = BTreeSet::<&str>::new();
    let mut owners = BTreeMap::<&str, &str>::new();
    for node in &snapshot.nodes {
        work.scan(is_cancelled)?;
        if let Some(path) = file_path(node) {
            file_nodes.insert(node.id.as_str());
            owners.insert(node.id.as_str(), path);
            file_ids
                .entry(path)
                .and_modify(|id| {
                    if node.id.as_str() < *id {
                        *id = node.id.as_str();
                    }
                })
                .or_insert(node.id.as_str());
        } else if node.kind != "file"
            && let Some(path) = string_property(node, "source_path")
        {
            owners.insert(node.id.as_str(), path);
        }
    }

    // `declares` from a file node owns its target too; the root owns every
    // node it declares even when that node names another source path.
    let mut owned = BTreeSet::<&str>::new();
    for edge in &snapshot.edges {
        work.scan(is_cancelled)?;
        if edge.kind != "declares" || !file_nodes.contains(edge.source.as_str()) {
            continue;
        }
        if edge.source == root.id {
            work.step(is_cancelled)?;
            owned.insert(edge.target.as_str());
        }
        if let Some(path) = owners.get(edge.source.as_str()).copied() {
            owners.entry(edge.target.as_str()).or_insert(path);
        }
    }
    for (node_id, path) in &owners {
        work.scan(is_cancelled)?;
        if *path == root_path {
            work.step(is_cancelled)?;
            owned.insert(node_id);
        }
    }
    owned.insert(root.id.as_str());

    let selected = |edge: &EdgeRecord| {
        edge.phase == SYMBOL_ROLLUP_PHASE
            && !is_structural_edge_kind(&edge.kind)
            && edge_kinds.allows(&edge.kind)
            && filter.matches_edge(snapshot, edge)
    };

    // Edges whose root-side node the file owns.
    let mut semantic_edges = 0_usize;
    let mut candidates = BTreeMap::<&str, &EdgeRecord>::new();
    for edge in &snapshot.edges {
        work.scan(is_cancelled)?;
        if edge.phase == SYMBOL_ROLLUP_PHASE {
            semantic_edges += 1;
        }
        let near = if reverse { &edge.target } else { &edge.source };
        if selected(edge) && owned.contains(near.as_str()) {
            work.step(is_cancelled)?;
            candidates.insert(edge.id.as_str(), edge);
        }
    }
    if semantic_edges == 0 {
        let mut rollup = SymbolRollup::empty(SymbolRollupStatus::NoSemanticEdges);
        rollup.owned_nodes = (owned.len() - 1) as u64;
        return Ok(rollup);
    }

    // Where each candidate is written, and for `deps` the edges written in
    // the root file whose source node another file owns.
    let mut written = BTreeMap::<&str, BTreeSet<&str>>::new();
    let mut written_in_root = BTreeSet::<&str>::new();
    for evidence in &snapshot.evidence {
        work.scan(is_cancelled)?;
        if evidence.owner_type != "edge" || evidence.path.is_empty() {
            continue;
        }
        if candidates.contains_key(evidence.owner_id.as_str()) {
            work.step(is_cancelled)?;
            written
                .entry(evidence.owner_id.as_str())
                .or_default()
                .insert(evidence.path.as_str());
        } else if !reverse && evidence.path == root_path {
            work.step(is_cancelled)?;
            written_in_root.insert(evidence.owner_id.as_str());
        }
    }
    if !written_in_root.is_empty() {
        for edge in &snapshot.edges {
            work.scan(is_cancelled)?;
            if written_in_root.contains(edge.id.as_str()) && selected(edge) {
                work.step(is_cancelled)?;
                candidates.insert(edge.id.as_str(), edge);
                written
                    .entry(edge.id.as_str())
                    .or_default()
                    .insert(root_path);
            }
        }
    }

    let mut files = BTreeMap::<&str, FileAggregate<'_>>::new();
    let mut attributed_edges = 0_u64;
    let mut unattributed_edges = 0_u64;
    for (edge_id, edge) in &candidates {
        work.step(is_cancelled)?;
        let fallback = owners.get(edge.source.as_str()).copied();
        let source_files = written.get(edge_id).map_or_else(
            || fallback.into_iter().collect::<BTreeSet<_>>(),
            Clone::clone,
        );
        let far_files = if reverse {
            source_files
                .into_iter()
                .filter(|path| *path != root_path)
                .collect::<Vec<_>>()
        } else if source_files.contains(root_path) {
            owners
                .get(edge.target.as_str())
                .copied()
                .filter(|path| *path != root_path)
                .into_iter()
                .collect()
        } else {
            // Written in another file, such as the `use` items of a module
            // file whose module node the root declares.
            continue;
        };
        let far_end_in_root = if reverse {
            written
                .get(edge_id)
                .is_some_and(|paths| paths.contains(root_path))
                || (!written.contains_key(edge_id) && fallback == Some(root_path))
        } else {
            owners.get(edge.target.as_str()).copied() == Some(root_path)
        };
        let mut attributed = false;
        for path in far_files {
            if !file_ids.contains_key(path) {
                continue;
            }
            work.step(is_cancelled)?;
            let aggregate = files.entry(path).or_default();
            aggregate.edge_ids.insert(edge_id);
            *aggregate.edge_kinds.entry(edge.kind.as_str()).or_default() += 1;
            attributed = true;
        }
        if attributed {
            attributed_edges += 1;
        } else if !far_end_in_root {
            unattributed_edges += 1;
        }
    }

    let total_files = files.len() as u64;
    let mut listed = Vec::with_capacity(files.len().min(MAX_SYMBOL_ROLLUP_FILES));
    for (path, aggregate) in files.into_iter().take(MAX_SYMBOL_ROLLUP_FILES) {
        work.step(is_cancelled)?;
        let node_id = file_ids[path];
        let mut edge_ids =
            Vec::with_capacity(aggregate.edge_ids.len().min(MAX_SYMBOL_ROLLUP_EDGE_IDS));
        for edge_id in aggregate.edge_ids.iter().take(MAX_SYMBOL_ROLLUP_EDGE_IDS) {
            work.step(is_cancelled)?;
            edge_ids.push((*edge_id).to_owned());
        }
        listed.push(SymbolRollupFile {
            node_id: node_id.to_owned(),
            path: path.to_owned(),
            edge_count: aggregate.edge_ids.len() as u64,
            edge_kinds: aggregate
                .edge_kinds
                .into_iter()
                .map(|(kind, edge_count)| SymbolRollupEdgeKind {
                    kind: kind.to_owned(),
                    edge_count,
                })
                .collect(),
            edge_ids,
            file_edge: file_neighbors.contains(node_id),
        });
    }
    Ok(SymbolRollup {
        rollup: DependencyRollup::Symbols,
        status: SymbolRollupStatus::RolledUp,
        owned_nodes: (owned.len() - 1) as u64,
        attributed_edges,
        unattributed_edges,
        total_files,
        files: listed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{preprocessing_work_limit, traverse_bounded_filtered};
    use crate::service_limits::{
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS, MAX_GRAPH_SNAPSHOT_SCAN_WORK_ITEMS,
    };
    use depgraph_store::{CoverageRecord, EvidenceRecord, ScanRecord};
    use serde_json::json;

    type FileSummary = (String, u64, Vec<(String, u64)>, Vec<String>, bool);

    fn node(id: &str, kind: &str, properties: serde_json::Value) -> NodeRecord {
        NodeRecord {
            id: id.to_owned(),
            kind: kind.to_owned(),
            locator: if kind == "file" {
                format!("file:{}", properties["path"].as_str().unwrap_or(id))
            } else {
                format!("test:{id}")
            },
            display_name: id.to_owned(),
            properties,
        }
    }

    fn file(id: &str, path: &str) -> NodeRecord {
        node(id, "file", json!({"path": path}))
    }

    fn owned(id: &str, kind: &str, path: &str) -> NodeRecord {
        node(id, kind, json!({"source_path": path}))
    }

    fn edge(id: &str, source: &str, target: &str, kind: &str, phase: &str) -> EdgeRecord {
        EdgeRecord {
            id: id.to_owned(),
            site_id: None,
            source: source.to_owned(),
            target: target.to_owned(),
            kind: kind.to_owned(),
            phase: phase.to_owned(),
            environment: "host".to_owned(),
            profile_id: "profile:rust".to_owned(),
            resolution_status: "resolved".to_owned(),
            precision: "exact".to_owned(),
            condition: json!({"op": "true"}),
            generated: false,
        }
    }

    fn evidence(edge_id: &str, path: &str) -> EvidenceRecord {
        EvidenceRecord {
            owner_type: "edge".to_owned(),
            owner_id: edge_id.to_owned(),
            ordinal: 0,
            kind: "semantic".to_owned(),
            extractor: "rust-analyzer-hir".to_owned(),
            extractor_version: "1".to_owned(),
            path: path.to_owned(),
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 2,
            detail: None,
            properties: json!({}),
        }
    }

    fn graph(
        nodes: Vec<NodeRecord>,
        edges: Vec<EdgeRecord>,
        evidence: Vec<EvidenceRecord>,
    ) -> GraphSnapshot {
        GraphSnapshot {
            scan: ScanRecord {
                id: "scan".to_owned(),
                root: "/tmp".to_owned(),
                status: "completed".to_owned(),
                strict: false,
                started_at: String::new(),
                completed_at: None,
                project_code_executed: false,
                error: None,
                parent_snapshot_id: None,
                source_revision: None,
                health_policy_config_digest: None,
                health_analyzer_version: None,
                health_finding_contract_version: None,
            },
            profiles: Vec::new(),
            nodes,
            sites: Vec::new(),
            edges,
            evidence,
            diagnostics: Vec::new(),
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: CoverageRecord::default(),
            profile_matrix: depgraph_store::ProfileMatrixRecord::default(),
            analysis_dependency_coverage: None,
        }
    }

    /// `src/user.rs` imports `src/model.rs` at file level and calls into it
    /// through symbols. `src/lib.rs` declares the module `other`, whose `use`
    /// item is written in `src/other.rs`.
    fn fixture() -> GraphSnapshot {
        graph(
            vec![
                file("file:lib", "src/lib.rs"),
                file("file:model", "src/model.rs"),
                file("file:user", "src/user.rs"),
                file("file:other", "src/other.rs"),
                owned("module:other", "module", "src/lib.rs"),
                owned("sym:thing", "type", "src/model.rs"),
                owned("sym:make", "symbol", "src/model.rs"),
                owned("sym:run", "symbol", "src/user.rs"),
                node("sym:declared", "symbol", json!({})),
                node("ext:std", "external_system", json!({})),
            ],
            vec![
                edge("f:use", "file:user", "file:model", "imports", "source"),
                edge("d:other", "file:lib", "module:other", "declares", "source"),
                edge(
                    "d:declared",
                    "file:model",
                    "sym:declared",
                    "declares",
                    "semantic",
                ),
                edge("s:call", "sym:run", "sym:make", "calls", "semantic"),
                edge("s:type", "sym:run", "sym:thing", "type_uses", "semantic"),
                edge(
                    "s:import",
                    "module:other",
                    "sym:thing",
                    "imports",
                    "semantic",
                ),
                edge("s:ext", "sym:make", "ext:std", "calls", "semantic"),
                edge(
                    "s:internal",
                    "sym:make",
                    "sym:thing",
                    "type_uses",
                    "semantic",
                ),
                edge("s:declared", "sym:run", "sym:declared", "calls", "semantic"),
            ],
            vec![
                evidence("f:use", "src/user.rs"),
                evidence("s:call", "src/user.rs"),
                evidence("s:type", "src/user.rs"),
                evidence("s:import", "src/other.rs"),
                evidence("s:ext", "src/model.rs"),
                evidence("s:internal", "src/model.rs"),
            ],
        )
    }

    fn rollup_with(
        snapshot: &GraphSnapshot,
        selector: &str,
        reverse: bool,
        filter: &GraphQueryFilter,
        edge_kinds: &EdgeKindFilter,
        work: &mut SymbolRollupWork,
    ) -> Result<SymbolRollup> {
        let traversal =
            traverse_bounded_filtered(snapshot, selector, false, reverse, filter, 1_000)?;
        let neighbors = traversal
            .result
            .nodes
            .iter()
            .map(|node| node.id.as_str())
            .collect::<BTreeSet<_>>();
        symbol_rollup_cancellable(
            snapshot,
            &traversal.result.root,
            reverse,
            filter,
            edge_kinds,
            &neighbors,
            work,
            &mut || false,
        )
    }

    fn rollup(snapshot: &GraphSnapshot, selector: &str, reverse: bool) -> SymbolRollup {
        rollup_with(
            snapshot,
            selector,
            reverse,
            &GraphQueryFilter::default(),
            &EdgeKindFilter::default(),
            &mut SymbolRollupWork::new(
                MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
                MAX_GRAPH_SNAPSHOT_SCAN_WORK_ITEMS,
            ),
        )
        .unwrap()
    }

    fn summary(rollup: &SymbolRollup) -> Vec<FileSummary> {
        rollup
            .files
            .iter()
            .map(|file| {
                (
                    file.path.clone(),
                    file.edge_count,
                    file.edge_kinds
                        .iter()
                        .map(|kind| (kind.kind.clone(), kind.edge_count))
                        .collect(),
                    file.edge_ids.clone(),
                    file.file_edge,
                )
            })
            .collect()
    }

    fn file_summary(
        path: &str,
        edge_count: u64,
        kinds: &[(&str, u64)],
        edge_ids: &[&str],
        file_edge: bool,
    ) -> FileSummary {
        (
            path.to_owned(),
            edge_count,
            kinds
                .iter()
                .map(|(kind, count)| ((*kind).to_owned(), *count))
                .collect(),
            edge_ids.iter().map(|id| (*id).to_owned()).collect(),
            file_edge,
        )
    }

    #[test]
    fn dependents_group_incoming_semantic_edges_by_the_file_that_writes_them() {
        let snapshot = fixture();
        let result = rollup(&snapshot, "id:file:model", true);
        assert_eq!(result.status, SymbolRollupStatus::RolledUp);
        // sym:thing and sym:make name src/model.rs; the file declares sym:declared.
        assert_eq!(result.owned_nodes, 3);
        assert_eq!(
            summary(&result),
            vec![
                file_summary("src/other.rs", 1, &[("imports", 1)], &["s:import"], false),
                // s:declared has no evidence and falls back to the owner of sym:run.
                file_summary(
                    "src/user.rs",
                    3,
                    &[("calls", 2), ("type_uses", 1)],
                    &["s:call", "s:declared", "s:type"],
                    true
                ),
            ]
        );
        assert_eq!(result.files[1].node_id, "file:user");
        assert_eq!(result.attributed_edges, 4);
        // s:internal stays inside src/model.rs.
        assert_eq!(result.unattributed_edges, 0);
        assert_eq!(result.total_files, 2);
    }

    #[test]
    fn deps_group_the_outgoing_edges_written_in_the_file_by_the_target_owner() {
        let snapshot = fixture();
        // The `use` item of module `other` is written in src/other.rs, so
        // src/other.rs depends on src/model.rs, although lib.rs owns the module.
        let other = rollup(&snapshot, "id:file:other", false);
        assert_eq!(other.owned_nodes, 0);
        assert_eq!(
            summary(&other),
            vec![file_summary(
                "src/model.rs",
                1,
                &[("imports", 1)],
                &["s:import"],
                false
            )]
        );
        let lib = rollup(&snapshot, "id:file:lib", false);
        assert_eq!(lib.owned_nodes, 1);
        assert!(lib.files.is_empty());
        assert_eq!((lib.attributed_edges, lib.unattributed_edges), (0, 0));

        // A call to an external crate has no file at its far end.
        let model = rollup(&snapshot, "id:file:model", false);
        assert!(model.files.is_empty());
        assert_eq!((model.attributed_edges, model.unattributed_edges), (0, 1));

        let user = rollup(&snapshot, "id:file:user", false);
        assert_eq!(
            summary(&user),
            vec![file_summary(
                "src/model.rs",
                3,
                &[("calls", 2), ("type_uses", 1)],
                &["s:call", "s:declared", "s:type"],
                true
            )]
        );
    }

    #[test]
    fn the_rollup_follows_the_edge_selection_and_reports_why_it_is_empty() {
        let snapshot = fixture();
        let calls = rollup_with(
            &snapshot,
            "id:file:model",
            true,
            &GraphQueryFilter::default(),
            &EdgeKindFilter::try_new(vec!["calls".to_owned()], None).unwrap(),
            &mut SymbolRollupWork::new(usize::MAX, usize::MAX),
        )
        .unwrap();
        assert_eq!(
            summary(&calls),
            vec![file_summary(
                "src/user.rs",
                2,
                &[("calls", 2)],
                &["s:call", "s:declared"],
                true
            )]
        );
        let source_only = rollup_with(
            &snapshot,
            "id:file:model",
            true,
            &GraphQueryFilter::new(
                vec!["source".to_owned()],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
            .unwrap(),
            &EdgeKindFilter::default(),
            &mut SymbolRollupWork::new(usize::MAX, usize::MAX),
        )
        .unwrap();
        assert_eq!(source_only.status, SymbolRollupStatus::RolledUp);
        assert!(source_only.files.is_empty());

        let symbol = rollup(&snapshot, "id:sym:make", true);
        assert_eq!(symbol, SymbolRollup::empty(SymbolRollupStatus::RootNotFile));

        // A syntax-only snapshot has file edges but no semantic edge.
        let mut syntax_only = fixture();
        syntax_only.edges.retain(|edge| edge.phase != "semantic");
        let result = rollup(&syntax_only, "id:file:model", true);
        assert_eq!(result.status, SymbolRollupStatus::NoSemanticEdges);
        assert_eq!(result.owned_nodes, 2);
        assert!(result.files.is_empty());
    }

    #[test]
    fn edge_ids_and_files_are_bounded() {
        let mut nodes = vec![
            file("file:model", "src/model.rs"),
            owned("sym:thing", "type", "src/model.rs"),
        ];
        let mut edges = Vec::new();
        let mut evidence_records = Vec::new();
        for index in 0..=MAX_SYMBOL_ROLLUP_FILES {
            let path = format!("src/user{index:05}.rs");
            nodes.push(file(&format!("file:user{index:05}"), &path));
            for call in 0..2 {
                let id = format!("s:{index:05}:{call}");
                edges.push(edge(&id, "sym:caller", "sym:thing", "calls", "semantic"));
                evidence_records.push(evidence(&id, &path));
            }
        }
        for call in 0..(MAX_SYMBOL_ROLLUP_EDGE_IDS + 3) {
            let id = format!("s:hub:{call:03}");
            edges.push(edge(
                &id,
                "sym:caller",
                "sym:thing",
                "type_uses",
                "semantic",
            ));
            evidence_records.push(evidence(&id, "src/user00000.rs"));
        }
        let snapshot = graph(nodes, edges, evidence_records);
        let result = rollup(&snapshot, "id:file:model", true);
        assert_eq!(result.total_files, (MAX_SYMBOL_ROLLUP_FILES + 1) as u64);
        assert_eq!(result.files.len(), MAX_SYMBOL_ROLLUP_FILES);
        let hub = &result.files[0];
        assert_eq!(hub.path, "src/user00000.rs");
        assert_eq!(hub.edge_count, (MAX_SYMBOL_ROLLUP_EDGE_IDS + 5) as u64);
        assert_eq!(hub.edge_ids.len(), MAX_SYMBOL_ROLLUP_EDGE_IDS);
        assert_eq!(hub.edge_ids[0], "s:00000:0");
    }

    /// The scans visit every node, edge, and evidence record of the snapshot
    /// and count against the fixed snapshot scan ceiling, like the path-step
    /// scans of Issue #620. A snapshot whose scans exceed the request budget
    /// still rolls up within the default budgets, with the request work of the
    /// small graph.
    #[test]
    fn snapshot_wide_scans_count_against_the_scan_ceiling_not_the_request_work() {
        const UNRELATED_NODES: usize = 200_000;
        const UNRELATED_EDGES: usize = 300_000;
        const UNRELATED_EVIDENCE: usize = 600_000;
        let small = fixture();
        let mut large = small.clone();
        large.nodes.extend(std::iter::repeat_n(
            node("", "symbol", json!({"source_path": "src/unrelated.rs"})),
            UNRELATED_NODES,
        ));
        large.edges.extend(std::iter::repeat_n(
            edge("", "", "", "calls", "semantic"),
            UNRELATED_EDGES,
        ));
        large.evidence.extend(std::iter::repeat_n(
            evidence("", "src/unrelated.rs"),
            UNRELATED_EVIDENCE,
        ));

        let run = |snapshot: &GraphSnapshot, reverse: bool, maximum: usize, scan_maximum: usize| {
            let mut work = SymbolRollupWork::new(maximum, scan_maximum);
            let result = rollup_with(
                snapshot,
                "id:file:model",
                reverse,
                &GraphQueryFilter::default(),
                &EdgeKindFilter::default(),
                &mut work,
            );
            (result, work.used(), work.scanned())
        };
        for reverse in [true, false] {
            let (expected, small_used, _) = run(
                &small,
                reverse,
                MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
                MAX_GRAPH_SNAPSHOT_SCAN_WORK_ITEMS,
            );
            let (actual, used, scanned) = run(
                &large,
                reverse,
                MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
                MAX_GRAPH_SNAPSHOT_SCAN_WORK_ITEMS,
            );
            assert_eq!(actual.unwrap(), expected.unwrap());
            assert!(
                scanned > MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
                "{scanned}"
            );
            assert_eq!(used, small_used, "request work");

            // Exactly the measured work passes; one item less under either
            // budget fails and names that budget.
            assert!(run(&large, reverse, used, scanned).0.is_ok());
            for (maximum, scan_maximum, exhausted) in [
                (used - 1, scanned, used - 1),
                (used, scanned - 1, scanned - 1),
            ] {
                let error = run(&large, reverse, maximum, scan_maximum)
                    .0
                    .expect_err("one item under either budget rejects the rollup");
                assert_eq!(preprocessing_work_limit(&error), Some(exhausted));
            }
        }
    }

    #[test]
    fn the_rollup_is_cancellable() {
        let snapshot = fixture();
        let traversal = traverse_bounded_filtered(
            &snapshot,
            "id:file:model",
            false,
            true,
            &GraphQueryFilter::default(),
            1_000,
        )
        .unwrap();
        let mut calls = 0;
        let error = symbol_rollup_cancellable(
            &snapshot,
            &traversal.result.root,
            true,
            &GraphQueryFilter::default(),
            &EdgeKindFilter::default(),
            &BTreeSet::new(),
            &mut SymbolRollupWork::new(usize::MAX, usize::MAX),
            &mut || {
                calls += 1;
                calls > 5
            },
        )
        .expect_err("cancellation stops the rollup");
        assert!(crate::query::is_cancelled(&error));
    }
}
