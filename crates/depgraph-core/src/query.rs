use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use anyhow::{Context, Result, bail};
use depgraph_protocol::Condition;
use depgraph_store::{
    DiagnosticRecord, EdgeRecord, EvidenceRecord, GraphSnapshot, NodeRecord, PhaseCoverageRecord,
    ProfileCorrelationRecord, ProfileMatrixRecord, SiteRecord,
    phase_coverage_for_effective_profile, runtime_context_for_edge,
};
use petgraph::{algo::tarjan_scc, graph::DiGraph};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleLevel {
    Package,
    File,
    Symbol,
    Type,
    Route,
}

impl CycleLevel {
    fn node_kind(self) -> &'static str {
        match self {
            Self::Package => "package_instance",
            Self::File => "file",
            Self::Symbol => "symbol",
            Self::Type => "type",
            Self::Route => "route",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TraversalResult {
    pub root: NodeRecord,
    pub nodes: Vec<NodeRecord>,
    pub edges: Vec<EdgeRecord>,
    pub steps: Vec<PathStep>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathStep {
    pub edge: EdgeRecord,
    pub condition_text: String,
    pub evidence: Vec<EvidenceRecord>,
    pub effective_profile_id: Option<String>,
    pub correlation_status: Option<String>,
    pub observed_difference_reasons: Vec<String>,
    pub phase_coverage: BTreeMap<String, PhaseCoverageRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WhyResult {
    pub from: NodeRecord,
    pub to: NodeRecord,
    pub path_found: bool,
    pub steps: Vec<PathStep>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CycleResult {
    pub level: String,
    pub node_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnresolvedResult {
    pub site: SiteRecord,
    pub evidence: Vec<EvidenceRecord>,
    pub effective_profile_id: Option<String>,
    pub correlation_status: Option<String>,
    pub observed_difference_reasons: Vec<String>,
    pub phase_coverage: BTreeMap<String, PhaseCoverageRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphQueryFilter {
    pub phases: Vec<String>,
    pub profiles: Vec<String>,
    pub sessions: Vec<String>,
    pub environments: Vec<String>,
}

impl GraphQueryFilter {
    pub fn new(
        phases: Vec<String>,
        profiles: Vec<String>,
        sessions: Vec<String>,
        environments: Vec<String>,
    ) -> Result<Self> {
        Ok(Self {
            phases: normalize_query_filter("phase", phases)?,
            profiles: normalize_query_filter("profile", profiles)?,
            sessions: normalize_query_filter("session", sessions)?,
            environments: normalize_query_filter("environment", environments)?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.phases.is_empty()
            && self.profiles.is_empty()
            && self.sessions.is_empty()
            && self.environments.is_empty()
    }

    pub fn matches_edge(&self, snapshot: &GraphSnapshot, edge: &EdgeRecord) -> bool {
        if !self.phases.is_empty() && self.phases.binary_search(&edge.phase).is_err() {
            return false;
        }
        if !self.profiles.is_empty() && self.profiles.binary_search(&edge.profile_id).is_err() {
            return false;
        }
        if self.sessions.is_empty() && self.environments.is_empty() {
            return true;
        }
        if edge.phase != "runtime" {
            return false;
        }
        let context = runtime_context_for_edge(snapshot, edge);
        let session_matches = self.sessions.is_empty()
            || context
                .session_ids
                .iter()
                .chain(context.source_session_ids.iter())
                .any(|value| self.sessions.binary_search(value).is_ok());
        let environment_matches = self.environments.is_empty()
            || context
                .environment_names
                .iter()
                .chain(context.runtimes.iter())
                .chain(context.regions.iter())
                .any(|value| self.environments.binary_search(value).is_ok());
        session_matches && environment_matches
    }

    pub fn matches_evidence(&self, evidence: &EvidenceRecord) -> bool {
        if evidence.kind != "runtime" {
            return self.sessions.is_empty() && self.environments.is_empty();
        }
        let session_matches = self.sessions.is_empty()
            || ["session_id", "source_session_id"].iter().any(|key| {
                evidence
                    .properties
                    .get(key)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| self.sessions.iter().any(|item| item == value))
            });
        let environment_matches = self.environments.is_empty()
            || evidence
                .properties
                .get("environment")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|environment| {
                    ["name", "runtime", "region"].iter().any(|key| {
                        environment
                            .get(*key)
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|value| self.environments.iter().any(|item| item == value))
                    })
                });
        session_matches && environment_matches
    }

    pub fn matches_diagnostic(&self, diagnostic: &DiagnosticRecord) -> bool {
        let string_property_matches = |key: &str, values: &[String]| {
            values.is_empty()
                || diagnostic
                    .properties
                    .get(key)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| values.iter().any(|item| item == value))
        };
        let phase_matches = string_property_matches("phase", &self.phases);
        let profile_matches = string_property_matches("profile_id", &self.profiles);
        let session_matches = self.sessions.is_empty()
            || ["session_id", "source_session_id"].iter().any(|key| {
                diagnostic
                    .properties
                    .get(key)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| self.sessions.iter().any(|item| item == value))
            });
        let environment_matches = self.environments.is_empty()
            || diagnostic
                .properties
                .get("environment")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|environment| {
                    ["name", "runtime", "region"].iter().any(|key| {
                        environment
                            .get(*key)
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|value| self.environments.iter().any(|item| item == value))
                    })
                });
        phase_matches && profile_matches && session_matches && environment_matches
    }
}

fn normalize_query_filter(name: &str, values: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            bail!("{name} filter must not be empty");
        }
        normalized.push(value.to_owned());
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

pub fn resolve_selector(snapshot: &GraphSnapshot, selector: &str) -> Result<NodeRecord> {
    let (kind, query) = selector
        .split_once(':')
        .filter(|(prefix, _)| {
            matches!(
                *prefix,
                "id" | "path" | "package" | "route" | "symbol" | "type"
            )
        })
        .unwrap_or(("bare", selector));
    let query = query.trim();
    if query.is_empty() {
        bail!("selector must not be empty");
    }

    let mut exact = Vec::new();
    let mut partial = Vec::new();
    for node in &snapshot.nodes {
        let kind_matches = match kind {
            "package" => node.kind == "package_instance",
            "route" => node.kind == "route",
            "path" => node.kind == "file",
            "symbol" => node.kind == "symbol",
            "type" => node.kind == "type",
            _ => true,
        };
        if !kind_matches {
            continue;
        }
        let values = [&node.id, &node.locator, &node.display_name];
        let path_matches = kind == "path"
            && node
                .properties
                .get("path")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|path| path == query);
        let resolver_identity_matches = matches!(kind, "symbol" | "type")
            && node
                .properties
                .get("canonical_identity")
                .and_then(|identity| identity.get("resolver_identity"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|identity| identity == query);
        let exact_match = if kind == "id" {
            node.id == query
        } else {
            path_matches
                || resolver_identity_matches
                || values.iter().any(|value| value.as_str() == query)
        };
        if exact_match {
            exact.push(node.clone());
        } else if values.iter().any(|value| value.contains(query)) {
            partial.push(node.clone());
        }
    }
    choose_unique(
        selector,
        if exact.is_empty() && kind != "id" {
            partial
        } else {
            exact
        },
    )
}

fn choose_unique(selector: &str, mut candidates: Vec<NodeRecord>) -> Result<NodeRecord> {
    candidates.sort_by(|left, right| left.id.cmp(&right.id));
    match candidates.len() {
        0 => bail!("selector {selector:?} did not match any node"),
        1 => Ok(candidates.remove(0)),
        _ => {
            let choices = candidates
                .iter()
                .take(10)
                .map(|node| format!("{} ({}, id:{})", node.locator, node.kind, node.id))
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "selector {selector:?} is ambiguous; select a candidate with id:<stable-id>. candidates: {choices}"
            )
        }
    }
}

pub fn traverse(
    snapshot: &GraphSnapshot,
    selector: &str,
    transitive: bool,
    reverse: bool,
) -> Result<TraversalResult> {
    traverse_filtered(
        snapshot,
        selector,
        transitive,
        reverse,
        &GraphQueryFilter::default(),
    )
}

pub fn traverse_filtered(
    snapshot: &GraphSnapshot,
    selector: &str,
    transitive: bool,
    reverse: bool,
    filter: &GraphQueryFilter,
) -> Result<TraversalResult> {
    let root = resolve_selector(snapshot, selector)?;
    let node_map = node_map(snapshot);
    let adjacency = adjacency(snapshot, reverse, filter);
    let mut queue = VecDeque::from([root.id.clone()]);
    let mut visited = BTreeSet::from([root.id.clone()]);
    let mut selected_edges = BTreeMap::new();

    while let Some(node_id) = queue.pop_front() {
        if let Some(edges) = adjacency.get(&node_id) {
            for edge in edges {
                selected_edges.insert(edge.id.clone(), (*edge).clone());
                let next = if reverse { &edge.source } else { &edge.target };
                if visited.insert(next.clone()) && transitive {
                    queue.push_back(next.clone());
                }
            }
        }
        if !transitive {
            break;
        }
    }

    let nodes = visited
        .iter()
        .filter(|id| *id != &root.id)
        .filter_map(|id| node_map.get(id).cloned())
        .collect();
    let edges: Vec<_> = selected_edges.into_values().collect();
    let evidence = edge_evidence_map_filtered(snapshot, filter);
    let correlations = edge_correlation_map(&snapshot.profile_matrix);
    let steps = edges
        .iter()
        .map(|edge| {
            path_step(
                snapshot,
                edge,
                &evidence,
                correlations.get(edge.id.as_str()).copied(),
            )
        })
        .collect();
    Ok(TraversalResult {
        root,
        nodes,
        edges,
        steps,
    })
}

pub fn why(snapshot: &GraphSnapshot, from: &str, to: &str) -> Result<WhyResult> {
    why_filtered(snapshot, from, to, &GraphQueryFilter::default())
}

pub fn why_filtered(
    snapshot: &GraphSnapshot,
    from: &str,
    to: &str,
    filter: &GraphQueryFilter,
) -> Result<WhyResult> {
    let from = resolve_selector(snapshot, from)?;
    let to = resolve_selector(snapshot, to)?;
    if from.id == to.id {
        return Ok(WhyResult {
            from,
            to,
            path_found: true,
            steps: Vec::new(),
        });
    }
    let adjacency = adjacency(snapshot, false, filter);
    let mut queue = VecDeque::from([from.id.clone()]);
    let mut seen = BTreeSet::from([from.id.clone()]);
    let mut predecessor: HashMap<String, &EdgeRecord> = HashMap::new();
    while let Some(node_id) = queue.pop_front() {
        if let Some(edges) = adjacency.get(&node_id) {
            for edge in edges {
                if seen.insert(edge.target.clone()) {
                    predecessor.insert(edge.target.clone(), edge);
                    if edge.target == to.id {
                        queue.clear();
                        break;
                    }
                    queue.push_back(edge.target.clone());
                }
            }
        }
    }
    if !predecessor.contains_key(&to.id) {
        return Ok(WhyResult {
            from,
            to,
            path_found: false,
            steps: Vec::new(),
        });
    }
    let evidence_map = edge_evidence_map_filtered(snapshot, filter);
    let correlations = edge_correlation_map(&snapshot.profile_matrix);
    let mut current = to.id.clone();
    let mut reversed = Vec::new();
    while current != from.id {
        let edge = predecessor
            .get(&current)
            .with_context(|| format!("path reconstruction failed at {current}"))?;
        reversed.push(path_step(
            snapshot,
            edge,
            &evidence_map,
            correlations.get(edge.id.as_str()).copied(),
        ));
        current = edge.source.clone();
    }
    reversed.reverse();
    Ok(WhyResult {
        from,
        to,
        path_found: true,
        steps: reversed,
    })
}

pub fn cycles(snapshot: &GraphSnapshot, level: CycleLevel) -> Vec<CycleResult> {
    let allowed: BTreeSet<_> = snapshot
        .nodes
        .iter()
        .filter(|node| node.kind == level.node_kind())
        .map(|node| node.id.clone())
        .collect();
    let mut graph = DiGraph::<String, ()>::new();
    let mut indexes = BTreeMap::new();
    for id in &allowed {
        indexes.insert(id.clone(), graph.add_node(id.clone()));
    }
    let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for edge in &snapshot.edges {
        if allowed.contains(&edge.source) && allowed.contains(&edge.target) {
            graph.add_edge(indexes[&edge.source], indexes[&edge.target], ());
            adjacency
                .entry(edge.source.clone())
                .or_default()
                .push(edge.target.clone());
        }
    }
    for targets in adjacency.values_mut() {
        targets.sort();
        targets.dedup();
    }
    let mut results = Vec::new();
    for component in tarjan_scc(&graph) {
        let mut ids: Vec<_> = component
            .iter()
            .map(|index| graph[*index].clone())
            .collect();
        ids.sort();
        let self_loop = ids.len() == 1
            && adjacency
                .get(&ids[0])
                .is_some_and(|targets| targets.contains(&ids[0]));
        if ids.len() < 2 && !self_loop {
            continue;
        }
        let component_set: BTreeSet<_> = ids.iter().cloned().collect();
        let cycle =
            representative_cycle(&ids[0], &component_set, &adjacency).unwrap_or_else(|| {
                let mut fallback = ids.clone();
                fallback.push(ids[0].clone());
                fallback
            });
        results.push(CycleResult {
            level: level.node_kind().to_owned(),
            node_ids: cycle,
        });
    }
    results.sort_by(|left, right| left.node_ids.cmp(&right.node_ids));
    results
}

fn representative_cycle(
    start: &str,
    component: &BTreeSet<String>,
    adjacency: &BTreeMap<String, Vec<String>>,
) -> Option<Vec<String>> {
    let mut queue = VecDeque::new();
    let mut predecessor: HashMap<String, String> = HashMap::new();
    for next in adjacency.get(start).into_iter().flatten() {
        if !component.contains(next) {
            continue;
        }
        if next == start {
            return Some(vec![start.to_owned(), start.to_owned()]);
        }
        predecessor.insert(next.clone(), start.to_owned());
        queue.push_back(next.clone());
    }
    while let Some(node) = queue.pop_front() {
        for next in adjacency.get(&node).into_iter().flatten() {
            if !component.contains(next) {
                continue;
            }
            if next == start {
                let mut path = vec![node.clone()];
                let mut current = node;
                while current != start {
                    current = predecessor.get(&current)?.clone();
                    path.push(current.clone());
                }
                path.reverse();
                path.push(start.to_owned());
                return Some(path);
            }
            if !predecessor.contains_key(next) {
                predecessor.insert(next.clone(), node.clone());
                queue.push_back(next.clone());
            }
        }
    }
    None
}

pub fn unresolved(snapshot: &GraphSnapshot) -> Vec<UnresolvedResult> {
    let evidence = snapshot
        .evidence
        .iter()
        .filter(|item| item.owner_type == "site")
        .fold(
            BTreeMap::<String, Vec<EvidenceRecord>>::new(),
            |mut map, item| {
                map.entry(item.owner_id.clone())
                    .or_default()
                    .push(item.clone());
                map
            },
        );
    let correlations = site_correlation_map(&snapshot.profile_matrix);
    snapshot
        .sites
        .iter()
        .filter(|site| site.resolution_status == "unresolved")
        .map(|site| {
            let correlation = correlations.get(site.id.as_str()).copied();
            UnresolvedResult {
                site: site.clone(),
                evidence: evidence.get(&site.id).cloned().unwrap_or_default(),
                effective_profile_id: correlation
                    .map(|correlation| correlation.effective_profile_id.clone()),
                correlation_status: correlation.map(|correlation| correlation.status.clone()),
                observed_difference_reasons: correlation
                    .map(|correlation| correlation.difference_reasons.clone())
                    .unwrap_or_default(),
                phase_coverage: correlation
                    .map(|correlation| {
                        phase_coverage_for_effective_profile(
                            &snapshot.profile_matrix,
                            &correlation.effective_profile_id,
                        )
                    })
                    .unwrap_or_default(),
            }
        })
        .collect()
}

fn edge_correlation_map(matrix: &ProfileMatrixRecord) -> BTreeMap<&str, &ProfileCorrelationRecord> {
    matrix
        .correlations
        .iter()
        .flat_map(|correlation| {
            correlation
                .edge_ids_by_phase
                .values()
                .flatten()
                .map(move |edge_id| (edge_id.as_str(), correlation))
        })
        .collect()
}

fn site_correlation_map(matrix: &ProfileMatrixRecord) -> BTreeMap<&str, &ProfileCorrelationRecord> {
    matrix
        .correlations
        .iter()
        .flat_map(|correlation| {
            correlation
                .site_ids_by_phase
                .values()
                .flatten()
                .map(move |site_id| (site_id.as_str(), correlation))
        })
        .collect()
}

fn path_step(
    snapshot: &GraphSnapshot,
    edge: &EdgeRecord,
    evidence: &BTreeMap<String, Vec<EvidenceRecord>>,
    correlation: Option<&ProfileCorrelationRecord>,
) -> PathStep {
    PathStep {
        edge: edge.clone(),
        condition_text: render_condition(&edge.condition),
        evidence: evidence.get(&edge.id).cloned().unwrap_or_default(),
        effective_profile_id: correlation
            .map(|correlation| correlation.effective_profile_id.clone()),
        correlation_status: correlation.map(|correlation| correlation.status.clone()),
        observed_difference_reasons: correlation
            .map(|correlation| correlation.difference_reasons.clone())
            .unwrap_or_default(),
        phase_coverage: correlation
            .map(|correlation| {
                phase_coverage_for_effective_profile(
                    &snapshot.profile_matrix,
                    &correlation.effective_profile_id,
                )
            })
            .unwrap_or_default(),
    }
}

pub(crate) fn path_steps_for_edges_filtered(
    snapshot: &GraphSnapshot,
    edges: &[EdgeRecord],
    filter: &GraphQueryFilter,
) -> Vec<PathStep> {
    let evidence = edge_evidence_map_filtered(snapshot, filter);
    let correlations = edge_correlation_map(&snapshot.profile_matrix);
    edges
        .iter()
        .map(|edge| {
            path_step(
                snapshot,
                edge,
                &evidence,
                correlations.get(edge.id.as_str()).copied(),
            )
        })
        .collect()
}

pub fn render_condition(value: &serde_json::Value) -> String {
    serde_json::from_value::<Condition>(value.clone())
        .map(|condition| condition.render())
        .unwrap_or_else(|_| value.to_string())
}

fn node_map(snapshot: &GraphSnapshot) -> BTreeMap<String, NodeRecord> {
    snapshot
        .nodes
        .iter()
        .map(|node| (node.id.clone(), node.clone()))
        .collect()
}

fn edge_evidence_map_filtered(
    snapshot: &GraphSnapshot,
    filter: &GraphQueryFilter,
) -> BTreeMap<String, Vec<EvidenceRecord>> {
    let mut evidence = snapshot
        .evidence
        .iter()
        .filter(|item| item.owner_type == "edge" && filter.matches_evidence(item))
        .fold(
            BTreeMap::<String, Vec<EvidenceRecord>>::new(),
            |mut map, item| {
                map.entry(item.owner_id.clone())
                    .or_default()
                    .push(item.clone());
                map
            },
        );
    for records in evidence.values_mut() {
        records.sort_by(|left, right| {
            left.ordinal
                .cmp(&right.ordinal)
                .then(left.kind.cmp(&right.kind))
                .then(left.path.cmp(&right.path))
                .then(left.start_line.cmp(&right.start_line))
                .then(left.start_column.cmp(&right.start_column))
                .then(left.end_line.cmp(&right.end_line))
                .then(left.end_column.cmp(&right.end_column))
                .then(left.extractor.cmp(&right.extractor))
                .then(left.extractor_version.cmp(&right.extractor_version))
                .then(left.detail.cmp(&right.detail))
                .then_with(|| {
                    left.properties
                        .to_string()
                        .cmp(&right.properties.to_string())
                })
        });
    }
    evidence
}

fn adjacency<'a>(
    snapshot: &'a GraphSnapshot,
    reverse: bool,
    filter: &GraphQueryFilter,
) -> BTreeMap<String, Vec<&'a EdgeRecord>> {
    let mut adjacency = BTreeMap::<String, Vec<&EdgeRecord>>::new();
    for edge in snapshot
        .edges
        .iter()
        .filter(|edge| filter.matches_edge(snapshot, edge))
    {
        let key = if reverse { &edge.target } else { &edge.source };
        adjacency.entry(key.clone()).or_default().push(edge);
    }
    for edges in adjacency.values_mut() {
        edges.sort_by(|left, right| {
            let left_target = if reverse { &left.source } else { &left.target };
            let right_target = if reverse {
                &right.source
            } else {
                &right.target
            };
            left_target.cmp(right_target).then(left.id.cmp(&right.id))
        });
    }
    adjacency
}

#[cfg(test)]
mod tests {
    use super::*;
    use depgraph_store::{CoverageRecord, ScanRecord};
    use serde_json::json;

    fn node(id: &str, kind: &str, locator: &str, display_name: &str) -> NodeRecord {
        NodeRecord {
            id: id.to_owned(),
            kind: kind.to_owned(),
            locator: locator.to_owned(),
            display_name: display_name.to_owned(),
            properties: json!({}),
        }
    }

    fn evidence(owner_type: &str, owner_id: &str, ordinal: i64, path: &str) -> EvidenceRecord {
        EvidenceRecord {
            owner_type: owner_type.to_owned(),
            owner_id: owner_id.to_owned(),
            ordinal,
            kind: "semantic".to_owned(),
            extractor: "go-types".to_owned(),
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

    fn snapshot() -> GraphSnapshot {
        let nodes = ["a", "b", "c"]
            .into_iter()
            .map(|id| NodeRecord {
                id: id.to_owned(),
                kind: "file".to_owned(),
                locator: format!("file://{id}"),
                display_name: id.to_owned(),
                properties: json!({}),
            })
            .collect();
        let edges = [("a", "b"), ("b", "c"), ("c", "a")]
            .into_iter()
            .enumerate()
            .map(|(index, (source, target))| EdgeRecord {
                id: format!("e{index}"),
                site_id: Some(format!("s{index}")),
                source: source.to_owned(),
                target: target.to_owned(),
                kind: "imports".to_owned(),
                phase: "syntax".to_owned(),
                environment: "any".to_owned(),
                profile_id: "test".to_owned(),
                resolution_status: "resolved".to_owned(),
                precision: "exact".to_owned(),
                condition: json!({"op":"all","conditions":[]}),
                generated: false,
            })
            .collect();
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
            },
            profiles: Vec::new(),
            nodes,
            sites: Vec::new(),
            edges,
            evidence: Vec::new(),
            diagnostics: Vec::new(),
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: CoverageRecord::default(),
            profile_matrix: depgraph_store::ProfileMatrixRecord::default(),
        }
    }

    #[test]
    fn shortest_path_is_deterministic() -> Result<()> {
        let result = why(&snapshot(), "id:a", "id:c")?;
        assert!(result.path_found);
        assert_eq!(result.steps.len(), 2);
        assert_eq!(result.steps[0].edge.id, "e0");
        Ok(())
    }

    #[test]
    fn unreachable_nodes_are_a_deterministic_query_result() -> Result<()> {
        let mut disconnected = snapshot();
        disconnected.edges.clear();
        let result = why(&disconnected, "id:c", "id:a")?;
        assert!(!result.path_found);
        assert!(result.steps.is_empty());
        assert_eq!(result.from.id, "c");
        assert_eq!(result.to.id, "a");
        Ok(())
    }

    #[test]
    fn finds_representative_file_cycle() {
        let result = cycles(&snapshot(), CycleLevel::File);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].node_ids.first(), result[0].node_ids.last());
    }

    #[test]
    fn semantic_selectors_only_match_their_node_kind() -> Result<()> {
        let mut graph = snapshot();
        let mut type_node = node(
            "type:sha256:222",
            "type",
            "example.com/module.Common",
            "Common",
        );
        type_node.properties = json!({
            "canonical_identity": {"resolver_identity": 42}
        });
        graph.nodes = vec![
            node(
                "symbol:sha256:111",
                "symbol",
                "example.com/module.Common",
                "Common",
            ),
            type_node,
            node("file:sha256:333", "file", "file://Common", "Common"),
        ];

        assert_eq!(
            resolve_selector(&graph, "symbol:Common")?.id,
            "symbol:sha256:111"
        );
        assert_eq!(
            resolve_selector(&graph, "type:Common")?.id,
            "type:sha256:222"
        );
        assert_eq!(
            resolve_selector(&graph, "id:symbol:sha256:111")?.kind,
            "symbol"
        );
        Ok(())
    }

    #[test]
    fn semantic_selector_prefers_exact_resolver_identity_over_locator_partial_matches() -> Result<()>
    {
        let mut graph = snapshot();
        let symbol_resolver = "example.com/semantic/model.InferredCall";
        let type_resolver = "example.com/semantic/model.GenericMatcher";
        let semantic_node = |id: &str, kind: &str, resolver: &str, display_name: &str| NodeRecord {
            id: id.to_owned(),
            kind: kind.to_owned(),
            locator: format!("go-{kind}:{resolver}"),
            display_name: display_name.to_owned(),
            properties: json!({
                "language": "go",
                "package_locator": "go-package:example.com/semantic/model",
                "canonical_identity": {
                    "language": "go",
                    "package_locator": "go-package:example.com/semantic/model",
                    "identity_kind": "named",
                    "resolver_identity": resolver,
                }
            }),
        };
        graph.nodes = vec![
            semantic_node("symbol:origin", "symbol", symbol_resolver, "InferredCall"),
            semantic_node(
                "symbol:instance",
                "symbol",
                &format!("{symbol_resolver}[int]"),
                "InferredCall[int]",
            ),
            semantic_node("type:origin", "type", type_resolver, "GenericMatcher"),
            semantic_node(
                "type:instance",
                "type",
                &format!("{type_resolver}[string]"),
                "GenericMatcher[string]",
            ),
        ];

        assert_eq!(
            resolve_selector(&graph, &format!("symbol:{symbol_resolver}"))?.id,
            "symbol:origin"
        );
        assert_eq!(
            resolve_selector(&graph, &format!("type:{type_resolver}"))?.id,
            "type:origin"
        );
        Ok(())
    }

    #[test]
    fn legacy_selector_prefixes_remain_compatible() -> Result<()> {
        let mut graph = snapshot();
        let mut file = node("file:id", "file", "file://src/lib.rs", "lib.rs");
        file.properties = json!({"path": "src/lib.rs"});
        graph.nodes = vec![
            file,
            node("package:id", "package_instance", "pkg://demo", "demo"),
            node(
                "route:id",
                "route",
                "route:///products/$id",
                "/products/$id",
            ),
        ];

        assert_eq!(resolve_selector(&graph, "id:file:id")?.id, "file:id");
        assert_eq!(resolve_selector(&graph, "path:src/lib.rs")?.id, "file:id");
        assert_eq!(resolve_selector(&graph, "package:demo")?.id, "package:id");
        assert_eq!(
            resolve_selector(&graph, "route:/products/$id")?.id,
            "route:id"
        );
        Ok(())
    }

    #[test]
    fn ambiguous_selector_lists_stable_ids_in_deterministic_order() {
        let mut graph = snapshot();
        graph.nodes = vec![
            node("symbol:z", "symbol", "go://z.Shared", "Shared"),
            node("symbol:a", "symbol", "go://a.Shared", "Shared"),
        ];

        let message = resolve_selector(&graph, "symbol:Shared")
            .expect_err("selector must be ambiguous")
            .to_string();
        assert_eq!(
            message,
            "selector \"symbol:Shared\" is ambiguous; select a candidate with id:<stable-id>. candidates: go://a.Shared (symbol, id:symbol:a), go://z.Shared (symbol, id:symbol:z)"
        );
    }

    #[test]
    fn traversal_steps_include_only_owned_edge_evidence_in_canonical_order() -> Result<()> {
        let mut graph = snapshot();
        graph.edges[0].phase = "semantic".to_owned();
        graph.evidence = vec![
            evidence("edge", "e0", 2, "second.go"),
            evidence("site", "e0", 0, "site.go"),
            evidence("edge", "e1", 0, "other-edge.go"),
            evidence("edge", "e0", 0, "first.go"),
        ];

        let deps = traverse(&graph, "id:a", false, false)?;
        assert_eq!(deps.edges.len(), 1);
        assert_eq!(deps.steps.len(), 1);
        assert_eq!(deps.steps[0].edge.id, "e0");
        assert_eq!(
            deps.steps[0]
                .evidence
                .iter()
                .map(|item| (item.ordinal, item.path.as_str()))
                .collect::<Vec<_>>(),
            vec![(0, "first.go"), (2, "second.go")]
        );

        let dependents = traverse(&graph, "id:b", false, true)?;
        assert_eq!(dependents.steps.len(), 1);
        assert_eq!(dependents.steps[0].edge.id, "e0");
        assert_eq!(dependents.steps[0].evidence.len(), 2);
        Ok(())
    }

    #[test]
    fn diagnostic_filters_match_source_session_phase_profile_and_environment() -> Result<()> {
        let diagnostic = DiagnosticRecord {
            ordinal: 0,
            id: "diagnostic:runtime".to_owned(),
            severity: "warning".to_owned(),
            code: "RUNTIME_TARGET_UNMATCHED".to_owned(),
            message: "unmatched".to_owned(),
            path: None,
            adapter: Some("runtime-trace".to_owned()),
            start_line: None,
            start_column: None,
            end_line: None,
            end_column: None,
            properties: json!({
                "session_id":"runtime-session:stable",
                "source_session_id":"collector-session",
                "phase":"runtime",
                "profile_id":"profile:runtime",
                "environment":{
                    "name":"production",
                    "runtime":"nodejs-24",
                    "region":"test-region-1"
                }
            }),
        };
        let matching = GraphQueryFilter::new(
            vec!["runtime".to_owned()],
            vec!["profile:runtime".to_owned()],
            vec!["collector-session".to_owned()],
            vec!["nodejs-24".to_owned()],
        )?;
        assert!(matching.matches_diagnostic(&diagnostic));
        assert!(
            !GraphQueryFilter::new(vec!["build".to_owned()], Vec::new(), Vec::new(), Vec::new())?
                .matches_diagnostic(&diagnostic)
        );
        assert!(
            !GraphQueryFilter::new(
                Vec::new(),
                Vec::new(),
                vec!["another-session".to_owned()],
                Vec::new()
            )?
            .matches_diagnostic(&diagnostic)
        );
        Ok(())
    }

    #[test]
    fn environment_filter_is_scoped_to_runtime_evidence_context() -> Result<()> {
        let mut graph = snapshot();
        graph.edges[0].environment = "production".to_owned();
        let filter = GraphQueryFilter::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec!["production".to_owned()],
        )?;
        assert!(!filter.matches_edge(&graph, &graph.edges[0]));

        graph.edges[0].phase = "runtime".to_owned();
        assert!(!filter.matches_edge(&graph, &graph.edges[0]));
        let mut runtime_evidence = evidence("edge", "e0", 0, "");
        runtime_evidence.kind = "runtime".to_owned();
        runtime_evidence.properties = json!({
            "session_id":"runtime-session",
            "source_session_id":"collector-session",
            "environment":{"name":"production"}
        });
        graph.evidence.push(runtime_evidence);
        assert!(filter.matches_edge(&graph, &graph.edges[0]));
        Ok(())
    }

    #[test]
    fn representative_symbol_cycle_is_deterministic() {
        let mut graph = snapshot();
        for node in &mut graph.nodes {
            node.kind = "symbol".to_owned();
        }
        let expected_node_ids = vec![
            "a".to_owned(),
            "b".to_owned(),
            "c".to_owned(),
            "a".to_owned(),
        ];

        let first = cycles(&graph, CycleLevel::Symbol);
        graph.edges.reverse();
        let reversed = cycles(&graph, CycleLevel::Symbol);

        assert_eq!(first[0].level, "symbol");
        assert_eq!(first[0].node_ids, expected_node_ids);
        assert_eq!(reversed[0].node_ids, expected_node_ids);
    }
}
