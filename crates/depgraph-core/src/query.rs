use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use anyhow::{Context, Result, bail};
use depgraph_protocol::Condition;
use depgraph_store::{EdgeRecord, EvidenceRecord, GraphSnapshot, NodeRecord, SiteRecord};
use petgraph::{algo::tarjan_scc, graph::DiGraph};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleLevel {
    Package,
    File,
    Route,
}

impl CycleLevel {
    fn node_kind(self) -> &'static str {
        match self {
            Self::Package => "package_instance",
            Self::File => "file",
            Self::Route => "route",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TraversalResult {
    pub root: NodeRecord,
    pub nodes: Vec<NodeRecord>,
    pub edges: Vec<EdgeRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PathStep {
    pub edge: EdgeRecord,
    pub condition_text: String,
    pub evidence: Vec<EvidenceRecord>,
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
}

pub fn resolve_selector(snapshot: &GraphSnapshot, selector: &str) -> Result<NodeRecord> {
    let (kind, query) = selector
        .split_once(':')
        .filter(|(prefix, _)| matches!(*prefix, "id" | "path" | "package" | "route"))
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
        let exact_match = if kind == "id" {
            node.id == query
        } else {
            path_matches || values.iter().any(|value| value.as_str() == query)
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
                .map(|node| format!("{} ({})", node.locator, node.kind))
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "selector {selector:?} is ambiguous; use an explicit prefix or stable id. candidates: {choices}"
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
    let root = resolve_selector(snapshot, selector)?;
    let node_map = node_map(snapshot);
    let adjacency = adjacency(snapshot, reverse);
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
    Ok(TraversalResult {
        root,
        nodes,
        edges: selected_edges.into_values().collect(),
    })
}

pub fn why(snapshot: &GraphSnapshot, from: &str, to: &str) -> Result<WhyResult> {
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
    let adjacency = adjacency(snapshot, false);
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
    let evidence_map = snapshot
        .evidence
        .iter()
        .filter(|item| item.owner_type == "edge")
        .fold(
            BTreeMap::<String, Vec<EvidenceRecord>>::new(),
            |mut map, item| {
                map.entry(item.owner_id.clone())
                    .or_default()
                    .push(item.clone());
                map
            },
        );
    let mut current = to.id.clone();
    let mut reversed = Vec::new();
    while current != from.id {
        let edge = predecessor
            .get(&current)
            .with_context(|| format!("path reconstruction failed at {current}"))?;
        reversed.push(PathStep {
            edge: (*edge).clone(),
            condition_text: render_condition(&edge.condition),
            evidence: evidence_map.get(&edge.id).cloned().unwrap_or_default(),
        });
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
    snapshot
        .sites
        .iter()
        .filter(|site| site.resolution_status == "unresolved")
        .map(|site| UnresolvedResult {
            site: site.clone(),
            evidence: evidence.get(&site.id).cloned().unwrap_or_default(),
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

fn adjacency(snapshot: &GraphSnapshot, reverse: bool) -> BTreeMap<String, Vec<&EdgeRecord>> {
    let mut adjacency = BTreeMap::<String, Vec<&EdgeRecord>>::new();
    for edge in &snapshot.edges {
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
}
