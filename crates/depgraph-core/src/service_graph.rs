use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use depgraph_store::{EdgeRecord, GraphSnapshot};

use crate::{
    CancellationToken,
    query::{
        GraphQueryFilter, PathStep, QueryPageDiagnostic, TraversalPageItem, TraversalResult,
        WhyResult, path_steps_for_edges_filtered, resolve_selector, traversal_page_items,
        traverse_bounded_filtered_cancellable,
    },
    service::{
        DepgraphService, DepgraphServiceError, DepgraphServiceResult, ResolvedSnapshotId,
        SnapshotReadRequest,
    },
};

const MAX_GRAPH_SELECTOR_BYTES: usize = 4_096;

type CanonicalAdjacency<'a> = BTreeMap<&'a str, BTreeMap<(&'a str, &'a str), &'a EdgeRecord>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DependencyDirection {
    Outgoing,
    Incoming,
}

impl DependencyDirection {
    #[must_use]
    pub const fn is_incoming(self) -> bool {
        matches!(self, Self::Incoming)
    }
}

#[derive(Clone, Debug)]
pub struct DependenciesRequest {
    selector: String,
    direction: DependencyDirection,
    transitive: bool,
    filter: GraphQueryFilter,
    max_traversal: usize,
}

impl DependenciesRequest {
    pub fn try_new(
        selector: impl Into<String>,
        direction: DependencyDirection,
        transitive: bool,
        filter: GraphQueryFilter,
        max_traversal: usize,
    ) -> DepgraphServiceResult<Self> {
        let selector = selector.into();
        validate_selector(&selector)?;
        validate_filter(&filter)?;
        if max_traversal == 0 {
            return Err(DepgraphServiceError::InvalidInput);
        }
        Ok(Self {
            selector,
            direction,
            transitive,
            filter,
            max_traversal,
        })
    }

    #[must_use]
    pub fn selector(&self) -> &str {
        &self.selector
    }

    #[must_use]
    pub const fn direction(&self) -> DependencyDirection {
        self.direction
    }

    #[must_use]
    pub const fn transitive(&self) -> bool {
        self.transitive
    }

    #[must_use]
    pub const fn filter(&self) -> &GraphQueryFilter {
        &self.filter
    }

    #[must_use]
    pub const fn max_traversal(&self) -> usize {
        self.max_traversal
    }
}

#[derive(Clone, Debug)]
pub struct DependenciesResult {
    snapshot_id: ResolvedSnapshotId,
    scan_id: String,
    traversal: TraversalResult,
    items: Vec<TraversalPageItem>,
    complete: bool,
    traversed_edges: u64,
    diagnostics: Vec<QueryPageDiagnostic>,
}

impl DependenciesResult {
    #[must_use]
    pub const fn snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    #[must_use]
    pub const fn traversal(&self) -> &TraversalResult {
        &self.traversal
    }

    pub fn items(&self) -> &[TraversalPageItem] {
        &self.items
    }

    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    #[must_use]
    pub const fn traversed_edges(&self) -> u64 {
        self.traversed_edges
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[QueryPageDiagnostic] {
        &self.diagnostics
    }
}

#[derive(Clone, Debug)]
pub struct ExplainPathRequest {
    from: String,
    to: String,
    filter: GraphQueryFilter,
    max_traversal: usize,
}

impl ExplainPathRequest {
    pub fn try_new(
        from: impl Into<String>,
        to: impl Into<String>,
        filter: GraphQueryFilter,
        max_traversal: usize,
    ) -> DepgraphServiceResult<Self> {
        let from = from.into();
        let to = to.into();
        validate_selector(&from)?;
        validate_selector(&to)?;
        validate_filter(&filter)?;
        if max_traversal == 0 {
            return Err(DepgraphServiceError::InvalidInput);
        }
        Ok(Self {
            from,
            to,
            filter,
            max_traversal,
        })
    }

    #[must_use]
    pub fn from(&self) -> &str {
        &self.from
    }

    #[must_use]
    pub fn to(&self) -> &str {
        &self.to
    }

    #[must_use]
    pub const fn filter(&self) -> &GraphQueryFilter {
        &self.filter
    }

    #[must_use]
    pub const fn max_traversal(&self) -> usize {
        self.max_traversal
    }
}

#[derive(Clone, Debug)]
pub struct ExplainPathResult {
    snapshot_id: ResolvedSnapshotId,
    scan_id: String,
    path: WhyResult,
    items: Vec<TraversalPageItem>,
    traversed_edges: u64,
}

impl ExplainPathResult {
    #[must_use]
    pub const fn snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    #[must_use]
    pub const fn path(&self) -> &WhyResult {
        &self.path
    }

    #[must_use]
    pub fn items(&self) -> &[TraversalPageItem] {
        &self.items
    }

    #[must_use]
    pub const fn traversed_edges(&self) -> u64 {
        self.traversed_edges
    }
}

impl DepgraphService {
    pub fn dependencies(
        &self,
        snapshot_request: &mut SnapshotReadRequest,
        request: &DependenciesRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<DependenciesResult> {
        let snapshot_id = snapshot_request.snapshot_id().clone();
        let snapshot = load_pinned_snapshot(snapshot_request, cancellation)?;
        let scan_id = snapshot.scan.id.clone();
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let execution = traverse_bounded_filtered_cancellable(
            &snapshot,
            request.selector(),
            request.transitive(),
            request.direction().is_incoming(),
            request.filter(),
            request.max_traversal(),
            || cancellation.is_cancelled(),
        )
        .map_err(|source| {
            if cancellation.is_cancelled() {
                DepgraphServiceError::Cancelled
            } else {
                DepgraphServiceError::graph_query(source)
            }
        })?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let items =
            traversal_page_items(&execution.result).map_err(|_| DepgraphServiceError::Integrity)?;
        Ok(DependenciesResult {
            snapshot_id,
            scan_id,
            traversal: execution.result,
            items,
            complete: execution.complete,
            traversed_edges: execution.traversed_edges,
            diagnostics: execution.diagnostics,
        })
    }

    pub fn explain_path(
        &self,
        snapshot_request: &mut SnapshotReadRequest,
        request: &ExplainPathRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<ExplainPathResult> {
        let snapshot_id = snapshot_request.snapshot_id().clone();
        let snapshot = load_pinned_snapshot(snapshot_request, cancellation)?;
        let scan_id = snapshot.scan.id.clone();
        let (path, traversed_edges) = explain_path_bounded(&snapshot, request, cancellation)?;
        let items = path_page_items(&snapshot, &path)?;
        Ok(ExplainPathResult {
            snapshot_id,
            scan_id,
            path,
            items,
            traversed_edges,
        })
    }
}

fn validate_selector(selector: &str) -> DepgraphServiceResult<()> {
    if selector.trim().is_empty()
        || selector.len() > MAX_GRAPH_SELECTOR_BYTES
        || selector.chars().any(char::is_control)
    {
        return Err(DepgraphServiceError::InvalidInput);
    }
    Ok(())
}

fn validate_filter(filter: &GraphQueryFilter) -> DepgraphServiceResult<()> {
    for values in [
        &filter.phases,
        &filter.profiles,
        &filter.sessions,
        &filter.environments,
    ] {
        if values.len() > 1_024
            || values.iter().any(|value| {
                value.is_empty() || value.len() > 4_096 || value.chars().any(char::is_control)
            })
        {
            return Err(DepgraphServiceError::InvalidInput);
        }
    }
    Ok(())
}

fn load_pinned_snapshot(
    request: &mut SnapshotReadRequest,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<GraphSnapshot> {
    if cancellation.is_cancelled() {
        return Err(DepgraphServiceError::Cancelled);
    }
    let snapshot_id = request.snapshot_id().as_str().to_owned();
    let cancellation_check = cancellation.clone();
    let loaded = request.store().interruptible_read(
        move || cancellation_check.is_cancelled(),
        |store| store.load_completed_snapshot(&snapshot_id),
    );
    if cancellation.is_cancelled() {
        return Err(DepgraphServiceError::Cancelled);
    }
    loaded.map_err(DepgraphServiceError::store_operation)
}

fn explain_path_bounded(
    snapshot: &GraphSnapshot,
    request: &ExplainPathRequest,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<(WhyResult, u64)> {
    let from =
        resolve_selector(snapshot, request.from()).map_err(DepgraphServiceError::graph_query)?;
    let to = resolve_selector(snapshot, request.to()).map_err(DepgraphServiceError::graph_query)?;
    if from.id == to.id {
        return Ok((
            WhyResult {
                from,
                to,
                path_found: true,
                steps: Vec::new(),
            },
            0,
        ));
    }

    let adjacency = canonical_outgoing_adjacency(
        snapshot,
        request.filter(),
        request.max_traversal(),
        cancellation,
    )?;
    let mut queue = VecDeque::from([from.id.clone()]);
    let mut seen = BTreeSet::from([from.id.clone()]);
    let mut predecessor = HashMap::<String, &EdgeRecord>::new();
    let mut traversed_edges = 0_usize;

    while let Some(node_id) = queue.pop_front() {
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        for edge in adjacency
            .get(node_id.as_str())
            .into_iter()
            .flat_map(|edges| edges.values())
        {
            if cancellation.is_cancelled() {
                return Err(DepgraphServiceError::Cancelled);
            }
            if traversed_edges >= request.max_traversal() {
                return Err(DepgraphServiceError::ResourceExhausted);
            }
            traversed_edges += 1;
            if seen.insert(edge.target.clone()) {
                predecessor.insert(edge.target.clone(), edge);
                if edge.target == to.id {
                    let steps = reconstruct_path(
                        snapshot,
                        request.filter(),
                        &from.id,
                        &to.id,
                        &predecessor,
                    )?;
                    return Ok((
                        WhyResult {
                            from,
                            to,
                            path_found: true,
                            steps,
                        },
                        traversed_edges
                            .try_into()
                            .map_err(|_| DepgraphServiceError::ResourceExhausted)?,
                    ));
                }
                queue.push_back(edge.target.clone());
            }
        }
    }

    Ok((
        WhyResult {
            from,
            to,
            path_found: false,
            steps: Vec::new(),
        },
        traversed_edges
            .try_into()
            .map_err(|_| DepgraphServiceError::ResourceExhausted)?,
    ))
}

fn canonical_outgoing_adjacency<'a>(
    snapshot: &'a GraphSnapshot,
    filter: &GraphQueryFilter,
    max_inspected_edges: usize,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<CanonicalAdjacency<'a>> {
    let mut ordered = BTreeMap::<&str, BTreeMap<(&str, &str), &EdgeRecord>>::new();
    for (inspected_edges, edge) in snapshot.edges.iter().enumerate() {
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        if inspected_edges >= max_inspected_edges {
            return Err(DepgraphServiceError::ResourceExhausted);
        }
        if filter.matches_edge(snapshot, edge) {
            ordered
                .entry(edge.source.as_str())
                .or_default()
                .insert((edge.target.as_str(), edge.id.as_str()), edge);
        }
    }
    if cancellation.is_cancelled() {
        return Err(DepgraphServiceError::Cancelled);
    }
    Ok(ordered)
}

fn reconstruct_path(
    snapshot: &GraphSnapshot,
    filter: &GraphQueryFilter,
    from: &str,
    to: &str,
    predecessor: &HashMap<String, &EdgeRecord>,
) -> DepgraphServiceResult<Vec<PathStep>> {
    let mut current = to;
    let mut reversed = Vec::new();
    while current != from {
        let edge = predecessor
            .get(current)
            .ok_or(DepgraphServiceError::Integrity)?;
        reversed.push((*edge).clone());
        current = &edge.source;
    }
    reversed.reverse();
    Ok(path_steps_for_edges_filtered(snapshot, &reversed, filter))
}

fn path_page_items(
    snapshot: &GraphSnapshot,
    path: &WhyResult,
) -> DepgraphServiceResult<Vec<TraversalPageItem>> {
    let nodes = snapshot
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    path.steps
        .iter()
        .map(|step| {
            let source = nodes
                .get(step.edge.source.as_str())
                .ok_or(DepgraphServiceError::Integrity)?;
            let target = nodes
                .get(step.edge.target.as_str())
                .ok_or(DepgraphServiceError::Integrity)?;
            Ok(TraversalPageItem {
                source: (*source).clone(),
                target: (*target).clone(),
                step: step.clone(),
            })
        })
        .collect()
}
