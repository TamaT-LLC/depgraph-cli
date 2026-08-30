use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    ops::Bound::{Excluded, Unbounded},
};

use depgraph_store::{
    EdgeRecord, EvidenceRecord, GraphSnapshot, PhaseCoverageRecord, ProfileCorrelationRecord,
    ProfileMatrixEntryRecord, SiteRecord,
};

use crate::{
    CancellationToken,
    impact::{ImpactFilters, ImpactResult, impact_cancellable, read_git_changed_set_cancellable},
    query::{
        BoundedTraversalResult, CycleLevel, CycleResult, GraphQueryFilter, PathStep,
        QueryPageDiagnostic, TraversalPageItem, TraversalResult, UnresolvedResult, WhyResult,
        is_cancelled as is_query_cancelled, is_integrity as is_query_integrity,
        is_resource_exhausted as is_query_resource_exhausted,
        materialize_path_steps_bounded_cancellable, resolve_selector_bounded_cancellable,
        traversal_page_items, traverse_bounded_filtered_cancellable,
    },
    service::{
        DepgraphService, DepgraphServiceError, DepgraphServiceResult, RepositoryPathSelector,
        ResolvedSnapshotId, SnapshotReadRequest,
    },
    service_limits::{
        MAX_CYCLE_NODE_IDS, MAX_DEPENDENCY_PATH_STEPS, MAX_GRAPH_EVIDENCE_ITEMS,
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS, MAX_UNRESOLVED_CORRELATION_REASONS,
        MAX_UNRESOLVED_PHASES,
    },
};

const MAX_GRAPH_SELECTOR_BYTES: usize = 4_096;
const MAX_GRAPH_FILTER_ITEMS: usize = 1_024;
const MAX_GRAPH_FILTER_VALUE_BYTES: usize = 4_096;
const MAX_GIT_REF_BYTES: usize = 256;
pub const MAX_UNRESOLVED_EVIDENCE_PER_SITE: usize = MAX_GRAPH_EVIDENCE_ITEMS;
pub const MAX_UNRESOLVED_TARGETS_PER_SITE: usize = 256;

type CanonicalAdjacency<'a> = BTreeMap<&'a str, BTreeMap<(&'a str, &'a str), &'a EdgeRecord>>;

#[derive(Clone, Debug)]
pub struct ImpactRequest {
    selector: String,
    changed_since: Option<String>,
    filters: ImpactFilters,
}

impl ImpactRequest {
    pub fn try_new(
        selector: impl Into<String>,
        changed_since: Option<String>,
        filters: ImpactFilters,
    ) -> DepgraphServiceResult<Self> {
        let selector = selector.into();
        validate_selector(&selector)?;
        if changed_since.as_deref().is_some_and(|value| {
            value.is_empty()
                || value.len() > MAX_GIT_REF_BYTES
                || value.starts_with('-')
                || value.chars().any(char::is_control)
        }) || filters.max_nodes == 0
            || filters.max_edges == 0
            || filters.max_nodes > crate::MAX_INTERACTIVE_QUERY_TRAVERSAL
            || filters.max_edges > crate::MAX_INTERACTIVE_QUERY_TRAVERSAL
        {
            return Err(DepgraphServiceError::InvalidInput);
        }
        for values in [
            &filters.profiles,
            &filters.conditions,
            &filters.phases,
            &filters.sessions,
            &filters.environments,
        ] {
            validate_string_filter(values)?;
        }
        Ok(Self {
            selector,
            changed_since,
            filters,
        })
    }

    #[must_use]
    pub fn selector(&self) -> &str {
        &self.selector
    }

    #[must_use]
    pub fn changed_since(&self) -> Option<&str> {
        self.changed_since.as_deref()
    }

    #[must_use]
    pub const fn filters(&self) -> &ImpactFilters {
        &self.filters
    }
}

#[derive(Clone, Debug)]
pub struct ImpactServiceResult {
    snapshot_id: ResolvedSnapshotId,
    scan_id: String,
    impact: ImpactResult,
}

impl ImpactServiceResult {
    #[must_use]
    pub const fn snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    #[must_use]
    pub const fn impact(&self) -> &ImpactResult {
        &self.impact
    }
}

#[derive(Clone, Debug)]
pub struct CyclesRequest {
    level: CycleLevel,
    max_traversal: usize,
}

impl CyclesRequest {
    pub fn try_new(level: CycleLevel, max_traversal: usize) -> DepgraphServiceResult<Self> {
        validate_traversal_limit(max_traversal)?;
        Ok(Self {
            level,
            max_traversal,
        })
    }

    #[must_use]
    pub const fn level(&self) -> CycleLevel {
        self.level
    }

    #[must_use]
    pub const fn max_traversal(&self) -> usize {
        self.max_traversal
    }
}

#[derive(Clone, Debug)]
pub struct CyclesResult {
    snapshot_id: ResolvedSnapshotId,
    scan_id: String,
    cycles: Vec<CycleResult>,
}

impl CyclesResult {
    #[must_use]
    pub const fn snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    #[must_use]
    pub fn cycles(&self) -> &[CycleResult] {
        &self.cycles
    }
}

#[derive(Clone, Debug)]
pub struct UnresolvedRequest {
    kinds: Vec<String>,
    max_traversal: usize,
}

impl UnresolvedRequest {
    pub fn try_new(kinds: Vec<String>, max_traversal: usize) -> DepgraphServiceResult<Self> {
        validate_string_filter(&kinds)?;
        validate_traversal_limit(max_traversal)?;
        let mut kinds = kinds;
        kinds.sort();
        kinds.dedup();
        Ok(Self {
            kinds,
            max_traversal,
        })
    }

    #[must_use]
    pub fn kinds(&self) -> &[String] {
        &self.kinds
    }

    #[must_use]
    pub const fn max_traversal(&self) -> usize {
        self.max_traversal
    }
}

#[derive(Clone, Debug)]
pub struct UnresolvedServiceResult {
    snapshot_id: ResolvedSnapshotId,
    scan_id: String,
    items: Vec<UnresolvedResult>,
}

impl UnresolvedServiceResult {
    #[must_use]
    pub const fn snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    #[must_use]
    pub fn items(&self) -> &[UnresolvedResult] {
        &self.items
    }
}

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
        validate_traversal_limit(max_traversal)?;
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
        validate_traversal_limit(max_traversal)?;
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
        .map_err(|source| graph_query_service_error(source, cancellation))?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        ensure_dependency_traversal_complete(&execution)?;
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
        let items = path_page_items(&snapshot, &path, cancellation)?;
        Ok(ExplainPathResult {
            snapshot_id,
            scan_id,
            path,
            items,
            traversed_edges,
        })
    }

    pub fn impact(
        &self,
        snapshot_request: &mut SnapshotReadRequest,
        request: &ImpactRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<ImpactServiceResult> {
        if request.changed_since().is_some() && !snapshot_request.is_current() {
            return Err(DepgraphServiceError::InvalidInput);
        }
        let snapshot_id = snapshot_request.snapshot_id().clone();
        let snapshot = load_pinned_snapshot(snapshot_request, cancellation)?;
        preflight_impact_snapshot(&snapshot, cancellation)?;
        let changed_set = request
            .changed_since()
            .map(|git_ref| {
                read_git_changed_set_cancellable(self.config().canonical_root(), git_ref, || {
                    cancellation.is_cancelled()
                })
            })
            .transpose()
            .map_err(|source| impact_changed_set_service_error(source, cancellation))?;
        if let Some(changed_set) = changed_set.as_ref()
            && snapshot.scan.source_revision.as_deref() != Some(changed_set.head.as_str())
        {
            return Err(DepgraphServiceError::SnapshotWorktreeMismatch);
        }
        let result = impact_cancellable(
            &snapshot,
            request.selector(),
            changed_set.as_ref(),
            request.filters().clone(),
            || cancellation.is_cancelled(),
        )
        .map_err(|source| {
            if cancellation.is_cancelled() {
                DepgraphServiceError::Cancelled
            } else if crate::impact::is_resource_exhausted(&source) {
                DepgraphServiceError::ResourceExhausted
            } else if crate::impact::is_integrity(&source) {
                DepgraphServiceError::Integrity
            } else {
                DepgraphServiceError::graph_query(source)
            }
        })?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        if !result.complete {
            return Err(DepgraphServiceError::ResourceExhausted);
        }
        Ok(ImpactServiceResult {
            snapshot_id,
            scan_id: snapshot.scan.id,
            impact: result,
        })
    }

    pub fn cycles(
        &self,
        snapshot_request: &mut SnapshotReadRequest,
        request: &CyclesRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<CyclesResult> {
        let snapshot_id = snapshot_request.snapshot_id().clone();
        let snapshot = load_pinned_snapshot(snapshot_request, cancellation)?;
        let cycles = cycles_bounded_cancellable(&snapshot, request, cancellation)?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        Ok(CyclesResult {
            snapshot_id,
            scan_id: snapshot.scan.id,
            cycles,
        })
    }

    pub fn unresolved(
        &self,
        snapshot_request: &mut SnapshotReadRequest,
        request: &UnresolvedRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<UnresolvedServiceResult> {
        let snapshot_id = snapshot_request.snapshot_id().clone();
        let snapshot = load_pinned_snapshot(snapshot_request, cancellation)?;
        let items = unresolved_bounded_cancellable(&snapshot, request, cancellation)?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        Ok(UnresolvedServiceResult {
            snapshot_id,
            scan_id: snapshot.scan.id,
            items,
        })
    }
}

fn impact_changed_set_service_error(
    source: anyhow::Error,
    cancellation: &CancellationToken,
) -> DepgraphServiceError {
    if cancellation.is_cancelled() {
        DepgraphServiceError::Cancelled
    } else if crate::impact::is_resource_exhausted(&source) {
        DepgraphServiceError::ResourceExhausted
    } else {
        DepgraphServiceError::graph_query(source)
    }
}

fn validate_traversal_limit(limit: usize) -> DepgraphServiceResult<()> {
    if !(1..=crate::MAX_INTERACTIVE_QUERY_TRAVERSAL).contains(&limit) {
        return Err(DepgraphServiceError::InvalidInput);
    }
    Ok(())
}

fn graph_query_service_error(
    source: anyhow::Error,
    cancellation: &CancellationToken,
) -> DepgraphServiceError {
    if cancellation.is_cancelled() || is_query_cancelled(&source) {
        DepgraphServiceError::Cancelled
    } else if is_query_resource_exhausted(&source) {
        DepgraphServiceError::ResourceExhausted
    } else if is_query_integrity(&source) {
        DepgraphServiceError::Integrity
    } else {
        DepgraphServiceError::graph_query(source)
    }
}

fn ensure_dependency_traversal_complete(
    execution: &BoundedTraversalResult,
) -> DepgraphServiceResult<()> {
    if !execution.complete {
        return Err(DepgraphServiceError::ResourceExhausted);
    }
    Ok(())
}

fn validate_string_filter(values: &[String]) -> DepgraphServiceResult<()> {
    if values.len() > MAX_GRAPH_FILTER_ITEMS
        || values.iter().any(|value| {
            value.is_empty()
                || value.len() > MAX_GRAPH_FILTER_VALUE_BYTES
                || value.chars().any(char::is_control)
        })
    {
        return Err(DepgraphServiceError::InvalidInput);
    }
    Ok(())
}

fn preflight_impact_snapshot(
    snapshot: &GraphSnapshot,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<()> {
    for length in [
        snapshot.nodes.len(),
        snapshot.sites.len(),
        snapshot.profile_matrix.entries.len(),
        snapshot.profile_matrix.correlations.len(),
        snapshot.edges.len(),
        snapshot.evidence.len(),
    ] {
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        if length > MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS {
            return Err(DepgraphServiceError::ResourceExhausted);
        }
    }
    let mut evidence_per_owner = BTreeMap::<(&str, &str), usize>::new();
    for _ in snapshot
        .nodes
        .iter()
        .map(|_| ())
        .chain(snapshot.sites.iter().map(|_| ()))
        .chain(snapshot.edges.iter().map(|_| ()))
    {
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
    }
    for evidence in &snapshot.evidence {
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        if matches!(evidence.owner_type.as_str(), "edge" | "site") {
            let count = evidence_per_owner
                .entry((evidence.owner_type.as_str(), evidence.owner_id.as_str()))
                .or_default();
            *count += 1;
            if *count > MAX_UNRESOLVED_EVIDENCE_PER_SITE {
                return Err(DepgraphServiceError::ResourceExhausted);
            }
        }
    }
    Ok(())
}

fn phase_step(
    steps: &mut usize,
    maximum: usize,
    is_cancelled: &mut impl FnMut() -> bool,
) -> DepgraphServiceResult<()> {
    if is_cancelled() {
        return Err(DepgraphServiceError::Cancelled);
    }
    if *steps >= maximum {
        return Err(DepgraphServiceError::ResourceExhausted);
    }
    *steps += 1;
    Ok(())
}

fn cycles_bounded_cancellable(
    snapshot: &GraphSnapshot,
    request: &CyclesRequest,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<Vec<CycleResult>> {
    cycles_bounded_with_cancellation(snapshot, request, &mut || cancellation.is_cancelled())
}

pub(crate) fn cycles_bounded_with_cancellation(
    snapshot: &GraphSnapshot,
    request: &CyclesRequest,
    is_cancelled: &mut impl FnMut() -> bool,
) -> DepgraphServiceResult<Vec<CycleResult>> {
    let maximum = request.max_traversal();
    let mut preprocessing = 0;
    let mut allowed = BTreeSet::new();
    for node in &snapshot.nodes {
        cycle_phase_step(
            &mut preprocessing,
            maximum,
            CycleWorkPhase::Preprocessing,
            is_cancelled,
        )?;
        if node.kind == request.level().node_kind() {
            allowed.insert(node.id.clone());
        }
    }
    let mut adjacency = BTreeMap::<String, BTreeSet<String>>::new();
    let mut reverse = BTreeMap::<String, BTreeSet<String>>::new();
    for edge in &snapshot.edges {
        cycle_phase_step(
            &mut preprocessing,
            maximum,
            CycleWorkPhase::Preprocessing,
            is_cancelled,
        )?;
        if allowed.contains(&edge.source) && allowed.contains(&edge.target) {
            cycle_phase_step(
                &mut preprocessing,
                maximum,
                CycleWorkPhase::Preprocessing,
                is_cancelled,
            )?;
            adjacency
                .entry(edge.source.clone())
                .or_default()
                .insert(edge.target.clone());
            #[cfg(test)]
            CYCLE_ADJACENCY_INSERT_VISITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            cycle_phase_step(
                &mut preprocessing,
                maximum,
                CycleWorkPhase::Preprocessing,
                is_cancelled,
            )?;
            reverse
                .entry(edge.target.clone())
                .or_default()
                .insert(edge.source.clone());
            #[cfg(test)]
            CYCLE_ADJACENCY_INSERT_VISITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    let mut traversal = 0;
    let mut seen = BTreeSet::new();
    let mut finish = Vec::with_capacity(allowed.len());
    for start in &allowed {
        cycle_phase_step(
            &mut traversal,
            maximum,
            CycleWorkPhase::Traversal,
            is_cancelled,
        )?;
        if !seen.insert(start.clone()) {
            continue;
        }
        let mut stack = vec![(start.clone(), None::<String>)];
        while let Some((node, previous)) = stack.last_mut() {
            cycle_phase_step(
                &mut traversal,
                maximum,
                CycleWorkPhase::Traversal,
                is_cancelled,
            )?;
            let next = adjacency
                .get(node)
                .and_then(|targets| match previous.as_ref() {
                    Some(previous) => targets
                        .range((Excluded(previous.clone()), Unbounded))
                        .next(),
                    None => targets.first(),
                });
            if let Some(next) = next.cloned() {
                *previous = Some(next.clone());
                if seen.insert(next.clone()) {
                    stack.push((next, None));
                }
            } else {
                let (node, _) = stack.pop().ok_or(DepgraphServiceError::Integrity)?;
                finish.push(node);
            }
        }
    }

    let mut assigned = BTreeSet::new();
    let mut components = Vec::<BTreeSet<String>>::new();
    while let Some(start) = finish.pop() {
        cycle_phase_step(
            &mut traversal,
            maximum,
            CycleWorkPhase::Traversal,
            is_cancelled,
        )?;
        if !assigned.insert(start.clone()) {
            continue;
        }
        let mut component = BTreeSet::new();
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            cycle_phase_step(
                &mut traversal,
                maximum,
                CycleWorkPhase::Traversal,
                is_cancelled,
            )?;
            component.insert(node.clone());
            #[cfg(test)]
            CYCLE_COMPONENT_INSERT_VISITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            for next in reverse.get(&node).into_iter().flatten().rev() {
                cycle_phase_step(
                    &mut traversal,
                    maximum,
                    CycleWorkPhase::Traversal,
                    is_cancelled,
                )?;
                if assigned.insert(next.clone()) {
                    stack.push(next.clone());
                }
            }
        }
        components.push(component);
    }

    let mut finalization = 0;
    let mut ordered_results = BTreeMap::<Vec<String>, String>::new();
    for component in components {
        cycle_phase_step(
            &mut finalization,
            maximum,
            CycleWorkPhase::Finalization,
            is_cancelled,
        )?;
        let start = component.first().ok_or(DepgraphServiceError::Integrity)?;
        let self_loop = component.len() == 1
            && adjacency
                .get(start)
                .is_some_and(|targets| targets.contains(start));
        if component.len() < 2 && !self_loop {
            continue;
        }
        let node_ids = representative_cycle_bounded(
            start,
            &component,
            &adjacency,
            &mut finalization,
            maximum,
            is_cancelled,
        )?
        .ok_or(DepgraphServiceError::Integrity)?;
        if node_ids.len() > MAX_CYCLE_NODE_IDS {
            return Err(DepgraphServiceError::ResourceExhausted);
        }
        cycle_phase_step(
            &mut finalization,
            maximum,
            CycleWorkPhase::Finalization,
            is_cancelled,
        )?;
        ordered_results
            .entry(node_ids)
            .or_insert_with(|| request.level().node_kind().to_owned());
    }
    let mut results = Vec::with_capacity(ordered_results.len());
    for (node_ids, level) in ordered_results {
        cycle_phase_step(
            &mut finalization,
            maximum,
            CycleWorkPhase::Finalization,
            is_cancelled,
        )?;
        results.push(CycleResult { level, node_ids });
        #[cfg(test)]
        CYCLE_RESULT_MATERIALIZATION_VISITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    Ok(results)
}

fn representative_cycle_bounded(
    start: &str,
    component: &BTreeSet<String>,
    adjacency: &BTreeMap<String, BTreeSet<String>>,
    steps: &mut usize,
    maximum: usize,
    is_cancelled: &mut impl FnMut() -> bool,
) -> DepgraphServiceResult<Option<Vec<String>>> {
    let mut queue = VecDeque::new();
    let mut predecessor = HashMap::<String, String>::new();
    for next in adjacency.get(start).into_iter().flatten() {
        cycle_phase_step(steps, maximum, CycleWorkPhase::Finalization, is_cancelled)?;
        if !component.contains(next) {
            continue;
        }
        if next == start {
            let mut cycle = Vec::with_capacity(2);
            for _ in 0..2 {
                cycle_phase_step(steps, maximum, CycleWorkPhase::Finalization, is_cancelled)?;
                cycle.push(start.to_owned());
            }
            return Ok(Some(cycle));
        }
        predecessor.insert(next.clone(), start.to_owned());
        queue.push_back(next.clone());
    }
    while let Some(node) = queue.pop_front() {
        cycle_phase_step(steps, maximum, CycleWorkPhase::Finalization, is_cancelled)?;
        for next in adjacency.get(&node).into_iter().flatten() {
            cycle_phase_step(steps, maximum, CycleWorkPhase::Finalization, is_cancelled)?;
            if !component.contains(next) {
                continue;
            }
            if next == start {
                let mut path = vec![node.clone()];
                let mut current = node;
                while current != start {
                    cycle_phase_step(steps, maximum, CycleWorkPhase::Finalization, is_cancelled)?;
                    if path.len() >= MAX_CYCLE_NODE_IDS - 1 {
                        return Err(DepgraphServiceError::ResourceExhausted);
                    }
                    current = predecessor
                        .get(&current)
                        .ok_or(DepgraphServiceError::Integrity)?
                        .clone();
                    path.push(current.clone());
                }
                path.reverse();
                if path.len() >= MAX_CYCLE_NODE_IDS {
                    return Err(DepgraphServiceError::ResourceExhausted);
                }
                cycle_phase_step(steps, maximum, CycleWorkPhase::Finalization, is_cancelled)?;
                path.push(start.to_owned());
                return Ok(Some(path));
            }
            if !predecessor.contains_key(next) {
                predecessor.insert(next.clone(), node.clone());
                queue.push_back(next.clone());
            }
        }
    }
    Ok(None)
}

#[derive(Clone, Copy)]
enum CycleWorkPhase {
    Preprocessing,
    Traversal,
    Finalization,
}

fn cycle_phase_step(
    steps: &mut usize,
    maximum: usize,
    phase: CycleWorkPhase,
    is_cancelled: &mut impl FnMut() -> bool,
) -> DepgraphServiceResult<()> {
    if is_cancelled() {
        return Err(DepgraphServiceError::Cancelled);
    }
    if *steps >= maximum {
        return Err(DepgraphServiceError::ResourceExhausted);
    }
    *steps += 1;
    #[cfg(test)]
    match phase {
        CycleWorkPhase::Preprocessing => {
            CYCLE_PREPROCESSING_WORK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        CycleWorkPhase::Traversal => {
            CYCLE_TRAVERSAL_WORK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        CycleWorkPhase::Finalization => {
            CYCLE_FINALIZATION_WORK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    #[cfg(not(test))]
    let _ = phase;
    Ok(())
}

#[cfg(test)]
static CYCLE_PREPROCESSING_WORK: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static CYCLE_TRAVERSAL_WORK: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static CYCLE_FINALIZATION_WORK: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static CYCLE_ADJACENCY_INSERT_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static CYCLE_COMPONENT_INSERT_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static CYCLE_RESULT_MATERIALIZATION_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn unresolved_bounded_cancellable(
    snapshot: &GraphSnapshot,
    request: &UnresolvedRequest,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<Vec<UnresolvedResult>> {
    unresolved_bounded_with_cancellation(snapshot, request, &mut || cancellation.is_cancelled())
}

fn unresolved_bounded_with_cancellation(
    snapshot: &GraphSnapshot,
    request: &UnresolvedRequest,
    is_cancelled: &mut impl FnMut() -> bool,
) -> DepgraphServiceResult<Vec<UnresolvedResult>> {
    let maximum = request.max_traversal();
    let mut preprocessing = 0;
    let mut evidence = BTreeMap::<String, Vec<EvidenceRecord>>::new();
    for item in &snapshot.evidence {
        phase_step(&mut preprocessing, maximum, is_cancelled)?;
        if item.owner_type == "site" {
            let records = evidence.entry(item.owner_id.clone()).or_default();
            if records.len() >= MAX_UNRESOLVED_EVIDENCE_PER_SITE {
                return Err(DepgraphServiceError::ResourceExhausted);
            }
            records.push(item.clone());
        }
    }
    for records in evidence.values_mut() {
        if is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        records.sort_by(|left, right| {
            left.ordinal
                .cmp(&right.ordinal)
                .then(left.kind.cmp(&right.kind))
                .then(left.path.cmp(&right.path))
                .then(left.start_line.cmp(&right.start_line))
                .then(left.start_column.cmp(&right.start_column))
        });
    }
    let mut phases = BTreeMap::<String, BTreeSet<String>>::new();
    for edge in &snapshot.edges {
        phase_step(&mut preprocessing, maximum, is_cancelled)?;
        if let Some(site_id) = &edge.site_id {
            let site_phases = phases.entry(site_id.clone()).or_default();
            if !site_phases.contains(edge.phase.as_str()) {
                if site_phases.len() >= MAX_UNRESOLVED_PHASES {
                    return Err(DepgraphServiceError::ResourceExhausted);
                }
                site_phases.insert(edge.phase.clone());
            }
        }
    }
    let mut correlations = BTreeMap::<String, &ProfileCorrelationRecord>::new();
    for correlation in &snapshot.profile_matrix.correlations {
        phase_step(&mut preprocessing, maximum, is_cancelled)?;
        for site_id in correlation.site_ids_by_phase.values().flatten() {
            phase_step(&mut preprocessing, maximum, is_cancelled)?;
            if correlations.insert(site_id.clone(), correlation).is_some() {
                return Err(DepgraphServiceError::Integrity);
            }
        }
    }
    let phase_coverage = phase_coverage_index_cancellable(
        &snapshot.profile_matrix.entries,
        &mut preprocessing,
        maximum,
        is_cancelled,
    )?;

    let mut finalization_work = 0;
    let mut finalization =
        UnresolvedFinalization::new(&mut finalization_work, maximum, is_cancelled);
    let mut ordered_items = BTreeMap::new();
    for site in &snapshot.sites {
        finalization.step()?;
        if site.resolution_status != "unresolved"
            || (!request.kinds().is_empty() && request.kinds().binary_search(&site.kind).is_err())
        {
            continue;
        }
        if site.target_ids.len() > MAX_UNRESOLVED_TARGETS_PER_SITE {
            return Err(DepgraphServiceError::ResourceExhausted);
        }
        let correlation = correlations.get(&site.id).copied();
        let result = unresolved_result(
            site,
            evidence.remove(&site.id).unwrap_or_default(),
            phases.remove(&site.id).unwrap_or_default(),
            correlation,
            &phase_coverage,
            &mut finalization,
        )?;
        finalization.step()?;
        if ordered_items.insert(site.id.clone(), result).is_some() {
            return Err(DepgraphServiceError::Integrity);
        }
        #[cfg(test)]
        UNRESOLVED_ORDERED_INSERT_VISITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    let mut items = Vec::with_capacity(ordered_items.len());
    for item in ordered_items.into_values() {
        finalization.step()?;
        items.push(item);
        #[cfg(test)]
        UNRESOLVED_ORDERED_MATERIALIZATION_VISITS
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    Ok(items)
}

fn unresolved_result(
    site: &SiteRecord,
    evidence: Vec<EvidenceRecord>,
    phases: BTreeSet<String>,
    correlation: Option<&ProfileCorrelationRecord>,
    phase_coverage: &BTreeMap<&str, &BTreeMap<String, PhaseCoverageRecord>>,
    finalization: &mut UnresolvedFinalization<'_>,
) -> DepgraphServiceResult<UnresolvedResult> {
    let coverage = correlation
        .and_then(|item| {
            phase_coverage
                .get(item.effective_profile_id.as_str())
                .copied()
        })
        .map(|coverage| clone_phase_coverage_cancellable(coverage, finalization))
        .transpose()?
        .unwrap_or_default();
    let observed_difference_reasons = correlation
        .map(|item| clone_correlation_reasons_cancellable(&item.difference_reasons, finalization))
        .transpose()?
        .unwrap_or_default();
    finalization.check_cancelled()?;
    Ok(UnresolvedResult {
        site: site.clone(),
        evidence,
        phases: phases.into_iter().collect(),
        effective_profile_id: correlation.map(|item| item.effective_profile_id.clone()),
        correlation_status: correlation.map(|item| item.status.clone()),
        observed_difference_reasons,
        phase_coverage: coverage,
    })
}

struct UnresolvedFinalization<'a> {
    work: &'a mut usize,
    maximum: usize,
    is_cancelled: &'a mut dyn FnMut() -> bool,
}

impl<'a> UnresolvedFinalization<'a> {
    fn new(work: &'a mut usize, maximum: usize, is_cancelled: &'a mut dyn FnMut() -> bool) -> Self {
        Self {
            work,
            maximum,
            is_cancelled,
        }
    }

    fn check_cancelled(&mut self) -> DepgraphServiceResult<()> {
        if (self.is_cancelled)() {
            return Err(DepgraphServiceError::Cancelled);
        }
        Ok(())
    }

    fn step(&mut self) -> DepgraphServiceResult<()> {
        self.check_cancelled()?;
        if *self.work >= self.maximum {
            return Err(DepgraphServiceError::ResourceExhausted);
        }
        *self.work += 1;
        Ok(())
    }
}

fn phase_coverage_index_cancellable<'a>(
    entries: &'a [ProfileMatrixEntryRecord],
    preprocessing: &mut usize,
    maximum: usize,
    is_cancelled: &mut impl FnMut() -> bool,
) -> DepgraphServiceResult<BTreeMap<&'a str, &'a BTreeMap<String, PhaseCoverageRecord>>> {
    #[cfg(test)]
    PHASE_COVERAGE_INDEX_BUILDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut index = BTreeMap::new();
    for entry in entries {
        if is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        if *preprocessing >= maximum {
            return Err(DepgraphServiceError::ResourceExhausted);
        }
        *preprocessing += 1;
        #[cfg(test)]
        PHASE_COVERAGE_ENTRY_VISITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if entry.phase_coverage.len() > maximum {
            return Err(DepgraphServiceError::ResourceExhausted);
        }
        if !index.contains_key(entry.id.as_str()) && index.len() >= maximum {
            return Err(DepgraphServiceError::ResourceExhausted);
        }
        index
            .entry(entry.id.as_str())
            .or_insert(&entry.phase_coverage);
    }
    if is_cancelled() {
        return Err(DepgraphServiceError::Cancelled);
    }
    Ok(index)
}

fn clone_phase_coverage_cancellable(
    coverage: &BTreeMap<String, PhaseCoverageRecord>,
    finalization: &mut UnresolvedFinalization<'_>,
) -> DepgraphServiceResult<BTreeMap<String, PhaseCoverageRecord>> {
    let mut cloned = BTreeMap::new();
    for (phase, record) in coverage {
        finalization.step()?;
        #[cfg(test)]
        PHASE_COVERAGE_MATERIALIZATION_VISITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        cloned.insert(phase.clone(), record.clone());
    }
    Ok(cloned)
}

fn clone_correlation_reasons_cancellable(
    reasons: &[String],
    finalization: &mut UnresolvedFinalization<'_>,
) -> DepgraphServiceResult<Vec<String>> {
    if reasons.len() > MAX_UNRESOLVED_CORRELATION_REASONS {
        return Err(DepgraphServiceError::ResourceExhausted);
    }
    let mut cloned = Vec::with_capacity(reasons.len());
    for reason in reasons {
        finalization.step()?;
        #[cfg(test)]
        CORRELATION_REASON_MATERIALIZATION_VISITS
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        cloned.push(reason.clone());
    }
    Ok(cloned)
}

#[cfg(test)]
static PHASE_COVERAGE_INDEX_BUILDS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static PHASE_COVERAGE_ENTRY_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static PHASE_COVERAGE_MATERIALIZATION_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static CORRELATION_REASON_MATERIALIZATION_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static UNRESOLVED_ORDERED_INSERT_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static UNRESOLVED_ORDERED_MATERIALIZATION_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn validate_selector(selector: &str) -> DepgraphServiceResult<()> {
    if selector.trim().is_empty()
        || selector.len() > MAX_GRAPH_SELECTOR_BYTES
        || selector.chars().any(char::is_control)
    {
        return Err(DepgraphServiceError::InvalidInput);
    }
    if selector.starts_with("path:") {
        RepositoryPathSelector::parse(selector)?;
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
        validate_string_filter(values)?;
    }
    Ok(())
}

pub(crate) fn load_pinned_snapshot(
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
    let from = resolve_selector_bounded_cancellable(
        snapshot,
        request.from(),
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
        &mut || cancellation.is_cancelled(),
    )
    .map_err(|source| graph_query_service_error(source, cancellation))?;
    let to = resolve_selector_bounded_cancellable(
        snapshot,
        request.to(),
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
        &mut || cancellation.is_cancelled(),
    )
    .map_err(|source| graph_query_service_error(source, cancellation))?;
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
                        cancellation,
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
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<Vec<PathStep>> {
    let mut current = to;
    let mut reversed = Vec::new();
    while current != from {
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        if reversed.len() >= MAX_DEPENDENCY_PATH_STEPS {
            return Err(DepgraphServiceError::ResourceExhausted);
        }
        let edge = predecessor
            .get(current)
            .ok_or(DepgraphServiceError::Integrity)?;
        reversed.push(*edge);
        current = &edge.source;
    }
    reversed.reverse();
    materialize_path_steps_bounded_cancellable(
        snapshot,
        filter,
        &reversed,
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
        &mut || cancellation.is_cancelled(),
    )
    .map_err(|source| graph_query_service_error(source, cancellation))
}

fn path_page_items(
    snapshot: &GraphSnapshot,
    path: &WhyResult,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<Vec<TraversalPageItem>> {
    path_page_items_with_limit(
        snapshot,
        path,
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
        &mut || cancellation.is_cancelled(),
    )
}

fn path_page_items_with_limit(
    snapshot: &GraphSnapshot,
    path: &WhyResult,
    maximum_work: usize,
    is_cancelled: &mut impl FnMut() -> bool,
) -> DepgraphServiceResult<Vec<TraversalPageItem>> {
    let mut work = PathEndpointWork::new(maximum_work);
    if path.steps.is_empty() {
        work.check_cancelled(is_cancelled)?;
        return Ok(Vec::new());
    }
    let mut needed = BTreeSet::new();
    for step in &path.steps {
        work.step(is_cancelled)?;
        if step.edge.source.is_empty() || step.edge.target.is_empty() {
            return Err(DepgraphServiceError::Integrity);
        }
        needed.insert(step.edge.source.as_str());
        needed.insert(step.edge.target.as_str());
    }
    let mut nodes = BTreeMap::new();
    for node in &snapshot.nodes {
        work.step(is_cancelled)?;
        #[cfg(test)]
        PATH_ENDPOINT_NODE_SCAN_VISITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if needed.contains(node.id.as_str()) {
            work.step(is_cancelled)?;
            if nodes.insert(node.id.as_str(), node).is_some() {
                return Err(DepgraphServiceError::Integrity);
            }
        }
    }
    if nodes.len() != needed.len() {
        return Err(DepgraphServiceError::Integrity);
    }
    let mut items = Vec::with_capacity(path.steps.len());
    for step in &path.steps {
        work.step(is_cancelled)?;
        let source = nodes
            .get(step.edge.source.as_str())
            .ok_or(DepgraphServiceError::Integrity)?;
        let target = nodes
            .get(step.edge.target.as_str())
            .ok_or(DepgraphServiceError::Integrity)?;
        items.push(TraversalPageItem {
            source: (*source).clone(),
            target: (*target).clone(),
            step: step.clone(),
        });
        #[cfg(test)]
        PATH_ENDPOINT_ITEM_MATERIALIZATION_VISITS
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    Ok(items)
}

struct PathEndpointWork {
    used: usize,
    maximum: usize,
}

impl PathEndpointWork {
    const fn new(maximum: usize) -> Self {
        Self { used: 0, maximum }
    }

    fn check_cancelled(
        &self,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> DepgraphServiceResult<()> {
        if is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        Ok(())
    }

    fn step(&mut self, is_cancelled: &mut impl FnMut() -> bool) -> DepgraphServiceResult<()> {
        self.check_cancelled(is_cancelled)?;
        if self.used >= self.maximum {
            return Err(DepgraphServiceError::ResourceExhausted);
        }
        self.used += 1;
        #[cfg(test)]
        PATH_ENDPOINT_WORK_ITEMS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
static PATH_ENDPOINT_WORK_ITEMS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static PATH_ENDPOINT_NODE_SCAN_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static PATH_ENDPOINT_ITEM_MATERIALIZATION_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use depgraph_store::{
        CoverageRecord, EdgeRecord, GraphSnapshot, NodeRecord, PhaseCoverageRecord,
        ProfileCorrelationRecord, ProfileMatrixEntryRecord, ScanRecord,
    };
    use serde_json::json;

    use super::*;

    #[test]
    fn issue_317_path_selectors_use_the_portable_repository_path_contract() {
        for selector in [
            "path:src/lib.rs",
            "path:generated/not-present.rs",
            "id:path:src/lib.rs",
            "symbol:crate::module",
        ] {
            validate_selector(selector)
                .unwrap_or_else(|error| panic!("valid selector {selector:?}: {error:?}"));
        }

        for selector in [
            "path:",
            "path:/etc/passwd",
            "path:../outside.rs",
            "path:src/../../outside.rs",
            r"path:C:\Windows\win.ini",
            "path:C:/Windows/win.ini",
            r"path:\\server\share\secret.rs",
            "path:nested/file.rs:private",
            "path:nested/CON.rs",
            "path:nested/file.rs.",
        ] {
            assert!(
                matches!(
                    validate_selector(selector),
                    Err(DepgraphServiceError::InvalidRepositoryPath { .. })
                ),
                "portable path selector accepted {selector:?}"
            );
        }
    }

    #[test]
    fn changed_set_preprocessing_errors_map_to_resource_exhausted_with_cancellation_precedence() {
        let cancellation = CancellationToken::new();
        let resource = impact_changed_set_service_error(
            crate::impact::changed_set_preprocessing_exhausted_for_test(),
            &cancellation,
        );
        assert!(matches!(resource, DepgraphServiceError::ResourceExhausted));

        let ordinary = impact_changed_set_service_error(
            anyhow::anyhow!("invalid Git ref"),
            &CancellationToken::new(),
        );
        assert!(matches!(ordinary, DepgraphServiceError::GraphQuery { .. }));

        cancellation.cancel();
        let cancelled = impact_changed_set_service_error(
            crate::impact::changed_set_preprocessing_exhausted_for_test(),
            &cancellation,
        );
        assert!(matches!(cancelled, DepgraphServiceError::Cancelled));
    }

    static SERVICE_GRAPH_COUNTER_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_cycle_counters() {
        for counter in [
            &CYCLE_PREPROCESSING_WORK,
            &CYCLE_TRAVERSAL_WORK,
            &CYCLE_FINALIZATION_WORK,
            &CYCLE_ADJACENCY_INSERT_VISITS,
            &CYCLE_COMPONENT_INSERT_VISITS,
            &CYCLE_RESULT_MATERIALIZATION_VISITS,
        ] {
            counter.store(0, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn cycle_snapshot(component_count: usize, component_size: usize) -> GraphSnapshot {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        for component in 0..component_count {
            for index in 0..component_size {
                let id = format!("file:{component:02}:{index:02}");
                nodes.push(NodeRecord {
                    id: id.clone(),
                    kind: "file".to_owned(),
                    locator: format!("id:{id}"),
                    display_name: id,
                    properties: json!({}),
                });
                edges.push(EdgeRecord {
                    id: format!("edge:{component:02}:{index:02}"),
                    site_id: None,
                    source: format!("file:{component:02}:{index:02}"),
                    target: format!("file:{component:02}:{:02}", (index + 1) % component_size),
                    kind: "imports".to_owned(),
                    phase: "source".to_owned(),
                    environment: "host".to_owned(),
                    profile_id: "fixture:profile".to_owned(),
                    resolution_status: "resolved".to_owned(),
                    precision: "exact".to_owned(),
                    condition: json!({"op":"all","conditions":[]}),
                    generated: false,
                });
            }
        }
        GraphSnapshot {
            scan: ScanRecord {
                id: "scan:cycles".to_owned(),
                root: ".".to_owned(),
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
            profile_matrix: Default::default(),
        }
    }

    #[test]
    fn dependency_service_rejects_adjacency_scan_overflow_without_partial_result() {
        let snapshot = cycle_snapshot(1, 3);
        let execution = crate::query::traverse_bounded_filtered_cancellable_with_adjacency_limit(
            &snapshot,
            "id:file:00:00",
            true,
            false,
            &GraphQueryFilter::default(),
            100,
            1,
            || false,
        )
        .expect("bounded query reports its incomplete execution");
        assert!(!execution.complete);
        assert!(matches!(
            ensure_dependency_traversal_complete(&execution),
            Err(DepgraphServiceError::ResourceExhausted)
        ));
    }

    fn unresolved_snapshot(site_count: usize) -> GraphSnapshot {
        let mut snapshot = cycle_snapshot(1, 2);
        snapshot.edges.clear();
        snapshot.sites = (0..site_count)
            .rev()
            .map(|index| {
                serde_json::from_value(json!({
                    "id": format!("site:{index:04}"),
                    "source": "file:00:00",
                    "kind": "import",
                    "specifier": format!("fixture:missing-{index:04}"),
                    "resolution_status": "unresolved",
                    "target_ids": [],
                    "profile_id": "fixture:profile",
                    "condition": {"op":"all","conditions":[]},
                    "precision": "exact",
                    "reason": "not_found"
                }))
                .expect("valid unresolved site")
            })
            .collect();
        snapshot
    }

    fn path_correlation_snapshot(reason_count: usize, phase_count: usize) -> GraphSnapshot {
        let mut snapshot = cycle_snapshot(1, 2);
        snapshot.profile_matrix.correlations = vec![ProfileCorrelationRecord {
            id: "correlation:path".to_owned(),
            effective_profile_id: "effective:path".to_owned(),
            source: "file:00:00".to_owned(),
            kind: "imports".to_owned(),
            specifier: "file:00:01".to_owned(),
            status: "matched".to_owned(),
            condition_union: json!({"op":"all","conditions":[]}),
            conditions_by_phase: BTreeMap::new(),
            targets_by_phase: BTreeMap::new(),
            resolutions_by_phase: BTreeMap::new(),
            site_ids_by_phase: BTreeMap::new(),
            edge_ids_by_phase: BTreeMap::from([(
                "source".to_owned(),
                vec!["edge:00:00".to_owned()],
            )]),
            difference_reasons: (0..reason_count)
                .map(|index| format!("reason-{index:03}"))
                .collect(),
            diagnostic_id: None,
        }];
        let mut phase_coverage = BTreeMap::new();
        for index in 0..phase_count {
            phase_coverage.insert(format!("phase-{index:03}"), PhaseCoverageRecord::default());
        }
        snapshot.profile_matrix.entries = vec![ProfileMatrixEntryRecord {
            id: "effective:path".to_owned(),
            effective_input_id: "effective-input:path".to_owned(),
            language: "rust".to_owned(),
            profile_ids: Vec::new(),
            parent_profile_ids: Vec::new(),
            phases: Vec::new(),
            condition_union: json!({"op":"all","conditions":[]}),
            phase_coverage,
            selection_reasons: Vec::new(),
            axis_conflicts: Vec::new(),
        }];
        snapshot
    }

    fn reconstruct_fixture_path(snapshot: &GraphSnapshot) -> DepgraphServiceResult<Vec<PathStep>> {
        let edge = &snapshot.edges[0];
        let predecessor = HashMap::from([(edge.target.clone(), edge)]);
        reconstruct_path(
            snapshot,
            &GraphQueryFilter::default(),
            &edge.source,
            &edge.target,
            &predecessor,
            &CancellationToken::new(),
        )
    }

    #[test]
    fn path_correlation_public_caps_fail_closed_at_the_service_boundary() {
        let exact = path_correlation_snapshot(
            MAX_UNRESOLVED_CORRELATION_REASONS,
            crate::service_limits::MAX_GRAPH_PHASE_COVERAGE_ITEMS,
        );
        let exact = reconstruct_fixture_path(&exact).expect("exact public caps succeed");
        assert_eq!(exact.len(), 1);
        assert_eq!(
            exact[0].observed_difference_reasons.len(),
            MAX_UNRESOLVED_CORRELATION_REASONS
        );
        assert_eq!(
            exact[0].phase_coverage.len(),
            crate::service_limits::MAX_GRAPH_PHASE_COVERAGE_ITEMS
        );

        let reasons_over = path_correlation_snapshot(
            MAX_UNRESOLVED_CORRELATION_REASONS + 1,
            crate::service_limits::MAX_GRAPH_PHASE_COVERAGE_ITEMS,
        );
        assert!(matches!(
            reconstruct_fixture_path(&reasons_over),
            Err(DepgraphServiceError::ResourceExhausted)
        ));

        let phases_over = path_correlation_snapshot(
            MAX_UNRESOLVED_CORRELATION_REASONS,
            crate::service_limits::MAX_GRAPH_PHASE_COVERAGE_ITEMS + 1,
        );
        assert!(matches!(
            reconstruct_fixture_path(&phases_over),
            Err(DepgraphServiceError::ResourceExhausted)
        ));
    }

    fn matrix_entry(id: &str, sites: u64) -> ProfileMatrixEntryRecord {
        ProfileMatrixEntryRecord {
            id: id.to_owned(),
            effective_input_id: format!("input:{id}"),
            language: "rust".to_owned(),
            profile_ids: vec![id.to_owned()],
            parent_profile_ids: Vec::new(),
            phases: vec!["source".to_owned()],
            condition_union: json!({"op":"all","conditions":[]}),
            phase_coverage: BTreeMap::from([(
                "source".to_owned(),
                PhaseCoverageRecord {
                    sites,
                    ..PhaseCoverageRecord::default()
                },
            )]),
            selection_reasons: Vec::new(),
            axis_conflicts: Vec::new(),
        }
    }

    fn phase_coverage(count: usize) -> BTreeMap<String, PhaseCoverageRecord> {
        (0..count)
            .map(|index| {
                (
                    format!("phase-{index}"),
                    PhaseCoverageRecord {
                        sites: index as u64,
                        ..PhaseCoverageRecord::default()
                    },
                )
            })
            .collect()
    }

    #[test]
    fn phase_coverage_index_is_single_pass_bounded_cancellable_and_first_wins() {
        let _guard = SERVICE_GRAPH_COUNTER_TEST_LOCK
            .lock()
            .expect("phase coverage index test lock");
        let mut entries = (0..128)
            .map(|index| matrix_entry(&format!("profile:{index}"), index as u64))
            .collect::<Vec<_>>();
        entries.insert(1, matrix_entry("profile:0", u64::MAX));
        let initial_work = 7_usize;
        let exact_maximum = initial_work + entries.len();

        PHASE_COVERAGE_INDEX_BUILDS.store(0, std::sync::atomic::Ordering::Relaxed);
        PHASE_COVERAGE_ENTRY_VISITS.store(0, std::sync::atomic::Ordering::Relaxed);
        let mut work = initial_work;
        let index =
            phase_coverage_index_cancellable(&entries, &mut work, exact_maximum, &mut || false)
                .expect("the exact shared work bound must be accepted");
        assert_eq!(work, exact_maximum);
        assert_eq!(
            PHASE_COVERAGE_INDEX_BUILDS.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            PHASE_COVERAGE_ENTRY_VISITS.load(std::sync::atomic::Ordering::Relaxed),
            entries.len()
        );
        assert_eq!(
            index["profile:0"]["source"].sites, 0,
            "duplicate effective profile IDs must retain the first matrix entry"
        );
        for site in 0..10_000 {
            let profile = format!("profile:{}", site % 128);
            assert!(index.contains_key(profile.as_str()));
        }
        assert_eq!(
            PHASE_COVERAGE_ENTRY_VISITS.load(std::sync::atomic::Ordering::Relaxed),
            entries.len(),
            "per-site lookups must not rescan matrix entries"
        );

        let mut over_limit_entries = entries.clone();
        over_limit_entries.push(matrix_entry("profile:over-limit", 1));
        let mut work = initial_work;
        assert!(matches!(
            phase_coverage_index_cancellable(
                &over_limit_entries,
                &mut work,
                exact_maximum,
                &mut || false,
            )
            .expect_err("one entry above the shared work bound must fail closed"),
            DepgraphServiceError::ResourceExhausted
        ));

        PHASE_COVERAGE_ENTRY_VISITS.store(0, std::sync::atomic::Ordering::Relaxed);
        let mut work = 0_usize;
        let mut cancellation_checks = 0_usize;
        assert!(matches!(
            phase_coverage_index_cancellable(&entries, &mut work, entries.len(), &mut || {
                cancellation_checks += 1;
                cancellation_checks >= 4
            },)
            .expect_err("cancellation inside the matrix-entry scan must fail closed"),
            DepgraphServiceError::Cancelled
        ));
        assert_eq!(work, 3);
        assert_eq!(
            PHASE_COVERAGE_ENTRY_VISITS.load(std::sync::atomic::Ordering::Relaxed),
            3
        );
    }

    #[test]
    fn phase_coverage_materialization_uses_one_cumulative_exact_work_bound() {
        let _guard = SERVICE_GRAPH_COUNTER_TEST_LOCK
            .lock()
            .expect("service graph counter test lock");
        let coverage = phase_coverage(8);
        let initial_work = 7_usize;
        let materializations = 16_usize;
        let exact_maximum = initial_work + coverage.len() * materializations;
        let mut work = initial_work;
        {
            let mut never_cancel = || false;
            let mut finalization =
                UnresolvedFinalization::new(&mut work, exact_maximum, &mut never_cancel);
            PHASE_COVERAGE_MATERIALIZATION_VISITS.store(0, std::sync::atomic::Ordering::Relaxed);
            for _ in 0..materializations {
                let cloned = clone_phase_coverage_cancellable(&coverage, &mut finalization)
                    .expect("the exact cumulative phase-materialization bound must be accepted");
                assert_eq!(cloned, coverage);
            }
        }
        assert_eq!(work, exact_maximum);
        assert_eq!(
            PHASE_COVERAGE_MATERIALIZATION_VISITS.load(std::sync::atomic::Ordering::Relaxed),
            coverage.len() * materializations
        );
        {
            let mut never_cancel = || false;
            let mut finalization =
                UnresolvedFinalization::new(&mut work, exact_maximum, &mut never_cancel);
            assert!(matches!(
                clone_phase_coverage_cancellable(&coverage, &mut finalization)
                    .expect_err("the first phase above the cumulative work bound must fail closed"),
                DepgraphServiceError::ResourceExhausted
            ));
        }

        PHASE_COVERAGE_MATERIALIZATION_VISITS.store(0, std::sync::atomic::Ordering::Relaxed);
        let mut work = 0_usize;
        let mut checks = 0_usize;
        {
            let mut cancel_on_fourth_check = || {
                checks += 1;
                checks >= 4
            };
            let mut finalization =
                UnresolvedFinalization::new(&mut work, coverage.len(), &mut cancel_on_fourth_check);
            assert!(matches!(
                clone_phase_coverage_cancellable(&coverage, &mut finalization)
                    .expect_err("cancellation inside phase materialization must fail closed"),
                DepgraphServiceError::Cancelled
            ));
        }
        assert_eq!(work, 3);
        assert_eq!(
            PHASE_COVERAGE_MATERIALIZATION_VISITS.load(std::sync::atomic::Ordering::Relaxed),
            3
        );
    }

    #[test]
    fn correlation_reason_materialization_enforces_cap_budget_order_and_cancellation() {
        let _guard = SERVICE_GRAPH_COUNTER_TEST_LOCK
            .lock()
            .expect("service graph counter test lock");
        let reasons = (0..MAX_UNRESOLVED_CORRELATION_REASONS)
            .map(|index| format!("reason-{index:02}"))
            .collect::<Vec<_>>();
        let initial_work = 5_usize;
        let exact_maximum = initial_work + reasons.len();
        let mut work = initial_work;
        CORRELATION_REASON_MATERIALIZATION_VISITS.store(0, std::sync::atomic::Ordering::Relaxed);
        let cloned = {
            let mut never_cancel = || false;
            let mut finalization =
                UnresolvedFinalization::new(&mut work, exact_maximum, &mut never_cancel);
            clone_correlation_reasons_cancellable(&reasons, &mut finalization)
                .expect("exactly 16 reasons must materialize")
        };
        assert_eq!(cloned, reasons, "reason order must be preserved");
        assert_eq!(work, exact_maximum);
        assert_eq!(
            CORRELATION_REASON_MATERIALIZATION_VISITS.load(std::sync::atomic::Ordering::Relaxed),
            MAX_UNRESOLVED_CORRELATION_REASONS
        );

        let mut over_limit = reasons.clone();
        over_limit.push("reason-over-limit".to_owned());
        let mut work = 0_usize;
        let mut cancellation_checks = 0_usize;
        let mut cancellation = || {
            cancellation_checks += 1;
            false
        };
        {
            let mut finalization =
                UnresolvedFinalization::new(&mut work, usize::MAX, &mut cancellation);
            assert!(matches!(
                clone_correlation_reasons_cancellable(&over_limit, &mut finalization)
                    .expect_err("reason 17 must return no partial vector"),
                DepgraphServiceError::ResourceExhausted
            ));
        }
        assert_eq!(work, 0, "oversize input is rejected before materialization");
        assert_eq!(
            cancellation_checks, 0,
            "oversize input is rejected before iterating"
        );

        CORRELATION_REASON_MATERIALIZATION_VISITS.store(0, std::sync::atomic::Ordering::Relaxed);
        let mut work = 0_usize;
        let mut cancel_during_copy = || {
            CORRELATION_REASON_MATERIALIZATION_VISITS.load(std::sync::atomic::Ordering::Relaxed)
                >= 3
        };
        {
            let mut finalization =
                UnresolvedFinalization::new(&mut work, reasons.len(), &mut cancel_during_copy);
            assert!(matches!(
                clone_correlation_reasons_cancellable(&reasons, &mut finalization)
                    .expect_err("cancellation during reason copy must return no partial vector"),
                DepgraphServiceError::Cancelled
            ));
        }
        assert_eq!(work, 3);
        assert_eq!(
            CORRELATION_REASON_MATERIALIZATION_VISITS.load(std::sync::atomic::Ordering::Relaxed),
            3
        );
    }

    #[test]
    fn unresolved_results_are_incrementally_ordered_tightly_bounded_and_cancellable() {
        let _guard = SERVICE_GRAPH_COUNTER_TEST_LOCK
            .lock()
            .expect("unresolved ordering test lock");
        let site_count = 32_usize;
        let snapshot = unresolved_snapshot(site_count);
        let exact_work = site_count * 3;
        let request = UnresolvedRequest::try_new(Vec::new(), exact_work)
            .expect("exact unresolved work request");
        let reset = || {
            UNRESOLVED_ORDERED_INSERT_VISITS.store(0, std::sync::atomic::Ordering::Relaxed);
            UNRESOLVED_ORDERED_MATERIALIZATION_VISITS
                .store(0, std::sync::atomic::Ordering::Relaxed);
        };

        reset();
        let items = unresolved_bounded_cancellable(&snapshot, &request, &CancellationToken::new())
            .expect("the exact unresolved finalization bound succeeds");
        assert_eq!(items.len(), site_count);
        assert!(
            items
                .windows(2)
                .all(|pair| pair[0].site.id < pair[1].site.id)
        );
        assert_eq!(
            UNRESOLVED_ORDERED_INSERT_VISITS.load(std::sync::atomic::Ordering::Relaxed),
            site_count
        );
        assert_eq!(
            UNRESOLVED_ORDERED_MATERIALIZATION_VISITS.load(std::sync::atomic::Ordering::Relaxed),
            site_count
        );

        let below = UnresolvedRequest::try_new(Vec::new(), exact_work - 1)
            .expect("one-below unresolved work request");
        assert!(matches!(
            unresolved_bounded_cancellable(&snapshot, &below, &CancellationToken::new())
                .expect_err("one finalization work item above the bound returns no result"),
            DepgraphServiceError::ResourceExhausted
        ));

        for (counter, stage) in [
            (&UNRESOLVED_ORDERED_INSERT_VISITS, "ordered insertion"),
            (
                &UNRESOLVED_ORDERED_MATERIALIZATION_VISITS,
                "ordered materialization",
            ),
        ] {
            reset();
            let result = unresolved_bounded_with_cancellation(&snapshot, &request, &mut || {
                counter.load(std::sync::atomic::Ordering::Relaxed) >= 3
            });
            assert!(
                matches!(result, Err(DepgraphServiceError::Cancelled)),
                "stage: {stage}"
            );
            assert_eq!(
                counter.load(std::sync::atomic::Ordering::Relaxed),
                3,
                "stage: {stage}"
            );
        }

        let mut duplicate = unresolved_snapshot(2);
        duplicate.sites.push(duplicate.sites[0].clone());
        let request =
            UnresolvedRequest::try_new(Vec::new(), 100).expect("duplicate-site unresolved request");
        assert!(matches!(
            unresolved_bounded_cancellable(&duplicate, &request, &CancellationToken::new())
                .expect_err("duplicate site IDs must not overwrite an earlier result"),
            DepgraphServiceError::Integrity
        ));
    }

    #[test]
    fn unresolved_phase_aggregation_accepts_four_distinct_and_rejects_the_fifth() {
        let edge = |index: usize, phase: &str| EdgeRecord {
            id: format!("edge:phase:{index}"),
            site_id: Some("site:0000".to_owned()),
            source: "file:00:00".to_owned(),
            target: "file:00:01".to_owned(),
            kind: "imports".to_owned(),
            phase: phase.to_owned(),
            environment: "host".to_owned(),
            profile_id: "fixture:profile".to_owned(),
            resolution_status: "unresolved".to_owned(),
            precision: "exact".to_owned(),
            condition: json!({"op":"all","conditions":[]}),
            generated: false,
        };
        let request = UnresolvedRequest::try_new(Vec::new(), 100).expect("bounded request");
        let mut exact = unresolved_snapshot(1);
        exact.edges = ["source", "semantic", "build", "runtime", "source"]
            .into_iter()
            .enumerate()
            .map(|(index, phase)| edge(index, phase))
            .collect();
        let items = unresolved_bounded_cancellable(&exact, &request, &CancellationToken::new())
            .expect("four distinct phases and a duplicate succeed");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].phases.len(), MAX_UNRESOLVED_PHASES);

        let mut over = exact;
        over.edges.push(edge(over.edges.len(), "fifth"));
        assert!(matches!(
            unresolved_bounded_cancellable(&over, &request, &CancellationToken::new()),
            Err(DepgraphServiceError::ResourceExhausted)
        ));
    }

    #[test]
    fn path_endpoints_are_scanned_once_only_when_steps_exist_and_are_tightly_bounded() {
        let _guard = SERVICE_GRAPH_COUNTER_TEST_LOCK
            .lock()
            .expect("path endpoint test lock");
        let node_count = 128_usize;
        let mut snapshot = cycle_snapshot(1, 2);
        snapshot.edges.clear();
        snapshot.nodes = (0..node_count)
            .map(|index| NodeRecord {
                id: format!("path:{index:04}"),
                kind: "file".to_owned(),
                locator: format!("id:path:{index:04}"),
                display_name: format!("path-{index:04}"),
                properties: json!({}),
            })
            .collect();
        let from = snapshot.nodes[0].clone();
        let to = snapshot.nodes[node_count - 1].clone();
        let reset = || {
            PATH_ENDPOINT_WORK_ITEMS.store(0, std::sync::atomic::Ordering::Relaxed);
            PATH_ENDPOINT_NODE_SCAN_VISITS.store(0, std::sync::atomic::Ordering::Relaxed);
            PATH_ENDPOINT_ITEM_MATERIALIZATION_VISITS
                .store(0, std::sync::atomic::Ordering::Relaxed);
        };

        let zero_request = ExplainPathRequest::try_new(
            format!("id:{}", from.id),
            format!("id:{}", from.id),
            GraphQueryFilter::default(),
            1_000,
        )
        .expect("zero-step request");
        let (zero_step, traversed) =
            explain_path_bounded(&snapshot, &zero_request, &CancellationToken::new())
                .expect("zero-step service path");
        assert_eq!(traversed, 0);
        assert!(zero_step.steps.is_empty());
        reset();
        let items = path_page_items_with_limit(&snapshot, &zero_step, 1, &mut || false)
            .expect("zero-step path needs no snapshot-wide endpoint index");
        assert!(items.is_empty());
        assert_eq!(
            PATH_ENDPOINT_NODE_SCAN_VISITS.load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            PATH_ENDPOINT_WORK_ITEMS.load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        let path = WhyResult {
            from: from.clone(),
            to: to.clone(),
            path_found: true,
            steps: vec![PathStep {
                edge: EdgeRecord {
                    id: "edge:path".to_owned(),
                    site_id: None,
                    source: from.id.clone(),
                    target: to.id.clone(),
                    kind: "imports".to_owned(),
                    phase: "source".to_owned(),
                    environment: "host".to_owned(),
                    profile_id: "fixture:profile".to_owned(),
                    resolution_status: "resolved".to_owned(),
                    precision: "exact".to_owned(),
                    condition: json!({"op":"all","conditions":[]}),
                    generated: false,
                },
                condition_text: "all".to_owned(),
                evidence: Vec::new(),
                effective_profile_id: None,
                correlation_status: None,
                observed_difference_reasons: Vec::new(),
                phase_coverage: BTreeMap::new(),
            }],
        };
        let exact_work = node_count + 4;
        reset();
        let items = path_page_items_with_limit(&snapshot, &path, exact_work, &mut || false)
            .expect("the exact endpoint work bound succeeds");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].source.id, from.id);
        assert_eq!(items[0].target.id, to.id);
        assert_eq!(
            PATH_ENDPOINT_NODE_SCAN_VISITS.load(std::sync::atomic::Ordering::Relaxed),
            node_count
        );
        assert_eq!(
            PATH_ENDPOINT_WORK_ITEMS.load(std::sync::atomic::Ordering::Relaxed),
            exact_work
        );

        reset();
        assert!(matches!(
            path_page_items_with_limit(&snapshot, &path, exact_work - 1, &mut || false)
                .expect_err("one endpoint work item above the bound returns no path items"),
            DepgraphServiceError::ResourceExhausted
        ));

        reset();
        assert!(matches!(
            path_page_items_with_limit(&snapshot, &path, exact_work, &mut || {
                PATH_ENDPOINT_NODE_SCAN_VISITS.load(std::sync::atomic::Ordering::Relaxed) >= 3
            })
            .expect_err("cancellation during endpoint scanning returns no path items"),
            DepgraphServiceError::Cancelled
        ));
        assert_eq!(
            PATH_ENDPOINT_NODE_SCAN_VISITS.load(std::sync::atomic::Ordering::Relaxed),
            3
        );
    }

    #[test]
    fn cycle_ordered_construction_is_tightly_bounded_canonical_and_cancellable() {
        let _guard = SERVICE_GRAPH_COUNTER_TEST_LOCK
            .lock()
            .expect("cycle ordering test lock");
        let snapshot = cycle_snapshot(6, 4);
        let generous =
            CyclesRequest::try_new(CycleLevel::File, 10_000).expect("valid generous cycle request");

        reset_cycle_counters();
        let expected = cycles_bounded_with_cancellation(&snapshot, &generous, &mut || false)
            .expect("ordered cycle construction succeeds");
        assert_eq!(expected.len(), 6);
        for (component, cycle) in expected.iter().enumerate() {
            assert_eq!(
                cycle.node_ids,
                [
                    format!("file:{component:02}:00"),
                    format!("file:{component:02}:01"),
                    format!("file:{component:02}:02"),
                    format!("file:{component:02}:03"),
                    format!("file:{component:02}:00"),
                ]
            );
        }
        let exact_maximum = [
            CYCLE_PREPROCESSING_WORK.load(std::sync::atomic::Ordering::Relaxed),
            CYCLE_TRAVERSAL_WORK.load(std::sync::atomic::Ordering::Relaxed),
            CYCLE_FINALIZATION_WORK.load(std::sync::atomic::Ordering::Relaxed),
        ]
        .into_iter()
        .max()
        .expect("three cycle phases");

        reset_cycle_counters();
        let exact_request = CyclesRequest::try_new(CycleLevel::File, exact_maximum)
            .expect("exact cycle work request");
        let exact = cycles_bounded_with_cancellation(&snapshot, &exact_request, &mut || false)
            .expect("the exact largest phase work bound succeeds");
        assert_eq!(exact.len(), expected.len());
        for (actual, expected) in exact.iter().zip(&expected) {
            assert_eq!(actual.level, expected.level);
            assert_eq!(actual.node_ids, expected.node_ids);
        }

        reset_cycle_counters();
        let below_request = CyclesRequest::try_new(CycleLevel::File, exact_maximum - 1)
            .expect("one-below cycle work request");
        assert!(matches!(
            cycles_bounded_with_cancellation(&snapshot, &below_request, &mut || false)
                .expect_err("one work item above a phase bound returns no cycles"),
            DepgraphServiceError::ResourceExhausted
        ));

        for (counter, stage) in [
            (&CYCLE_ADJACENCY_INSERT_VISITS, "adjacency insertion"),
            (&CYCLE_COMPONENT_INSERT_VISITS, "component insertion"),
            (
                &CYCLE_RESULT_MATERIALIZATION_VISITS,
                "result materialization",
            ),
        ] {
            reset_cycle_counters();
            let result = cycles_bounded_with_cancellation(&snapshot, &generous, &mut || {
                counter.load(std::sync::atomic::Ordering::Relaxed) >= 3
            });
            assert!(
                matches!(result, Err(DepgraphServiceError::Cancelled)),
                "stage: {stage}"
            );
            assert_eq!(
                counter.load(std::sync::atomic::Ordering::Relaxed),
                3,
                "stage: {stage}"
            );
        }
    }
}
