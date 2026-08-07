use std::collections::BTreeMap;

pub use depgraph_store::CoverageRecord;
use depgraph_store::{
    CompletedSnapshotDetails, NodeSummaryRecord, NodeTextMatch, SnapshotNameRecord,
};
use serde::Serialize;

use crate::CancellationToken;
use crate::service::{
    DepgraphCapability, DepgraphService, DepgraphServiceError, DepgraphServiceResult,
    ResolvedSnapshotId, SnapshotLocator,
};

pub const MAX_FIND_NODES_QUERY_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeMatchMode {
    Exact,
    Prefix,
    Contains,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeProjection {
    id: String,
    kind: String,
    locator: String,
    display_name: String,
}

impl NodeProjection {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    #[must_use]
    pub fn locator(&self) -> &str {
        &self.locator
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindNodesResult {
    snapshot_id: ResolvedSnapshotId,
    nodes: Vec<NodeProjection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindNodesPageResult {
    snapshot_id: ResolvedSnapshotId,
    nodes: Vec<NodeProjection>,
    total_items: u64,
}

impl FindNodesPageResult {
    #[must_use]
    pub const fn snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub fn nodes(&self) -> &[NodeProjection] {
        &self.nodes
    }

    #[must_use]
    pub const fn total_items(&self) -> u64 {
        self.total_items
    }
}

impl FindNodesResult {
    #[must_use]
    pub const fn snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub fn nodes(&self) -> &[NodeProjection] {
        &self.nodes
    }
}

impl From<NodeSummaryRecord> for NodeProjection {
    fn from(node: NodeSummaryRecord) -> Self {
        Self {
            id: node.id,
            kind: node.kind,
            locator: node.locator,
            display_name: node.display_name,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedSnapshotView {
    id: String,
    names: Vec<String>,
    status: String,
    source_kind: String,
    source_attempt_id: String,
    scan_id: String,
    build_attempt_id: Option<String>,
    runtime_import_id: Option<String>,
    runtime_session_ids: Vec<String>,
    parent_snapshot_id: Option<String>,
    source_revision: Option<String>,
    profile_ids: Vec<String>,
    created_at: String,
    coverage: CoverageRecord,
}

impl CompletedSnapshotView {
    fn from_store(details: CompletedSnapshotDetails) -> DepgraphServiceResult<Self> {
        let snapshot = details.snapshot;
        if snapshot.status != "completed" {
            return Err(DepgraphServiceError::Integrity);
        }
        Ok(Self {
            id: snapshot.id,
            names: details.names,
            status: snapshot.status,
            source_kind: snapshot.source_kind,
            source_attempt_id: snapshot.source_attempt_id,
            scan_id: snapshot.scan_id,
            build_attempt_id: snapshot.build_attempt_id,
            runtime_import_id: snapshot.runtime_import_id,
            runtime_session_ids: snapshot.runtime_session_ids,
            parent_snapshot_id: snapshot.parent_snapshot_id,
            source_revision: snapshot.source_revision,
            profile_ids: snapshot.profile_ids,
            created_at: snapshot.created_at,
            coverage: details.coverage,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.names
    }

    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }

    #[must_use]
    pub fn source_kind(&self) -> &str {
        &self.source_kind
    }

    #[must_use]
    pub fn source_attempt_id(&self) -> &str {
        &self.source_attempt_id
    }

    #[must_use]
    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    #[must_use]
    pub fn build_attempt_id(&self) -> Option<&str> {
        self.build_attempt_id.as_deref()
    }

    #[must_use]
    pub fn runtime_import_id(&self) -> Option<&str> {
        self.runtime_import_id.as_deref()
    }

    #[must_use]
    pub fn runtime_session_ids(&self) -> &[String] {
        &self.runtime_session_ids
    }

    #[must_use]
    pub fn parent_snapshot_id(&self) -> Option<&str> {
        self.parent_snapshot_id.as_deref()
    }

    #[must_use]
    pub fn source_revision(&self) -> Option<&str> {
        self.source_revision.as_deref()
    }

    #[must_use]
    pub fn profile_ids(&self) -> &[String] {
        &self.profile_ids
    }

    #[must_use]
    pub fn created_at(&self) -> &str {
        &self.created_at
    }

    #[must_use]
    pub const fn coverage(&self) -> &CoverageRecord {
        &self.coverage
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamedCompletedSnapshot {
    name: String,
    named_at: String,
    #[serde(flatten)]
    snapshot: CompletedSnapshotView,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedSnapshotsPage {
    snapshots: Vec<NamedCompletedSnapshot>,
    total_items: u64,
}

impl CompletedSnapshotsPage {
    #[must_use]
    pub fn snapshots(&self) -> &[NamedCompletedSnapshot] {
        &self.snapshots
    }

    #[must_use]
    pub const fn total_items(&self) -> u64 {
        self.total_items
    }
}

impl NamedCompletedSnapshot {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn named_at(&self) -> &str {
        &self.named_at
    }

    #[must_use]
    pub const fn snapshot(&self) -> &CompletedSnapshotView {
        &self.snapshot
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CurrentSnapshotAvailability {
    Available,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentSnapshot {
    details: Option<CompletedSnapshotView>,
}

impl CurrentSnapshot {
    fn unavailable() -> Self {
        Self { details: None }
    }

    fn available(details: CompletedSnapshotView) -> Self {
        Self {
            details: Some(details),
        }
    }

    #[must_use]
    pub const fn availability(&self) -> CurrentSnapshotAvailability {
        if self.details.is_some() {
            CurrentSnapshotAvailability::Available
        } else {
            CurrentSnapshotAvailability::Unavailable
        }
    }

    #[must_use]
    pub const fn details(&self) -> Option<&CompletedSnapshotView> {
        self.details.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepgraphContext {
    repository_id: String,
    enabled_capabilities: Vec<DepgraphCapability>,
    current_snapshot: CurrentSnapshot,
}

impl DepgraphContext {
    #[must_use]
    pub fn repository_id(&self) -> &str {
        &self.repository_id
    }

    #[must_use]
    pub fn enabled_capabilities(&self) -> &[DepgraphCapability] {
        &self.enabled_capabilities
    }

    #[must_use]
    pub const fn current_snapshot(&self) -> &CurrentSnapshot {
        &self.current_snapshot
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceProjection {
    kind: String,
    extractor: String,
    extractor_version: String,
    path: String,
    start_line: u64,
    start_column: u64,
    end_line: u64,
    end_column: u64,
}

impl EvidenceProjection {
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }
    #[must_use]
    pub fn extractor(&self) -> &str {
        &self.extractor
    }
    #[must_use]
    pub fn extractor_version(&self) -> &str {
        &self.extractor_version
    }
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
    #[must_use]
    pub const fn start_line(&self) -> u64 {
        self.start_line
    }
    #[must_use]
    pub const fn start_column(&self) -> u64 {
        self.start_column
    }
    #[must_use]
    pub const fn end_line(&self) -> u64 {
        self.end_line
    }
    #[must_use]
    pub const fn end_column(&self) -> u64 {
        self.end_column
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteProjection {
    id: String,
    source: String,
    kind: String,
    specifier: Option<String>,
    profile_id: String,
    resolution_status: String,
    target_ids: Vec<String>,
    reason: Option<String>,
    evidence: Vec<EvidenceProjection>,
}
impl SiteProjection {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }
    #[must_use]
    pub fn specifier(&self) -> Option<&str> {
        self.specifier.as_deref()
    }
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }
    #[must_use]
    pub fn resolution_status(&self) -> &str {
        &self.resolution_status
    }
    #[must_use]
    pub fn target_ids(&self) -> &[String] {
        &self.target_ids
    }
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
    #[must_use]
    pub fn evidence(&self) -> &[EvidenceProjection] {
        &self.evidence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeProjection {
    id: String,
    site_id: Option<String>,
    source: String,
    target: String,
    kind: String,
    phase: String,
    profile_id: String,
    resolution_status: String,
    precision: String,
    condition: String,
    evidence: Vec<EvidenceProjection>,
}
impl EdgeProjection {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn site_id(&self) -> Option<&str> {
        self.site_id.as_deref()
    }
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }
    #[must_use]
    pub fn phase(&self) -> &str {
        &self.phase
    }
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }
    #[must_use]
    pub fn resolution_status(&self) -> &str {
        &self.resolution_status
    }
    #[must_use]
    pub fn precision(&self) -> &str {
        &self.precision
    }
    #[must_use]
    pub fn condition(&self) -> &str {
        &self.condition
    }
    #[must_use]
    pub fn evidence(&self) -> &[EvidenceProjection] {
        &self.evidence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EdgeDirection {
    Incoming,
    Outgoing,
    Both,
}

macro_rules! graph_page {
    ($name:ident, $item:ty) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            snapshot_id: ResolvedSnapshotId,
            items: Vec<$item>,
            total_items: u64,
        }
        impl $name {
            fn new(snapshot_id: ResolvedSnapshotId, items: Vec<$item>, total_items: u64) -> Self {
                Self {
                    snapshot_id,
                    items,
                    total_items,
                }
            }
            #[must_use]
            pub const fn snapshot_id(&self) -> &ResolvedSnapshotId {
                &self.snapshot_id
            }
            #[must_use]
            pub fn items(&self) -> &[$item] {
                &self.items
            }
            #[must_use]
            pub const fn total_items(&self) -> u64 {
                self.total_items
            }
        }
    };
}
graph_page!(GraphSitesPageResult, SiteProjection);
graph_page!(GraphEdgesPageResult, EdgeProjection);
graph_page!(GraphEvidencePageResult, EvidenceProjection);

impl DepgraphService {
    pub fn get_context(&self) -> DepgraphServiceResult<DepgraphContext> {
        self.get_context_cancellable(&CancellationToken::new())
    }

    pub fn get_context_cancellable(
        &self,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<DepgraphContext> {
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let mut read_store = self.read_store_factory().open()?;
        let cancellation_check = cancellation.clone();
        let current = read_store.store().interruptible_read(
            move || cancellation_check.is_cancelled(),
            |store| {
                let snapshot_id = store.current_snapshot_id()?;
                snapshot_id
                    .map(|snapshot_id| store.completed_snapshot_details(&snapshot_id))
                    .transpose()
            },
        );
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let current = current.map_err(DepgraphServiceError::store_operation)?;
        let current_snapshot = match current {
            Some(details) => {
                CurrentSnapshot::available(CompletedSnapshotView::from_store(details)?)
            }
            None => CurrentSnapshot::unavailable(),
        };
        Ok(DepgraphContext {
            repository_id: self.config().logical_repository_id().to_owned(),
            enabled_capabilities: self.config().capabilities().iter().collect(),
            current_snapshot,
        })
    }

    pub fn find_nodes(
        &self,
        snapshot: &SnapshotLocator,
        query: &str,
        match_mode: NodeMatchMode,
    ) -> DepgraphServiceResult<FindNodesResult> {
        validate_find_nodes_query(query)?;
        let cancellation = CancellationToken::new();
        let snapshot_id = self.resolve_snapshot_id_cancellable(snapshot, &cancellation)?;
        let page_size = self.config().limits().max_page_items();
        let mut offset = 0usize;
        let mut nodes = Vec::new();
        loop {
            let page = self.find_nodes_page(
                &snapshot_id,
                query,
                match_mode,
                &[],
                offset,
                page_size,
                &cancellation,
            )?;
            let returned = page.nodes.len();
            nodes.extend(page.nodes);
            offset = offset
                .checked_add(returned)
                .ok_or(DepgraphServiceError::ResourceExhausted)?;
            if u64::try_from(offset).map_err(|_| DepgraphServiceError::ResourceExhausted)?
                >= page.total_items
            {
                break;
            }
            if returned == 0 {
                return Err(DepgraphServiceError::Integrity);
            }
        }
        Ok(FindNodesResult { snapshot_id, nodes })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn find_nodes_page(
        &self,
        snapshot_id: &ResolvedSnapshotId,
        query: &str,
        match_mode: NodeMatchMode,
        kinds: &[String],
        offset: usize,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<FindNodesPageResult> {
        validate_find_nodes_query(query)?;
        validate_page_limit(self, limit)?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let mut read_store = self.read_store_factory().open()?;
        let cancellation_check = cancellation.clone();
        let page = read_store.store().find_completed_snapshot_nodes_page(
            snapshot_id.as_str(),
            query,
            match match_mode {
                NodeMatchMode::Exact => NodeTextMatch::Exact,
                NodeMatchMode::Prefix => NodeTextMatch::Prefix,
                NodeMatchMode::Contains => NodeTextMatch::Contains,
            },
            kinds,
            offset,
            limit,
            move || cancellation_check.is_cancelled(),
        );
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let page = page.map_err(DepgraphServiceError::store_operation)?;
        Ok(FindNodesPageResult {
            snapshot_id: snapshot_id.clone(),
            nodes: page.items.into_iter().map(Into::into).collect(),
            total_items: page.total_items,
        })
    }

    pub fn list_completed_snapshots(&self) -> DepgraphServiceResult<Vec<NamedCompletedSnapshot>> {
        let mut read_store = self.read_store_factory().open()?;
        let names = read_store
            .store()
            .snapshot_names()
            .map_err(DepgraphServiceError::store_operation)?;
        let mut details_by_id = BTreeMap::<String, CompletedSnapshotDetails>::new();
        names
            .into_iter()
            .map(|named| {
                let details = if let Some(details) = details_by_id.get(&named.snapshot_id) {
                    details.clone()
                } else {
                    let details = read_store
                        .store()
                        .completed_snapshot_details(&named.snapshot_id)
                        .map_err(DepgraphServiceError::store_operation)?;
                    details_by_id.insert(named.snapshot_id.clone(), details.clone());
                    details
                };
                let snapshot = CompletedSnapshotView::from_store(details)?;
                Ok(NamedCompletedSnapshot {
                    name: named.name,
                    named_at: named.named_at,
                    snapshot,
                })
            })
            .collect()
    }

    pub fn list_completed_snapshots_page(
        &self,
        offset: usize,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<CompletedSnapshotsPage> {
        validate_page_limit(self, limit)?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let mut read_store = self.read_store_factory().open()?;
        let cancellation_check = cancellation.clone();
        let names = read_store
            .store()
            .snapshot_names_page(offset, limit, move || cancellation_check.is_cancelled());
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let names = names.map_err(DepgraphServiceError::store_operation)?;
        let cancellation_check = cancellation.clone();
        let detail_rows: anyhow::Result<Vec<(SnapshotNameRecord, CompletedSnapshotDetails)>> =
            read_store.store().interruptible_read(
                move || cancellation_check.is_cancelled(),
                |store| {
                    let mut details_by_id = BTreeMap::<String, CompletedSnapshotDetails>::new();
                    let mut rows = Vec::with_capacity(names.items.len());
                    for named in names.items {
                        let details = if let Some(details) = details_by_id.get(&named.snapshot_id) {
                            details.clone()
                        } else {
                            let details = store.completed_snapshot_details(&named.snapshot_id)?;
                            details_by_id.insert(named.snapshot_id.clone(), details.clone());
                            details
                        };
                        rows.push((named, details));
                    }
                    Ok(rows)
                },
            );
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let snapshots = detail_rows
            .map_err(DepgraphServiceError::store_operation)?
            .into_iter()
            .map(|(named, details)| {
                Ok(NamedCompletedSnapshot {
                    name: named.name,
                    named_at: named.named_at,
                    snapshot: CompletedSnapshotView::from_store(details)?,
                })
            })
            .collect::<DepgraphServiceResult<Vec<_>>>()?;
        Ok(CompletedSnapshotsPage {
            snapshots,
            total_items: names.total_items,
        })
    }

    pub fn show_completed_snapshot(
        &self,
        snapshot: &SnapshotLocator,
    ) -> DepgraphServiceResult<CompletedSnapshotView> {
        self.show_completed_snapshot_cancellable(snapshot, &CancellationToken::new())
    }

    pub fn show_completed_snapshot_cancellable(
        &self,
        snapshot: &SnapshotLocator,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<CompletedSnapshotView> {
        let mut request = self.start_snapshot_request_at_cancellable(snapshot, cancellation)?;
        let snapshot_id = request.snapshot_id().to_string();
        let cancellation_check = cancellation.clone();
        let details = request.store().interruptible_read(
            move || cancellation_check.is_cancelled(),
            |store| store.completed_snapshot_details(&snapshot_id),
        );
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        CompletedSnapshotView::from_store(details.map_err(DepgraphServiceError::store_operation)?)
    }

    pub fn list_sites_page(
        &self,
        snapshot_id: &ResolvedSnapshotId,
        node_id: Option<&str>,
        offset: usize,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<GraphSitesPageResult> {
        validate_page_limit(self, limit)?;
        let snapshot = self.load_agent_snapshot(snapshot_id, cancellation)?;
        let mut items = snapshot
            .sites
            .into_iter()
            .filter(|site| node_id.is_none_or(|id| site.source == id))
            .map(|site| {
                let mut evidence = site_evidence(&snapshot.evidence, "site", &site.id);
                evidence.sort_by(evidence_order);
                SiteProjection {
                    id: site.id,
                    source: site.source,
                    kind: site.kind,
                    specifier: site.specifier,
                    profile_id: site.profile_id,
                    resolution_status: site.resolution_status,
                    target_ids: site.target_ids,
                    reason: site.reason,
                    evidence,
                }
            })
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.id.cmp(&right.id));
        graph_page_from_items(snapshot_id, items, offset, limit, GraphSitesPageResult::new)
    }

    pub fn list_edges_page(
        &self,
        snapshot_id: &ResolvedSnapshotId,
        node_id: &str,
        direction: EdgeDirection,
        offset: usize,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<GraphEdgesPageResult> {
        validate_page_limit(self, limit)?;
        let snapshot = self.load_agent_snapshot(snapshot_id, cancellation)?;
        let mut items = snapshot
            .edges
            .into_iter()
            .filter(|edge| match direction {
                EdgeDirection::Incoming => edge.target == node_id,
                EdgeDirection::Outgoing => edge.source == node_id,
                EdgeDirection::Both => edge.source == node_id || edge.target == node_id,
            })
            .map(|edge| {
                let mut evidence = site_evidence(&snapshot.evidence, "edge", &edge.id);
                evidence.sort_by(evidence_order);
                EdgeProjection {
                    id: edge.id,
                    site_id: edge.site_id,
                    source: edge.source,
                    target: edge.target,
                    kind: edge.kind,
                    phase: edge.phase,
                    profile_id: edge.profile_id,
                    resolution_status: edge.resolution_status,
                    precision: edge.precision,
                    condition: crate::query::render_condition(&edge.condition),
                    evidence,
                }
            })
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.id.cmp(&right.id));
        graph_page_from_items(snapshot_id, items, offset, limit, GraphEdgesPageResult::new)
    }

    pub fn list_site_evidence_page(
        &self,
        snapshot_id: &ResolvedSnapshotId,
        site_id: &str,
        offset: usize,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<GraphEvidencePageResult> {
        validate_page_limit(self, limit)?;
        let snapshot = self.load_agent_snapshot(snapshot_id, cancellation)?;
        if !snapshot.sites.iter().any(|site| site.id == site_id) {
            return Err(DepgraphServiceError::NotFound);
        }
        let mut items = site_evidence(&snapshot.evidence, "site", site_id);
        items.sort_by(evidence_order);
        graph_page_from_items(
            snapshot_id,
            items,
            offset,
            limit,
            GraphEvidencePageResult::new,
        )
    }

    fn load_agent_snapshot(
        &self,
        snapshot_id: &ResolvedSnapshotId,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<depgraph_store::GraphSnapshot> {
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let mut read_store = self.read_store_factory().open()?;
        let cancellation_check = cancellation.clone();
        let snapshot = read_store.store().interruptible_read(
            move || cancellation_check.is_cancelled(),
            |store| store.load_completed_snapshot(snapshot_id.as_str()),
        );
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        snapshot.map_err(DepgraphServiceError::store_operation)
    }
}

fn evidence_projection(record: &depgraph_store::EvidenceRecord) -> EvidenceProjection {
    EvidenceProjection {
        kind: record.kind.clone(),
        extractor: record.extractor.clone(),
        extractor_version: record.extractor_version.clone(),
        path: record.path.clone(),
        start_line: record.start_line,
        start_column: record.start_column,
        end_line: record.end_line,
        end_column: record.end_column,
    }
}

fn site_evidence(
    records: &[depgraph_store::EvidenceRecord],
    owner_type: &str,
    owner_id: &str,
) -> Vec<EvidenceProjection> {
    records
        .iter()
        .filter(|record| record.owner_type == owner_type && record.owner_id == owner_id)
        .map(evidence_projection)
        .collect()
}

fn evidence_order(left: &EvidenceProjection, right: &EvidenceProjection) -> std::cmp::Ordering {
    (
        &left.path,
        left.start_line,
        left.start_column,
        left.end_line,
        left.end_column,
        &left.extractor,
        &left.extractor_version,
        &left.kind,
    )
        .cmp(&(
            &right.path,
            right.start_line,
            right.start_column,
            right.end_line,
            right.end_column,
            &right.extractor,
            &right.extractor_version,
            &right.kind,
        ))
}

fn graph_page_from_items<T, R>(
    snapshot_id: &ResolvedSnapshotId,
    mut items: Vec<T>,
    offset: usize,
    limit: usize,
    build: impl FnOnce(ResolvedSnapshotId, Vec<T>, u64) -> R,
) -> DepgraphServiceResult<R> {
    let total_items =
        u64::try_from(items.len()).map_err(|_| DepgraphServiceError::ResourceExhausted)?;
    let end = offset
        .checked_add(limit)
        .ok_or(DepgraphServiceError::ResourceExhausted)?
        .min(items.len());
    if offset > items.len() {
        items.clear();
    } else {
        items = items.drain(offset..end).collect();
    }
    Ok(build(snapshot_id.clone(), items, total_items))
}

fn validate_find_nodes_query(query: &str) -> DepgraphServiceResult<()> {
    if query.is_empty() || query.len() > MAX_FIND_NODES_QUERY_BYTES {
        return Err(DepgraphServiceError::InvalidInput);
    }
    Ok(())
}

fn validate_page_limit(service: &DepgraphService, limit: usize) -> DepgraphServiceResult<()> {
    if limit == 0 || limit > service.config().limits().max_page_items() {
        return Err(DepgraphServiceError::InvalidInput);
    }
    Ok(())
}
