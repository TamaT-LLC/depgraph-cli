use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

pub use depgraph_store::CoverageRecord;
use depgraph_store::{
    CompletedSnapshotDetails, NodeSummaryRecord, NodeTextMatch, SnapshotNameRecord,
};
use serde::Serialize;

use crate::CancellationToken;
use crate::edge_kind_selection::EdgeKindFilter;
use crate::import_evidence::{ImportEvidence, ImportSiteHint, project_import_evidence};
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

/// One node with its effective properties.
///
/// Node pages (`NodeProjection`) carry only the public identity fields. A
/// single-node read also needs the properties, for example the `path` of a
/// Web file node whose locator is `file://…` (Issue #601).
#[derive(Clone, Debug, PartialEq)]
pub struct NodeDetailProjection {
    node: NodeProjection,
    properties: serde_json::Value,
}

impl NodeDetailProjection {
    #[must_use]
    pub const fn node(&self) -> &NodeProjection {
        &self.node
    }

    #[must_use]
    pub const fn properties(&self) -> &serde_json::Value {
        &self.properties
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
    pub(crate) fn from_store(details: CompletedSnapshotDetails) -> DepgraphServiceResult<Self> {
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
    pub(crate) fn from_created_name(
        name: String,
        named_at: String,
        snapshot: CompletedSnapshotView,
    ) -> Self {
        Self {
            name,
            named_at,
            snapshot,
        }
    }

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
    import: Option<ImportEvidence>,
}

impl EvidenceProjection {
    /// Allowlisted import facts (Issue #544); `None` for non-import evidence.
    #[must_use]
    pub const fn import(&self) -> Option<&ImportEvidence> {
        self.import.as_ref()
    }
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
        if snapshot_id.is_attempt() {
            let cancellation_check = cancellation.clone();
            let snapshot = read_store.store().interruptible_read(
                move || cancellation_check.is_cancelled(),
                |store| {
                    let attempt_id = snapshot_id
                        .attempt_id()
                        .ok_or_else(|| anyhow::anyhow!("invalid partial attempt identity"))?;
                    store.load_snapshot(attempt_id)
                },
            );
            if cancellation.is_cancelled() {
                return Err(DepgraphServiceError::Cancelled);
            }
            let snapshot = snapshot.map_err(DepgraphServiceError::store_operation)?;
            let mut items = snapshot
                .nodes
                .into_iter()
                .filter(|node| kinds.is_empty() || kinds.iter().any(|kind| kind == &node.kind))
                .filter(|node| {
                    let matches = |value: &str| match match_mode {
                        NodeMatchMode::Exact => value == query,
                        NodeMatchMode::Prefix => value.starts_with(query),
                        NodeMatchMode::Contains => value.contains(query),
                    };
                    matches(&node.id)
                        || matches(&node.kind)
                        || matches(&node.locator)
                        || matches(&node.display_name)
                })
                .map(|node| NodeSummaryRecord {
                    id: node.id,
                    kind: node.kind,
                    locator: node.locator,
                    display_name: node.display_name,
                })
                .collect::<Vec<_>>();
            items.sort_by(|left, right| left.id.cmp(&right.id));
            let total_items =
                u64::try_from(items.len()).map_err(|_| DepgraphServiceError::ResourceExhausted)?;
            let end = offset
                .checked_add(limit)
                .ok_or(DepgraphServiceError::ResourceExhausted)?
                .min(items.len());
            let items = if offset >= items.len() {
                Vec::new()
            } else {
                items.drain(offset..end).collect()
            };
            return Ok(FindNodesPageResult {
                snapshot_id: snapshot_id.clone(),
                nodes: items.into_iter().map(Into::into).collect(),
                total_items,
            });
        }
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

    /// Read one node by exact id together with its effective properties.
    ///
    /// The node is matched with the node page query in the same read as its
    /// properties, so the snapshot projection is validated exactly as for a
    /// node page (Issue #601).
    pub fn get_node(
        &self,
        snapshot_id: &ResolvedSnapshotId,
        node_id: &str,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<NodeDetailProjection> {
        validate_find_nodes_query(node_id)?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let mut read_store = self.read_store_factory().open()?;
        let cancellation_check = cancellation.clone();
        let node = if snapshot_id.is_attempt() {
            read_store.store().interruptible_read(
                move || cancellation_check.is_cancelled(),
                |store| {
                    let attempt_id = snapshot_id
                        .attempt_id()
                        .ok_or_else(|| anyhow::anyhow!("invalid partial attempt identity"))?;
                    let mut matches = store
                        .load_snapshot(attempt_id)?
                        .nodes
                        .into_iter()
                        .filter(|node| node.id == node_id);
                    let node = matches.next();
                    if matches.next().is_some() {
                        anyhow::bail!("partial snapshot projects node {node_id} more than once");
                    }
                    Ok(node)
                },
            )
        } else {
            read_store.store().find_completed_snapshot_node(
                snapshot_id.as_str(),
                node_id,
                move || cancellation_check.is_cancelled(),
            )
        };
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let node = node
            .map_err(DepgraphServiceError::store_operation)?
            .ok_or(DepgraphServiceError::NotFound)?;
        Ok(NodeDetailProjection {
            node: NodeProjection {
                id: node.id,
                kind: node.kind,
                locator: node.locator,
                display_name: node.display_name,
            },
            properties: node.properties,
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

    /// Lists dependency sites, optionally narrowed to one source node and/or
    /// one site ID. An unknown `site_id` yields an empty page.
    pub fn list_sites_page(
        &self,
        snapshot_id: &ResolvedSnapshotId,
        node_id: Option<&str>,
        site_id: Option<&str>,
        offset: usize,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<GraphSitesPageResult> {
        validate_page_limit(self, limit)?;
        let snapshot = self.load_agent_snapshot(snapshot_id, cancellation)?;
        let (items, total_items) = sites_page_items(
            &snapshot.sites,
            &snapshot.evidence,
            node_id,
            site_id,
            offset,
            limit,
        )?;
        Ok(GraphSitesPageResult::new(
            snapshot_id.clone(),
            items,
            total_items,
        ))
    }

    /// Lists the edges incident to one node. `edge_kinds` is applied before
    /// paging, so `total_items` counts only the selected edge kinds.
    #[allow(clippy::too_many_arguments)]
    pub fn list_edges_page(
        &self,
        snapshot_id: &ResolvedSnapshotId,
        node_id: &str,
        direction: EdgeDirection,
        edge_kinds: &EdgeKindFilter,
        offset: usize,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<GraphEdgesPageResult> {
        validate_page_limit(self, limit)?;
        let snapshot = self.load_agent_snapshot(snapshot_id, cancellation)?;
        let (items, total_items) = edges_page_items(
            &snapshot.edges,
            &snapshot.sites,
            &snapshot.evidence,
            node_id,
            direction,
            edge_kinds,
            offset,
            limit,
        )?;
        Ok(GraphEdgesPageResult::new(
            snapshot_id.clone(),
            items,
            total_items,
        ))
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
        let Some(site) = snapshot.sites.iter().find(|site| site.id == site_id) else {
            return Err(DepgraphServiceError::NotFound);
        };
        let hint = ImportSiteHint::new(&site.kind, site.specifier.as_deref());
        let mut items = site_evidence(&snapshot.evidence, "site", site_id, Some(hint));
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
    ) -> DepgraphServiceResult<Arc<depgraph_store::GraphSnapshot>> {
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let mut read_store = self.read_store_factory().open()?;
        let cancellation_check = cancellation.clone();
        let snapshot = read_store.store().interruptible_read(
            move || cancellation_check.is_cancelled(),
            |store| {
                if snapshot_id.is_attempt() {
                    let attempt_id = snapshot_id
                        .attempt_id()
                        .ok_or_else(|| anyhow::anyhow!("invalid partial attempt identity"))?;
                    store.load_snapshot(attempt_id).map(Arc::new)
                } else {
                    // Completed snapshots are immutable, so a long-lived reader
                    // may reuse one reconstruction while the store files are
                    // unchanged (Issue #599).
                    store.load_completed_snapshot_shared(snapshot_id.as_str())
                }
            },
        );
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        snapshot.map_err(DepgraphServiceError::store_operation)
    }
}

fn evidence_projection(
    record: &depgraph_store::EvidenceRecord,
    site: Option<ImportSiteHint<'_>>,
) -> EvidenceProjection {
    EvidenceProjection {
        import: project_import_evidence(&record.properties, site),
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
    site: Option<ImportSiteHint<'_>>,
) -> Vec<EvidenceProjection> {
    records
        .iter()
        .filter(|record| record.owner_type == owner_type && record.owner_id == owner_id)
        .map(|record| evidence_projection(record, site))
        .collect()
}

/// Selects one page of sites in ID order and builds evidence only for the
/// sites on that page, so the cost grows with `limit` instead of with the
/// number of sites in the snapshot.
fn sites_page_items(
    sites: &[depgraph_store::SiteRecord],
    evidence: &[depgraph_store::EvidenceRecord],
    node_id: Option<&str>,
    site_id: Option<&str>,
    offset: usize,
    limit: usize,
) -> DepgraphServiceResult<(Vec<SiteProjection>, u64)> {
    let mut selected = sites
        .iter()
        .filter(|site| node_id.is_none_or(|id| site.source == id))
        .filter(|site| site_id.is_none_or(|id| site.id == id))
        .collect::<Vec<_>>();
    selected.sort_by(|left, right| left.id.cmp(&right.id));
    let (page, total_items) = page_slice(selected, offset, limit)?;
    let owners = page
        .iter()
        .map(|site| site.id.as_str())
        .collect::<HashSet<_>>();
    let evidence = EvidenceByOwner::new(evidence, "site", &owners);
    let items = page
        .into_iter()
        .cloned()
        .map(|site| {
            let hint = ImportSiteHint::new(&site.kind, site.specifier.as_deref());
            let evidence = evidence.projections(&site.id, Some(hint));
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
        .collect();
    Ok((items, total_items))
}

/// Selects one page of the edges incident to `node_id` in ID order and builds
/// evidence only for the edges on that page.
#[allow(clippy::too_many_arguments)]
fn edges_page_items(
    edges: &[depgraph_store::EdgeRecord],
    sites: &[depgraph_store::SiteRecord],
    evidence: &[depgraph_store::EvidenceRecord],
    node_id: &str,
    direction: EdgeDirection,
    edge_kinds: &EdgeKindFilter,
    offset: usize,
    limit: usize,
) -> DepgraphServiceResult<(Vec<EdgeProjection>, u64)> {
    let mut selected = edges
        .iter()
        .filter(|edge| match direction {
            EdgeDirection::Incoming => edge.target == node_id,
            EdgeDirection::Outgoing => edge.source == node_id,
            EdgeDirection::Both => edge.source == node_id || edge.target == node_id,
        })
        .filter(|edge| edge_kinds.allows(&edge.kind))
        .collect::<Vec<_>>();
    selected.sort_by(|left, right| left.id.cmp(&right.id));
    let (page, total_items) = page_slice(selected, offset, limit)?;
    let wanted_sites = page
        .iter()
        .filter_map(|edge| edge.site_id.as_deref())
        .collect::<HashSet<_>>();
    // Later records overwrite earlier ones, as `collect` into a map would.
    let mut sites_by_id = HashMap::with_capacity(wanted_sites.len());
    for site in sites {
        if wanted_sites.contains(site.id.as_str()) {
            sites_by_id.insert(site.id.as_str(), site);
        }
    }
    let owners = page
        .iter()
        .map(|edge| edge.id.as_str())
        .collect::<HashSet<_>>();
    let evidence = EvidenceByOwner::new(evidence, "edge", &owners);
    let items = page
        .into_iter()
        .cloned()
        .map(|edge| {
            let hint = edge
                .site_id
                .as_deref()
                .and_then(|site_id| sites_by_id.get(site_id))
                .map(|site| ImportSiteHint::new(&site.kind, site.specifier.as_deref()));
            let evidence = evidence.projections(&edge.id, hint);
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
        .collect();
    Ok((items, total_items))
}

/// Evidence records of one owner type, grouped by owner ID in a single pass.
/// Only the owners on the current page are kept, and each owner's records stay
/// in snapshot order so the stable sort in `projections` matches a linear scan.
struct EvidenceByOwner<'a> {
    by_owner: HashMap<&'a str, Vec<&'a depgraph_store::EvidenceRecord>>,
}

impl<'a> EvidenceByOwner<'a> {
    fn new(
        records: &'a [depgraph_store::EvidenceRecord],
        owner_type: &str,
        owners: &HashSet<&str>,
    ) -> Self {
        let mut by_owner = HashMap::<_, Vec<_>>::with_capacity(owners.len());
        if owners.is_empty() {
            // An empty page (e.g. offset past the end) needs no evidence scan.
            return Self { by_owner };
        }
        for record in records {
            if record.owner_type == owner_type && owners.contains(record.owner_id.as_str()) {
                by_owner
                    .entry(record.owner_id.as_str())
                    .or_default()
                    .push(record);
            }
        }
        Self { by_owner }
    }

    fn projections(
        &self,
        owner_id: &str,
        site: Option<ImportSiteHint<'_>>,
    ) -> Vec<EvidenceProjection> {
        #[cfg(test)]
        tests::count_owner_evidence_build();
        let mut evidence = self
            .by_owner
            .get(owner_id)
            .map(|records| {
                records
                    .iter()
                    .map(|record| evidence_projection(record, site))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        evidence.sort_by(evidence_order);
        evidence
    }
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
    items: Vec<T>,
    offset: usize,
    limit: usize,
    build: impl FnOnce(ResolvedSnapshotId, Vec<T>, u64) -> R,
) -> DepgraphServiceResult<R> {
    let (items, total_items) = page_slice(items, offset, limit)?;
    Ok(build(snapshot_id.clone(), items, total_items))
}

/// Cuts `offset..offset + limit` out of `items` and returns it with the
/// number of items before paging.
fn page_slice<T>(
    mut items: Vec<T>,
    offset: usize,
    limit: usize,
) -> DepgraphServiceResult<(Vec<T>, u64)> {
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
    Ok((items, total_items))
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

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use depgraph_store::{EdgeRecord, EvidenceRecord, SiteRecord};
    use serde_json::{Value, json};

    use super::*;

    thread_local! {
        static OWNER_EVIDENCE_BUILDS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn count_owner_evidence_build() {
        OWNER_EVIDENCE_BUILDS.with(|count| count.set(count.get() + 1));
    }

    fn owner_evidence_builds<T>(run: impl FnOnce() -> T) -> (T, usize) {
        OWNER_EVIDENCE_BUILDS.with(|count| count.set(0));
        let value = run();
        (value, OWNER_EVIDENCE_BUILDS.with(Cell::get))
    }

    /// The paging implementation before #600: evidence for every selected
    /// site or edge, a linear evidence scan per owner, then sort and page.
    fn legacy_sites_page(
        sites: Vec<SiteRecord>,
        evidence: &[EvidenceRecord],
        node_id: Option<&str>,
        site_id: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> (Vec<SiteProjection>, u64) {
        let mut items = sites
            .into_iter()
            .filter(|site| node_id.is_none_or(|id| site.source == id))
            .filter(|site| site_id.is_none_or(|id| site.id == id))
            .map(|site| {
                let hint = ImportSiteHint::new(&site.kind, site.specifier.as_deref());
                let mut evidence = site_evidence(evidence, "site", &site.id, Some(hint));
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
        page_slice(items, offset, limit).expect("legacy page")
    }

    #[allow(clippy::too_many_arguments)]
    fn legacy_edges_page(
        edges: Vec<EdgeRecord>,
        sites: &[SiteRecord],
        evidence: &[EvidenceRecord],
        node_id: &str,
        direction: EdgeDirection,
        edge_kinds: &EdgeKindFilter,
        offset: usize,
        limit: usize,
    ) -> (Vec<EdgeProjection>, u64) {
        let sites = sites
            .iter()
            .map(|site| (site.id.as_str(), site))
            .collect::<BTreeMap<_, _>>();
        let mut items = edges
            .into_iter()
            .filter(|edge| match direction {
                EdgeDirection::Incoming => edge.target == node_id,
                EdgeDirection::Outgoing => edge.source == node_id,
                EdgeDirection::Both => edge.source == node_id || edge.target == node_id,
            })
            .filter(|edge| edge_kinds.allows(&edge.kind))
            .map(|edge| {
                let hint = edge
                    .site_id
                    .as_deref()
                    .and_then(|site_id| sites.get(site_id))
                    .map(|site| ImportSiteHint::new(&site.kind, site.specifier.as_deref()));
                let mut evidence = site_evidence(evidence, "edge", &edge.id, hint);
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
        page_slice(items, offset, limit).expect("legacy page")
    }

    struct Fixture {
        sites: Vec<SiteRecord>,
        edges: Vec<EdgeRecord>,
        evidence: Vec<EvidenceRecord>,
    }

    /// Deterministic pseudo-random order so the input is not already sorted.
    fn scrambled(count: usize) -> impl Iterator<Item = usize> {
        let step = (0..)
            .map(|candidate| count / 2 + 1 + candidate)
            .find(|step| gcd(*step, count) == 1)
            .expect("step");
        (0..count).map(move |index| (index * step + 7) % count)
    }

    fn gcd(left: usize, right: usize) -> usize {
        if right == 0 {
            left
        } else {
            gcd(right, left % right)
        }
    }

    fn evidence_record(owner_type: &str, owner_id: &str, ordinal: usize) -> EvidenceRecord {
        // Two records per owner share the whole sort key and differ only in
        // `properties`, so the test also pins the stable order among them.
        let properties = match ordinal % 3 {
            0 => json!({ "target_specifier": format!("crate::m{ordinal}") }),
            1 => json!({ "target_specifier": format!("crate::n{ordinal}") }),
            _ => json!({}),
        };
        EvidenceRecord {
            owner_type: owner_type.to_string(),
            owner_id: owner_id.to_string(),
            ordinal: i64::try_from(ordinal).expect("ordinal"),
            kind: "import".to_string(),
            extractor: "fixture".to_string(),
            extractor_version: "1".to_string(),
            path: format!("src/f{}.rs", ordinal % 4),
            start_line: u64::try_from(ordinal % 2).expect("line"),
            start_column: 1,
            end_line: 1,
            end_column: 2,
            detail: None,
            properties,
        }
    }

    fn fixture(site_count: usize) -> Fixture {
        let mut sites = Vec::new();
        let mut edges = Vec::new();
        let mut evidence = Vec::new();
        for index in scrambled(site_count) {
            let site_id = format!("site:{index:06}");
            let source = format!("node:{}", index % 13);
            sites.push(SiteRecord {
                id: site_id.clone(),
                source: source.clone(),
                kind: "import".to_string(),
                specifier: (index % 2 == 0).then(|| format!("pkg{index}")),
                profile_id: "profile".to_string(),
                resolution_status: "resolved".to_string(),
                precision: "exact".to_string(),
                condition: Value::Null,
                target_ids: vec![format!("node:{}", (index + 1) % 13)],
                reason: None,
            });
            edges.push(EdgeRecord {
                id: format!("edge:{index:06}"),
                site_id: (index % 5 != 0).then(|| site_id.clone()),
                source,
                target: format!("node:{}", (index + 1) % 13),
                kind: if index % 4 == 0 { "calls" } else { "imports" }.to_string(),
                phase: "build".to_string(),
                environment: "default".to_string(),
                profile_id: "profile".to_string(),
                resolution_status: "resolved".to_string(),
                precision: "exact".to_string(),
                condition: Value::Null,
                generated: false,
            });
        }
        // Interleave evidence of both owner types; some sites have none and
        // an edge reuses a site's ID to check that owner types stay apart.
        for index in scrambled(site_count) {
            for ordinal in 0..(index % 4) {
                evidence.push(evidence_record(
                    "site",
                    &format!("site:{index:06}"),
                    ordinal,
                ));
                evidence.push(evidence_record(
                    "edge",
                    &format!("edge:{index:06}"),
                    ordinal,
                ));
            }
            if index % 7 == 0 {
                evidence.push(evidence_record("edge", &format!("site:{index:06}"), 9));
            }
        }
        Fixture {
            sites,
            edges,
            evidence,
        }
    }

    #[test]
    fn sites_page_matches_legacy_paging_for_every_scope() {
        let fixture = fixture(240);
        let scopes: [(Option<&str>, Option<&str>); 6] = [
            (None, None),
            (Some("node:3"), None),
            (Some("node:missing"), None),
            (None, Some("site:000042")),
            (Some("node:3"), Some("site:000042")),
            (None, Some("site:missing")),
        ];
        for (node_id, site_id) in scopes {
            for (offset, limit) in [(0, 1), (0, 25), (17, 25), (230, 25), (240, 5), (500, 5)] {
                let expected = legacy_sites_page(
                    fixture.sites.clone(),
                    &fixture.evidence,
                    node_id,
                    site_id,
                    offset,
                    limit,
                );
                let actual = sites_page_items(
                    &fixture.sites,
                    &fixture.evidence,
                    node_id,
                    site_id,
                    offset,
                    limit,
                )
                .expect("sites page");
                assert_eq!(
                    actual, expected,
                    "node={node_id:?} site={site_id:?} offset={offset}"
                );
            }
        }
    }

    #[test]
    fn edges_page_matches_legacy_paging() {
        let fixture = fixture(240);
        let imports_only =
            EdgeKindFilter::try_new(vec!["imports".to_string()], None).expect("filter");
        for direction in [
            EdgeDirection::Incoming,
            EdgeDirection::Outgoing,
            EdgeDirection::Both,
        ] {
            for filter in [&EdgeKindFilter::default(), &imports_only] {
                for (offset, limit) in [(0, 10), (5, 10), (35, 10), (100, 10)] {
                    let expected = legacy_edges_page(
                        fixture.edges.clone(),
                        &fixture.sites,
                        &fixture.evidence,
                        "node:4",
                        direction,
                        filter,
                        offset,
                        limit,
                    );
                    let actual = edges_page_items(
                        &fixture.edges,
                        &fixture.sites,
                        &fixture.evidence,
                        "node:4",
                        direction,
                        filter,
                        offset,
                        limit,
                    )
                    .expect("edges page");
                    assert_eq!(actual, expected, "direction={direction:?} offset={offset}");
                }
            }
        }
    }

    #[test]
    fn unscoped_sites_page_builds_evidence_only_for_the_page() {
        for site_count in [1_000, 20_000] {
            let fixture = fixture(site_count);
            let ((items, total_items), builds) = owner_evidence_builds(|| {
                sites_page_items(&fixture.sites, &fixture.evidence, None, None, 300, 100)
                    .expect("sites page")
            });
            assert_eq!(items.len(), 100);
            assert_eq!(total_items, u64::try_from(site_count).expect("count"));
            assert_eq!(builds, 100, "site_count={site_count}");
        }
        let fixture = fixture(1_000);
        let ((items, total_items), builds) = owner_evidence_builds(|| {
            sites_page_items(&fixture.sites, &fixture.evidence, None, None, 5_000, 100)
                .expect("sites page past the end")
        });
        assert!(items.is_empty());
        assert_eq!(total_items, 1_000);
        assert_eq!(builds, 0);
    }

    #[test]
    fn edges_page_builds_evidence_only_for_the_page() {
        let fixture = fixture(20_000);
        let ((items, total_items), builds) = owner_evidence_builds(|| {
            edges_page_items(
                &fixture.edges,
                &fixture.sites,
                &fixture.evidence,
                "node:4",
                EdgeDirection::Both,
                &EdgeKindFilter::default(),
                0,
                50,
            )
            .expect("edges page")
        });
        assert_eq!(items.len(), 50);
        assert!(total_items > 50);
        assert_eq!(builds, 50);
    }
}
