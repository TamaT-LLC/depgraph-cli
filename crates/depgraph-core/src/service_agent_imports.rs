//! File-level import groups of one node with their import names (Issue #566).
//!
//! Import names are recorded on different edges per language. Rust records them
//! on the file-level `imports` / `reexports` edge itself, while TypeScript records
//! the file-level edge (`import` site, no names) and separate semantic edges to
//! the imported symbols, types or external declarations, whose site evidence
//! carries the names. Both share the source file and the import specifier, so
//! the edges of one `(source, specifier)` statement are grouped under the
//! file-level node they reach: one group per `(source, target)` pair, with every
//! name recorded for the specifiers of its edges.
//!
//! This module is a child of `service_agent` so it can reuse its private
//! snapshot loading and evidence projection helpers.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use depgraph_store::{EdgeRecord, NodeRecord, SiteRecord};

use super::{EdgeDirection, evidence_projection, validate_page_limit};
use crate::CancellationToken;
use crate::edge_kind_selection::EdgeKindFilter;
use crate::import_evidence::{ImportEvidence, ImportSiteHint};
use crate::service::{
    DepgraphService, DepgraphServiceError, DepgraphServiceResult, ResolvedSnapshotId,
};

/// Edge kinds grouped when the request does not name any.
pub const DEFAULT_IMPORT_GROUP_EDGE_KINDS: &[&str] = &[
    "imports",
    "lazy_imports",
    "reexports",
    "requires",
    "side_effect_imports",
];
/// Maximum distinct import names returned per group; `import_count` keeps the total.
pub const MAX_IMPORT_GROUP_NAMES: usize = 256;

/// Identity, display fields and properties of one node, as agent DTOs project it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphNodeFields {
    id: String,
    kind: String,
    locator: String,
    display_name: String,
    properties: serde_json::Value,
}

impl GraphNodeFields {
    pub(super) fn from_record(record: &NodeRecord) -> Self {
        Self {
            id: record.id.clone(),
            kind: record.kind.clone(),
            locator: record.locator.clone(),
            display_name: record.display_name.clone(),
            properties: record.properties.clone(),
        }
    }

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

    #[must_use]
    pub const fn properties(&self) -> &serde_json::Value {
        &self.properties
    }
}

/// One `(source, target)` group of import edges with the names imported through them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportGroupProjection {
    source: GraphNodeFields,
    target: GraphNodeFields,
    edge_kinds: Vec<String>,
    edge_count: u64,
    imports: Vec<ImportEvidence>,
    import_count: u64,
}

impl ImportGroupProjection {
    #[must_use]
    pub const fn source(&self) -> &GraphNodeFields {
        &self.source
    }

    #[must_use]
    pub const fn target(&self) -> &GraphNodeFields {
        &self.target
    }

    /// Sorted, distinct kinds of the grouped edges.
    #[must_use]
    pub fn edge_kinds(&self) -> &[String] {
        &self.edge_kinds
    }

    /// Number of grouped edge records, including the semantic edges folded in.
    #[must_use]
    pub const fn edge_count(&self) -> u64 {
        self.edge_count
    }

    /// Distinct import facts, sorted, at most [`MAX_IMPORT_GROUP_NAMES`].
    #[must_use]
    pub fn imports(&self) -> &[ImportEvidence] {
        &self.imports
    }

    /// Number of distinct import facts before truncation.
    #[must_use]
    pub const fn import_count(&self) -> u64 {
        self.import_count
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphImportGroupsPageResult {
    snapshot_id: ResolvedSnapshotId,
    items: Vec<ImportGroupProjection>,
    total_items: u64,
}

impl GraphImportGroupsPageResult {
    fn new(
        snapshot_id: ResolvedSnapshotId,
        items: Vec<ImportGroupProjection>,
        total_items: u64,
    ) -> Self {
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
    pub fn items(&self) -> &[ImportGroupProjection] {
        &self.items
    }

    #[must_use]
    pub const fn total_items(&self) -> u64 {
        self.total_items
    }
}

/// Edges of one group before its names are projected.
#[derive(Default)]
struct GroupAccumulator<'a> {
    edge_kinds: BTreeSet<&'a str>,
    edge_ids: BTreeSet<&'a str>,
    site_ids: BTreeSet<&'a str>,
    specifiers: BTreeSet<&'a str>,
}

type GroupKey<'a> = (&'a str, &'a str);

/// Sort key that orders import facts by specifier and name and makes them distinct.
type ImportKey = (
    String,
    Option<String>,
    Option<String>,
    Option<crate::import_evidence::ImportBindingKind>,
    bool,
);

fn import_key(import: &ImportEvidence) -> ImportKey {
    (
        import.specifier().to_owned(),
        import.local_name().map(str::to_owned),
        import.imported_name().map(str::to_owned),
        import.binding_kind(),
        import.type_only(),
    )
}

impl DepgraphService {
    /// Lists the file-level import groups incident to one node, each with the
    /// import names recorded for it. `edge_kinds` selects the grouped edges
    /// (default: [`DEFAULT_IMPORT_GROUP_EDGE_KINDS`]). Groups are ordered by
    /// `(source, target)` and paged before their names are projected.
    #[allow(clippy::too_many_arguments)]
    pub fn list_import_groups_page(
        &self,
        snapshot_id: &ResolvedSnapshotId,
        node_id: &str,
        direction: EdgeDirection,
        edge_kinds: &EdgeKindFilter,
        offset: usize,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<GraphImportGroupsPageResult> {
        validate_page_limit(self, limit)?;
        let snapshot = self.load_agent_snapshot(snapshot_id, cancellation)?;
        let nodes = snapshot
            .nodes
            .iter()
            .map(|node| (node.id.as_str(), node))
            .collect::<HashMap<_, _>>();
        let sites = snapshot
            .sites
            .iter()
            .map(|site| (site.id.as_str(), site))
            .collect::<HashMap<_, _>>();
        let use_default_kinds = edge_kinds.is_unrestricted();
        let selected = snapshot
            .edges
            .iter()
            .filter(|edge| match direction {
                EdgeDirection::Incoming => edge.target == node_id,
                EdgeDirection::Outgoing => edge.source == node_id,
                EdgeDirection::Both => edge.source == node_id || edge.target == node_id,
            })
            .filter(|edge| {
                if use_default_kinds {
                    DEFAULT_IMPORT_GROUP_EDGE_KINDS.contains(&edge.kind.as_str())
                } else {
                    edge_kinds.allows(&edge.kind)
                }
            })
            .collect::<Vec<_>>();
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }

        let specifier_of = |edge: &EdgeRecord| -> Option<&str> {
            edge.site_id
                .as_deref()
                .and_then(|site_id| sites.get(site_id))
                .and_then(|site| site.specifier.as_deref())
        };

        // Edges of one import specifier from one source describe one import
        // statement. An edge without a specifier is its own group.
        let mut groups = BTreeMap::<GroupKey<'_>, GroupAccumulator<'_>>::new();
        let mut statements = BTreeMap::<(&str, &str), Vec<&EdgeRecord>>::new();
        for edge in &selected {
            match specifier_of(edge) {
                Some(specifier) => statements
                    .entry((edge.source.as_str(), specifier))
                    .or_default()
                    .push(edge),
                None => add_edge(
                    groups
                        .entry((edge.source.as_str(), edge.target.as_str()))
                        .or_default(),
                    edge,
                    &sites,
                ),
            }
        }
        // When one statement reaches several nodes, the file-level ones anchor
        // it and the others (TypeScript symbols, types and external
        // declarations) join their groups. The anchors are the best-ranked
        // nodes: a file node first, then a node reached by an edge outside the
        // semantic phase (the statement itself, such as the package of an
        // external import), then the fewest edges.
        for edges in statements.into_values() {
            // (is file, reached outside the semantic phase, -edge count)
            let mut reached = BTreeMap::<&str, (bool, bool, usize)>::new();
            for edge in &edges {
                let other = counterpart(edge, node_id);
                let is_file = nodes
                    .get(other)
                    .ok_or(DepgraphServiceError::Integrity)?
                    .kind
                    == "file";
                let rank = reached.entry(other).or_insert((is_file, false, 0));
                rank.1 |= edge.phase != "semantic";
                rank.2 += 1;
            }
            let rank = |(is_file, statement, count): &(bool, bool, usize)| {
                (*is_file, *statement, std::cmp::Reverse(*count))
            };
            let best = reached.values().map(rank).max();
            let anchors = reached
                .iter()
                .filter(|(_, value)| Some(rank(value)) == best)
                .map(|(node, _)| *node)
                .collect::<BTreeSet<_>>();
            let keys = edges
                .iter()
                .filter(|edge| anchors.contains(counterpart(edge, node_id)))
                .map(|edge| (edge.source.as_str(), edge.target.as_str()))
                .collect::<BTreeSet<_>>();
            for edge in edges {
                if anchors.contains(counterpart(edge, node_id)) {
                    add_edge(
                        groups
                            .entry((edge.source.as_str(), edge.target.as_str()))
                            .or_default(),
                        edge,
                        &sites,
                    );
                } else {
                    for key in &keys {
                        add_edge(groups.entry(*key).or_default(), edge, &sites);
                    }
                }
            }
        }

        let total = groups.len();
        let page = groups
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect::<Vec<_>>();
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }

        // Every site of a page source whose specifier names one of its groups
        // contributes names, so TypeScript semantic sites count even when their
        // edges were not selected (an incoming request sees only file edges).
        let wanted_specifiers = page
            .iter()
            .flat_map(|((source, _), group)| {
                group
                    .specifiers
                    .iter()
                    .map(move |specifier| (*source, *specifier))
            })
            .collect::<HashSet<_>>();
        let mut sites_by_specifier = HashMap::<(&str, &str), Vec<&SiteRecord>>::new();
        if !wanted_specifiers.is_empty() {
            for site in &snapshot.sites {
                let Some(specifier) = site.specifier.as_deref() else {
                    continue;
                };
                let key = (site.source.as_str(), specifier);
                if wanted_specifiers.contains(&key) {
                    sites_by_specifier.entry(key).or_default().push(site);
                }
            }
        }
        let selected_by_id = selected
            .iter()
            .map(|edge| (edge.id.as_str(), *edge))
            .collect::<HashMap<_, _>>();
        let mut owners = HashMap::<(&str, &str), Vec<ImportEvidence>>::new();
        let mut owner_hints = HashMap::<(&str, &str), Option<ImportSiteHint<'_>>>::new();
        for ((source, _), group) in &page {
            for edge_id in &group.edge_ids {
                let hint = selected_by_id
                    .get(edge_id)
                    .and_then(|edge| edge.site_id.as_deref())
                    .and_then(|site_id| sites.get(site_id))
                    .map(|site| ImportSiteHint::new(&site.kind, site.specifier.as_deref()));
                owner_hints.insert(("edge", edge_id), hint);
            }
            let site_ids = group.site_ids.iter().copied().chain(
                group
                    .specifiers
                    .iter()
                    .filter_map(|specifier| sites_by_specifier.get(&(*source, *specifier)))
                    .flatten()
                    .map(|site| site.id.as_str()),
            );
            for site_id in site_ids {
                let hint = sites
                    .get(site_id)
                    .map(|site| ImportSiteHint::new(&site.kind, site.specifier.as_deref()));
                owner_hints.insert(("site", site_id), hint);
            }
        }
        for record in &snapshot.evidence {
            let owner = (record.owner_type.as_str(), record.owner_id.as_str());
            let Some(hint) = owner_hints.get(&owner) else {
                continue;
            };
            if let Some(import) = evidence_projection(record, *hint).import().cloned() {
                owners.entry(owner).or_default().push(import);
            }
        }
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }

        let mut items = Vec::with_capacity(page.len());
        for ((source, target), group) in page {
            let mut imports = BTreeMap::<ImportKey, ImportEvidence>::new();
            let mut collect = |owner: (&str, &str)| {
                for import in owners.get(&owner).into_iter().flatten() {
                    imports
                        .entry(import_key(import))
                        .or_insert_with(|| import.clone());
                }
            };
            for edge_id in &group.edge_ids {
                collect(("edge", edge_id));
            }
            for site_id in &group.site_ids {
                collect(("site", site_id));
            }
            for specifier in &group.specifiers {
                for site in sites_by_specifier
                    .get(&(source, *specifier))
                    .into_iter()
                    .flatten()
                {
                    collect(("site", site.id.as_str()));
                }
            }
            let imports = drop_unnamed_duplicates(imports.into_values().collect());
            let import_count = u64::try_from(imports.len())
                .map_err(|_| DepgraphServiceError::ResourceExhausted)?;
            let node = |id: &str| {
                nodes
                    .get(id)
                    .map(|record| GraphNodeFields::from_record(record))
                    .ok_or(DepgraphServiceError::Integrity)
            };
            items.push(ImportGroupProjection {
                source: node(source)?,
                target: node(target)?,
                edge_kinds: group
                    .edge_kinds
                    .iter()
                    .map(|kind| (*kind).to_owned())
                    .collect(),
                edge_count: u64::try_from(group.edge_ids.len())
                    .map_err(|_| DepgraphServiceError::ResourceExhausted)?,
                imports: imports.into_iter().take(MAX_IMPORT_GROUP_NAMES).collect(),
                import_count,
            });
        }
        let total_items =
            u64::try_from(total).map_err(|_| DepgraphServiceError::ResourceExhausted)?;
        Ok(GraphImportGroupsPageResult::new(
            snapshot_id.clone(),
            items,
            total_items,
        ))
    }
}

/// The endpoint of `edge` other than `node_id`; a self-loop counts as its target.
fn counterpart<'a>(edge: &'a EdgeRecord, node_id: &str) -> &'a str {
    if edge.source == node_id {
        &edge.target
    } else {
        &edge.source
    }
}

fn add_edge<'a>(
    group: &mut GroupAccumulator<'a>,
    edge: &'a EdgeRecord,
    sites: &HashMap<&str, &'a SiteRecord>,
) {
    group.edge_kinds.insert(edge.kind.as_str());
    group.edge_ids.insert(edge.id.as_str());
    if let Some(site) = edge.site_id.as_deref().and_then(|id| sites.get(id)) {
        group.site_ids.insert(site.id.as_str());
        if let Some(specifier) = site.specifier.as_deref() {
            group.specifiers.insert(specifier);
        }
    }
}

/// Drops a fact without imported or local name when another fact of the same
/// specifier names a binding: syntax evidence of an import statement restates
/// the specifier that its semantic evidence already describes with names.
fn drop_unnamed_duplicates(imports: Vec<ImportEvidence>) -> Vec<ImportEvidence> {
    let named_specifiers = imports
        .iter()
        .filter(|import| import.imported_name().is_some() || import.local_name().is_some())
        .map(|import| import.specifier().to_owned())
        .collect::<HashSet<_>>();
    imports
        .into_iter()
        .filter(|import| {
            import.imported_name().is_some()
                || import.local_name().is_some()
                || !named_specifiers.contains(import.specifier())
        })
        .collect()
}
