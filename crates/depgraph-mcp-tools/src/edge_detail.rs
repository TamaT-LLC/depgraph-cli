//! Output granularity of `agent_edges_list` (Issue #566).
//!
//! `full` keeps the frozen `Page<AgentEdge>` bytes. `summary` drops evidence bodies and
//! wraps the page in a closed shape tagged by a required `detail` field, so an empty
//! summary page never deserializes as an empty full page. `imports` pages file-level
//! `(source, target)` groups with the import names recorded for them, in the same
//! tagged shape.

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::dto::agent_node_from_fields;
use crate::{
    AgentEdge, AgentEdgeCommon, AgentEdgeSummary, AgentId, AgentImportEvidence, AgentToken,
    ContractBuildError, Page, RepositoryRelativePath,
};

/// Maximum distinct import facts listed per group.
pub const MAX_AGENT_IMPORT_GROUP_NAMES: usize = depgraph_core::service::MAX_IMPORT_GROUP_NAMES;
/// Maximum distinct edge kinds listed per group.
pub const MAX_AGENT_IMPORT_GROUP_EDGE_KINDS: usize = 64;
/// Byte budget of one `detail: "imports"` page. A hub file can import hundreds
/// of names, so the page ends early with a cursor instead of exceeding the result
/// size an Agent host accepts (Claude Code rejected a 76,164-character result in
/// Issue #566). A group whose names alone exceed the page is trimmed to
/// [`AGENT_IMPORT_GROUP_BYTES`] so every page holds at least one group.
pub const AGENT_IMPORT_GROUPS_PAGE_BYTES: u32 = 48 * 1024;
/// Largest serialized group: the page budget less room for the page fields and a
/// cursor of the largest accepted size.
pub const AGENT_IMPORT_GROUP_BYTES: usize =
    AGENT_IMPORT_GROUPS_PAGE_BYTES as usize - crate::MAX_CURSOR_BYTES - 256;

/// Requested output granularity of `agent_edges_list`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentEdgeDetail {
    /// Edges without evidence bodies; `evidence_count` tells how many records exist.
    Summary,
    /// The legacy complete edge projection with evidence (default).
    #[default]
    Full,
    /// File-level `(source, target)` groups of import edges with their import names.
    Imports,
}

impl AgentEdgeDetail {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Summary => "summary",
            Self::Full => "full",
            Self::Imports => "imports",
        }
    }

    #[must_use]
    pub const fn is_full(self) -> bool {
        matches!(self, Self::Full)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AgentEdgesSummaryTag {
    Summary,
}

/// `detail: "summary"` response of `agent_edges_list`.
///
/// Fields whose value is identical for every edge of the page are stated once in
/// `common` and omitted from each edge, as in the dependency list summary. Unlike that
/// summary, `common` is computed per page, because the edge list pages in the store and
/// never materializes the whole collection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEdgesSummaryResponse {
    detail: AgentEdgesSummaryTag,
    /// Fields shared by every edge of this page only; a later page can state a
    /// different set, so do not apply it to other pages.
    common: AgentEdgeCommon,
    edges: Page<AgentEdgeSummary>,
}

impl AgentEdgesSummaryResponse {
    /// Builds a summary page; every edge must keep each shared field in exactly one
    /// place, `common` or the edge.
    pub fn new(
        common: AgentEdgeCommon,
        edges: Page<AgentEdgeSummary>,
    ) -> Result<Self, ContractBuildError> {
        if !edges
            .items()
            .iter()
            .all(|edge| edge.is_consistent_with(&common))
        {
            return Err(ContractBuildError::DependencyDetailState);
        }
        Ok(Self {
            detail: AgentEdgesSummaryTag::Summary,
            common,
            edges,
        })
    }

    /// Hoists the fields shared by every edge of `edges` and projects each edge
    /// without them. A page later cut down by its byte budget keeps a valid `common`,
    /// because a value shared by every edge is shared by every remaining edge.
    #[must_use]
    pub fn project_items(edges: &[AgentEdge]) -> (AgentEdgeCommon, Vec<AgentEdgeSummary>) {
        let common = AgentEdgeCommon::from_edges(edges);
        let items = edges
            .iter()
            .map(|edge| AgentEdgeSummary::project(edge, &common))
            .collect();
        (common, items)
    }

    #[must_use]
    pub const fn common(&self) -> &AgentEdgeCommon {
        &self.common
    }

    #[must_use]
    pub const fn edges(&self) -> &Page<AgentEdgeSummary> {
        &self.edges
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentEdgesSummaryResponseWire {
    #[allow(dead_code)]
    detail: AgentEdgesSummaryTag,
    common: AgentEdgeCommon,
    edges: Page<AgentEdgeSummary>,
}

impl<'de> Deserialize<'de> for AgentEdgesSummaryResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentEdgesSummaryResponseWire::deserialize(deserializer)?;
        Self::new(wire.common, wire.edges).map_err(D::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AgentEdgesImportsTag {
    Imports,
}

/// One file-level `(source, target)` pair of `agent_edges_list` `detail: "imports"`,
/// with the import names recorded for its edges.
///
/// The group holds the selected edges between the two nodes and, for TypeScript, the
/// semantic edges from the same source with the same import specifier (their targets
/// are the imported symbols). `imports` lists the distinct import facts of the
/// evidence of those edges and of every site of the source with one of their
/// specifiers.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentImportGroup {
    source_id: AgentId,
    /// Repository-relative path of the source node, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_path: Option<RepositoryRelativePath>,
    target_id: AgentId,
    /// Repository-relative path of the target node, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_path: Option<RepositoryRelativePath>,
    /// Sorted, distinct kinds of the grouped edges.
    #[schemars(length(min = 1, max = 64))]
    edge_kinds: Vec<AgentToken>,
    /// Number of grouped edge records.
    #[schemars(range(min = 1))]
    edge_count: u64,
    /// Distinct import facts, sorted by specifier and local name; at most 256, and
    /// fewer when the group would not fit in one page.
    #[schemars(length(max = 256))]
    imports: Vec<AgentImportEvidence>,
    /// Number of distinct import facts; larger than the length of imports when the
    /// list was truncated.
    import_count: u64,
}

impl AgentImportGroup {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_id: AgentId,
        source_path: Option<RepositoryRelativePath>,
        target_id: AgentId,
        target_path: Option<RepositoryRelativePath>,
        edge_kinds: Vec<AgentToken>,
        edge_count: u64,
        imports: Vec<AgentImportEvidence>,
        import_count: u64,
    ) -> Result<Self, ContractBuildError> {
        let listed = u64::try_from(imports.len()).unwrap_or(u64::MAX);
        if edge_kinds.is_empty()
            || edge_kinds.len() > MAX_AGENT_IMPORT_GROUP_EDGE_KINDS
            || edge_kinds
                .windows(2)
                .any(|pair| pair[0].as_str() >= pair[1].as_str())
            || edge_count < u64::try_from(edge_kinds.len()).unwrap_or(u64::MAX)
            || imports.len() > MAX_AGENT_IMPORT_GROUP_NAMES
            || import_count < listed
        {
            return Err(ContractBuildError::DependencyDetailState);
        }
        Ok(Self {
            source_id,
            source_path,
            target_id,
            target_path,
            edge_kinds,
            edge_count,
            imports,
            import_count,
        })
    }

    /// Projects one core import group; import facts outside the contract are
    /// omitted and no longer counted.
    pub fn try_from_core(
        group: &depgraph_core::service::ImportGroupProjection,
    ) -> Result<Self, ContractBuildError> {
        let endpoint = |node: &depgraph_core::service::GraphNodeFields| {
            agent_node_from_fields(
                node.id(),
                node.kind(),
                node.locator(),
                node.display_name(),
                node.properties(),
            )
        };
        let source = endpoint(group.source())?;
        let target = endpoint(group.target())?;
        let edge_kinds = group
            .edge_kinds()
            .iter()
            .map(AgentToken::parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ContractBuildError::AgentDtoValue)?;
        let imports = group
            .imports()
            .iter()
            .filter_map(AgentImportEvidence::project)
            .collect::<Vec<_>>();
        let dropped = group.imports().len() - imports.len();
        let import_count = group
            .import_count()
            .saturating_sub(u64::try_from(dropped).unwrap_or(u64::MAX));
        let mut projected = Self::new(
            source.id().clone(),
            source.repository_path().cloned(),
            target.id().clone(),
            target.repository_path().cloned(),
            edge_kinds,
            group.edge_count(),
            imports,
            import_count,
        )?;
        projected.trim_to_bytes(AGENT_IMPORT_GROUP_BYTES);
        Ok(projected)
    }

    /// Drops trailing import facts until the compact JSON of the group fits in
    /// `max_bytes`, keeping `import_count`. The result depends only on the group,
    /// so pages and cursors stay deterministic.
    fn trim_to_bytes(&mut self, max_bytes: usize) {
        let size = |value: &Self| serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len());
        if size(self) <= max_bytes {
            return;
        }
        let imports = std::mem::take(&mut self.imports);
        let mut used = size(self);
        let mut kept = 0;
        for import in &imports {
            // One more element costs its bytes and a separating comma.
            let cost = serde_json::to_vec(import).map_or(usize::MAX, |bytes| bytes.len()) + 1;
            match used.checked_add(cost) {
                Some(next) if next <= max_bytes => used = next,
                _ => break,
            }
            kept += 1;
        }
        self.imports = imports;
        self.imports.truncate(kept);
    }

    #[must_use]
    pub const fn source_id(&self) -> &AgentId {
        &self.source_id
    }

    #[must_use]
    pub const fn target_id(&self) -> &AgentId {
        &self.target_id
    }

    #[must_use]
    pub const fn source_path(&self) -> Option<&RepositoryRelativePath> {
        self.source_path.as_ref()
    }

    #[must_use]
    pub const fn target_path(&self) -> Option<&RepositoryRelativePath> {
        self.target_path.as_ref()
    }

    #[must_use]
    pub fn edge_kinds(&self) -> &[AgentToken] {
        &self.edge_kinds
    }

    #[must_use]
    pub const fn edge_count(&self) -> u64 {
        self.edge_count
    }

    #[must_use]
    pub fn imports(&self) -> &[AgentImportEvidence] {
        &self.imports
    }

    #[must_use]
    pub const fn import_count(&self) -> u64 {
        self.import_count
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentImportGroupWire {
    source_id: AgentId,
    #[serde(default)]
    source_path: Option<RepositoryRelativePath>,
    target_id: AgentId,
    #[serde(default)]
    target_path: Option<RepositoryRelativePath>,
    edge_kinds: Vec<AgentToken>,
    edge_count: u64,
    imports: Vec<AgentImportEvidence>,
    import_count: u64,
}

impl<'de> Deserialize<'de> for AgentImportGroup {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentImportGroupWire::deserialize(deserializer)?;
        Self::new(
            wire.source_id,
            wire.source_path,
            wire.target_id,
            wire.target_path,
            wire.edge_kinds,
            wire.edge_count,
            wire.imports,
            wire.import_count,
        )
        .map_err(D::Error::custom)
    }
}

/// `detail: "imports"` response of `agent_edges_list`: a page of import groups.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEdgesImportsResponse {
    detail: AgentEdgesImportsTag,
    groups: Page<AgentImportGroup>,
}

impl AgentEdgesImportsResponse {
    #[must_use]
    pub const fn new(groups: Page<AgentImportGroup>) -> Self {
        Self {
            detail: AgentEdgesImportsTag::Imports,
            groups,
        }
    }

    #[must_use]
    pub const fn groups(&self) -> &Page<AgentImportGroup> {
        &self.groups
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentEdgesImportsResponseWire {
    #[allow(dead_code)]
    detail: AgentEdgesImportsTag,
    groups: Page<AgentImportGroup>,
}

impl<'de> Deserialize<'de> for AgentEdgesImportsResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentEdgesImportsResponseWire::deserialize(deserializer)?;
        Ok(Self::new(wire.groups))
    }
}

/// Result of `agent_edges_list` for any `detail`. `Full` serializes exactly like
/// `Page<AgentEdge>`; `Summary` carries its `detail` tag.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum AgentEdgesOutput {
    Full(Page<AgentEdge>),
    Summary(AgentEdgesSummaryResponse),
    Imports(AgentEdgesImportsResponse),
}

impl AgentEdgesOutput {
    #[must_use]
    pub const fn detail(&self) -> AgentEdgeDetail {
        match self {
            Self::Full(_) => AgentEdgeDetail::Full,
            Self::Summary(_) => AgentEdgeDetail::Summary,
            Self::Imports(_) => AgentEdgeDetail::Imports,
        }
    }
}

impl<'de> Deserialize<'de> for AgentEdgesOutput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value.get("detail") {
            None => serde_json::from_value(value).map(Self::Full),
            Some(serde_json::Value::String(detail)) if detail == "summary" => {
                serde_json::from_value(value).map(Self::Summary)
            }
            Some(serde_json::Value::String(detail)) if detail == "imports" => {
                serde_json::from_value(value).map(Self::Imports)
            }
            Some(_) => {
                return Err(D::Error::custom(ContractBuildError::DependencyDetailState));
            }
        }
        .map_err(D::Error::custom)
    }
}

impl JsonSchema for AgentEdgesOutput {
    fn schema_name() -> Cow<'static, str> {
        "AgentEdgesOutput".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::AgentEdgesOutput").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let full = generator.subschema_for::<Page<AgentEdge>>();
        let summary = generator.subschema_for::<AgentEdgesSummaryResponse>();
        let imports = generator.subschema_for::<AgentEdgesImportsResponse>();
        json_schema!({
            "description": "detail=full (default) is the legacy page of complete edges without a detail field; summary carries its detail tag and an edges page without evidence bodies; imports carries its detail tag and a page of file-level import groups with their import names.",
            "oneOf": [full, summary, imports]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentImportBindingKind, AgentImportSpecifier, AgentLabel};

    fn group_with_long_names(count: usize) -> AgentImportGroup {
        let specifier = format!("@scope/{}", "a".repeat(900));
        let imports = (0..count)
            .map(|index| {
                AgentImportEvidence::new(
                    AgentImportSpecifier::parse(&specifier).unwrap(),
                    Some(AgentImportBindingKind::Named),
                    Some(AgentLabel::parse(format!("name{index:03}{}", "b".repeat(200))).unwrap()),
                    None,
                    false,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        AgentImportGroup::new(
            AgentId::parse("file:a").unwrap(),
            None,
            AgentId::parse("file:b").unwrap(),
            None,
            vec![AgentToken::parse("imports").unwrap()],
            1,
            imports,
            300,
        )
        .unwrap()
    }

    // Issue #566: a group larger than one page is trimmed so the page can still
    // hold it and paging advances, and the count keeps the total.
    #[test]
    fn oversized_group_is_trimmed_to_fit_one_page() {
        let mut group = group_with_long_names(MAX_AGENT_IMPORT_GROUP_NAMES);
        assert!(serde_json::to_vec(&group).unwrap().len() > AGENT_IMPORT_GROUP_BYTES);
        group.trim_to_bytes(AGENT_IMPORT_GROUP_BYTES);
        let bytes = serde_json::to_vec(&group).unwrap().len();
        assert!(bytes <= AGENT_IMPORT_GROUP_BYTES, "{bytes}");
        assert!(!group.imports().is_empty());
        assert!(group.imports().len() < MAX_AGENT_IMPORT_GROUP_NAMES);
        assert_eq!(group.import_count(), 300);
        // The trimmed group still satisfies the contract and is deterministic.
        let value = serde_json::to_value(&group).unwrap();
        assert_eq!(
            serde_json::from_value::<AgentImportGroup>(value).unwrap(),
            group
        );
        let mut again = group_with_long_names(MAX_AGENT_IMPORT_GROUP_NAMES);
        again.trim_to_bytes(AGENT_IMPORT_GROUP_BYTES);
        assert_eq!(again, group);

        let mut small = group_with_long_names(2);
        let before = small.clone();
        small.trim_to_bytes(AGENT_IMPORT_GROUP_BYTES);
        assert_eq!(small, before);
    }
}
