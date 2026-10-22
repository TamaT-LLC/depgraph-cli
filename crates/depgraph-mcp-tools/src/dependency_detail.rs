//! Output granularity of the dependency list tools (Issue #542).
//!
//! `full` keeps the frozen `AgentDependenciesResponse` bytes. `summary` and `paths` are
//! smaller closed shapes tagged by a required `detail` field, so every detail level
//! deserializes to exactly one shape and the legacy shape never carries `detail`.

use std::{borrow::Cow, collections::BTreeSet};

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::dto::agent_node_from_fields;
use crate::{
    AgentCondition, AgentDependenciesResponse, AgentDependencyDirection, AgentEdge, AgentId,
    AgentLabel, AgentNode, AgentPhase, AgentPrecision, AgentResolutionStatus, AgentToken,
    ContractBuildError, MAX_AGENT_EVIDENCE_ITEMS, Page, RepositoryRelativePath,
};

/// Most degraded profiles one dependency response lists.
pub const MAX_AGENT_ANALYSIS_DEGRADATIONS: usize = 256;
/// Most reasons listed for one degraded profile.
pub const MAX_AGENT_ANALYSIS_DEGRADATION_REASONS: usize = 16;

/// One snapshot profile whose analysis fell back to a less precise mode
/// (Issue #579). For Rust, `analysis_mode` is `syntax-only`: rust-analyzer HIR
/// imports, types, and calls are missing, so dependents of a file can be
/// incomplete. `reasons` names the fallback, for example
/// `rust-hir-memory-budget` (the worker skipped HIR to stay within its memory
/// budget) or `rust-hir-syntax-only-fallback` (the core reran the unit after the
/// worker exceeded its memory limit).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAnalysisDegradation {
    profile_id: AgentId,
    language: AgentToken,
    analysis_mode: AgentToken,
    #[schemars(length(max = 16))]
    reasons: Vec<AgentLabel>,
}

impl AgentAnalysisDegradation {
    pub fn new(
        profile_id: AgentId,
        language: AgentToken,
        analysis_mode: AgentToken,
        reasons: Vec<AgentLabel>,
    ) -> Result<Self, ContractBuildError> {
        if reasons.len() > MAX_AGENT_ANALYSIS_DEGRADATION_REASONS {
            return Err(ContractBuildError::TooManySnapshotMetadataItems);
        }
        Ok(Self {
            profile_id,
            language,
            analysis_mode,
            reasons,
        })
    }

    /// Projects the core degradations. Like other metadata, an entry whose
    /// profile ID, language, or mode is outside the Agent contract is skipped,
    /// and so is a reason outside `AgentLabel`, instead of failing the response.
    #[must_use]
    pub fn project_core(source: &[depgraph_core::service::AnalysisDegradation]) -> Vec<Self> {
        source
            .iter()
            .filter_map(|degradation| {
                let reasons = degradation
                    .reasons
                    .iter()
                    .filter_map(|reason| AgentLabel::parse(reason).ok())
                    .take(MAX_AGENT_ANALYSIS_DEGRADATION_REASONS)
                    .collect();
                Self::new(
                    AgentId::parse(&degradation.profile_id).ok()?,
                    AgentToken::parse(&degradation.language).ok()?,
                    AgentToken::parse(&degradation.analysis_mode).ok()?,
                    reasons,
                )
                .ok()
            })
            .take(MAX_AGENT_ANALYSIS_DEGRADATIONS)
            .collect()
    }

    #[must_use]
    pub const fn profile_id(&self) -> &AgentId {
        &self.profile_id
    }

    #[must_use]
    pub const fn analysis_mode(&self) -> &AgentToken {
        &self.analysis_mode
    }

    #[must_use]
    pub fn reasons(&self) -> &[AgentLabel] {
        &self.reasons
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentAnalysisDegradationWire {
    profile_id: AgentId,
    language: AgentToken,
    analysis_mode: AgentToken,
    reasons: Vec<AgentLabel>,
}

impl<'de> Deserialize<'de> for AgentAnalysisDegradation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentAnalysisDegradationWire::deserialize(deserializer)?;
        Self::new(
            wire.profile_id,
            wire.language,
            wire.analysis_mode,
            wire.reasons,
        )
        .map_err(D::Error::custom)
    }
}

pub(crate) fn deserialize_analysis_degradations<'de, D>(
    deserializer: D,
) -> Result<Vec<AgentAnalysisDegradation>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<AgentAnalysisDegradation>::deserialize(deserializer)?;
    if values.len() > MAX_AGENT_ANALYSIS_DEGRADATIONS {
        return Err(D::Error::custom(
            ContractBuildError::TooManySnapshotMetadataItems,
        ));
    }
    Ok(values)
}

/// Requested output granularity of `graph_dependencies_list` / `graph_dependents_list`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentDependencyDetail {
    /// Unique source/target paths and edge kinds only.
    Paths,
    /// Edges without evidence; fields shared by every edge are emitted once in `common`.
    Summary,
    /// The legacy complete edge projection (default).
    #[default]
    Full,
}

impl AgentDependencyDetail {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Paths => "paths",
            Self::Summary => "summary",
            Self::Full => "full",
        }
    }

    #[must_use]
    pub const fn is_full(self) -> bool {
        matches!(self, Self::Full)
    }
}

/// Request-only values of one dependency list projection. The core traversal result does
/// not retain its request, so the direction and transitivity are carried explicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DependencyProjectionRequest {
    direction: AgentDependencyDirection,
    transitive: bool,
    detail: AgentDependencyDetail,
}

impl DependencyProjectionRequest {
    #[must_use]
    pub const fn new(
        direction: AgentDependencyDirection,
        transitive: bool,
        detail: AgentDependencyDetail,
    ) -> Self {
        Self {
            direction,
            transitive,
            detail,
        }
    }

    #[must_use]
    pub const fn direction(&self) -> AgentDependencyDirection {
        self.direction
    }

    #[must_use]
    pub const fn transitive(&self) -> bool {
        self.transitive
    }

    #[must_use]
    pub const fn detail(&self) -> AgentDependencyDetail {
        self.detail
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AgentDependencySummaryTag {
    Summary,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AgentDependencyPathsTag {
    Paths,
}

/// Edge fields whose value is identical for every edge in the scope of the response
/// that carries them.
///
/// A present field is omitted from every `AgentEdgeSummary`; an absent field is kept per
/// edge. The dependency list summary computes the set over the complete traversal, so it
/// is stable across pages and cursor continuation; the `agent_edges_list` summary
/// computes it per page, so it can differ between pages.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEdgeCommon {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    phase: Option<AgentPhase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resolution_status: Option<AgentResolutionStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    precision: Option<AgentPrecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile_id: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    condition: Option<AgentCondition>,
}

impl AgentEdgeCommon {
    /// Hoists every field that has one value across all `edges`. No edges means no
    /// shared field.
    #[must_use]
    pub fn from_edges(edges: &[AgentEdge]) -> Self {
        let Some((first, rest)) = edges.split_first() else {
            return Self::default();
        };
        Self {
            phase: rest
                .iter()
                .all(|edge| edge.phase() == first.phase())
                .then_some(first.phase()),
            resolution_status: rest
                .iter()
                .all(|edge| edge.resolution_status() == first.resolution_status())
                .then_some(first.resolution_status()),
            precision: rest
                .iter()
                .all(|edge| edge.precision() == first.precision())
                .then_some(first.precision()),
            profile_id: rest
                .iter()
                .all(|edge| edge.profile_id() == first.profile_id())
                .then(|| first.profile_id().clone()),
            condition: first
                .condition()
                .filter(|condition| rest.iter().all(|edge| edge.condition() == Some(*condition)))
                .cloned(),
        }
    }

    #[must_use]
    pub const fn phase(&self) -> Option<AgentPhase> {
        self.phase
    }

    #[must_use]
    pub const fn resolution_status(&self) -> Option<AgentResolutionStatus> {
        self.resolution_status
    }

    #[must_use]
    pub const fn precision(&self) -> Option<AgentPrecision> {
        self.precision
    }

    #[must_use]
    pub const fn profile_id(&self) -> Option<&AgentId> {
        self.profile_id.as_ref()
    }

    #[must_use]
    pub const fn condition(&self) -> Option<&AgentCondition> {
        self.condition.as_ref()
    }
}

/// One edge without evidence bodies. Fields hoisted into `AgentEdgeCommon` are omitted;
/// evidence is fetched individually through `agent_sites_list` / `agent_evidence_list`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEdgeSummary {
    id: AgentId,
    source_id: AgentId,
    target_id: AgentId,
    kind: AgentToken,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    phase: Option<AgentPhase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resolution_status: Option<AgentResolutionStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    precision: Option<AgentPrecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile_id: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    site_id: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    condition: Option<AgentCondition>,
    #[schemars(range(max = 64))]
    evidence_count: u16,
}

impl AgentEdgeSummary {
    /// Projects one complete edge, omitting every field present in `common`.
    #[must_use]
    pub fn project(edge: &AgentEdge, common: &AgentEdgeCommon) -> Self {
        Self {
            id: edge.id().clone(),
            source_id: edge.source_id().clone(),
            target_id: edge.target_id().clone(),
            kind: edge.kind().clone(),
            phase: common.phase.is_none().then_some(edge.phase()),
            resolution_status: common
                .resolution_status
                .is_none()
                .then_some(edge.resolution_status()),
            precision: common.precision.is_none().then_some(edge.precision()),
            profile_id: common
                .profile_id
                .is_none()
                .then(|| edge.profile_id().clone()),
            site_id: edge.site_id().cloned(),
            condition: if common.condition.is_some() {
                None
            } else {
                edge.condition().cloned()
            },
            // AgentEdge already bounds its evidence to MAX_AGENT_EVIDENCE_ITEMS.
            evidence_count: u16::try_from(edge.evidence().len()).unwrap_or(u16::MAX),
        }
    }

    #[must_use]
    pub const fn id(&self) -> &AgentId {
        &self.id
    }

    #[must_use]
    pub const fn evidence_count(&self) -> u16 {
        self.evidence_count
    }

    /// Every shared field lives in exactly one place: `common` or this edge.
    pub(crate) fn is_consistent_with(&self, common: &AgentEdgeCommon) -> bool {
        common.phase.is_some() != self.phase.is_some()
            && common.resolution_status.is_some() != self.resolution_status.is_some()
            && common.precision.is_some() != self.precision.is_some()
            && common.profile_id.is_some() != self.profile_id.is_some()
            && !(common.condition.is_some() && self.condition.is_some())
            && usize::from(self.evidence_count) <= MAX_AGENT_EVIDENCE_ITEMS
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentEdgeSummaryWire {
    id: AgentId,
    source_id: AgentId,
    target_id: AgentId,
    kind: AgentToken,
    #[serde(default)]
    phase: Option<AgentPhase>,
    #[serde(default)]
    resolution_status: Option<AgentResolutionStatus>,
    #[serde(default)]
    precision: Option<AgentPrecision>,
    #[serde(default)]
    profile_id: Option<AgentId>,
    #[serde(default)]
    site_id: Option<AgentId>,
    #[serde(default)]
    condition: Option<AgentCondition>,
    evidence_count: u16,
}

impl<'de> Deserialize<'de> for AgentEdgeSummary {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentEdgeSummaryWire::deserialize(deserializer)?;
        if usize::from(wire.evidence_count) > MAX_AGENT_EVIDENCE_ITEMS {
            return Err(D::Error::custom(ContractBuildError::TooManyEvidenceItems));
        }
        Ok(Self {
            id: wire.id,
            source_id: wire.source_id,
            target_id: wire.target_id,
            kind: wire.kind,
            phase: wire.phase,
            resolution_status: wire.resolution_status,
            precision: wire.precision,
            profile_id: wire.profile_id,
            site_id: wire.site_id,
            condition: wire.condition,
            evidence_count: wire.evidence_count,
        })
    }
}

/// `detail: "summary"` response of the dependency list tools.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDependenciesSummaryResponse {
    detail: AgentDependencySummaryTag,
    root: AgentNode,
    direction: AgentDependencyDirection,
    transitive: bool,
    traversal_complete: bool,
    traversed_edges: u64,
    /// Fields shared by every edge of the complete traversal; stable across pages.
    common: AgentEdgeCommon,
    edges: Page<AgentEdgeSummary>,
    /// Snapshot profiles analyzed in a less precise mode, such as Rust
    /// syntax-only after the HIR memory budget (Issue #579). Omitted when every
    /// profile ran at full precision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 256))]
    analysis_degradations: Vec<AgentAnalysisDegradation>,
    /// File-level rollup of the selector's symbol dependencies (Issue #623).
    /// Present only when the request sets `rollup`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "crate::AgentSymbolRollup")]
    symbol_rollup: Option<crate::AgentSymbolRollup>,
}

impl AgentDependenciesSummaryResponse {
    pub fn new(
        root: AgentNode,
        direction: AgentDependencyDirection,
        transitive: bool,
        traversal_complete: bool,
        traversed_edges: u64,
        common: AgentEdgeCommon,
        edges: Page<AgentEdgeSummary>,
    ) -> Result<Self, ContractBuildError> {
        if traversed_edges < edges.total_items() {
            return Err(ContractBuildError::TraversalCount);
        }
        if !edges
            .items()
            .iter()
            .all(|edge| edge.is_consistent_with(&common))
        {
            return Err(ContractBuildError::DependencyDetailState);
        }
        Ok(Self {
            detail: AgentDependencySummaryTag::Summary,
            root,
            direction,
            transitive,
            traversal_complete,
            traversed_edges,
            common,
            edges,
            analysis_degradations: Vec::new(),
            symbol_rollup: None,
        })
    }

    /// Attaches the snapshot's degraded profiles (Issue #579).
    #[must_use]
    pub fn with_analysis_degradations(
        mut self,
        analysis_degradations: Vec<AgentAnalysisDegradation>,
    ) -> Self {
        self.analysis_degradations = analysis_degradations;
        self
    }

    #[must_use]
    pub fn analysis_degradations(&self) -> &[AgentAnalysisDegradation] {
        &self.analysis_degradations
    }

    /// Attaches the file-level symbol rollup (Issue #623).
    #[must_use]
    pub fn with_symbol_rollup(mut self, symbol_rollup: Option<crate::AgentSymbolRollup>) -> Self {
        self.symbol_rollup = symbol_rollup;
        self
    }

    #[must_use]
    pub const fn symbol_rollup(&self) -> Option<&crate::AgentSymbolRollup> {
        self.symbol_rollup.as_ref()
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
struct AgentDependenciesSummaryResponseWire {
    #[allow(dead_code)]
    detail: AgentDependencySummaryTag,
    root: AgentNode,
    direction: AgentDependencyDirection,
    transitive: bool,
    traversal_complete: bool,
    traversed_edges: u64,
    common: AgentEdgeCommon,
    edges: Page<AgentEdgeSummary>,
    #[serde(default, deserialize_with = "deserialize_analysis_degradations")]
    analysis_degradations: Vec<AgentAnalysisDegradation>,
    #[serde(default)]
    symbol_rollup: Option<crate::AgentSymbolRollup>,
}

impl<'de> Deserialize<'de> for AgentDependenciesSummaryResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentDependenciesSummaryResponseWire::deserialize(deserializer)?;
        Self::new(
            wire.root,
            wire.direction,
            wire.transitive,
            wire.traversal_complete,
            wire.traversed_edges,
            wire.common,
            wire.edges,
        )
        .map(|response| {
            response
                .with_analysis_degradations(wire.analysis_degradations)
                .with_symbol_rollup(wire.symbol_rollup)
        })
        .map_err(D::Error::custom)
    }
}

/// One end of an `AgentDependencyPath`: the repository-relative path of the node, or its
/// node ID when the node has no path (for example an external package).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AgentDependencyEndpoint {
    Path(RepositoryRelativePath),
    Id(AgentId),
}

impl AgentDependencyEndpoint {
    fn split(&self) -> (Option<&RepositoryRelativePath>, Option<&AgentId>) {
        match self {
            Self::Path(path) => (Some(path), None),
            Self::Id(id) => (None, Some(id)),
        }
    }

    fn join(
        path: Option<RepositoryRelativePath>,
        id: Option<AgentId>,
    ) -> Result<Self, ContractBuildError> {
        match (path, id) {
            (Some(path), None) => Ok(Self::Path(path)),
            (None, Some(id)) => Ok(Self::Id(id)),
            _ => Err(ContractBuildError::DependencyDetailState),
        }
    }

    fn from_node(node: &AgentNode) -> Self {
        node.repository_path().map_or_else(
            || Self::Id(node.id().clone()),
            |path| Self::Path(path.clone()),
        )
    }
}

/// `detail: "paths"` item: which path depends on which, by which edge kind.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AgentDependencyPath {
    source: AgentDependencyEndpoint,
    target: AgentDependencyEndpoint,
    kind: AgentToken,
}

impl AgentDependencyPath {
    #[must_use]
    pub const fn new(
        source: AgentDependencyEndpoint,
        target: AgentDependencyEndpoint,
        kind: AgentToken,
    ) -> Self {
        Self {
            source,
            target,
            kind,
        }
    }

    /// Projects one core traversal item through the same node projection as `AgentNode`.
    pub(crate) fn try_from_core(
        item: &depgraph_core::query::TraversalPageItem,
    ) -> Result<Self, ContractBuildError> {
        let source = agent_node_from_fields(
            &item.source.id,
            &item.source.kind,
            &item.source.locator,
            &item.source.display_name,
            &item.source.properties,
        )?;
        let target = agent_node_from_fields(
            &item.target.id,
            &item.target.kind,
            &item.target.locator,
            &item.target.display_name,
            &item.target.properties,
        )?;
        let kind = AgentToken::parse(&item.step.edge.kind)
            .map_err(|_| ContractBuildError::AgentDtoValue)?;
        Ok(Self::new(
            AgentDependencyEndpoint::from_node(&source),
            AgentDependencyEndpoint::from_node(&target),
            kind,
        ))
    }

    #[must_use]
    pub const fn source(&self) -> &AgentDependencyEndpoint {
        &self.source
    }

    #[must_use]
    pub const fn target(&self) -> &AgentDependencyEndpoint {
        &self.target
    }

    #[must_use]
    pub const fn kind(&self) -> &AgentToken {
        &self.kind
    }
}

#[derive(Serialize)]
struct AgentDependencyPathRef<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    source_path: Option<&'a RepositoryRelativePath>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_id: Option<&'a AgentId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_path: Option<&'a RepositoryRelativePath>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_id: Option<&'a AgentId>,
    kind: &'a AgentToken,
}

impl Serialize for AgentDependencyPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (source_path, source_id) = self.source.split();
        let (target_path, target_id) = self.target.split();
        AgentDependencyPathRef {
            source_path,
            source_id,
            target_path,
            target_id,
            kind: &self.kind,
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentDependencyPathWire {
    #[serde(default)]
    source_path: Option<RepositoryRelativePath>,
    #[serde(default)]
    source_id: Option<AgentId>,
    #[serde(default)]
    target_path: Option<RepositoryRelativePath>,
    #[serde(default)]
    target_id: Option<AgentId>,
    kind: AgentToken,
}

impl<'de> Deserialize<'de> for AgentDependencyPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentDependencyPathWire::deserialize(deserializer)?;
        Ok(Self::new(
            AgentDependencyEndpoint::join(wire.source_path, wire.source_id)
                .map_err(D::Error::custom)?,
            AgentDependencyEndpoint::join(wire.target_path, wire.target_id)
                .map_err(D::Error::custom)?,
            wire.kind,
        ))
    }
}

impl JsonSchema for AgentDependencyPath {
    fn schema_name() -> Cow<'static, str> {
        "AgentDependencyPath".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::AgentDependencyPath").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let path = generator.subschema_for::<RepositoryRelativePath>();
        let id = generator.subschema_for::<AgentId>();
        let kind = generator.subschema_for::<AgentToken>();
        json_schema!({
            "type": "object",
            "description": "Each end carries exactly one of its repository-relative path or, when the node has no path, its node ID.",
            "properties": {
                "source_path": path.clone(),
                "source_id": id.clone(),
                "target_path": path,
                "target_id": id,
                "kind": kind
            },
            "required": ["kind"],
            "additionalProperties": false,
            "allOf": [
                {"oneOf": [{"required": ["source_path"]}, {"required": ["source_id"]}]},
                {"oneOf": [{"required": ["target_path"]}, {"required": ["target_id"]}]}
            ]
        })
    }
}

/// `detail: "paths"` response of the dependency list tools. Items are unique by
/// (source, target, kind) in traversal order, so `total_items` can be smaller than the
/// number of traversed edges.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDependencyPathsResponse {
    detail: AgentDependencyPathsTag,
    root: AgentNode,
    direction: AgentDependencyDirection,
    transitive: bool,
    traversal_complete: bool,
    traversed_edges: u64,
    paths: Page<AgentDependencyPath>,
    /// Snapshot profiles analyzed in a less precise mode, such as Rust
    /// syntax-only after the HIR memory budget (Issue #579). Omitted when every
    /// profile ran at full precision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 256))]
    analysis_degradations: Vec<AgentAnalysisDegradation>,
    /// File-level rollup of the selector's symbol dependencies (Issue #623).
    /// Present only when the request sets `rollup`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "crate::AgentSymbolRollup")]
    symbol_rollup: Option<crate::AgentSymbolRollup>,
}

impl AgentDependencyPathsResponse {
    pub fn new(
        root: AgentNode,
        direction: AgentDependencyDirection,
        transitive: bool,
        traversal_complete: bool,
        traversed_edges: u64,
        paths: Page<AgentDependencyPath>,
    ) -> Result<Self, ContractBuildError> {
        if traversed_edges < paths.total_items() {
            return Err(ContractBuildError::TraversalCount);
        }
        let mut seen = BTreeSet::new();
        if !paths.items().iter().all(|path| seen.insert(path)) {
            return Err(ContractBuildError::DependencyDetailState);
        }
        Ok(Self {
            detail: AgentDependencyPathsTag::Paths,
            root,
            direction,
            transitive,
            traversal_complete,
            traversed_edges,
            paths,
            analysis_degradations: Vec::new(),
            symbol_rollup: None,
        })
    }

    /// Attaches the snapshot's degraded profiles (Issue #579).
    #[must_use]
    pub fn with_analysis_degradations(
        mut self,
        analysis_degradations: Vec<AgentAnalysisDegradation>,
    ) -> Self {
        self.analysis_degradations = analysis_degradations;
        self
    }

    #[must_use]
    pub fn analysis_degradations(&self) -> &[AgentAnalysisDegradation] {
        &self.analysis_degradations
    }

    /// Attaches the file-level symbol rollup (Issue #623).
    #[must_use]
    pub fn with_symbol_rollup(mut self, symbol_rollup: Option<crate::AgentSymbolRollup>) -> Self {
        self.symbol_rollup = symbol_rollup;
        self
    }

    #[must_use]
    pub const fn symbol_rollup(&self) -> Option<&crate::AgentSymbolRollup> {
        self.symbol_rollup.as_ref()
    }

    #[must_use]
    pub const fn paths(&self) -> &Page<AgentDependencyPath> {
        &self.paths
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentDependencyPathsResponseWire {
    #[allow(dead_code)]
    detail: AgentDependencyPathsTag,
    root: AgentNode,
    direction: AgentDependencyDirection,
    transitive: bool,
    traversal_complete: bool,
    traversed_edges: u64,
    paths: Page<AgentDependencyPath>,
    #[serde(default, deserialize_with = "deserialize_analysis_degradations")]
    analysis_degradations: Vec<AgentAnalysisDegradation>,
    #[serde(default)]
    symbol_rollup: Option<crate::AgentSymbolRollup>,
}

impl<'de> Deserialize<'de> for AgentDependencyPathsResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentDependencyPathsResponseWire::deserialize(deserializer)?;
        Self::new(
            wire.root,
            wire.direction,
            wire.transitive,
            wire.traversal_complete,
            wire.traversed_edges,
            wire.paths,
        )
        .map(|response| {
            response
                .with_analysis_degradations(wire.analysis_degradations)
                .with_symbol_rollup(wire.symbol_rollup)
        })
        .map_err(D::Error::custom)
    }
}

/// Result of the dependency list tools for any `detail`. `Full` serializes exactly like
/// `AgentDependenciesResponse`; the other variants carry their `detail` tag.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum AgentDependenciesOutput {
    Full(AgentDependenciesResponse),
    Summary(AgentDependenciesSummaryResponse),
    Paths(AgentDependencyPathsResponse),
}

impl AgentDependenciesOutput {
    #[must_use]
    pub const fn detail(&self) -> AgentDependencyDetail {
        match self {
            Self::Full(_) => AgentDependencyDetail::Full,
            Self::Summary(_) => AgentDependencyDetail::Summary,
            Self::Paths(_) => AgentDependencyDetail::Paths,
        }
    }
}

impl<'de> Deserialize<'de> for AgentDependenciesOutput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let detail = match value.get("detail") {
            None => AgentDependencyDetail::Full,
            Some(serde_json::Value::String(detail)) if detail == "summary" => {
                AgentDependencyDetail::Summary
            }
            Some(serde_json::Value::String(detail)) if detail == "paths" => {
                AgentDependencyDetail::Paths
            }
            Some(_) => {
                return Err(D::Error::custom(ContractBuildError::DependencyDetailState));
            }
        };
        match detail {
            AgentDependencyDetail::Full => serde_json::from_value(value).map(Self::Full),
            AgentDependencyDetail::Summary => serde_json::from_value(value).map(Self::Summary),
            AgentDependencyDetail::Paths => serde_json::from_value(value).map(Self::Paths),
        }
        .map_err(D::Error::custom)
    }
}

impl JsonSchema for AgentDependenciesOutput {
    fn schema_name() -> Cow<'static, str> {
        "AgentDependenciesOutput".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::AgentDependenciesOutput").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let full = generator.subschema_for::<AgentDependenciesResponse>();
        let summary = generator.subschema_for::<AgentDependenciesSummaryResponse>();
        let paths = generator.subschema_for::<AgentDependencyPathsResponse>();
        json_schema!({
            "description": "detail=full (default) is the legacy shape without a detail field; summary and paths carry their detail tag.",
            "oneOf": [full, summary, paths]
        })
    }
}
