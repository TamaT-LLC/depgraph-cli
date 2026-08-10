use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU32,
};

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use sha2::{Digest as _, Sha256};

use crate::{
    AgentArtifactId, AgentCondition, AgentFieldName, AgentGraphExportContent, AgentId, AgentLabel,
    AgentLocator, AgentPolicyText, AgentToken, ContractBuildError, MAX_AGENT_CONDITION_BYTES, Page,
    PolicyApiChangeId, PolicyConfigDigest, PolicyEvaluationCollectionDigest, PolicyEvaluationId,
    PolicyViolationId, RepositoryRelativePath, Sha256Digest, SnapshotDiffCollectionDigest,
    SnapshotId, SnapshotName,
};

pub const MAX_AGENT_EVIDENCE_ITEMS: usize = depgraph_core::service::MAX_GRAPH_EVIDENCE_ITEMS;
pub const MAX_AGENT_TARGET_ITEMS: usize = 256;
pub const MAX_AGENT_SNAPSHOT_METADATA_ITEMS: usize = 1_024;
pub const MAX_AGENT_PATH_STEPS: usize = depgraph_core::service::MAX_DEPENDENCY_PATH_STEPS;
pub const MAX_AGENT_CYCLE_NODES: usize = depgraph_core::service::MAX_CYCLE_NODE_IDS;
pub const MAX_AGENT_CORRELATION_REASONS: usize =
    depgraph_core::service::MAX_UNRESOLVED_CORRELATION_REASONS;
pub const MAX_AGENT_PHASES: usize = depgraph_core::service::MAX_UNRESOLVED_PHASES;
pub const MAX_AGENT_QUERY_TEXT_BYTES: usize = depgraph_core::MAX_QUERY_BYTES;
pub const MAX_AGENT_QUERY_VALUES: usize = depgraph_core::MAX_QUERY_PROJECTIONS;
pub const MAX_AGENT_ARTIFACT_ITEMS: usize = depgraph_core::service::MAX_SHARED_ARTIFACT_ITEMS;
pub const MAX_AGENT_CHANGED_FIELDS: usize = 256;

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AgentEvidenceKind {
    Source,
    Semantic,
    Build,
    Runtime,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentPhase {
    Source,
    Semantic,
    Build,
    Runtime,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentResolutionStatus {
    Resolved,
    Candidates,
    External,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentPrecision {
    Exact,
    Overapprox,
    Heuristic,
    Observed,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AgentCycleLevel {
    Package,
    File,
    Symbol,
    Type,
    Route,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentQueryDirection {
    Forward,
    Reverse,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentQueryValue {
    Text {
        #[schemars(length(max = 65536))]
        value: String,
    },
    Unsigned {
        value: u64,
    },
    Boolean {
        value: bool,
    },
    Null {},
    Node {
        node_id: AgentId,
    },
    Path {
        path_id: AgentId,
        depth: u8,
        direction: AgentQueryDirection,
        #[schemars(length(max = 9))]
        node_ids: Vec<AgentId>,
        #[schemars(length(max = 8))]
        edge_ids: Vec<AgentId>,
    },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum AgentQueryValueWire {
    Text {
        value: String,
    },
    Unsigned {
        value: u64,
    },
    Boolean {
        value: bool,
    },
    Null {},
    Node {
        node_id: AgentId,
    },
    Path {
        path_id: AgentId,
        depth: u8,
        direction: AgentQueryDirection,
        node_ids: Vec<AgentId>,
        edge_ids: Vec<AgentId>,
    },
}

impl AgentQueryValue {
    fn from_wire(wire: AgentQueryValueWire) -> Result<Self, ContractBuildError> {
        let value = match wire {
            AgentQueryValueWire::Text { value } => Self::Text { value },
            AgentQueryValueWire::Unsigned { value } => Self::Unsigned { value },
            AgentQueryValueWire::Boolean { value } => Self::Boolean { value },
            AgentQueryValueWire::Null {} => Self::Null {},
            AgentQueryValueWire::Node { node_id } => Self::Node { node_id },
            AgentQueryValueWire::Path {
                path_id,
                depth,
                direction,
                node_ids,
                edge_ids,
            } => Self::Path {
                path_id,
                depth,
                direction,
                node_ids,
                edge_ids,
            },
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ContractBuildError> {
        match self {
            Self::Text { value }
                if value.len() > MAX_AGENT_QUERY_TEXT_BYTES
                    || value.chars().any(char::is_control) =>
            {
                Err(ContractBuildError::QueryValue)
            }
            Self::Path {
                depth,
                node_ids,
                edge_ids,
                ..
            } if *depth == 0
                || *depth > depgraph_core::MAX_QUERY_DEPTH
                || edge_ids.len() != usize::from(*depth)
                || node_ids.len() != edge_ids.len() + 1 =>
            {
                Err(ContractBuildError::QueryValue)
            }
            _ => Ok(()),
        }
    }
}

impl<'de> Deserialize<'de> for AgentQueryValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_wire(AgentQueryValueWire::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentQueryRow {
    #[schemars(length(max = 32))]
    values: Vec<AgentQueryValue>,
}

impl AgentQueryRow {
    pub fn new(values: Vec<AgentQueryValue>) -> Result<Self, ContractBuildError> {
        if values.is_empty() || values.len() > MAX_AGENT_QUERY_VALUES {
            return Err(ContractBuildError::TooManyQueryValues);
        }
        values.iter().try_for_each(AgentQueryValue::validate)?;
        Ok(Self { values })
    }

    #[must_use]
    pub fn values(&self) -> &[AgentQueryValue] {
        &self.values
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentQueryRowWire {
    values: Vec<AgentQueryValue>,
}

impl<'de> Deserialize<'de> for AgentQueryRow {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentQueryRowWire::deserialize(deserializer)?;
        Self::new(wire.values).map_err(D::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRuntimeMatchStatus {
    Resolved,
    External,
    Unresolved,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeLocatorMatch {
    status: AgentRuntimeMatchStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    node_id: Option<AgentId>,
}

impl AgentRuntimeLocatorMatch {
    fn new(
        status: AgentRuntimeMatchStatus,
        node_id: Option<AgentId>,
    ) -> Result<Self, ContractBuildError> {
        if matches!(status, AgentRuntimeMatchStatus::Resolved) != node_id.is_some() {
            return Err(ContractBuildError::AgentDtoValue);
        }
        Ok(Self { status, node_id })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentRuntimeLocatorMatchWire {
    status: AgentRuntimeMatchStatus,
    #[serde(default)]
    node_id: Option<AgentId>,
}

impl<'de> Deserialize<'de> for AgentRuntimeLocatorMatch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentRuntimeLocatorMatchWire::deserialize(deserializer)?;
        Self::new(wire.status, wire.node_id).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeTraceEvent {
    id: AgentId,
    sequence: u64,
    dependency_kind: AgentToken,
    source: AgentRuntimeLocatorMatch,
    target: AgentRuntimeLocatorMatch,
    count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    duration_ns: Option<u64>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeProfileMatch {
    status: AgentRuntimeMatchStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_profile_id: Option<AgentId>,
}

impl AgentRuntimeProfileMatch {
    fn new(
        status: AgentRuntimeMatchStatus,
        parent_profile_id: Option<AgentId>,
    ) -> Result<Self, ContractBuildError> {
        if matches!(status, AgentRuntimeMatchStatus::Resolved) != parent_profile_id.is_some()
            || matches!(status, AgentRuntimeMatchStatus::External)
        {
            return Err(ContractBuildError::AgentDtoValue);
        }
        Ok(Self {
            status,
            parent_profile_id,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentRuntimeProfileMatchWire {
    status: AgentRuntimeMatchStatus,
    #[serde(default)]
    parent_profile_id: Option<AgentId>,
}

impl<'de> Deserialize<'de> for AgentRuntimeProfileMatch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentRuntimeProfileMatchWire::deserialize(deserializer)?;
        Self::new(wire.status, wire.parent_profile_id).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeTraceSummary {
    events: u64,
    resolved_targets: u64,
    external_targets: u64,
    unresolved_targets: u64,
    redacted_values: u64,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeValidationResponse {
    schema_version: AgentLabel,
    profile_match: AgentRuntimeProfileMatch,
    summary: AgentRuntimeTraceSummary,
    events: Page<AgentRuntimeTraceEvent>,
}

impl AgentRuntimeValidationResponse {
    pub fn try_new(
        trace: &depgraph_core::ValidatedRuntimeTrace,
        events: Page<AgentRuntimeTraceEvent>,
    ) -> Result<Self, ContractBuildError> {
        if events.total_items() != trace.summary.events {
            return Err(ContractBuildError::TraversalCount);
        }
        let response = Self {
            schema_version: parse_agent_value(&trace.schema_version)?,
            profile_match: AgentRuntimeProfileMatch::new(
                agent_runtime_status(trace.profile_match.status),
                trace
                    .profile_match
                    .parent_profile_id
                    .as_deref()
                    .map(AgentId::parse)
                    .transpose()
                    .map_err(|_| ContractBuildError::AgentDtoValue)?,
            )?,
            summary: AgentRuntimeTraceSummary {
                events: trace.summary.events,
                resolved_targets: trace.summary.resolved_targets,
                external_targets: trace.summary.external_targets,
                unresolved_targets: trace.summary.unresolved_targets,
                redacted_values: trace.summary.redacted_values,
            },
            events,
        };
        response.validate()?;
        Ok(response)
    }

    #[must_use]
    pub const fn events(&self) -> &Page<AgentRuntimeTraceEvent> {
        &self.events
    }

    fn validate(&self) -> Result<(), ContractBuildError> {
        if self.events.total_items() != self.summary.events
            || self
                .summary
                .resolved_targets
                .checked_add(self.summary.external_targets)
                .and_then(|value| value.checked_add(self.summary.unresolved_targets))
                != Some(self.summary.events)
        {
            return Err(ContractBuildError::TraversalCount);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentRuntimeValidationResponseWire {
    schema_version: AgentLabel,
    profile_match: AgentRuntimeProfileMatch,
    summary: AgentRuntimeTraceSummary,
    events: Page<AgentRuntimeTraceEvent>,
}

impl<'de> Deserialize<'de> for AgentRuntimeValidationResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentRuntimeValidationResponseWire::deserialize(deserializer)?;
        let response = Self {
            schema_version: wire.schema_version,
            profile_match: wire.profile_match,
            summary: wire.summary,
            events: wire.events,
        };
        response.validate().map_err(D::Error::custom)?;
        Ok(response)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCorrelationStatus {
    Matched,
    Additional,
    Conflict,
    Unobserved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCorrelationDifference {
    ObservedAddition,
    NotObserved,
    TargetMismatch,
    ConditionMismatch,
    ResolutionMismatch,
    SemanticRefinement,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSnapshotAvailability {
    Available,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSourcePosition {
    line: NonZeroU32,
    column: NonZeroU32,
}

impl AgentSourcePosition {
    #[must_use]
    pub const fn new(line: NonZeroU32, column: NonZeroU32) -> Self {
        Self { line, column }
    }

    #[must_use]
    pub const fn line(self) -> u32 {
        self.line.get()
    }

    #[must_use]
    pub const fn column(self) -> u32 {
        self.column.get()
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSourceSpan {
    path: RepositoryRelativePath,
    start: AgentSourcePosition,
    end: AgentSourcePosition,
}

impl AgentSourceSpan {
    pub fn new(
        path: RepositoryRelativePath,
        start: AgentSourcePosition,
        end: AgentSourcePosition,
    ) -> Result<Self, ContractBuildError> {
        if (end.line(), end.column()) < (start.line(), start.column()) {
            return Err(ContractBuildError::SourceSpan);
        }
        Ok(Self { path, start, end })
    }

    #[must_use]
    pub const fn path(&self) -> &RepositoryRelativePath {
        &self.path
    }

    #[must_use]
    pub const fn start(&self) -> AgentSourcePosition {
        self.start
    }

    #[must_use]
    pub const fn end(&self) -> AgentSourcePosition {
        self.end
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSourceSpanWire {
    path: RepositoryRelativePath,
    start: AgentSourcePosition,
    end: AgentSourcePosition,
}

impl<'de> Deserialize<'de> for AgentSourceSpan {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentSourceSpanWire::deserialize(deserializer)?;
        Self::new(wire.path, wire.start, wire.end).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEvidence {
    kind: AgentEvidenceKind,
    extractor: AgentToken,
    extractor_version: AgentLabel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    span: Option<AgentSourceSpan>,
}

impl AgentEvidence {
    #[must_use]
    pub const fn new(
        kind: AgentEvidenceKind,
        extractor: AgentToken,
        extractor_version: AgentLabel,
        span: Option<AgentSourceSpan>,
    ) -> Self {
        Self {
            kind,
            extractor,
            extractor_version,
            span,
        }
    }

    #[must_use]
    pub const fn span(&self) -> Option<&AgentSourceSpan> {
        self.span.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentNode {
    id: AgentId,
    kind: AgentToken,
    locator: AgentLocator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<AgentLabel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    repository_path: Option<RepositoryRelativePath>,
}

impl AgentNode {
    #[must_use]
    pub const fn new(
        id: AgentId,
        kind: AgentToken,
        locator: AgentLocator,
        display_name: Option<AgentLabel>,
        repository_path: Option<RepositoryRelativePath>,
    ) -> Self {
        Self {
            id,
            kind,
            locator,
            display_name,
            repository_path,
        }
    }

    #[must_use]
    pub const fn id(&self) -> &AgentId {
        &self.id
    }

    #[must_use]
    pub const fn repository_path(&self) -> Option<&RepositoryRelativePath> {
        self.repository_path.as_ref()
    }
}

/// Closed four-field projection used only by bounded node discovery.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentNodeSummary {
    id: AgentId,
    kind: AgentToken,
    locator: AgentLocator,
    display_name: AgentLabel,
}

impl AgentNodeSummary {
    #[must_use]
    pub const fn new(
        id: AgentId,
        kind: AgentToken,
        locator: AgentLocator,
        display_name: AgentLabel,
    ) -> Self {
        Self {
            id,
            kind,
            locator,
            display_name,
        }
    }

    #[must_use]
    pub const fn id(&self) -> &AgentId {
        &self.id
    }
}

impl TryFrom<&depgraph_core::service::NodeProjection> for AgentNodeSummary {
    type Error = ContractBuildError;

    fn try_from(source: &depgraph_core::service::NodeProjection) -> Result<Self, Self::Error> {
        Ok(Self::new(
            parse_agent_value(source.id())?,
            parse_agent_value(source.kind())?,
            parse_agent_value(source.locator())?,
            parse_agent_value(source.display_name())?,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCoverage {
    profiles: u64,
    files_discovered: u64,
    files_analyzed: u64,
    files_skipped: u64,
    dependency_sites: u64,
    resolved: u64,
    candidates: u64,
    external: u64,
    unresolved: u64,
    unsupported_syntax: u64,
    project_code_executed: bool,
    #[schemars(length(max = 1024))]
    #[serde(deserialize_with = "deserialize_snapshot_metadata")]
    completeness: Vec<AgentToken>,
    #[schemars(length(max = 1024))]
    #[serde(deserialize_with = "deserialize_snapshot_metadata")]
    reasons: Vec<AgentLabel>,
}

impl TryFrom<&depgraph_core::service::CoverageRecord> for AgentCoverage {
    type Error = ContractBuildError;

    fn try_from(source: &depgraph_core::service::CoverageRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            profiles: source.profiles,
            files_discovered: source.files_discovered,
            files_analyzed: source.files_analyzed,
            files_skipped: source.files_skipped,
            dependency_sites: source.dependency_sites,
            resolved: source.resolved,
            candidates: source.candidates,
            external: source.external,
            unresolved: source.unresolved,
            unsupported_syntax: source.unsupported_syntax,
            project_code_executed: source.project_code_executed,
            completeness: parse_agent_values(&source.completeness)?,
            reasons: parse_agent_values(&source.reasons)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentScanStatus {
    Completed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentScanCacheSummary {
    hits: u64,
    misses: u64,
}

impl AgentScanCacheSummary {
    #[must_use]
    pub const fn new(hits: u64, misses: u64) -> Self {
        Self { hits, misses }
    }

    #[must_use]
    pub const fn hits(self) -> u64 {
        self.hits
    }

    #[must_use]
    pub const fn misses(self) -> u64 {
        self.misses
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentScanOutcome {
    scan_id: AgentId,
    status: AgentScanStatus,
    project_code_executed: bool,
    cache: AgentScanCacheSummary,
    coverage: AgentCoverage,
}

impl AgentScanOutcome {
    pub fn new(
        scan_id: AgentId,
        project_code_executed: bool,
        cache: AgentScanCacheSummary,
        coverage: AgentCoverage,
    ) -> Result<Self, ContractBuildError> {
        if project_code_executed || coverage.project_code_executed {
            return Err(ContractBuildError::AgentDtoValue);
        }
        Ok(Self {
            scan_id,
            status: AgentScanStatus::Completed,
            project_code_executed,
            cache,
            coverage,
        })
    }

    #[must_use]
    pub const fn scan_id(&self) -> &AgentId {
        &self.scan_id
    }

    #[must_use]
    pub const fn status(&self) -> AgentScanStatus {
        self.status
    }

    #[must_use]
    pub const fn project_code_executed(&self) -> bool {
        self.project_code_executed
    }

    #[must_use]
    pub const fn cache(&self) -> AgentScanCacheSummary {
        self.cache
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentScanOutcomeWire {
    scan_id: AgentId,
    status: AgentScanStatus,
    project_code_executed: bool,
    cache: AgentScanCacheSummary,
    coverage: AgentCoverage,
}

impl<'de> Deserialize<'de> for AgentScanOutcome {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentScanOutcomeWire::deserialize(deserializer)?;
        let outcome = Self::new(
            wire.scan_id,
            wire.project_code_executed,
            wire.cache,
            wire.coverage,
        )
        .map_err(D::Error::custom)?;
        if wire.status != outcome.status {
            return Err(D::Error::custom(ContractBuildError::AgentDtoValue));
        }
        Ok(outcome)
    }
}

impl TryFrom<&depgraph_core::service::ScanServiceOutcome> for AgentScanOutcome {
    type Error = ContractBuildError;

    fn try_from(source: &depgraph_core::service::ScanServiceOutcome) -> Result<Self, Self::Error> {
        let outcome = source.outcome();
        if outcome.status != "completed"
            || outcome.exit_code != 0
            || source.completed_snapshot_id().is_none()
        {
            return Err(ContractBuildError::AgentDtoValue);
        }
        let cache = AgentScanCacheSummary::new(
            u64::try_from(
                outcome
                    .cache_events
                    .iter()
                    .filter(|event| event.outcome == "hit")
                    .count(),
            )
            .map_err(|_| ContractBuildError::AgentDtoValue)?,
            u64::try_from(
                outcome
                    .cache_events
                    .iter()
                    .filter(|event| event.outcome == "miss")
                    .count(),
            )
            .map_err(|_| ContractBuildError::AgentDtoValue)?,
        );
        Self::new(
            parse_agent_value(&outcome.scan_id)?,
            outcome.coverage.project_code_executed,
            cache,
            AgentCoverage::try_from(&outcome.coverage)?,
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRuntimeStatus {
    Completed,
    Partial,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeOutcome {
    import_id: AgentId,
    session_id: AgentId,
    snapshot_id: SnapshotId,
    status: AgentRuntimeStatus,
    deduplicated: bool,
}

impl AgentRuntimeOutcome {
    #[must_use]
    pub const fn import_id(&self) -> &AgentId {
        &self.import_id
    }

    #[must_use]
    pub const fn session_id(&self) -> &AgentId {
        &self.session_id
    }

    #[must_use]
    pub const fn snapshot_id(&self) -> &SnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub const fn status(&self) -> AgentRuntimeStatus {
        self.status
    }

    #[must_use]
    pub const fn deduplicated(&self) -> bool {
        self.deduplicated
    }
}

impl TryFrom<&depgraph_core::service::RuntimeImportServiceOutcome> for AgentRuntimeOutcome {
    type Error = ContractBuildError;

    fn try_from(
        source: &depgraph_core::service::RuntimeImportServiceOutcome,
    ) -> Result<Self, Self::Error> {
        let result = source.result();
        let status = match result.status.as_str() {
            "completed" => AgentRuntimeStatus::Completed,
            "partial" => AgentRuntimeStatus::Partial,
            _ => return Err(ContractBuildError::AgentDtoValue),
        };
        let snapshot_id = SnapshotId::parse(&result.snapshot_id)
            .map_err(|_| ContractBuildError::AgentDtoValue)?;
        if snapshot_id.as_str() != source.completed_snapshot_id().as_str() {
            return Err(ContractBuildError::AgentDtoValue);
        }
        Ok(Self {
            import_id: parse_agent_value(&result.import_id)?,
            session_id: parse_agent_value(&result.session_id)?,
            snapshot_id,
            status,
            deduplicated: result.deduplicated,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCompletedSnapshot {
    snapshot_id: SnapshotId,
    #[schemars(length(max = 1024))]
    #[serde(deserialize_with = "deserialize_snapshot_metadata")]
    names: Vec<SnapshotName>,
    status: AgentToken,
    source_kind: AgentToken,
    source_attempt_id: AgentId,
    scan_id: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    build_attempt_id: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runtime_import_id: Option<AgentId>,
    #[schemars(length(max = 1024))]
    #[serde(deserialize_with = "deserialize_snapshot_metadata")]
    runtime_session_ids: Vec<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_snapshot_id: Option<SnapshotId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_revision: Option<AgentLabel>,
    #[schemars(length(max = 1024))]
    #[serde(deserialize_with = "deserialize_snapshot_metadata")]
    profile_ids: Vec<AgentId>,
    created_at: AgentLabel,
    coverage: AgentCoverage,
}

impl AgentCompletedSnapshot {
    #[must_use]
    pub const fn snapshot_id(&self) -> &SnapshotId {
        &self.snapshot_id
    }
}

impl TryFrom<&depgraph_core::service::CompletedSnapshotView> for AgentCompletedSnapshot {
    type Error = ContractBuildError;

    fn try_from(
        source: &depgraph_core::service::CompletedSnapshotView,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            snapshot_id: parse_agent_value(source.id())?,
            names: parse_agent_values(source.names())?,
            status: parse_agent_value(source.status())?,
            source_kind: parse_agent_value(source.source_kind())?,
            source_attempt_id: parse_agent_value(source.source_attempt_id())?,
            scan_id: parse_agent_value(source.scan_id())?,
            build_attempt_id: parse_optional_agent_value(source.build_attempt_id())?,
            runtime_import_id: parse_optional_agent_value(source.runtime_import_id())?,
            runtime_session_ids: parse_agent_values(source.runtime_session_ids())?,
            parent_snapshot_id: parse_optional_agent_value(source.parent_snapshot_id())?,
            source_revision: parse_optional_agent_value(source.source_revision())?,
            profile_ids: parse_agent_values(source.profile_ids())?,
            created_at: parse_agent_value(source.created_at())?,
            coverage: AgentCoverage::try_from(source.coverage())?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentNamedSnapshot {
    name: SnapshotName,
    named_at: AgentLabel,
    snapshot: AgentCompletedSnapshot,
}

impl AgentNamedSnapshot {
    #[must_use]
    pub const fn new(
        name: SnapshotName,
        named_at: AgentLabel,
        snapshot: AgentCompletedSnapshot,
    ) -> Self {
        Self {
            name,
            named_at,
            snapshot,
        }
    }

    #[must_use]
    pub const fn name(&self) -> &SnapshotName {
        &self.name
    }

    #[must_use]
    pub const fn snapshot(&self) -> &AgentCompletedSnapshot {
        &self.snapshot
    }
}

impl TryFrom<&depgraph_core::service::NamedCompletedSnapshot> for AgentNamedSnapshot {
    type Error = ContractBuildError;

    fn try_from(
        source: &depgraph_core::service::NamedCompletedSnapshot,
    ) -> Result<Self, Self::Error> {
        Ok(Self::new(
            parse_agent_value(source.name())?,
            parse_agent_value(source.named_at())?,
            AgentCompletedSnapshot::try_from(source.snapshot())?,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCurrentSnapshot {
    available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<AgentCompletedSnapshot>,
}

impl AgentCurrentSnapshot {
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            available: false,
            details: None,
        }
    }

    #[must_use]
    pub const fn available(details: AgentCompletedSnapshot) -> Self {
        Self {
            available: true,
            details: Some(details),
        }
    }
}

impl JsonSchema for AgentCurrentSnapshot {
    fn schema_name() -> Cow<'static, str> {
        "AgentCurrentSnapshot".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::AgentCurrentSnapshot").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let details = generator.subschema_for::<AgentCompletedSnapshot>();
        json_schema!({
            "oneOf": [
                {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {"available": {"const": false}},
                    "required": ["available"]
                },
                {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "available": {"const": true},
                        "details": details
                    },
                    "required": ["available", "details"]
                }
            ]
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentCurrentSnapshotWire {
    available: bool,
    #[serde(default)]
    details: Option<AgentCompletedSnapshot>,
}

impl<'de> Deserialize<'de> for AgentCurrentSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentCurrentSnapshotWire::deserialize(deserializer)?;
        match (wire.available, wire.details) {
            (false, None) => Ok(Self::unavailable()),
            (true, Some(details)) => Ok(Self::available(details)),
            _ => Err(D::Error::custom(ContractBuildError::SnapshotAvailability)),
        }
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentContext {
    repository_id: crate::LogicalRepositoryId,
    #[schemars(length(min = 1, max = 5))]
    enabled_capabilities: Vec<crate::AgentCapability>,
    snapshot: AgentCurrentSnapshot,
}

impl AgentContext {
    pub fn new(
        repository_id: crate::LogicalRepositoryId,
        enabled_capabilities: Vec<crate::AgentCapability>,
        snapshot: AgentCurrentSnapshot,
    ) -> Result<Self, ContractBuildError> {
        if enabled_capabilities.is_empty()
            || enabled_capabilities.len() > 5
            || enabled_capabilities
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(ContractBuildError::CapabilitySet);
        }
        Ok(Self {
            repository_id,
            enabled_capabilities,
            snapshot,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentContextWire {
    repository_id: crate::LogicalRepositoryId,
    enabled_capabilities: Vec<crate::AgentCapability>,
    snapshot: AgentCurrentSnapshot,
}

impl<'de> Deserialize<'de> for AgentContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentContextWire::deserialize(deserializer)?;
        Self::new(wire.repository_id, wire.enabled_capabilities, wire.snapshot)
            .map_err(D::Error::custom)
    }
}

impl TryFrom<&depgraph_core::service::DepgraphContext> for AgentContext {
    type Error = ContractBuildError;

    fn try_from(source: &depgraph_core::service::DepgraphContext) -> Result<Self, Self::Error> {
        let snapshot = match source.current_snapshot().details() {
            Some(details) => {
                AgentCurrentSnapshot::available(AgentCompletedSnapshot::try_from(details)?)
            }
            None => AgentCurrentSnapshot::unavailable(),
        };
        Self::new(
            parse_agent_value(source.repository_id())?,
            source
                .enabled_capabilities()
                .iter()
                .copied()
                .map(crate::AgentCapability::from)
                .collect(),
            snapshot,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSite {
    id: AgentId,
    source_id: AgentId,
    kind: AgentToken,
    specifier: AgentLocator,
    resolution_status: AgentResolutionStatus,
    profile_id: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<AgentLabel>,
    #[schemars(length(max = 256))]
    #[serde(deserialize_with = "deserialize_agent_targets")]
    target_ids: Vec<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    span: Option<AgentSourceSpan>,
    #[schemars(length(max = 64))]
    #[serde(deserialize_with = "deserialize_agent_evidence")]
    evidence: Vec<AgentEvidence>,
}

impl AgentSite {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: AgentId,
        source_id: AgentId,
        kind: AgentToken,
        specifier: AgentLocator,
        resolution_status: AgentResolutionStatus,
        profile_id: AgentId,
        target_ids: Vec<AgentId>,
        span: Option<AgentSourceSpan>,
        evidence: Vec<AgentEvidence>,
    ) -> Result<Self, ContractBuildError> {
        Self::new_with_reason(
            id,
            source_id,
            kind,
            specifier,
            resolution_status,
            profile_id,
            None,
            target_ids,
            span,
            evidence,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_reason(
        id: AgentId,
        source_id: AgentId,
        kind: AgentToken,
        specifier: AgentLocator,
        resolution_status: AgentResolutionStatus,
        profile_id: AgentId,
        reason: Option<AgentLabel>,
        target_ids: Vec<AgentId>,
        span: Option<AgentSourceSpan>,
        evidence: Vec<AgentEvidence>,
    ) -> Result<Self, ContractBuildError> {
        validate_agent_targets(&target_ids)?;
        validate_agent_evidence(&evidence)?;
        Ok(Self {
            id,
            source_id,
            kind,
            specifier,
            resolution_status,
            profile_id,
            reason,
            target_ids,
            span,
            evidence,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &AgentId {
        &self.id
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEdge {
    id: AgentId,
    source_id: AgentId,
    target_id: AgentId,
    kind: AgentToken,
    phase: AgentPhase,
    resolution_status: AgentResolutionStatus,
    precision: AgentPrecision,
    profile_id: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    site_id: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    condition: Option<AgentCondition>,
    #[schemars(length(max = 64))]
    #[serde(deserialize_with = "deserialize_agent_evidence")]
    evidence: Vec<AgentEvidence>,
}

impl AgentEdge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: AgentId,
        source_id: AgentId,
        target_id: AgentId,
        kind: AgentToken,
        phase: AgentPhase,
        resolution_status: AgentResolutionStatus,
        precision: AgentPrecision,
        profile_id: AgentId,
        site_id: Option<AgentId>,
        condition: Option<AgentLabel>,
        evidence: Vec<AgentEvidence>,
    ) -> Result<Self, ContractBuildError> {
        Self::new_with_condition(
            id,
            source_id,
            target_id,
            kind,
            phase,
            resolution_status,
            precision,
            profile_id,
            site_id,
            condition.map(AgentCondition::from),
            evidence,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_condition(
        id: AgentId,
        source_id: AgentId,
        target_id: AgentId,
        kind: AgentToken,
        phase: AgentPhase,
        resolution_status: AgentResolutionStatus,
        precision: AgentPrecision,
        profile_id: AgentId,
        site_id: Option<AgentId>,
        condition: Option<AgentCondition>,
        evidence: Vec<AgentEvidence>,
    ) -> Result<Self, ContractBuildError> {
        validate_agent_evidence(&evidence)?;
        Ok(Self {
            id,
            source_id,
            target_id,
            kind,
            phase,
            resolution_status,
            precision,
            profile_id,
            site_id,
            condition,
            evidence,
        })
    }

    #[must_use]
    pub const fn source_id(&self) -> &AgentId {
        &self.source_id
    }

    #[must_use]
    pub const fn target_id(&self) -> &AgentId {
        &self.target_id
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AgentDependencyDirection {
    Outgoing,
    Incoming,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPathStep {
    source: AgentNode,
    edge: AgentEdge,
    target: AgentNode,
}

impl AgentPathStep {
    pub fn new(
        source: AgentNode,
        edge: AgentEdge,
        target: AgentNode,
    ) -> Result<Self, ContractBuildError> {
        if source.id() != edge.source_id() || target.id() != edge.target_id() {
            return Err(ContractBuildError::PathTopology);
        }
        Ok(Self {
            source,
            edge,
            target,
        })
    }

    #[must_use]
    pub const fn source(&self) -> &AgentNode {
        &self.source
    }

    #[must_use]
    pub const fn edge(&self) -> &AgentEdge {
        &self.edge
    }

    #[must_use]
    pub const fn target(&self) -> &AgentNode {
        &self.target
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentPathStepWire {
    source: AgentNode,
    edge: AgentEdge,
    target: AgentNode,
}

impl<'de> Deserialize<'de> for AgentPathStep {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentPathStepWire::deserialize(deserializer)?;
        Self::new(wire.source, wire.edge, wire.target).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDependenciesResponse {
    root: AgentNode,
    direction: AgentDependencyDirection,
    transitive: bool,
    traversal_complete: bool,
    traversed_edges: u64,
    edges: Page<AgentEdge>,
}

impl AgentDependenciesResponse {
    pub fn new(
        root: AgentNode,
        direction: AgentDependencyDirection,
        transitive: bool,
        traversal_complete: bool,
        traversed_edges: u64,
        edges: Page<AgentEdge>,
    ) -> Result<Self, ContractBuildError> {
        if traversed_edges < edges.total_items() {
            return Err(ContractBuildError::TraversalCount);
        }
        Ok(Self {
            root,
            direction,
            transitive,
            traversal_complete,
            traversed_edges,
            edges,
        })
    }

    /// Projects bounded core traversal items without exposing core properties or paths.
    /// Request-only values are explicit because the core result does not retain its request.
    pub fn from_core(
        source: &depgraph_core::service::DependenciesResult,
        direction: AgentDependencyDirection,
        transitive: bool,
    ) -> Result<Self, ContractBuildError> {
        let root = AgentNode::try_from(source)?;
        let edges = source
            .items()
            .iter()
            .map(|item| AgentEdge::try_from(&item.step))
            .collect::<Result<Vec<_>, _>>()?;
        let total_items = u64::try_from(edges.len()).map_err(|_| ContractBuildError::PageTotal)?;
        let edges = Page::new(edges, total_items, true, None)?;
        Self::new(
            root,
            direction,
            transitive,
            source.complete(),
            source.traversed_edges(),
            edges,
        )
    }

    #[must_use]
    pub const fn edges(&self) -> &Page<AgentEdge> {
        &self.edges
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentDependenciesResponseWire {
    root: AgentNode,
    direction: AgentDependencyDirection,
    transitive: bool,
    traversal_complete: bool,
    traversed_edges: u64,
    edges: Page<AgentEdge>,
}

impl<'de> Deserialize<'de> for AgentDependenciesResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentDependenciesResponseWire::deserialize(deserializer)?;
        Self::new(
            wire.root,
            wire.direction,
            wire.transitive,
            wire.traversal_complete,
            wire.traversed_edges,
            wire.edges,
        )
        .map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPathResponse {
    from: AgentNode,
    to: AgentNode,
    path_found: bool,
    traversed_edges: u64,
    #[schemars(length(max = 1000))]
    steps: Vec<AgentPathStep>,
}

impl AgentPathResponse {
    pub fn new(
        from: AgentNode,
        to: AgentNode,
        path_found: bool,
        traversed_edges: u64,
        steps: Vec<AgentPathStep>,
    ) -> Result<Self, ContractBuildError> {
        if steps.len() > MAX_AGENT_PATH_STEPS {
            return Err(ContractBuildError::TooManyPathSteps);
        }
        if traversed_edges < u64::try_from(steps.len()).unwrap_or(u64::MAX)
            || (!path_found && !steps.is_empty())
            || (path_found && from.id() != to.id() && steps.is_empty())
            || (path_found && from.id() == to.id() && !steps.is_empty())
        {
            return Err(ContractBuildError::PathTopology);
        }
        if steps
            .first()
            .is_some_and(|first| first.source().id() != from.id())
        {
            return Err(ContractBuildError::PathTopology);
        }
        if steps
            .last()
            .is_some_and(|last| last.target().id() != to.id())
        {
            return Err(ContractBuildError::PathTopology);
        }
        if steps
            .windows(2)
            .any(|pair| pair[0].target().id() != pair[1].source().id())
        {
            return Err(ContractBuildError::PathTopology);
        }
        Ok(Self {
            from,
            to,
            path_found,
            traversed_edges,
            steps,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentPathResponseWire {
    from: AgentNode,
    to: AgentNode,
    path_found: bool,
    traversed_edges: u64,
    steps: Vec<AgentPathStep>,
}

impl<'de> Deserialize<'de> for AgentPathResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentPathResponseWire::deserialize(deserializer)?;
        Self::new(
            wire.from,
            wire.to,
            wire.path_found,
            wire.traversed_edges,
            wire.steps,
        )
        .map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentChangedSince {
    requested_ref: AgentLabel,
    resolved_ref: AgentId,
    merge_base: AgentId,
    head: AgentId,
    changed_paths: u64,
    mapped_nodes: u64,
}

impl AgentChangedSince {
    fn try_from_core(
        source: &depgraph_core::impact::ImpactResult,
    ) -> Result<Option<Self>, ContractBuildError> {
        let Some(changed) = source.changed_set.as_ref() else {
            return Ok(None);
        };
        Ok(Some(Self {
            requested_ref: parse_agent_value(&changed.requested_ref)?,
            resolved_ref: parse_agent_value(&changed.resolved_ref)?,
            merge_base: parse_agent_value(&changed.merge_base)?,
            head: parse_agent_value(&changed.head)?,
            changed_paths: changed
                .changes
                .len()
                .try_into()
                .map_err(|_| ContractBuildError::TraversalCount)?,
            mapped_nodes: source
                .changed_nodes
                .len()
                .try_into()
                .map_err(|_| ContractBuildError::TraversalCount)?,
        }))
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentImpact {
    node: AgentNode,
    depth: u32,
    changed_node_id: AgentId,
    #[schemars(length(max = 1000))]
    dependency_path: Vec<AgentPathStep>,
}

impl AgentImpact {
    pub fn new(
        node: AgentNode,
        depth: u32,
        changed_node_id: AgentId,
        dependency_path: Vec<AgentPathStep>,
    ) -> Result<Self, ContractBuildError> {
        if dependency_path.len() > MAX_AGENT_PATH_STEPS {
            return Err(ContractBuildError::TooManyPathSteps);
        }
        if dependency_path
            .windows(2)
            .any(|pair| pair[0].target().id() != pair[1].source().id())
            || dependency_path
                .first()
                .is_some_and(|first| first.source().id() != node.id())
            || dependency_path
                .last()
                .is_some_and(|last| last.target().id() != &changed_node_id)
            || (dependency_path.is_empty() && node.id() != &changed_node_id)
        {
            return Err(ContractBuildError::PathTopology);
        }
        Ok(Self {
            node,
            depth,
            changed_node_id,
            dependency_path,
        })
    }
}

#[derive(Debug)]
pub(crate) enum ImpactProjectionFailure {
    Cancelled,
    ConditionTooLarge,
    TooManyItems,
    TooManyMaterializedPathSteps,
    Contract(ContractBuildError),
}

impl From<ContractBuildError> for ImpactProjectionFailure {
    fn from(error: ContractBuildError) -> Self {
        Self::Contract(error)
    }
}

pub(crate) struct AgentImpactProjection<'a> {
    result: &'a depgraph_core::impact::ImpactResult,
    nodes: BTreeMap<String, AgentNode>,
}

impl<'a> AgentImpactProjection<'a> {
    pub(crate) fn try_new(
        result: &'a depgraph_core::impact::ImpactResult,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<Self, ImpactProjectionFailure> {
        #[cfg(test)]
        IMPACT_LOOKUP_BUILDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if result.filters.max_nodes == 0
            || result.filters.max_nodes > depgraph_core::MAX_INTERACTIVE_QUERY_TRAVERSAL
            || result.impacts.len() > result.filters.max_nodes
        {
            return Err(ImpactProjectionFailure::TooManyItems);
        }
        if is_cancelled() {
            return Err(ImpactProjectionFailure::Cancelled);
        }
        let mut nodes = BTreeMap::new();
        insert_impact_projection_node(
            &mut nodes,
            &result.root.id,
            &result.root.kind,
            &result.root.locator,
            &result.root.display_name,
            &result.root.properties,
        )?;
        if nodes.len() > result.filters.max_nodes {
            return Err(ImpactProjectionFailure::TooManyItems);
        }
        for impact in &result.impacts {
            if is_cancelled() {
                return Err(ImpactProjectionFailure::Cancelled);
            }
            insert_impact_projection_node(
                &mut nodes,
                &impact.node.id,
                &impact.node.kind,
                &impact.node.locator,
                &impact.node.display_name,
                &impact.node.properties,
            )?;
            if nodes.len() > result.filters.max_nodes {
                return Err(ImpactProjectionFailure::TooManyItems);
            }
        }
        let mut materialized_path_steps = 0_usize;
        let mut required_path_nodes = BTreeSet::new();
        for impact in &result.impacts {
            if impact.dependency_path.len() > MAX_AGENT_PATH_STEPS {
                return Err(ContractBuildError::TooManyPathSteps.into());
            }
            materialized_path_steps = materialized_path_steps
                .checked_add(impact.dependency_path.len())
                .ok_or(ImpactProjectionFailure::TooManyMaterializedPathSteps)?;
            if materialized_path_steps > depgraph_core::service::MAX_IMPACT_MATERIALIZED_PATH_STEPS
            {
                return Err(ImpactProjectionFailure::TooManyMaterializedPathSteps);
            }
            for step in &impact.dependency_path {
                if is_cancelled() {
                    return Err(ImpactProjectionFailure::Cancelled);
                }
                for id in [&step.edge.source, &step.edge.target] {
                    if !nodes.contains_key(id) {
                        required_path_nodes.insert(id.clone());
                    }
                }
            }
        }
        // Changed nodes are not part of the public response. Scan them once only to enrich path
        // endpoints that the response actually needs; indexing every changed node could reject a
        // valid paginated result whose traversal itself stayed within `max_nodes`.
        for node in &result.changed_nodes {
            if is_cancelled() {
                return Err(ImpactProjectionFailure::Cancelled);
            }
            if required_path_nodes.remove(&node.id) {
                insert_impact_projection_node(
                    &mut nodes,
                    &node.id,
                    &node.kind,
                    &node.locator,
                    &node.display_name,
                    &node.properties,
                )?;
            }
        }
        for id in required_path_nodes {
            if is_cancelled() {
                return Err(ImpactProjectionFailure::Cancelled);
            }
            nodes.insert(id.clone(), impact_path_node(&id)?);
        }
        if nodes.len() > result.filters.max_nodes {
            return Err(ImpactProjectionFailure::TooManyItems);
        }
        if is_cancelled() {
            return Err(ImpactProjectionFailure::Cancelled);
        }
        Ok(Self { result, nodes })
    }

    pub(crate) fn convert_all(
        &self,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<Vec<AgentImpact>, ImpactProjectionFailure> {
        let mut projected = Vec::with_capacity(self.result.impacts.len());
        for impact in &self.result.impacts {
            if is_cancelled() {
                return Err(ImpactProjectionFailure::Cancelled);
            }
            let node = self
                .nodes
                .get(&impact.node.id)
                .cloned()
                .ok_or(ContractBuildError::AgentDtoValue)?;
            let mut dependency_path = Vec::with_capacity(impact.dependency_path.len());
            for step in &impact.dependency_path {
                if is_cancelled() {
                    return Err(ImpactProjectionFailure::Cancelled);
                }
                let source = self
                    .nodes
                    .get(&step.edge.source)
                    .cloned()
                    .ok_or(ContractBuildError::AgentDtoValue)?;
                let target = self
                    .nodes
                    .get(&step.edge.target)
                    .cloned()
                    .ok_or(ContractBuildError::AgentDtoValue)?;
                dependency_path.push(AgentPathStep::new(
                    source,
                    AgentEdge::try_from_core_cancellable(step, is_cancelled)?,
                    target,
                )?);
            }
            projected.push(AgentImpact::new(
                node,
                impact
                    .depth
                    .try_into()
                    .map_err(|_| ContractBuildError::TraversalCount)?,
                parse_agent_value(&impact.changed_node_id)?,
                dependency_path,
            )?);
        }
        if is_cancelled() {
            return Err(ImpactProjectionFailure::Cancelled);
        }
        Ok(projected)
    }
}

fn insert_impact_projection_node(
    nodes: &mut BTreeMap<String, AgentNode>,
    id: &str,
    kind: &str,
    locator: &str,
    display_name: &str,
    properties: &serde_json::Value,
) -> Result<(), ContractBuildError> {
    let projected = agent_node_from_fields(id, kind, locator, display_name, properties)?;
    if let Some(existing) = nodes.get(id) {
        if existing != &projected {
            return Err(ContractBuildError::AgentDtoValue);
        }
    } else {
        nodes.insert(id.to_owned(), projected);
    }
    Ok(())
}

#[cfg(test)]
static IMPACT_LOOKUP_BUILDS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn impact_path_node(id: &str) -> Result<AgentNode, ContractBuildError> {
    let id = AgentId::parse(id).map_err(|_| ContractBuildError::AgentDtoValue)?;
    Ok(AgentNode::new(
        id.clone(),
        AgentToken::parse("unknown").expect("fixed Agent token is valid"),
        AgentLocator::parse(format!("id:{}", id.as_str()))
            .map_err(|_| ContractBuildError::AgentDtoValue)?,
        None,
        None,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentImpactWire {
    node: AgentNode,
    depth: u32,
    changed_node_id: AgentId,
    dependency_path: Vec<AgentPathStep>,
}

impl<'de> Deserialize<'de> for AgentImpact {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentImpactWire::deserialize(deserializer)?;
        Self::new(
            wire.node,
            wire.depth,
            wire.changed_node_id,
            wire.dependency_path,
        )
        .map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentImpactResponse {
    root: AgentNode,
    root_impacted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    changed_since: Option<AgentChangedSince>,
    impacts: Page<AgentImpact>,
}

impl AgentImpactResponse {
    pub fn new(
        root: AgentNode,
        root_impacted: bool,
        changed_since: Option<AgentChangedSince>,
        impacts: Page<AgentImpact>,
    ) -> Result<Self, ContractBuildError> {
        if root_impacted != (impacts.total_items() > 0) {
            return Err(ContractBuildError::ImpactState);
        }
        Ok(Self {
            root,
            root_impacted,
            changed_since,
            impacts,
        })
    }

    pub(crate) fn core_fields(
        impact: &depgraph_core::impact::ImpactResult,
    ) -> Result<(AgentNode, bool, Option<AgentChangedSince>), ContractBuildError> {
        Ok((
            agent_node_from_fields(
                &impact.root.id,
                &impact.root.kind,
                &impact.root.locator,
                &impact.root.display_name,
                &impact.root.properties,
            )?,
            impact.root_impacted,
            AgentChangedSince::try_from_core(impact)?,
        ))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentImpactResponseWire {
    root: AgentNode,
    root_impacted: bool,
    #[serde(default)]
    changed_since: Option<AgentChangedSince>,
    impacts: Page<AgentImpact>,
}

impl<'de> Deserialize<'de> for AgentImpactResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentImpactResponseWire::deserialize(deserializer)?;
        Self::new(
            wire.root,
            wire.root_impacted,
            wire.changed_since,
            wire.impacts,
        )
        .map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCycle {
    level: AgentCycleLevel,
    #[schemars(length(min = 2, max = 1000))]
    node_ids: Vec<AgentId>,
}

impl AgentCycle {
    pub fn new(level: AgentCycleLevel, node_ids: Vec<AgentId>) -> Result<Self, ContractBuildError> {
        if node_ids.len() > MAX_AGENT_CYCLE_NODES {
            return Err(ContractBuildError::TooManyCycleNodes);
        }
        if node_ids.len() < 2 || node_ids.first() != node_ids.last() {
            return Err(ContractBuildError::CycleTopology);
        }
        Ok(Self { level, node_ids })
    }

    pub(crate) fn try_from_core_cancellable(
        source: &depgraph_core::query::CycleResult,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<Self, ImpactProjectionFailure> {
        if is_cancelled() {
            return Err(ImpactProjectionFailure::Cancelled);
        }
        let level = match source.level.as_str() {
            "package_instance" => AgentCycleLevel::Package,
            "file" => AgentCycleLevel::File,
            "symbol" => AgentCycleLevel::Symbol,
            "type" => AgentCycleLevel::Type,
            "route" => AgentCycleLevel::Route,
            _ => return Err(ContractBuildError::AgentDtoValue.into()),
        };
        if source.node_ids.len() > MAX_AGENT_CYCLE_NODES {
            return Err(ContractBuildError::TooManyCycleNodes.into());
        }
        let mut node_ids = Vec::with_capacity(source.node_ids.len());
        for node_id in &source.node_ids {
            if is_cancelled() {
                return Err(ImpactProjectionFailure::Cancelled);
            }
            node_ids.push(parse_agent_value(node_id)?);
        }
        if is_cancelled() {
            return Err(ImpactProjectionFailure::Cancelled);
        }
        Self::new(level, node_ids).map_err(Into::into)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentCycleWire {
    level: AgentCycleLevel,
    node_ids: Vec<AgentId>,
}

impl<'de> Deserialize<'de> for AgentCycle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentCycleWire::deserialize(deserializer)?;
        Self::new(wire.level, wire.node_ids).map_err(D::Error::custom)
    }
}

impl TryFrom<&depgraph_core::query::CycleResult> for AgentCycle {
    type Error = ContractBuildError;

    fn try_from(source: &depgraph_core::query::CycleResult) -> Result<Self, Self::Error> {
        Self::try_from_core_cancellable(source, &mut || false).map_err(projection_contract_error)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentUnresolved {
    site: AgentSite,
    #[schemars(length(max = 4))]
    phases: Vec<AgentPhase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effective_profile_id: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    correlation_status: Option<AgentCorrelationStatus>,
    #[schemars(length(max = 16))]
    observed_difference_reasons: Vec<AgentCorrelationDifference>,
}

impl AgentUnresolved {
    pub fn new(
        site: AgentSite,
        phases: Vec<AgentPhase>,
        effective_profile_id: Option<AgentId>,
        correlation_status: Option<AgentCorrelationStatus>,
        observed_difference_reasons: Vec<AgentCorrelationDifference>,
    ) -> Result<Self, ContractBuildError> {
        if phases.len() > MAX_AGENT_PHASES {
            return Err(ContractBuildError::TooManyPhases);
        }
        if observed_difference_reasons.len() > MAX_AGENT_CORRELATION_REASONS {
            return Err(ContractBuildError::TooManyCorrelationReasons);
        }
        if site.resolution_status != AgentResolutionStatus::Unresolved
            || correlation_status.is_some() != effective_profile_id.is_some()
            || (!observed_difference_reasons.is_empty() && correlation_status.is_none())
        {
            return Err(ContractBuildError::UnresolvedState);
        }
        Ok(Self {
            site,
            phases,
            effective_profile_id,
            correlation_status,
            observed_difference_reasons,
        })
    }

    pub(crate) fn try_from_core_cancellable(
        source: &depgraph_core::query::UnresolvedResult,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<Self, ImpactProjectionFailure> {
        if source.phases.len() > MAX_AGENT_PHASES {
            return Err(ContractBuildError::TooManyPhases.into());
        }
        if source.observed_difference_reasons.len() > MAX_AGENT_CORRELATION_REASONS {
            return Err(ContractBuildError::TooManyCorrelationReasons.into());
        }
        let mut phases = Vec::with_capacity(source.phases.len());
        for phase in &source.phases {
            if is_cancelled() {
                return Err(ImpactProjectionFailure::Cancelled);
            }
            phases.push(agent_phase(phase)?);
        }
        phases.sort_by_key(|phase| match phase {
            AgentPhase::Source => 0,
            AgentPhase::Semantic => 1,
            AgentPhase::Build => 2,
            AgentPhase::Runtime => 3,
        });
        phases.dedup();
        if is_cancelled() {
            return Err(ImpactProjectionFailure::Cancelled);
        }
        let correlation_status = source
            .correlation_status
            .as_deref()
            .map(|status| match status {
                "matched" => Ok(AgentCorrelationStatus::Matched),
                "additional" => Ok(AgentCorrelationStatus::Additional),
                "conflict" => Ok(AgentCorrelationStatus::Conflict),
                "unobserved" => Ok(AgentCorrelationStatus::Unobserved),
                _ => Err(ContractBuildError::AgentDtoValue),
            })
            .transpose()?;
        let mut observed_difference_reasons =
            Vec::with_capacity(source.observed_difference_reasons.len());
        for reason in &source.observed_difference_reasons {
            if is_cancelled() {
                return Err(ImpactProjectionFailure::Cancelled);
            }
            observed_difference_reasons.push(match reason.as_str() {
                "observed_addition" => AgentCorrelationDifference::ObservedAddition,
                "not_observed" => AgentCorrelationDifference::NotObserved,
                "target_mismatch" => AgentCorrelationDifference::TargetMismatch,
                "condition_mismatch" => AgentCorrelationDifference::ConditionMismatch,
                "resolution_mismatch" => AgentCorrelationDifference::ResolutionMismatch,
                "semantic_refinement" => AgentCorrelationDifference::SemanticRefinement,
                _ => return Err(ContractBuildError::AgentDtoValue.into()),
            });
        }
        Self::new(
            agent_site_from_core_cancellable(source, is_cancelled)?,
            phases,
            parse_optional_agent_value(source.effective_profile_id.as_deref())?,
            correlation_status,
            observed_difference_reasons,
        )
        .map_err(Into::into)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentUnresolvedWire {
    site: AgentSite,
    phases: Vec<AgentPhase>,
    #[serde(default)]
    effective_profile_id: Option<AgentId>,
    #[serde(default)]
    correlation_status: Option<AgentCorrelationStatus>,
    observed_difference_reasons: Vec<AgentCorrelationDifference>,
}

impl<'de> Deserialize<'de> for AgentUnresolved {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentUnresolvedWire::deserialize(deserializer)?;
        Self::new(
            wire.site,
            wire.phases,
            wire.effective_profile_id,
            wire.correlation_status,
            wire.observed_difference_reasons,
        )
        .map_err(D::Error::custom)
    }
}

impl TryFrom<&depgraph_core::query::UnresolvedResult> for AgentUnresolved {
    type Error = ContractBuildError;

    fn try_from(source: &depgraph_core::query::UnresolvedResult) -> Result<Self, Self::Error> {
        Self::try_from_core_cancellable(source, &mut || false).map_err(projection_contract_error)
    }
}

impl TryFrom<&depgraph_core::query::UnresolvedResult> for AgentSite {
    type Error = ContractBuildError;

    fn try_from(source: &depgraph_core::query::UnresolvedResult) -> Result<Self, Self::Error> {
        agent_site_from_core_cancellable(source, &mut || false).map_err(projection_contract_error)
    }
}

fn agent_site_from_core_cancellable(
    source: &depgraph_core::query::UnresolvedResult,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<AgentSite, ImpactProjectionFailure> {
    let site = &source.site;
    if source.evidence.len() > MAX_AGENT_EVIDENCE_ITEMS {
        return Err(ContractBuildError::TooManyEvidenceItems.into());
    }
    let mut evidence = Vec::with_capacity(source.evidence.len());
    for record in &source.evidence {
        if is_cancelled() {
            return Err(ImpactProjectionFailure::Cancelled);
        }
        evidence.push(agent_evidence(
            &record.kind,
            &record.extractor,
            &record.extractor_version,
            &record.path,
            record.start_line,
            record.start_column,
            record.end_line,
            record.end_column,
        )?);
    }
    let span = source.evidence.first().and_then(|record| {
        safe_source_span(
            &record.path,
            record.start_line,
            record.start_column,
            record.end_line,
            record.end_column,
        )
    });
    let specifier = site
        .specifier
        .as_deref()
        .and_then(|value| AgentLocator::parse(value).ok())
        .or_else(|| AgentLocator::parse(format!("id:{}", site.id)).ok())
        .ok_or(ContractBuildError::AgentDtoValue)?;
    let resolution_status = match site.resolution_status.as_str() {
        "resolved" => AgentResolutionStatus::Resolved,
        "candidates" => AgentResolutionStatus::Candidates,
        "external" => AgentResolutionStatus::External,
        "unresolved" => AgentResolutionStatus::Unresolved,
        _ => return Err(ContractBuildError::AgentDtoValue.into()),
    };
    let mut target_ids = Vec::with_capacity(site.target_ids.len());
    for target_id in &site.target_ids {
        if is_cancelled() {
            return Err(ImpactProjectionFailure::Cancelled);
        }
        target_ids.push(parse_agent_value(target_id)?);
    }
    if is_cancelled() {
        return Err(ImpactProjectionFailure::Cancelled);
    }
    AgentSite::new_with_reason(
        parse_agent_value(&site.id)?,
        parse_agent_value(&site.source)?,
        parse_agent_value(&site.kind)?,
        specifier,
        resolution_status,
        parse_agent_value(&site.profile_id)?,
        site.reason
            .as_deref()
            .and_then(|value| AgentLabel::parse(value).ok()),
        target_ids,
        span,
        evidence,
    )
    .map_err(Into::into)
}

fn projection_contract_error(error: ImpactProjectionFailure) -> ContractBuildError {
    match error {
        ImpactProjectionFailure::Contract(error) => error,
        ImpactProjectionFailure::ConditionTooLarge => ContractBuildError::PageByteLimit,
        ImpactProjectionFailure::Cancelled
        | ImpactProjectionFailure::TooManyItems
        | ImpactProjectionFailure::TooManyMaterializedPathSteps => {
            ContractBuildError::AgentDtoValue
        }
    }
}

impl AgentEdge {
    pub(crate) fn try_from_core_cancellable(
        source: &depgraph_core::query::PathStep,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<Self, ImpactProjectionFailure> {
        if is_cancelled() {
            return Err(ImpactProjectionFailure::Cancelled);
        }
        let edge = &source.edge;
        if source.evidence.len() > MAX_AGENT_EVIDENCE_ITEMS {
            return Err(ContractBuildError::TooManyEvidenceItems.into());
        }
        let mut evidence = Vec::with_capacity(source.evidence.len());
        for record in &source.evidence {
            if is_cancelled() {
                return Err(ImpactProjectionFailure::Cancelled);
            }
            evidence.push(agent_evidence(
                &record.kind,
                &record.extractor,
                &record.extractor_version,
                &record.path,
                record.start_line,
                record.start_column,
                record.end_line,
                record.end_column,
            )?);
        }
        if is_cancelled() {
            return Err(ImpactProjectionFailure::Cancelled);
        }
        let phase = agent_phase(&edge.phase)?;
        let resolution_status = match edge.resolution_status.as_str() {
            "resolved" => AgentResolutionStatus::Resolved,
            "candidates" => AgentResolutionStatus::Candidates,
            "external" => AgentResolutionStatus::External,
            "unresolved" => AgentResolutionStatus::Unresolved,
            _ => return Err(ContractBuildError::AgentDtoValue.into()),
        };
        let precision = match edge.precision.as_str() {
            "exact" => AgentPrecision::Exact,
            "overapprox" => AgentPrecision::Overapprox,
            "heuristic" => AgentPrecision::Heuristic,
            "observed" => AgentPrecision::Observed,
            _ => return Err(ContractBuildError::AgentDtoValue.into()),
        };
        let projected = Self::new_with_condition(
            parse_agent_value(&edge.id)?,
            parse_agent_value(&edge.source)?,
            parse_agent_value(&edge.target)?,
            parse_agent_value(&edge.kind)?,
            phase,
            resolution_status,
            precision,
            parse_agent_value(&edge.profile_id)?,
            parse_optional_agent_value(edge.site_id.as_deref())?,
            Some(parse_projected_agent_condition(&source.condition_text)?),
            evidence,
        )?;
        if is_cancelled() {
            return Err(ImpactProjectionFailure::Cancelled);
        }
        Ok(projected)
    }
}

impl TryFrom<&depgraph_core::query::PathStep> for AgentEdge {
    type Error = ContractBuildError;

    fn try_from(source: &depgraph_core::query::PathStep) -> Result<Self, Self::Error> {
        Self::try_from_core_cancellable(source, &mut || false).map_err(projection_contract_error)
    }
}

impl TryFrom<&depgraph_core::query::TraversalPageItem> for AgentPathStep {
    type Error = ContractBuildError;

    fn try_from(source: &depgraph_core::query::TraversalPageItem) -> Result<Self, Self::Error> {
        Self::new(
            agent_node_from_fields(
                &source.source.id,
                &source.source.kind,
                &source.source.locator,
                &source.source.display_name,
                &source.source.properties,
            )?,
            AgentEdge::try_from(&source.step)?,
            agent_node_from_fields(
                &source.target.id,
                &source.target.kind,
                &source.target.locator,
                &source.target.display_name,
                &source.target.properties,
            )?,
        )
    }
}

impl TryFrom<&depgraph_core::service::NodeProjection> for AgentNode {
    type Error = ContractBuildError;

    fn try_from(source: &depgraph_core::service::NodeProjection) -> Result<Self, Self::Error> {
        agent_node_from_fields(
            source.id(),
            source.kind(),
            source.locator(),
            source.display_name(),
            &serde_json::Value::Null,
        )
    }
}

impl TryFrom<&depgraph_core::service::EvidenceProjection> for AgentEvidence {
    type Error = ContractBuildError;

    fn try_from(source: &depgraph_core::service::EvidenceProjection) -> Result<Self, Self::Error> {
        agent_evidence(
            source.kind(),
            source.extractor(),
            source.extractor_version(),
            source.path(),
            source.start_line(),
            source.start_column(),
            source.end_line(),
            source.end_column(),
        )
    }
}

impl TryFrom<&depgraph_core::service::SiteProjection> for AgentSite {
    type Error = ContractBuildError;

    fn try_from(source: &depgraph_core::service::SiteProjection) -> Result<Self, Self::Error> {
        let evidence = source
            .evidence()
            .iter()
            .map(AgentEvidence::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let targets = source
            .target_ids()
            .iter()
            .map(|id| parse_agent_value(id))
            .collect::<Result<Vec<_>, _>>()?;
        let span = source.evidence().first().and_then(|evidence| {
            safe_source_span(
                evidence.path(),
                evidence.start_line(),
                evidence.start_column(),
                evidence.end_line(),
                evidence.end_column(),
            )
        });
        let specifier = source
            .specifier()
            .and_then(|value| AgentLocator::parse(value).ok())
            .or_else(|| AgentLocator::parse(format!("id:{}", source.id())).ok())
            .ok_or(ContractBuildError::AgentDtoValue)?;
        let status = match source.resolution_status() {
            "resolved" => AgentResolutionStatus::Resolved,
            "candidates" => AgentResolutionStatus::Candidates,
            "external" => AgentResolutionStatus::External,
            "unresolved" => AgentResolutionStatus::Unresolved,
            _ => return Err(ContractBuildError::AgentDtoValue),
        };
        AgentSite::new_with_reason(
            parse_agent_value(source.id())?,
            parse_agent_value(source.source())?,
            parse_agent_value(source.kind())?,
            specifier,
            status,
            parse_agent_value(source.profile_id())?,
            source
                .reason()
                .and_then(|value| AgentLabel::parse(value).ok()),
            targets,
            span,
            evidence,
        )
    }
}

impl TryFrom<&depgraph_core::service::EdgeProjection> for AgentEdge {
    type Error = ContractBuildError;

    fn try_from(source: &depgraph_core::service::EdgeProjection) -> Result<Self, Self::Error> {
        let evidence = source
            .evidence()
            .iter()
            .map(AgentEvidence::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let phase = agent_phase(source.phase())?;
        let status = match source.resolution_status() {
            "resolved" => AgentResolutionStatus::Resolved,
            "candidates" => AgentResolutionStatus::Candidates,
            "external" => AgentResolutionStatus::External,
            "unresolved" => AgentResolutionStatus::Unresolved,
            _ => return Err(ContractBuildError::AgentDtoValue),
        };
        let precision = match source.precision() {
            "exact" => AgentPrecision::Exact,
            "overapprox" => AgentPrecision::Overapprox,
            "heuristic" => AgentPrecision::Heuristic,
            "observed" => AgentPrecision::Observed,
            _ => return Err(ContractBuildError::AgentDtoValue),
        };
        AgentEdge::new_with_condition(
            parse_agent_value(source.id())?,
            parse_agent_value(source.source())?,
            parse_agent_value(source.target())?,
            parse_agent_value(source.kind())?,
            phase,
            status,
            precision,
            parse_agent_value(source.profile_id())?,
            parse_optional_agent_value(source.site_id())?,
            Some(parse_agent_condition(source.condition())?),
            evidence,
        )
    }
}

impl TryFrom<&depgraph_core::service::DependenciesResult> for AgentNode {
    type Error = ContractBuildError;

    fn try_from(source: &depgraph_core::service::DependenciesResult) -> Result<Self, Self::Error> {
        let root = &source.traversal().root;
        agent_node_from_fields(
            &root.id,
            &root.kind,
            &root.locator,
            &root.display_name,
            &root.properties,
        )
    }
}

impl TryFrom<&depgraph_core::service::ExplainPathResult> for AgentPathResponse {
    type Error = ContractBuildError;

    fn try_from(source: &depgraph_core::service::ExplainPathResult) -> Result<Self, Self::Error> {
        let path = source.path();
        let from = agent_node_from_fields(
            &path.from.id,
            &path.from.kind,
            &path.from.locator,
            &path.from.display_name,
            &path.from.properties,
        )?;
        let to = agent_node_from_fields(
            &path.to.id,
            &path.to.kind,
            &path.to.locator,
            &path.to.display_name,
            &path.to.properties,
        )?;
        let steps = source
            .items()
            .iter()
            .map(AgentPathStep::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(from, to, path.path_found, source.traversed_edges(), steps)
    }
}

fn agent_node_from_fields(
    id: &str,
    kind: &str,
    locator: &str,
    display_name: &str,
    properties: &serde_json::Value,
) -> Result<AgentNode, ContractBuildError> {
    let id = AgentId::parse(id).map_err(|_| ContractBuildError::AgentDtoValue)?;
    let locator = AgentLocator::parse(locator)
        .or_else(|_| AgentLocator::parse(format!("id:{}", id.as_str())))
        .map_err(|_| ContractBuildError::AgentDtoValue)?;
    let repository_path = ["path", "source_path"]
        .into_iter()
        .filter_map(|key| properties.get(key).and_then(serde_json::Value::as_str))
        .find_map(|path| RepositoryRelativePath::parse(path).ok());
    Ok(AgentNode::new(
        id,
        parse_agent_value(kind)?,
        locator,
        AgentLabel::parse(display_name).ok(),
        repository_path,
    ))
}

fn safe_source_span(
    path: &str,
    start_line: u64,
    start_column: u64,
    end_line: u64,
    end_column: u64,
) -> Option<AgentSourceSpan> {
    let path = RepositoryRelativePath::parse(path).ok()?;
    let start = AgentSourcePosition::new(
        NonZeroU32::new(u32::try_from(start_line).ok()?)?,
        NonZeroU32::new(u32::try_from(start_column).ok()?)?,
    );
    let end = AgentSourcePosition::new(
        NonZeroU32::new(u32::try_from(end_line).ok()?)?,
        NonZeroU32::new(u32::try_from(end_column).ok()?)?,
    );
    AgentSourceSpan::new(path, start, end).ok()
}

#[allow(clippy::too_many_arguments)]
fn agent_evidence(
    kind: &str,
    extractor: &str,
    extractor_version: &str,
    path: &str,
    start_line: u64,
    start_column: u64,
    end_line: u64,
    end_column: u64,
) -> Result<AgentEvidence, ContractBuildError> {
    let kind = match kind {
        "source" => AgentEvidenceKind::Source,
        "semantic" => AgentEvidenceKind::Semantic,
        "build" => AgentEvidenceKind::Build,
        "runtime" => AgentEvidenceKind::Runtime,
        _ => return Err(ContractBuildError::AgentDtoValue),
    };
    let span = safe_source_span(path, start_line, start_column, end_line, end_column);
    Ok(AgentEvidence::new(
        kind,
        parse_agent_value(extractor)?,
        parse_agent_value(extractor_version)?,
        span,
    ))
}

fn agent_phase(value: &str) -> Result<AgentPhase, ContractBuildError> {
    match value {
        "source" => Ok(AgentPhase::Source),
        "semantic" => Ok(AgentPhase::Semantic),
        "build" => Ok(AgentPhase::Build),
        "runtime" => Ok(AgentPhase::Runtime),
        _ => Err(ContractBuildError::AgentDtoValue),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSnapshot {
    availability: AgentSnapshotAvailability,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_id: Option<SnapshotId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<SnapshotName>,
}

impl JsonSchema for AgentSnapshot {
    fn schema_name() -> Cow<'static, str> {
        "AgentSnapshot".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::AgentSnapshot").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let snapshot_id = generator.subschema_for::<SnapshotId>();
        let snapshot_name = generator.subschema_for::<SnapshotName>();
        json_schema!({
            "oneOf": [
                {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "availability": { "const": "available" },
                        "snapshot_id": snapshot_id,
                        "name": snapshot_name
                    },
                    "required": ["availability", "snapshot_id"]
                },
                {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "availability": { "const": "unavailable" }
                    },
                    "required": ["availability"]
                }
            ]
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSnapshotWire {
    availability: AgentSnapshotAvailability,
    #[serde(default)]
    snapshot_id: Option<SnapshotId>,
    #[serde(default)]
    name: Option<SnapshotName>,
}

impl<'de> Deserialize<'de> for AgentSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentSnapshotWire::deserialize(deserializer)?;
        match (wire.availability, wire.snapshot_id) {
            (AgentSnapshotAvailability::Available, Some(snapshot_id)) => {
                Ok(Self::available(snapshot_id, wire.name))
            }
            (AgentSnapshotAvailability::Unavailable, None) if wire.name.is_none() => {
                Ok(Self::unavailable())
            }
            _ => Err(D::Error::custom(ContractBuildError::SnapshotAvailability)),
        }
    }
}

impl AgentSnapshot {
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            availability: AgentSnapshotAvailability::Unavailable,
            snapshot_id: None,
            name: None,
        }
    }

    #[must_use]
    pub const fn available(snapshot_id: SnapshotId, name: Option<SnapshotName>) -> Self {
        Self {
            availability: AgentSnapshotAvailability::Available,
            snapshot_id: Some(snapshot_id),
            name,
        }
    }
}

fn validate_agent_evidence(evidence: &[AgentEvidence]) -> Result<(), ContractBuildError> {
    if evidence.len() > MAX_AGENT_EVIDENCE_ITEMS {
        return Err(ContractBuildError::TooManyEvidenceItems);
    }
    Ok(())
}

fn validate_agent_targets(targets: &[AgentId]) -> Result<(), ContractBuildError> {
    if targets.len() > MAX_AGENT_TARGET_ITEMS {
        return Err(ContractBuildError::TooManyTargetItems);
    }
    Ok(())
}

fn deserialize_agent_evidence<'de, D>(deserializer: D) -> Result<Vec<AgentEvidence>, D::Error>
where
    D: Deserializer<'de>,
{
    let evidence = Vec::<AgentEvidence>::deserialize(deserializer)?;
    validate_agent_evidence(&evidence).map_err(D::Error::custom)?;
    Ok(evidence)
}

fn deserialize_agent_targets<'de, D>(deserializer: D) -> Result<Vec<AgentId>, D::Error>
where
    D: Deserializer<'de>,
{
    let targets = Vec::<AgentId>::deserialize(deserializer)?;
    validate_agent_targets(&targets).map_err(D::Error::custom)?;
    Ok(targets)
}

fn parse_projected_agent_condition(value: &str) -> Result<AgentCondition, ImpactProjectionFailure> {
    if value.len() > MAX_AGENT_CONDITION_BYTES {
        return Err(ImpactProjectionFailure::ConditionTooLarge);
    }
    AgentCondition::parse(value)
        .map_err(|_| ImpactProjectionFailure::Contract(ContractBuildError::AgentDtoValue))
}

fn parse_agent_condition(value: &str) -> Result<AgentCondition, ContractBuildError> {
    if value.len() > MAX_AGENT_CONDITION_BYTES {
        return Err(ContractBuildError::PageByteLimit);
    }
    AgentCondition::parse(value).map_err(|_| ContractBuildError::AgentDtoValue)
}

fn parse_agent_value<T>(value: &str) -> Result<T, ContractBuildError>
where
    T: std::str::FromStr,
{
    value.parse().map_err(|_| ContractBuildError::AgentDtoValue)
}

fn parse_optional_agent_value<T>(value: Option<&str>) -> Result<Option<T>, ContractBuildError>
where
    T: std::str::FromStr,
{
    value.map(parse_agent_value).transpose()
}

fn parse_agent_values<T>(values: &[String]) -> Result<Vec<T>, ContractBuildError>
where
    T: std::str::FromStr,
{
    if values.len() > MAX_AGENT_SNAPSHOT_METADATA_ITEMS {
        return Err(ContractBuildError::TooManySnapshotMetadataItems);
    }
    values
        .iter()
        .map(|value| parse_agent_value(value))
        .collect()
}

fn deserialize_snapshot_metadata<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let values = Vec::<T>::deserialize(deserializer)?;
    if values.len() > MAX_AGENT_SNAPSHOT_METADATA_ITEMS {
        return Err(D::Error::custom(
            ContractBuildError::TooManySnapshotMetadataItems,
        ));
    }
    Ok(values)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundedQueryProjectionFailure {
    Cancelled,
    Contract(ContractBuildError),
}

impl From<ContractBuildError> for BoundedQueryProjectionFailure {
    fn from(error: ContractBuildError) -> Self {
        Self::Contract(error)
    }
}

pub fn project_bounded_query_rows(
    result: &depgraph_core::service::BoundedQueryServiceResult,
) -> Result<Vec<AgentQueryRow>, ContractBuildError> {
    project_bounded_query_rows_cancellable(result, &mut || false).map_err(|error| match error {
        BoundedQueryProjectionFailure::Contract(error) => error,
        BoundedQueryProjectionFailure::Cancelled => ContractBuildError::AgentDtoValue,
    })
}

pub fn project_bounded_query_rows_cancellable(
    result: &depgraph_core::service::BoundedQueryServiceResult,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<AgentQueryRow>, BoundedQueryProjectionFailure> {
    if is_cancelled() {
        return Err(BoundedQueryProjectionFailure::Cancelled);
    }
    let executed = result.result().ok_or(ContractBuildError::QueryValue)?;
    let mut rows = Vec::with_capacity(executed.rows.len());
    for row in &executed.rows {
        if is_cancelled() {
            return Err(BoundedQueryProjectionFailure::Cancelled);
        }
        let mut values = Vec::with_capacity(row.len());
        for value in row {
            if is_cancelled() {
                return Err(BoundedQueryProjectionFailure::Cancelled);
            }
            values.push(agent_query_value(value)?);
        }
        rows.push(AgentQueryRow::new(values)?);
    }
    if is_cancelled() {
        return Err(BoundedQueryProjectionFailure::Cancelled);
    }
    Ok(rows)
}

fn agent_query_value(value: &serde_json::Value) -> Result<AgentQueryValue, ContractBuildError> {
    let projected = match value {
        serde_json::Value::Null => AgentQueryValue::Null {},
        serde_json::Value::Bool(value) => AgentQueryValue::Boolean { value: *value },
        serde_json::Value::Number(value) => AgentQueryValue::Unsigned {
            value: value.as_u64().ok_or(ContractBuildError::QueryValue)?,
        },
        serde_json::Value::String(value) => AgentQueryValue::Text {
            value: value.clone(),
        },
        serde_json::Value::Object(object)
            if object.len() == 4 && object.contains_key("locator") =>
        {
            AgentQueryValue::Node {
                node_id: AgentId::parse(
                    object
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(ContractBuildError::QueryValue)?,
                )
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            }
        }
        serde_json::Value::Object(object)
            if object.len() == 7
                && object.contains_key("nodes")
                && object.contains_key("edges") =>
        {
            let edge_ids = query_entity_ids(
                object
                    .get("edges")
                    .and_then(serde_json::Value::as_array)
                    .ok_or(ContractBuildError::QueryValue)?,
            )?;
            let node_ids = query_entity_ids(
                object
                    .get("nodes")
                    .and_then(serde_json::Value::as_array)
                    .ok_or(ContractBuildError::QueryValue)?,
            )?;
            let depth = u8::try_from(
                object
                    .get("depth")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or(ContractBuildError::QueryValue)?,
            )
            .map_err(|_| ContractBuildError::QueryValue)?;
            let direction = match object.get("direction").and_then(serde_json::Value::as_str) {
                Some("forward") => AgentQueryDirection::Forward,
                Some("reverse") => AgentQueryDirection::Reverse,
                _ => return Err(ContractBuildError::QueryValue),
            };
            AgentQueryValue::Path {
                path_id: AgentId::parse(
                    object
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(ContractBuildError::QueryValue)?,
                )
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
                depth,
                direction,
                node_ids,
                edge_ids,
            }
        }
        _ => return Err(ContractBuildError::QueryValue),
    };
    projected.validate()?;
    Ok(projected)
}

fn query_entity_ids(entities: &[serde_json::Value]) -> Result<Vec<AgentId>, ContractBuildError> {
    entities
        .iter()
        .map(|entity| {
            AgentId::parse(
                entity
                    .as_object()
                    .and_then(|object| object.get("id"))
                    .and_then(serde_json::Value::as_str)
                    .ok_or(ContractBuildError::QueryValue)?,
            )
            .map_err(|_| ContractBuildError::AgentDtoValue)
        })
        .collect()
}

impl TryFrom<&depgraph_core::ValidatedRuntimeTraceEvent> for AgentRuntimeTraceEvent {
    type Error = ContractBuildError;

    fn try_from(source: &depgraph_core::ValidatedRuntimeTraceEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            id: AgentId::parse(&source.id).map_err(|_| ContractBuildError::AgentDtoValue)?,
            sequence: source.sequence,
            dependency_kind: parse_agent_value(&source.dependency_kind)?,
            source: agent_runtime_locator(&source.source)?,
            target: agent_runtime_locator(&source.target)?,
            count: source.count,
            duration_ns: source.duration_ns,
        })
    }
}

fn agent_runtime_locator(
    source: &depgraph_core::MatchedRuntimeTraceLocator,
) -> Result<AgentRuntimeLocatorMatch, ContractBuildError> {
    AgentRuntimeLocatorMatch::new(
        agent_runtime_status(source.status),
        source
            .node_id
            .as_deref()
            .map(AgentId::parse)
            .transpose()
            .map_err(|_| ContractBuildError::AgentDtoValue)?,
    )
}

const fn agent_runtime_status(
    status: depgraph_core::RuntimeTraceMatchStatus,
) -> AgentRuntimeMatchStatus {
    match status {
        depgraph_core::RuntimeTraceMatchStatus::Resolved => AgentRuntimeMatchStatus::Resolved,
        depgraph_core::RuntimeTraceMatchStatus::External => AgentRuntimeMatchStatus::External,
        depgraph_core::RuntimeTraceMatchStatus::Unresolved => AgentRuntimeMatchStatus::Unresolved,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum AgentSnapshotDiffSchemaVersion {
    #[serde(rename = "depgraph-snapshot-diff-service-v1")]
    V1,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AgentSnapshotDiffRecordType {
    Coverage,
    Edge,
    Evidence,
    Node,
    Profile,
    Site,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AgentSnapshotDiffChangeType {
    Added,
    Changed,
    Removed,
    RenameCandidate,
    Renamed,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSnapshotDiffChange {
    pub record_type: AgentSnapshotDiffRecordType,
    pub change_type: AgentSnapshotDiffChangeType,
    pub id: AgentArtifactId,
    #[schemars(length(max = 256))]
    pub changed_fields: Vec<AgentFieldName>,
}

impl AgentSnapshotDiffChange {
    pub fn try_new(
        record_type: AgentSnapshotDiffRecordType,
        change_type: AgentSnapshotDiffChangeType,
        id: String,
        changed_fields: Vec<String>,
    ) -> Result<Self, ContractBuildError> {
        let value = Self {
            record_type,
            change_type,
            id: AgentArtifactId::parse(id).map_err(|_| ContractBuildError::AgentDtoValue)?,
            changed_fields: changed_fields
                .into_iter()
                .map(AgentFieldName::parse)
                .collect::<Result<_, _>>()
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ContractBuildError> {
        if self.changed_fields.len() > MAX_AGENT_CHANGED_FIELDS {
            return Err(ContractBuildError::TooManyChangedFields);
        }
        if self
            .changed_fields
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
            || matches!(
                self.change_type,
                AgentSnapshotDiffChangeType::Added | AgentSnapshotDiffChangeType::Removed
            ) && !self.changed_fields.is_empty()
        {
            return Err(ContractBuildError::SnapshotDiffState);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSnapshotDiffChangeWire {
    record_type: AgentSnapshotDiffRecordType,
    change_type: AgentSnapshotDiffChangeType,
    id: AgentArtifactId,
    changed_fields: Vec<AgentFieldName>,
}

impl<'de> Deserialize<'de> for AgentSnapshotDiffChange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentSnapshotDiffChangeWire::deserialize(deserializer)?;
        let value = Self {
            record_type: wire.record_type,
            change_type: wire.change_type,
            id: wire.id,
            changed_fields: wire.changed_fields,
        };
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSnapshotDiffResponse {
    pub schema_version: AgentSnapshotDiffSchemaVersion,
    pub from_snapshot_id: SnapshotId,
    pub to_snapshot_id: SnapshotId,
    pub total_changes: u64,
    pub empty: bool,
    #[schemars(length(max = 50000))]
    pub changes: Vec<AgentSnapshotDiffChange>,
    pub collection_digest: SnapshotDiffCollectionDigest,
}

impl AgentSnapshotDiffResponse {
    pub fn try_new(
        schema_version: &str,
        from_snapshot_id: &str,
        to_snapshot_id: &str,
        total_changes: u64,
        empty: bool,
        changes: Vec<AgentSnapshotDiffChange>,
        collection_digest: &str,
    ) -> Result<Self, ContractBuildError> {
        if schema_version != depgraph_core::service::SNAPSHOT_DIFF_SERVICE_SCHEMA_VERSION {
            return Err(ContractBuildError::AgentDtoValue);
        }
        let value = Self {
            schema_version: AgentSnapshotDiffSchemaVersion::V1,
            from_snapshot_id: SnapshotId::parse(from_snapshot_id)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            to_snapshot_id: SnapshotId::parse(to_snapshot_id)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            total_changes,
            empty,
            changes,
            collection_digest: SnapshotDiffCollectionDigest::parse(collection_digest)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ContractBuildError> {
        if self.changes.len() > MAX_AGENT_ARTIFACT_ITEMS {
            return Err(ContractBuildError::TooManyArtifactItems);
        }
        if self.empty != self.changes.is_empty()
            || self.total_changes > u64::try_from(self.changes.len()).unwrap_or(u64::MAX)
            || self.changes.windows(2).any(|pair| {
                (&pair[0].record_type, &pair[0].change_type, &pair[0].id)
                    >= (&pair[1].record_type, &pair[1].change_type, &pair[1].id)
            })
        {
            return Err(ContractBuildError::SnapshotDiffState);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSnapshotDiffResponseWire {
    schema_version: AgentSnapshotDiffSchemaVersion,
    from_snapshot_id: SnapshotId,
    to_snapshot_id: SnapshotId,
    total_changes: u64,
    empty: bool,
    changes: Vec<AgentSnapshotDiffChange>,
    collection_digest: SnapshotDiffCollectionDigest,
}

impl<'de> Deserialize<'de> for AgentSnapshotDiffResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentSnapshotDiffResponseWire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            from_snapshot_id: wire.from_snapshot_id,
            to_snapshot_id: wire.to_snapshot_id,
            total_changes: wire.total_changes,
            empty: wire.empty,
            changes: wire.changes,
            collection_digest: wire.collection_digest,
        };
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentPolicySeverity {
    Warning,
    Error,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPolicyViolation {
    pub id: PolicyViolationId,
    pub rule_id: AgentId,
    pub severity: AgentPolicySeverity,
    pub message: AgentPolicyText,
    pub source_id: AgentArtifactId,
    pub target_id: AgentArtifactId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<AgentArtifactId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<PolicyApiChangeId>,
    pub suppressed: bool,
}

impl AgentPolicyViolation {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        id: &str,
        rule_id: &str,
        severity: AgentPolicySeverity,
        message: &str,
        source_id: &str,
        target_id: &str,
        profile_id: Option<&str>,
        change_id: Option<&str>,
        suppressed: bool,
    ) -> Result<Self, ContractBuildError> {
        Ok(Self {
            id: PolicyViolationId::parse(id).map_err(|_| ContractBuildError::AgentDtoValue)?,
            rule_id: AgentId::parse(rule_id).map_err(|_| ContractBuildError::AgentDtoValue)?,
            severity,
            message: AgentPolicyText::parse(message)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            source_id: AgentArtifactId::parse(source_id)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            target_id: AgentArtifactId::parse(target_id)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            profile_id: profile_id
                .map(AgentArtifactId::parse)
                .transpose()
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            change_id: change_id
                .map(PolicyApiChangeId::parse)
                .transpose()
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            suppressed,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentPolicyApiChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPolicyApiChange {
    pub id: PolicyApiChangeId,
    pub rule_id: AgentId,
    pub kind: AgentPolicyApiChangeKind,
    pub breaking: bool,
    #[schemars(length(max = 256))]
    pub changed_fields: Vec<AgentFieldName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_id: Option<AgentArtifactId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_id: Option<AgentArtifactId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<AgentArtifactId>,
}

impl AgentPolicyApiChange {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        id: &str,
        rule_id: &str,
        kind: AgentPolicyApiChangeKind,
        breaking: bool,
        changed_fields: Vec<String>,
        before_id: Option<&str>,
        after_id: Option<&str>,
        profile_id: Option<&str>,
    ) -> Result<Self, ContractBuildError> {
        let value = Self {
            id: PolicyApiChangeId::parse(id).map_err(|_| ContractBuildError::AgentDtoValue)?,
            rule_id: AgentId::parse(rule_id).map_err(|_| ContractBuildError::AgentDtoValue)?,
            kind,
            breaking,
            changed_fields: changed_fields
                .into_iter()
                .map(AgentFieldName::parse)
                .collect::<Result<_, _>>()
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            before_id: before_id
                .map(AgentArtifactId::parse)
                .transpose()
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            after_id: after_id
                .map(AgentArtifactId::parse)
                .transpose()
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            profile_id: profile_id
                .map(AgentArtifactId::parse)
                .transpose()
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ContractBuildError> {
        if self.changed_fields.len() > MAX_AGENT_CHANGED_FIELDS {
            return Err(ContractBuildError::TooManyChangedFields);
        }
        if self
            .changed_fields
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(ContractBuildError::PolicyEvaluationState);
        }
        let valid_shape = match self.kind {
            AgentPolicyApiChangeKind::Added => {
                !self.breaking
                    && self.before_id.is_none()
                    && self.after_id.is_some()
                    && self.changed_fields.is_empty()
            }
            AgentPolicyApiChangeKind::Removed => {
                self.breaking
                    && self.before_id.is_some()
                    && self.after_id.is_none()
                    && self.changed_fields.is_empty()
            }
            AgentPolicyApiChangeKind::Changed => {
                self.breaking
                    && self.before_id.is_some()
                    && self.after_id.is_some()
                    && !self.changed_fields.is_empty()
            }
        };
        if !valid_shape {
            return Err(ContractBuildError::PolicyEvaluationState);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentPolicyApiChangeWire {
    id: PolicyApiChangeId,
    rule_id: AgentId,
    kind: AgentPolicyApiChangeKind,
    breaking: bool,
    changed_fields: Vec<AgentFieldName>,
    #[serde(default)]
    before_id: Option<AgentArtifactId>,
    #[serde(default)]
    after_id: Option<AgentArtifactId>,
    #[serde(default)]
    profile_id: Option<AgentArtifactId>,
}

impl<'de> Deserialize<'de> for AgentPolicyApiChange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentPolicyApiChangeWire::deserialize(deserializer)?;
        let value = Self {
            id: wire.id,
            rule_id: wire.rule_id,
            kind: wire.kind,
            breaking: wire.breaking,
            changed_fields: wire.changed_fields,
            before_id: wire.before_id,
            after_id: wire.after_id,
            profile_id: wire.profile_id,
        };
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPolicySummary {
    pub errors: u64,
    pub warnings: u64,
    pub suppressed: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentPolicyAnnotationLevel {
    Warning,
    Error,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPolicyAnnotation {
    pub violation_id: PolicyViolationId,
    pub rule_id: AgentId,
    pub level: AgentPolicyAnnotationLevel,
    pub path: RepositoryRelativePath,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
    pub title: AgentLabel,
    pub message: AgentPolicyText,
}

impl AgentPolicyAnnotation {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        violation_id: &str,
        rule_id: &str,
        level: AgentPolicyAnnotationLevel,
        path: &str,
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
        title: &str,
        message: &str,
    ) -> Result<Self, ContractBuildError> {
        let value = Self {
            violation_id: PolicyViolationId::parse(violation_id)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            rule_id: AgentId::parse(rule_id).map_err(|_| ContractBuildError::AgentDtoValue)?,
            level,
            path: RepositoryRelativePath::parse(path)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            start_line,
            start_column,
            end_line,
            end_column,
            title: AgentLabel::parse(title).map_err(|_| ContractBuildError::AgentDtoValue)?,
            message: AgentPolicyText::parse(message)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ContractBuildError> {
        if self.start_line == 0
            || self.start_column == 0
            || self.end_line == 0
            || self.end_column == 0
            || (self.end_line, self.end_column) < (self.start_line, self.start_column)
        {
            return Err(ContractBuildError::SourceSpan);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentPolicyAnnotationWire {
    violation_id: PolicyViolationId,
    rule_id: AgentId,
    level: AgentPolicyAnnotationLevel,
    path: RepositoryRelativePath,
    start_line: u32,
    start_column: u32,
    end_line: u32,
    end_column: u32,
    title: AgentLabel,
    message: AgentPolicyText,
}

impl<'de> Deserialize<'de> for AgentPolicyAnnotation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentPolicyAnnotationWire::deserialize(deserializer)?;
        let value = Self {
            violation_id: wire.violation_id,
            rule_id: wire.rule_id,
            level: wire.level,
            path: wire.path,
            start_line: wire.start_line,
            start_column: wire.start_column,
            end_line: wire.end_line,
            end_column: wire.end_column,
            title: wire.title,
            message: wire.message,
        };
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPolicyEvaluationResponse {
    pub from_snapshot_id: SnapshotId,
    pub to_snapshot_id: SnapshotId,
    pub result_id: PolicyEvaluationId,
    pub policy_config_digest: PolicyConfigDigest,
    pub passed: bool,
    #[schemars(range(max = 1))]
    pub exit_code: u8,
    #[schemars(length(max = 50000))]
    pub api_changes: Vec<AgentPolicyApiChange>,
    #[schemars(length(max = 50000))]
    pub violations: Vec<AgentPolicyViolation>,
    #[schemars(length(max = 50000))]
    pub annotations: Vec<AgentPolicyAnnotation>,
    pub summary: AgentPolicySummary,
    pub collection_digest: PolicyEvaluationCollectionDigest,
}

impl AgentPolicyEvaluationResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        from_snapshot_id: &str,
        to_snapshot_id: &str,
        result_id: &str,
        policy_config_digest: &str,
        passed: bool,
        exit_code: u8,
        api_changes: Vec<AgentPolicyApiChange>,
        violations: Vec<AgentPolicyViolation>,
        annotations: Vec<AgentPolicyAnnotation>,
        summary: AgentPolicySummary,
        collection_digest: &str,
    ) -> Result<Self, ContractBuildError> {
        let value = Self {
            from_snapshot_id: SnapshotId::parse(from_snapshot_id)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            to_snapshot_id: SnapshotId::parse(to_snapshot_id)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            result_id: PolicyEvaluationId::parse(result_id)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            policy_config_digest: PolicyConfigDigest::parse(policy_config_digest)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            passed,
            exit_code,
            api_changes,
            violations,
            annotations,
            summary,
            collection_digest: PolicyEvaluationCollectionDigest::parse(collection_digest)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ContractBuildError> {
        let items = self
            .api_changes
            .len()
            .saturating_add(self.violations.len())
            .saturating_add(self.annotations.len());
        if self.api_changes.len() > MAX_AGENT_ARTIFACT_ITEMS
            || self.violations.len() > MAX_AGENT_ARTIFACT_ITEMS
            || self.annotations.len() > MAX_AGENT_ARTIFACT_ITEMS
            || items > MAX_AGENT_ARTIFACT_ITEMS
        {
            return Err(ContractBuildError::TooManyArtifactItems);
        }

        let mut errors = 0_u64;
        let mut warnings = 0_u64;
        let mut suppressed = 0_u64;
        let mut violation_by_id = BTreeMap::new();
        for violation in &self.violations {
            if violation_by_id
                .insert(violation.id.as_str(), violation)
                .is_some()
            {
                return Err(ContractBuildError::PolicyEvaluationState);
            }
            if violation.suppressed {
                suppressed += 1;
            } else {
                match violation.severity {
                    AgentPolicySeverity::Warning => warnings += 1,
                    AgentPolicySeverity::Error => errors += 1,
                }
            }
        }
        if self.summary
            != (AgentPolicySummary {
                errors,
                warnings,
                suppressed,
            })
            || self.passed != (errors == 0)
            || self.exit_code != u8::from(errors > 0)
        {
            return Err(ContractBuildError::PolicyEvaluationState);
        }

        let changes = self
            .api_changes
            .iter()
            .map(|change| (change.id.as_str(), change.rule_id.as_str()))
            .collect::<BTreeMap<_, _>>();
        if changes.len() != self.api_changes.len()
            || self.violations.iter().any(|violation| {
                violation.change_id.as_ref().is_some_and(|change_id| {
                    changes.get(change_id.as_str()).copied() != Some(violation.rule_id.as_str())
                })
            })
        {
            return Err(ContractBuildError::PolicyEvaluationState);
        }

        let mut annotated = BTreeSet::new();
        for annotation in &self.annotations {
            let Some(violation) = violation_by_id.get(annotation.violation_id.as_str()) else {
                return Err(ContractBuildError::PolicyEvaluationState);
            };
            let expected_level = match violation.severity {
                AgentPolicySeverity::Warning => AgentPolicyAnnotationLevel::Warning,
                AgentPolicySeverity::Error => AgentPolicyAnnotationLevel::Error,
            };
            if violation.suppressed
                || annotation.rule_id != violation.rule_id
                || annotation.level != expected_level
                || !annotated.insert(annotation.violation_id.as_str())
            {
                return Err(ContractBuildError::PolicyEvaluationState);
            }
        }
        if self
            .violations
            .iter()
            .any(|violation| !violation.suppressed && !annotated.contains(violation.id.as_str()))
        {
            return Err(ContractBuildError::PolicyEvaluationState);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentPolicyEvaluationResponseWire {
    from_snapshot_id: SnapshotId,
    to_snapshot_id: SnapshotId,
    result_id: PolicyEvaluationId,
    policy_config_digest: PolicyConfigDigest,
    passed: bool,
    exit_code: u8,
    api_changes: Vec<AgentPolicyApiChange>,
    violations: Vec<AgentPolicyViolation>,
    annotations: Vec<AgentPolicyAnnotation>,
    summary: AgentPolicySummary,
    collection_digest: PolicyEvaluationCollectionDigest,
}

impl<'de> Deserialize<'de> for AgentPolicyEvaluationResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentPolicyEvaluationResponseWire::deserialize(deserializer)?;
        let value = Self {
            from_snapshot_id: wire.from_snapshot_id,
            to_snapshot_id: wire.to_snapshot_id,
            result_id: wire.result_id,
            policy_config_digest: wire.policy_config_digest,
            passed: wire.passed,
            exit_code: wire.exit_code,
            api_changes: wire.api_changes,
            violations: wire.violations,
            annotations: wire.annotations,
            summary: wire.summary,
            collection_digest: wire.collection_digest,
        };
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum AgentGraphExportSchemaVersion {
    #[serde(rename = "depgraph-graph-export-service-v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentGraphExportFormat {
    Json,
    Dot,
    Mermaid,
    Graphml,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRepositoryInitOutcome {
    output_path: RepositoryRelativePath,
}

impl JsonSchema for AgentRepositoryInitOutcome {
    fn schema_name() -> Cow<'static, str> {
        "AgentRepositoryInitOutcome".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::AgentRepositoryInitOutcome").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "output_path": {
                    "type": "string",
                    "const": depgraph_core::config::CONFIG_FILE,
                },
            },
            "required": ["output_path"],
        })
    }
}

impl AgentRepositoryInitOutcome {
    pub fn new(output_path: impl AsRef<str>) -> Result<Self, ContractBuildError> {
        let output_path = RepositoryRelativePath::parse(output_path)
            .map_err(|_| ContractBuildError::AgentDtoValue)?;
        if output_path.as_str() != depgraph_core::config::CONFIG_FILE {
            return Err(ContractBuildError::AgentDtoValue);
        }
        Ok(Self { output_path })
    }

    #[must_use]
    pub const fn output_path(&self) -> &RepositoryRelativePath {
        &self.output_path
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentRepositoryInitOutcomeWire {
    output_path: RepositoryRelativePath,
}

impl<'de> Deserialize<'de> for AgentRepositoryInitOutcome {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentRepositoryInitOutcomeWire::deserialize(deserializer)?;
        Self::new(wire.output_path.as_str()).map_err(D::Error::custom)
    }
}

impl TryFrom<&depgraph_core::service::RepositoryInitResult> for AgentRepositoryInitOutcome {
    type Error = ContractBuildError;

    fn try_from(
        source: &depgraph_core::service::RepositoryInitResult,
    ) -> Result<Self, Self::Error> {
        Self::new(source.output_path().as_str())
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentExportOutcome {
    output_path: RepositoryRelativePath,
    format: AgentGraphExportFormat,
    #[schemars(range(min = 1))]
    output_bytes: u64,
    content_sha256: Sha256Digest,
}

impl AgentExportOutcome {
    pub fn new(
        output_path: impl AsRef<str>,
        format: AgentGraphExportFormat,
        output_bytes: u64,
        content_sha256: impl AsRef<str>,
    ) -> Result<Self, ContractBuildError> {
        if output_bytes == 0 {
            return Err(ContractBuildError::AgentDtoValue);
        }
        Ok(Self {
            output_path: RepositoryRelativePath::parse(output_path)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            format,
            output_bytes,
            content_sha256: Sha256Digest::parse(content_sha256)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
        })
    }

    #[must_use]
    pub const fn output_path(&self) -> &RepositoryRelativePath {
        &self.output_path
    }

    #[must_use]
    pub const fn format(&self) -> AgentGraphExportFormat {
        self.format
    }

    #[must_use]
    pub const fn output_bytes(&self) -> u64 {
        self.output_bytes
    }

    #[must_use]
    pub const fn content_sha256(&self) -> &Sha256Digest {
        &self.content_sha256
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentExportOutcomeWire {
    output_path: RepositoryRelativePath,
    format: AgentGraphExportFormat,
    output_bytes: u64,
    content_sha256: Sha256Digest,
}

impl<'de> Deserialize<'de> for AgentExportOutcome {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentExportOutcomeWire::deserialize(deserializer)?;
        Self::new(
            wire.output_path.as_str(),
            wire.format,
            wire.output_bytes,
            wire.content_sha256.as_str(),
        )
        .map_err(D::Error::custom)
    }
}

impl TryFrom<&depgraph_core::service::ExportFileResult> for AgentExportOutcome {
    type Error = ContractBuildError;

    fn try_from(source: &depgraph_core::service::ExportFileResult) -> Result<Self, Self::Error> {
        let format = match source.format() {
            depgraph_core::service::GraphExportFormat::Json => AgentGraphExportFormat::Json,
            depgraph_core::service::GraphExportFormat::Dot => AgentGraphExportFormat::Dot,
            depgraph_core::service::GraphExportFormat::Mermaid => AgentGraphExportFormat::Mermaid,
            depgraph_core::service::GraphExportFormat::Graphml => AgentGraphExportFormat::Graphml,
        };
        Self::new(
            source.output_path().as_str(),
            format,
            source.output_bytes(),
            source.content_sha256(),
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum AgentGraphExportMediaType {
    #[serde(rename = "application/json")]
    Json,
    #[serde(rename = "text/vnd.graphviz")]
    Graphviz,
    #[serde(rename = "text/vnd.mermaid")]
    Mermaid,
    #[serde(rename = "application/graphml+xml")]
    Graphml,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentGraphExportResponse {
    pub schema_version: AgentGraphExportSchemaVersion,
    pub snapshot_id: SnapshotId,
    pub format: AgentGraphExportFormat,
    pub media_type: AgentGraphExportMediaType,
    pub content: AgentGraphExportContent,
    pub content_sha256: Sha256Digest,
    pub output_bytes: u64,
    #[schemars(range(max = 50000))]
    pub node_count: u64,
    #[schemars(range(max = 100000))]
    pub edge_count: u64,
}

impl AgentGraphExportResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        schema_version: &str,
        snapshot_id: &str,
        format: AgentGraphExportFormat,
        media_type: AgentGraphExportMediaType,
        content: String,
        content_sha256: &str,
        output_bytes: u64,
        node_count: u64,
        edge_count: u64,
    ) -> Result<Self, ContractBuildError> {
        if schema_version != depgraph_core::service::GRAPH_EXPORT_SERVICE_SCHEMA_VERSION {
            return Err(ContractBuildError::AgentDtoValue);
        }
        let value = Self {
            schema_version: AgentGraphExportSchemaVersion::V1,
            snapshot_id: SnapshotId::parse(snapshot_id)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            format,
            media_type,
            content: AgentGraphExportContent::parse(content)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            content_sha256: Sha256Digest::parse(content_sha256)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            output_bytes,
            node_count,
            edge_count,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ContractBuildError> {
        let expected_media_type = match self.format {
            AgentGraphExportFormat::Json => AgentGraphExportMediaType::Json,
            AgentGraphExportFormat::Dot => AgentGraphExportMediaType::Graphviz,
            AgentGraphExportFormat::Mermaid => AgentGraphExportMediaType::Mermaid,
            AgentGraphExportFormat::Graphml => AgentGraphExportMediaType::Graphml,
        };
        let digest = hex::encode(Sha256::digest(self.content.as_str().as_bytes()));
        if self.media_type != expected_media_type
            || self.output_bytes != u64::try_from(self.content.as_str().len()).unwrap_or(u64::MAX)
            || self.content_sha256.as_str() != digest
            || self.node_count > depgraph_core::service::MAX_GRAPH_EXPORT_NODES as u64
            || self.edge_count > depgraph_core::service::MAX_GRAPH_EXPORT_EDGES as u64
        {
            return Err(ContractBuildError::GraphExportState);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentGraphExportResponseWire {
    schema_version: AgentGraphExportSchemaVersion,
    snapshot_id: SnapshotId,
    format: AgentGraphExportFormat,
    media_type: AgentGraphExportMediaType,
    content: AgentGraphExportContent,
    content_sha256: Sha256Digest,
    output_bytes: u64,
    node_count: u64,
    edge_count: u64,
}

impl<'de> Deserialize<'de> for AgentGraphExportResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentGraphExportResponseWire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            snapshot_id: wire.snapshot_id,
            format: wire.format,
            media_type: wire.media_type,
            content: wire.content,
            content_sha256: wire.content_sha256,
            output_bytes: wire.output_bytes,
            node_count: wire.node_count,
            edge_count: wire.edge_count,
        };
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}

#[cfg(test)]
mod impact_projection_tests {
    use std::sync::Mutex;

    use serde_json::json;

    use super::{
        AgentCycle, AgentEdge, AgentImpactProjection, AgentUnresolved, IMPACT_LOOKUP_BUILDS,
        ImpactProjectionFailure, MAX_AGENT_CORRELATION_REASONS, MAX_AGENT_EVIDENCE_ITEMS,
        MAX_AGENT_PHASES, agent_site_from_core_cancellable,
    };
    use crate::ContractBuildError;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn impact_result_with_changed_nodes(
        item_count: usize,
        changed_node_count: usize,
    ) -> depgraph_core::ImpactResult {
        let node = |index: usize| {
            json!({
                "id": format!("node:impact-{index}"),
                "kind": "file",
                "locator": format!("id:node:impact-{index}"),
                "display_name": format!("impact-{index}"),
                "properties": {}
            })
        };
        let impacts = (0..item_count)
            .map(|index| {
                json!({
                    "node": node(index),
                    "depth": 0,
                    "changed_node_id": format!("node:impact-{index}"),
                    "dependency_path": []
                })
            })
            .collect::<Vec<_>>();
        let changed_nodes = (0..changed_node_count)
            .map(|index| {
                json!({
                    "id": format!("node:unused-changed-{index}"),
                    "kind": "file",
                    "locator": format!("id:node:unused-changed-{index}"),
                    "display_name": format!("unused-changed-{index}"),
                    "properties": {}
                })
            })
            .collect::<Vec<_>>();
        serde_json::from_value(json!({
            "root": node(0),
            "root_impacted": item_count > 0,
            "complete": true,
            "filters": {
                "profiles": [],
                "conditions": [],
                "max_nodes": item_count.max(1),
                "max_edges": 1
            },
            "mappings": [],
            "changed_nodes": changed_nodes,
            "impacts": impacts,
            "diagnostics": []
        }))
        .expect("valid core impact result")
    }

    fn impact_result(item_count: usize) -> depgraph_core::ImpactResult {
        impact_result_with_changed_nodes(item_count, 0)
    }

    fn core_path_step(evidence_count: usize, first_kind: &str) -> depgraph_core::query::PathStep {
        let evidence = (0..evidence_count)
            .map(|ordinal| {
                json!({
                    "owner_type": "edge",
                    "owner_id": "edge:bounded",
                    "ordinal": ordinal,
                    "kind": if ordinal == 0 { first_kind } else { "source" },
                    "extractor": "fixture",
                    "extractor_version": "1.0",
                    "path": "src/main.rs",
                    "start_line": 1,
                    "start_column": 1,
                    "end_line": 1,
                    "end_column": 2,
                    "detail": null,
                    "properties": {}
                })
            })
            .collect::<Vec<_>>();
        serde_json::from_value(json!({
            "edge": {
                "id": "edge:bounded",
                "source": "node:source",
                "target": "node:target",
                "kind": "imports",
                "phase": "source",
                "environment": "host",
                "profile_id": "profile:test",
                "resolution_status": "resolved",
                "precision": "exact",
                "condition": {"op":"all","conditions":[]},
                "generated": false
            },
            "condition_text": "all",
            "evidence": evidence,
            "effective_profile_id": null,
            "correlation_status": null,
            "observed_difference_reasons": [],
            "phase_coverage": {}
        }))
        .expect("valid core path step")
    }

    fn core_unresolved(
        evidence_count: usize,
        first_evidence_kind: &str,
        reasons: Vec<String>,
    ) -> depgraph_core::UnresolvedResult {
        depgraph_core::UnresolvedResult {
            site: serde_json::from_value(json!({
                "id": "site:missing",
                "source": "node:source",
                "kind": "import",
                "specifier": "id:node:missing",
                "profile_id": "profile:test",
                "resolution_status": "unresolved",
                "precision": "exact",
                "condition": {"op":"all","conditions":[]},
                "target_ids": ["node:missing"],
                "reason": "not_found"
            }))
            .expect("valid site record"),
            evidence: (0..evidence_count)
                .map(|ordinal| {
                    serde_json::from_value(json!({
                        "owner_type": "site",
                        "owner_id": "site:missing",
                        "ordinal": ordinal,
                        "kind": if ordinal == 0 { first_evidence_kind } else { "source" },
                        "extractor": "fixture",
                        "extractor_version": "1.0",
                        "path": "src/main.rs",
                        "start_line": 1,
                        "start_column": 1,
                        "end_line": 1,
                        "end_column": 2,
                        "detail": null,
                        "properties": {}
                    }))
                    .expect("valid evidence record")
                })
                .collect(),
            phases: Vec::new(),
            effective_profile_id: Some("profile:test".to_owned()),
            correlation_status: Some("matched".to_owned()),
            observed_difference_reasons: reasons,
            phase_coverage: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn impact_projection_builds_one_lookup_and_accepts_more_than_one_page() {
        let _guard = TEST_LOCK.lock().expect("projection test lock");
        IMPACT_LOOKUP_BUILDS.store(0, std::sync::atomic::Ordering::Relaxed);
        let result = impact_result(usize::from(crate::MAX_PAGE_ITEMS) + 1);
        let projection = match AgentImpactProjection::try_new(&result, &mut || false) {
            Ok(projection) => projection,
            Err(_) => panic!("valid complete result must project"),
        };
        assert_eq!(
            IMPACT_LOOKUP_BUILDS.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        let converted = match projection.convert_all(&mut || false) {
            Ok(converted) => converted,
            Err(_) => panic!("valid complete result must convert"),
        };
        assert_eq!(converted.len(), usize::from(crate::MAX_PAGE_ITEMS) + 1);
        assert_eq!(
            IMPACT_LOOKUP_BUILDS.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "converting every impact must reuse the one projection lookup"
        );
    }

    #[test]
    fn impact_projection_does_not_index_changed_nodes_absent_from_public_paths() {
        let _guard = TEST_LOCK.lock().expect("projection test lock");
        let result = impact_result_with_changed_nodes(2, usize::from(crate::MAX_PAGE_ITEMS) + 1);
        let projection = AgentImpactProjection::try_new(&result, &mut || false)
            .unwrap_or_else(|_| panic!("unused changed nodes must not consume the output lookup"));
        let converted = projection
            .convert_all(&mut || false)
            .unwrap_or_else(|_| panic!("valid bounded impacts must convert"));
        assert_eq!(converted.len(), 2);
    }

    #[test]
    fn impact_projection_cancellation_fails_without_partial_lookup_or_conversion() {
        let _guard = TEST_LOCK.lock().expect("projection test lock");
        let result = impact_result(4);

        let mut lookup_checks = 0_usize;
        let lookup = AgentImpactProjection::try_new(&result, &mut || {
            lookup_checks += 1;
            lookup_checks >= 3
        });
        assert!(matches!(lookup, Err(ImpactProjectionFailure::Cancelled)));

        let projection = match AgentImpactProjection::try_new(&result, &mut || false) {
            Ok(projection) => projection,
            Err(_) => panic!("valid complete result must project"),
        };
        let mut conversion_checks = 0_usize;
        let conversion = projection.convert_all(&mut || {
            conversion_checks += 1;
            conversion_checks >= 2
        });
        assert!(matches!(
            conversion,
            Err(ImpactProjectionFailure::Cancelled)
        ));
    }

    #[test]
    fn cycle_projection_checks_cancellation_inside_node_id_conversion() {
        let cycle = depgraph_core::CycleResult {
            level: "file".to_owned(),
            node_ids: vec![
                "node:one".to_owned(),
                "node:two".to_owned(),
                "node:three".to_owned(),
                "node:one".to_owned(),
            ],
        };
        let mut checks = 0_usize;
        let projected = AgentCycle::try_from_core_cancellable(&cycle, &mut || {
            checks += 1;
            checks >= 3
        });
        assert!(matches!(projected, Err(ImpactProjectionFailure::Cancelled)));
    }

    #[test]
    fn path_step_evidence_is_never_silently_truncated() {
        let exact = AgentEdge::try_from(&core_path_step(MAX_AGENT_EVIDENCE_ITEMS, "source"))
            .expect("exactly 64 evidence records must project");
        assert_eq!(
            serde_json::to_value(exact).expect("serialize AgentEdge")["evidence"]
                .as_array()
                .expect("evidence array")
                .len(),
            MAX_AGENT_EVIDENCE_ITEMS
        );

        let error = AgentEdge::try_from(&core_path_step(
            MAX_AGENT_EVIDENCE_ITEMS + 1,
            "invalid-before-conversion",
        ))
        .expect_err("evidence item 65 must reject the entire DTO");
        assert_eq!(error, ContractBuildError::TooManyEvidenceItems);

        let step = core_path_step(3, "source");
        let mut checks = 0_usize;
        let cancelled = AgentEdge::try_from_core_cancellable(&step, &mut || {
            checks += 1;
            checks >= 3
        });
        assert!(matches!(cancelled, Err(ImpactProjectionFailure::Cancelled)));
    }

    #[test]
    fn unresolved_oversize_guards_run_before_bulk_projection() {
        let mut exact_phases = core_unresolved(0, "source", Vec::new());
        exact_phases.phases = ["source", "semantic", "build", "runtime"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let exact = AgentUnresolved::try_from_core_cancellable(&exact_phases, &mut || false)
            .expect("exactly four phases project");
        assert_eq!(
            serde_json::to_value(exact).expect("serialize unresolved")["phases"]
                .as_array()
                .expect("phase array")
                .len(),
            MAX_AGENT_PHASES
        );

        let mut too_many_phases = core_unresolved(0, "source", Vec::new());
        too_many_phases.phases = (0..=MAX_AGENT_PHASES)
            .map(|index| format!("invalid-before-conversion-{index}"))
            .collect();
        let mut phase_checks = 0_usize;
        let error = AgentUnresolved::try_from_core_cancellable(&too_many_phases, &mut || {
            phase_checks += 1;
            false
        })
        .expect_err("phase item five must reject the entire DTO");
        assert!(matches!(
            error,
            ImpactProjectionFailure::Contract(ContractBuildError::TooManyPhases)
        ));
        assert_eq!(phase_checks, 0, "phase cap is checked before conversion");

        let too_many_reasons = core_unresolved(
            0,
            "source",
            (0..=MAX_AGENT_CORRELATION_REASONS)
                .map(|index| format!("invalid-reason-{index}"))
                .collect(),
        );
        let mut reason_checks = 0_usize;
        let error = AgentUnresolved::try_from_core_cancellable(&too_many_reasons, &mut || {
            reason_checks += 1;
            false
        })
        .expect_err("reason 17 must reject the entire DTO");
        assert!(matches!(
            error,
            ImpactProjectionFailure::Contract(ContractBuildError::TooManyCorrelationReasons)
        ));
        assert_eq!(reason_checks, 0, "reason cap is checked before conversion");

        let too_much_evidence = core_unresolved(
            MAX_AGENT_EVIDENCE_ITEMS + 1,
            "invalid-before-conversion",
            Vec::new(),
        );
        let mut evidence_checks = 0_usize;
        let error = agent_site_from_core_cancellable(&too_much_evidence, &mut || {
            evidence_checks += 1;
            false
        })
        .expect_err("evidence item 65 must reject the entire site DTO");
        assert!(matches!(
            error,
            ImpactProjectionFailure::Contract(ContractBuildError::TooManyEvidenceItems)
        ));
        assert_eq!(
            evidence_checks, 0,
            "evidence cap is checked before conversion"
        );
    }

    #[test]
    fn unresolved_projection_checks_cancellation_inside_evidence_conversion() {
        let unresolved = core_unresolved(3, "source", Vec::new());
        let mut checks = 0_usize;
        let projected = AgentUnresolved::try_from_core_cancellable(&unresolved, &mut || {
            checks += 1;
            checks >= 3
        });
        assert!(matches!(projected, Err(ImpactProjectionFailure::Cancelled)));
    }
}
