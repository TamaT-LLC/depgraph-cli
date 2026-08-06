use std::{borrow::Cow, num::NonZeroU32};

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::{
    AgentId, AgentLabel, AgentLocator, AgentToken, ContractBuildError, RepositoryRelativePath,
    SnapshotId, SnapshotName,
};

pub const MAX_AGENT_EVIDENCE_ITEMS: usize = 64;
pub const MAX_AGENT_TARGET_ITEMS: usize = 256;
pub const MAX_AGENT_SNAPSHOT_METADATA_ITEMS: usize = 1_024;

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
        validate_agent_targets(&target_ids)?;
        validate_agent_evidence(&evidence)?;
        Ok(Self {
            id,
            source_id,
            kind,
            specifier,
            resolution_status,
            profile_id,
            target_ids,
            span,
            evidence,
        })
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
    condition: Option<AgentLabel>,
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
