use std::{borrow::Cow, num::NonZeroU32};

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::{
    AgentId, AgentLabel, AgentLocator, AgentToken, ContractBuildError, RepositoryRelativePath,
    SnapshotId, SnapshotName,
};

pub const MAX_AGENT_EVIDENCE_ITEMS: usize = 64;
pub const MAX_AGENT_TARGET_ITEMS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
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
