//! Output granularity of `get_context` (Issue #566).
//!
//! `full` keeps the frozen `AgentContext` bytes, whose snapshot lists every
//! `profile_id`. `summary` replaces that list with `profile_count` and carries a
//! required `detail` tag, so the legacy shape never carries `detail` and the
//! shared `AgentCompletedSnapshot` of `snapshot_get` / `snapshot_list` is unchanged.
//!
//! This is a child module of `dto` so it can read the private fields of the
//! frozen snapshot DTO without widening their visibility.

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use super::{
    AgentCompletedSnapshot, AgentContext, AgentCoverage, AgentCurrentSnapshot,
    deserialize_snapshot_metadata,
};
use crate::{AgentId, AgentLabel, AgentToken, ContractBuildError, SnapshotId, SnapshotName};

/// Requested output granularity of `get_context`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentContextDetail {
    /// The snapshot states `profile_count` instead of every `profile_id`.
    Summary,
    /// The legacy context with every `profile_id` (default).
    #[default]
    Full,
}

impl AgentContextDetail {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Summary => "summary",
            Self::Full => "full",
        }
    }

    #[must_use]
    pub const fn is_full(self) -> bool {
        matches!(self, Self::Full)
    }
}

/// `AgentCompletedSnapshot` with `profile_ids` replaced by `profile_count`.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCompletedSnapshotSummary {
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
    /// Number of analysis profiles of the snapshot; `detail=full`, `snapshot_get`
    /// and `snapshot_list` list their IDs as `profile_ids`.
    #[schemars(range(max = 1024))]
    profile_count: u64,
    created_at: AgentLabel,
    coverage: AgentCoverage,
}

impl AgentCompletedSnapshotSummary {
    #[must_use]
    pub const fn snapshot_id(&self) -> &SnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub const fn profile_count(&self) -> u64 {
        self.profile_count
    }
}

impl From<&AgentCompletedSnapshot> for AgentCompletedSnapshotSummary {
    fn from(source: &AgentCompletedSnapshot) -> Self {
        Self {
            snapshot_id: source.snapshot_id.clone(),
            names: source.names.clone(),
            status: source.status.clone(),
            source_kind: source.source_kind.clone(),
            source_attempt_id: source.source_attempt_id.clone(),
            scan_id: source.scan_id.clone(),
            build_attempt_id: source.build_attempt_id.clone(),
            runtime_import_id: source.runtime_import_id.clone(),
            runtime_session_ids: source.runtime_session_ids.clone(),
            parent_snapshot_id: source.parent_snapshot_id.clone(),
            source_revision: source.source_revision.clone(),
            // The list is bounded by MAX_AGENT_SNAPSHOT_METADATA_ITEMS, so it fits.
            profile_count: u64::try_from(source.profile_ids.len()).unwrap_or(u64::MAX),
            created_at: source.created_at.clone(),
            coverage: source.coverage.clone(),
        }
    }
}

/// `AgentCurrentSnapshot` whose details are an `AgentCompletedSnapshotSummary`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCurrentSnapshotSummary {
    available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<AgentCompletedSnapshotSummary>,
}

impl AgentCurrentSnapshotSummary {
    #[must_use]
    pub const fn details(&self) -> Option<&AgentCompletedSnapshotSummary> {
        self.details.as_ref()
    }
}

impl From<&AgentCurrentSnapshot> for AgentCurrentSnapshotSummary {
    fn from(source: &AgentCurrentSnapshot) -> Self {
        Self {
            available: source.available,
            details: source
                .details
                .as_ref()
                .map(AgentCompletedSnapshotSummary::from),
        }
    }
}

impl JsonSchema for AgentCurrentSnapshotSummary {
    fn schema_name() -> Cow<'static, str> {
        "AgentCurrentSnapshotSummary".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::AgentCurrentSnapshotSummary").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let details = generator.subschema_for::<AgentCompletedSnapshotSummary>();
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
struct AgentCurrentSnapshotSummaryWire {
    available: bool,
    #[serde(default)]
    details: Option<AgentCompletedSnapshotSummary>,
}

impl<'de> Deserialize<'de> for AgentCurrentSnapshotSummary {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentCurrentSnapshotSummaryWire::deserialize(deserializer)?;
        if wire.available != wire.details.is_some() {
            return Err(D::Error::custom(ContractBuildError::SnapshotAvailability));
        }
        Ok(Self {
            available: wire.available,
            details: wire.details,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AgentContextSummaryTag {
    Summary,
}

/// `detail: "summary"` response of `get_context`: the context whose snapshot states
/// `profile_count` instead of every `profile_id`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentContextSummary {
    detail: AgentContextSummaryTag,
    repository_id: crate::LogicalRepositoryId,
    #[schemars(length(min = 1, max = 5))]
    enabled_capabilities: Vec<crate::AgentCapability>,
    snapshot: AgentCurrentSnapshotSummary,
}

impl AgentContextSummary {
    #[must_use]
    pub const fn snapshot(&self) -> &AgentCurrentSnapshotSummary {
        &self.snapshot
    }
}

impl From<&AgentContext> for AgentContextSummary {
    fn from(source: &AgentContext) -> Self {
        Self {
            detail: AgentContextSummaryTag::Summary,
            repository_id: source.repository_id.clone(),
            enabled_capabilities: source.enabled_capabilities.clone(),
            snapshot: AgentCurrentSnapshotSummary::from(&source.snapshot),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentContextSummaryWire {
    #[allow(dead_code)]
    detail: AgentContextSummaryTag,
    repository_id: crate::LogicalRepositoryId,
    enabled_capabilities: Vec<crate::AgentCapability>,
    snapshot: AgentCurrentSnapshotSummary,
}

impl<'de> Deserialize<'de> for AgentContextSummary {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentContextSummaryWire::deserialize(deserializer)?;
        // Reuse the capability-set validation of the full context.
        let validated = AgentContext::new(
            wire.repository_id,
            wire.enabled_capabilities,
            AgentCurrentSnapshot::unavailable(),
        )
        .map_err(D::Error::custom)?;
        Ok(Self {
            detail: AgentContextSummaryTag::Summary,
            repository_id: validated.repository_id,
            enabled_capabilities: validated.enabled_capabilities,
            snapshot: wire.snapshot,
        })
    }
}

/// Result of `get_context` for any `detail`. `Full` serializes exactly like
/// `AgentContext`; `Summary` carries its `detail` tag.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum AgentContextOutput {
    Full(AgentContext),
    Summary(AgentContextSummary),
}

impl AgentContextOutput {
    /// Projects a context at the requested granularity.
    #[must_use]
    pub fn project(context: AgentContext, detail: AgentContextDetail) -> Self {
        match detail {
            AgentContextDetail::Full => Self::Full(context),
            AgentContextDetail::Summary => Self::Summary(AgentContextSummary::from(&context)),
        }
    }

    #[must_use]
    pub const fn detail(&self) -> AgentContextDetail {
        match self {
            Self::Full(_) => AgentContextDetail::Full,
            Self::Summary(_) => AgentContextDetail::Summary,
        }
    }
}

impl<'de> Deserialize<'de> for AgentContextOutput {
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
            Some(_) => {
                return Err(D::Error::custom(ContractBuildError::DependencyDetailState));
            }
        }
        .map_err(D::Error::custom)
    }
}

impl JsonSchema for AgentContextOutput {
    fn schema_name() -> Cow<'static, str> {
        "AgentContextOutput".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::AgentContextOutput").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let full = generator.subschema_for::<AgentContext>();
        let summary = generator.subschema_for::<AgentContextSummary>();
        json_schema!({
            "description": "detail=full (default) is the legacy context without a detail field; summary carries its detail tag and states profile_count instead of the snapshot profile_ids.",
            "oneOf": [full, summary]
        })
    }
}
