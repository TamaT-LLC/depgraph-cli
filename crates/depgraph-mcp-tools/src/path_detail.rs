//! Output granularity of `graph_path_get` (Issue #566).
//!
//! `full` keeps the frozen `AgentPathResponse` bytes. `summary` and `paths` reuse the
//! dependency list item shapes and carry a required `detail` tag, so every detail level
//! deserializes to exactly one shape and the legacy shape never carries `detail`.

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::{
    AgentDependencyDetail, AgentDependencyPath, AgentEdge, AgentEdgeCommon, AgentEdgeSummary,
    AgentNode, AgentPathResponse, ContractBuildError, MAX_AGENT_PATH_STEPS,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AgentPathSummaryTag {
    Summary,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AgentPathPathsTag {
    Paths,
}

/// Endpoint and counter checks shared by the light path shapes. Step topology is
/// validated by the full projection they are derived from.
fn validate_light_path(
    from: &AgentNode,
    to: &AgentNode,
    path_found: bool,
    traversed_edges: u64,
    steps: usize,
) -> Result<(), ContractBuildError> {
    if steps > MAX_AGENT_PATH_STEPS {
        return Err(ContractBuildError::TooManyPathSteps);
    }
    if traversed_edges < u64::try_from(steps).unwrap_or(u64::MAX)
        || (!path_found && steps != 0)
        || (path_found && from.id() != to.id() && steps == 0)
        || (path_found && from.id() == to.id() && steps != 0)
    {
        return Err(ContractBuildError::PathTopology);
    }
    Ok(())
}

/// `detail: "summary"` response of `graph_path_get`: the path edges without evidence,
/// with fields shared by every step stated once in `common`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPathSummaryResponse {
    detail: AgentPathSummaryTag,
    from: AgentNode,
    to: AgentNode,
    path_found: bool,
    traversed_edges: u64,
    common: AgentEdgeCommon,
    #[schemars(length(max = 1000))]
    steps: Vec<AgentEdgeSummary>,
}

impl AgentPathSummaryResponse {
    pub fn new(
        from: AgentNode,
        to: AgentNode,
        path_found: bool,
        traversed_edges: u64,
        common: AgentEdgeCommon,
        steps: Vec<AgentEdgeSummary>,
    ) -> Result<Self, ContractBuildError> {
        validate_light_path(&from, &to, path_found, traversed_edges, steps.len())?;
        if !steps.iter().all(|step| step.is_consistent_with(&common)) {
            return Err(ContractBuildError::DependencyDetailState);
        }
        Ok(Self {
            detail: AgentPathSummaryTag::Summary,
            from,
            to,
            path_found,
            traversed_edges,
            common,
            steps,
        })
    }

    #[must_use]
    pub fn steps(&self) -> &[AgentEdgeSummary] {
        &self.steps
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentPathSummaryResponseWire {
    #[allow(dead_code)]
    detail: AgentPathSummaryTag,
    from: AgentNode,
    to: AgentNode,
    path_found: bool,
    traversed_edges: u64,
    common: AgentEdgeCommon,
    steps: Vec<AgentEdgeSummary>,
}

impl<'de> Deserialize<'de> for AgentPathSummaryResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentPathSummaryResponseWire::deserialize(deserializer)?;
        Self::new(
            wire.from,
            wire.to,
            wire.path_found,
            wire.traversed_edges,
            wire.common,
            wire.steps,
        )
        .map_err(D::Error::custom)
    }
}

/// `detail: "paths"` response of `graph_path_get`: each step as the source and target
/// path (or node ID when a node has no path) and the edge kind.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPathPathsResponse {
    detail: AgentPathPathsTag,
    from: AgentNode,
    to: AgentNode,
    path_found: bool,
    traversed_edges: u64,
    #[schemars(length(max = 1000))]
    steps: Vec<AgentDependencyPath>,
}

impl AgentPathPathsResponse {
    pub fn new(
        from: AgentNode,
        to: AgentNode,
        path_found: bool,
        traversed_edges: u64,
        steps: Vec<AgentDependencyPath>,
    ) -> Result<Self, ContractBuildError> {
        validate_light_path(&from, &to, path_found, traversed_edges, steps.len())?;
        Ok(Self {
            detail: AgentPathPathsTag::Paths,
            from,
            to,
            path_found,
            traversed_edges,
            steps,
        })
    }

    #[must_use]
    pub fn steps(&self) -> &[AgentDependencyPath] {
        &self.steps
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentPathPathsResponseWire {
    #[allow(dead_code)]
    detail: AgentPathPathsTag,
    from: AgentNode,
    to: AgentNode,
    path_found: bool,
    traversed_edges: u64,
    steps: Vec<AgentDependencyPath>,
}

impl<'de> Deserialize<'de> for AgentPathPathsResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentPathPathsResponseWire::deserialize(deserializer)?;
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

/// Result of `graph_path_get` for any `detail`. `Full` serializes exactly like
/// `AgentPathResponse`; the other variants carry their `detail` tag.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum AgentPathOutput {
    Full(AgentPathResponse),
    Summary(AgentPathSummaryResponse),
    Paths(AgentPathPathsResponse),
}

impl AgentPathOutput {
    /// Projects one explained path at `detail`. The light shapes are derived from the
    /// validated full projection, so they share its topology checks.
    pub fn project(
        source: &depgraph_core::service::ExplainPathResult,
        detail: AgentDependencyDetail,
    ) -> Result<Self, ContractBuildError> {
        let full = AgentPathResponse::try_from(source)?;
        match detail {
            AgentDependencyDetail::Full => Ok(Self::Full(full)),
            AgentDependencyDetail::Summary => {
                let edges = full
                    .steps()
                    .iter()
                    .map(|step| step.edge().clone())
                    .collect::<Vec<AgentEdge>>();
                let common = AgentEdgeCommon::from_edges(&edges);
                let steps = edges
                    .iter()
                    .map(|edge| AgentEdgeSummary::project(edge, &common))
                    .collect();
                AgentPathSummaryResponse::new(
                    full.from().clone(),
                    full.to().clone(),
                    full.path_found(),
                    full.traversed_edges(),
                    common,
                    steps,
                )
                .map(Self::Summary)
            }
            AgentDependencyDetail::Paths => {
                let steps = source
                    .items()
                    .iter()
                    .map(AgentDependencyPath::try_from_core)
                    .collect::<Result<Vec<_>, _>>()?;
                AgentPathPathsResponse::new(
                    full.from().clone(),
                    full.to().clone(),
                    full.path_found(),
                    full.traversed_edges(),
                    steps,
                )
                .map(Self::Paths)
            }
        }
    }

    #[must_use]
    pub const fn detail(&self) -> AgentDependencyDetail {
        match self {
            Self::Full(_) => AgentDependencyDetail::Full,
            Self::Summary(_) => AgentDependencyDetail::Summary,
            Self::Paths(_) => AgentDependencyDetail::Paths,
        }
    }
}

impl<'de> Deserialize<'de> for AgentPathOutput {
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
            Some(serde_json::Value::String(detail)) if detail == "paths" => {
                serde_json::from_value(value).map(Self::Paths)
            }
            Some(_) => {
                return Err(D::Error::custom(ContractBuildError::DependencyDetailState));
            }
        }
        .map_err(D::Error::custom)
    }
}

impl JsonSchema for AgentPathOutput {
    fn schema_name() -> Cow<'static, str> {
        "AgentPathOutput".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::AgentPathOutput").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let full = generator.subschema_for::<AgentPathResponse>();
        let summary = generator.subschema_for::<AgentPathSummaryResponse>();
        let paths = generator.subschema_for::<AgentPathPathsResponse>();
        json_schema!({
            "description": "detail=full (default) is the legacy shape without a detail field; summary and paths carry their detail tag.",
            "oneOf": [full, summary, paths]
        })
    }
}
