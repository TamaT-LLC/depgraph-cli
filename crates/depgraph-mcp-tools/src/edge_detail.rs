//! Output granularity of `agent_edges_list` (Issue #566).
//!
//! `full` keeps the frozen `Page<AgentEdge>` bytes. `summary` drops evidence bodies and
//! wraps the page in a closed shape tagged by a required `detail` field, so an empty
//! summary page never deserializes as an empty full page.

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::{AgentEdge, AgentEdgeCommon, AgentEdgeSummary, ContractBuildError, Page};

/// Requested output granularity of `agent_edges_list`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentEdgeDetail {
    /// Edges without evidence bodies; `evidence_count` tells how many records exist.
    Summary,
    /// The legacy complete edge projection with evidence (default).
    #[default]
    Full,
}

impl AgentEdgeDetail {
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

/// Result of `agent_edges_list` for any `detail`. `Full` serializes exactly like
/// `Page<AgentEdge>`; `Summary` carries its `detail` tag.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum AgentEdgesOutput {
    Full(Page<AgentEdge>),
    Summary(AgentEdgesSummaryResponse),
}

impl AgentEdgesOutput {
    #[must_use]
    pub const fn detail(&self) -> AgentEdgeDetail {
        match self {
            Self::Full(_) => AgentEdgeDetail::Full,
            Self::Summary(_) => AgentEdgeDetail::Summary,
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
        json_schema!({
            "description": "detail=full (default) is the legacy page of complete edges without a detail field; summary carries its detail tag and an edges page without evidence bodies.",
            "oneOf": [full, summary]
        })
    }
}
