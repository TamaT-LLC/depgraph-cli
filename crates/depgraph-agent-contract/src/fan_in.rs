//! Items of the `graph_fan_in_list` ranking (Issue #566).

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::dto::agent_node_from_fields;
use crate::{AgentId, AgentToken, ContractBuildError, RepositoryRelativePath};

/// One node of the fan-in ranking with its distinct dependents.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentFanInItem {
    node_id: AgentId,
    kind: AgentToken,
    /// Repository-relative path of the node, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<RepositoryRelativePath>,
    /// Distinct source nodes with at least one selected edge to this node, the
    /// node itself excluded.
    #[schemars(range(min = 1))]
    fan_in: u64,
    /// Selected edge records from those sources; at least fan_in.
    #[schemars(range(min = 1))]
    edge_count: u64,
}

impl AgentFanInItem {
    pub fn new(
        node_id: AgentId,
        kind: AgentToken,
        path: Option<RepositoryRelativePath>,
        fan_in: u64,
        edge_count: u64,
    ) -> Result<Self, ContractBuildError> {
        if fan_in == 0 || edge_count < fan_in {
            return Err(ContractBuildError::AgentDtoValue);
        }
        Ok(Self {
            node_id,
            kind,
            path,
            fan_in,
            edge_count,
        })
    }

    /// Projects one core ranking entry through the same node projection as `AgentNode`.
    pub fn try_from_core(
        entry: &depgraph_core::service::FanInEntry,
    ) -> Result<Self, ContractBuildError> {
        let node = entry.node();
        let projected = agent_node_from_fields(
            node.id(),
            node.kind(),
            node.locator(),
            node.display_name(),
            node.properties(),
        )?;
        let kind = AgentToken::parse(node.kind()).map_err(|_| ContractBuildError::AgentDtoValue)?;
        Self::new(
            projected.id().clone(),
            kind,
            projected.repository_path().cloned(),
            entry.fan_in(),
            entry.edge_count(),
        )
    }

    #[must_use]
    pub const fn node_id(&self) -> &AgentId {
        &self.node_id
    }

    #[must_use]
    pub const fn kind(&self) -> &AgentToken {
        &self.kind
    }

    #[must_use]
    pub const fn path(&self) -> Option<&RepositoryRelativePath> {
        self.path.as_ref()
    }

    #[must_use]
    pub const fn fan_in(&self) -> u64 {
        self.fan_in
    }

    #[must_use]
    pub const fn edge_count(&self) -> u64 {
        self.edge_count
    }

    /// Directory-boundary prefix match on the node path, as `health_hotspots_list`
    /// applies `path_prefixes`: `src/lib` matches `src/lib` and `src/lib/a.rs`, never
    /// `src/library.rs`. A node without a path never matches.
    #[must_use]
    pub fn path_has_prefix(&self, prefix: &RepositoryRelativePath) -> bool {
        self.path.as_ref().is_some_and(|path| {
            path.as_str()
                .strip_prefix(prefix.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentFanInItemWire {
    node_id: AgentId,
    kind: AgentToken,
    #[serde(default)]
    path: Option<RepositoryRelativePath>,
    fan_in: u64,
    edge_count: u64,
}

impl<'de> Deserialize<'de> for AgentFanInItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentFanInItemWire::deserialize(deserializer)?;
        Self::new(
            wire.node_id,
            wire.kind,
            wire.path,
            wire.fan_in,
            wire.edge_count,
        )
        .map_err(D::Error::custom)
    }
}
