//! Repository discovery contracts.
//!
//! Agents need the logical repository identity before they can address other
//! tools. These DTOs expose only the logical ID and the current snapshot
//! summary; host-private roots and Store paths are never projected (NFR-005).

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::{
    AgentCompletedSnapshot, AgentCurrentSnapshot, ContractBuildError, LogicalRepositoryId,
};

/// Upper bound for repository identities carried by one list or error detail.
pub const MAX_AGENT_REPOSITORY_ITEMS: usize = 64;

/// Bounded, unique, ascending set of logical repository IDs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AgentRepositoryIds(Vec<LogicalRepositoryId>);

impl AgentRepositoryIds {
    /// Canonicalizes the IDs (ascending, duplicates removed) and enforces the bounds.
    pub fn new(mut repository_ids: Vec<LogicalRepositoryId>) -> Result<Self, ContractBuildError> {
        repository_ids.sort_unstable();
        repository_ids.dedup();
        if !within_repository_bounds(repository_ids.len()) {
            return Err(ContractBuildError::RepositorySet);
        }
        Ok(Self(repository_ids))
    }

    #[must_use]
    pub fn single(repository_id: LogicalRepositoryId) -> Self {
        Self(vec![repository_id])
    }

    #[must_use]
    pub fn as_slice(&self) -> &[LogicalRepositoryId] {
        &self.0
    }
}

impl JsonSchema for AgentRepositoryIds {
    fn schema_name() -> Cow<'static, str> {
        "AgentRepositoryIds".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::AgentRepositoryIds").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let item = generator.subschema_for::<LogicalRepositoryId>();
        json_schema!({
            "type": "array",
            "items": item,
            "minItems": 1,
            "maxItems": MAX_AGENT_REPOSITORY_ITEMS,
            "uniqueItems": true
        })
    }
}

impl<'de> Deserialize<'de> for AgentRepositoryIds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repository_ids = Vec::<LogicalRepositoryId>::deserialize(deserializer)?;
        if !within_repository_bounds(repository_ids.len())
            || !is_strictly_ascending(&repository_ids)
        {
            return Err(D::Error::custom(ContractBuildError::RepositorySet));
        }
        Ok(Self(repository_ids))
    }
}

/// One repository the server can address, with its latest completed snapshot.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRepositorySummary {
    repository_id: LogicalRepositoryId,
    snapshot: AgentCurrentSnapshot,
}

impl AgentRepositorySummary {
    #[must_use]
    pub const fn new(repository_id: LogicalRepositoryId, snapshot: AgentCurrentSnapshot) -> Self {
        Self {
            repository_id,
            snapshot,
        }
    }

    #[must_use]
    pub const fn repository_id(&self) -> &LogicalRepositoryId {
        &self.repository_id
    }

    #[must_use]
    pub const fn snapshot(&self) -> &AgentCurrentSnapshot {
        &self.snapshot
    }
}

impl TryFrom<&depgraph_core::service::DepgraphContext> for AgentRepositorySummary {
    type Error = ContractBuildError;

    fn try_from(source: &depgraph_core::service::DepgraphContext) -> Result<Self, Self::Error> {
        let repository_id = LogicalRepositoryId::parse(source.repository_id())
            .map_err(|_| ContractBuildError::AgentDtoValue)?;
        let snapshot = match source.current_snapshot().details() {
            Some(details) => {
                AgentCurrentSnapshot::available(AgentCompletedSnapshot::try_from(details)?)
            }
            None => AgentCurrentSnapshot::unavailable(),
        };
        Ok(Self::new(repository_id, snapshot))
    }
}

/// Result of `repository_list`: bounded, unique, ordered by repository ID.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRepositoryList {
    #[schemars(length(min = 1, max = 64))]
    repositories: Vec<AgentRepositorySummary>,
}

impl AgentRepositoryList {
    /// Orders the summaries by repository ID and rejects empty, oversized, or duplicate sets.
    pub fn new(mut repositories: Vec<AgentRepositorySummary>) -> Result<Self, ContractBuildError> {
        repositories.sort_by(|left, right| left.repository_id.cmp(&right.repository_id));
        Self::validated(repositories)
    }

    #[must_use]
    pub fn repositories(&self) -> &[AgentRepositorySummary] {
        &self.repositories
    }

    fn validated(repositories: Vec<AgentRepositorySummary>) -> Result<Self, ContractBuildError> {
        let ordered = repositories
            .windows(2)
            .all(|pair| pair[0].repository_id < pair[1].repository_id);
        if !within_repository_bounds(repositories.len()) || !ordered {
            return Err(ContractBuildError::RepositorySet);
        }
        Ok(Self { repositories })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentRepositoryListWire {
    repositories: Vec<AgentRepositorySummary>,
}

impl<'de> Deserialize<'de> for AgentRepositoryList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentRepositoryListWire::deserialize(deserializer)?;
        Self::validated(wire.repositories).map_err(D::Error::custom)
    }
}

const fn within_repository_bounds(count: usize) -> bool {
    count >= 1 && count <= MAX_AGENT_REPOSITORY_ITEMS
}

fn is_strictly_ascending(repository_ids: &[LogicalRepositoryId]) -> bool {
    repository_ids.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use schemars::schema_for;

    use super::{AgentRepositoryList, MAX_AGENT_REPOSITORY_ITEMS};

    #[test]
    fn schema_length_literal_matches_the_repository_bound() {
        // `#[schemars(length(max = 64))]` cannot name the constant, so pin them together.
        let schema = serde_json::to_value(schema_for!(AgentRepositoryList)).unwrap();
        assert_eq!(
            schema["properties"]["repositories"]["maxItems"],
            MAX_AGENT_REPOSITORY_ITEMS
        );
    }
}
