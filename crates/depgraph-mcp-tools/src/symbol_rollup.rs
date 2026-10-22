//! Agent projection of the file-level symbol rollup of the dependency list
//! tools (Issue #623).
//!
//! The rollup is present only when the request sets `rollup: "symbols"`, so
//! every response without it keeps its depgraph-mcp-tools-v1 bytes.

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::{AgentId, AgentToken, ContractBuildError, RepositoryRelativePath};

/// Most files one rollup lists; `total_files` counts every file.
pub const MAX_AGENT_SYMBOL_ROLLUP_FILES: usize =
    depgraph_core::symbol_rollup::MAX_SYMBOL_ROLLUP_FILES;
/// Most edge IDs listed for one rollup file.
pub const MAX_AGENT_SYMBOL_ROLLUP_EDGE_IDS: usize =
    depgraph_core::symbol_rollup::MAX_SYMBOL_ROLLUP_EDGE_IDS;
/// Most edge kinds listed for one rollup file.
pub const MAX_AGENT_SYMBOL_ROLLUP_EDGE_KINDS: usize = 256;

/// `rollup` input of `graph_dependencies_list` / `graph_dependents_list`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentDependencyRollup {
    /// Group the semantic edges of the nodes the selector file owns by the other file.
    Symbols,
}

impl AgentDependencyRollup {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Symbols => "symbols",
        }
    }

    #[must_use]
    pub const fn to_core(self) -> depgraph_core::symbol_rollup::DependencyRollup {
        match self {
            Self::Symbols => depgraph_core::symbol_rollup::DependencyRollup::Symbols,
        }
    }
}

/// Whether the rollup could group anything.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSymbolRollupStatus {
    /// The semantic edges were grouped; `files` can still be empty.
    RolledUp,
    /// The snapshot has no semantic edge, for example Rust analyzed in
    /// syntax-only mode (see `analysis_degradations`).
    NoSemanticEdges,
    /// The selector is not a file node with a path.
    RootNotFile,
}

/// Edges of one kind behind one rollup file.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSymbolRollupEdgeKind {
    kind: AgentToken,
    edge_count: u64,
}

/// One other file and the semantic edges that connect it with the selector.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSymbolRollupFile {
    node_id: AgentId,
    path: RepositoryRelativePath,
    /// Edges behind this file.
    edge_count: u64,
    /// `edge_count` by edge kind, in kind order.
    #[schemars(length(max = 256))]
    edge_kinds: Vec<AgentSymbolRollupEdgeKind>,
    /// The first 16 edge IDs in ID order; read them with agent_edges_list.
    #[schemars(length(max = 16))]
    edge_ids: Vec<AgentId>,
    /// Whether the edge list already has a direct edge with this file node.
    file_edge: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSymbolRollupFileWire {
    node_id: AgentId,
    path: RepositoryRelativePath,
    edge_count: u64,
    edge_kinds: Vec<AgentSymbolRollupEdgeKind>,
    edge_ids: Vec<AgentId>,
    file_edge: bool,
}

impl TryFrom<AgentSymbolRollupFileWire> for AgentSymbolRollupFile {
    type Error = ContractBuildError;

    fn try_from(wire: AgentSymbolRollupFileWire) -> Result<Self, Self::Error> {
        if wire.edge_kinds.len() > MAX_AGENT_SYMBOL_ROLLUP_EDGE_KINDS
            || wire.edge_ids.len() > MAX_AGENT_SYMBOL_ROLLUP_EDGE_IDS
            || u64::try_from(wire.edge_ids.len()).unwrap_or(u64::MAX) > wire.edge_count
            || wire
                .edge_kinds
                .iter()
                .try_fold(0_u64, |total, kind| total.checked_add(kind.edge_count))
                != Some(wire.edge_count)
        {
            return Err(ContractBuildError::TooManySnapshotMetadataItems);
        }
        Ok(Self {
            node_id: wire.node_id,
            path: wire.path,
            edge_count: wire.edge_count,
            edge_kinds: wire.edge_kinds,
            edge_ids: wire.edge_ids,
            file_edge: wire.file_edge,
        })
    }
}

impl AgentSymbolRollupFile {
    #[must_use]
    pub const fn node_id(&self) -> &AgentId {
        &self.node_id
    }

    #[must_use]
    pub const fn path(&self) -> &RepositoryRelativePath {
        &self.path
    }

    #[must_use]
    pub const fn edge_count(&self) -> u64 {
        self.edge_count
    }

    #[must_use]
    pub fn edge_ids(&self) -> &[AgentId] {
        &self.edge_ids
    }

    #[must_use]
    pub const fn file_edge(&self) -> bool {
        self.file_edge
    }
}

/// File-level rollup of the semantic edges of the nodes the selector file
/// owns. It is a view over existing edges: no edge is created, and each file
/// names the edges behind it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSymbolRollup {
    rollup: AgentDependencyRollup,
    status: AgentSymbolRollupStatus,
    /// Nodes the selector file owns (source_path or declares), the file itself excluded.
    owned_nodes: u64,
    /// Semantic edges that reach at least one other file.
    attributed_edges: u64,
    /// Semantic edges whose far end has no file node, such as an external crate.
    unattributed_edges: u64,
    /// Every other file reached; files lists at most 4096.
    total_files: u64,
    /// Files in path order.
    #[schemars(length(max = 4096))]
    files: Vec<AgentSymbolRollupFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSymbolRollupWire {
    rollup: AgentDependencyRollup,
    status: AgentSymbolRollupStatus,
    owned_nodes: u64,
    attributed_edges: u64,
    unattributed_edges: u64,
    total_files: u64,
    files: Vec<AgentSymbolRollupFile>,
}

impl TryFrom<AgentSymbolRollupWire> for AgentSymbolRollup {
    type Error = ContractBuildError;

    fn try_from(wire: AgentSymbolRollupWire) -> Result<Self, Self::Error> {
        if wire.files.len() > MAX_AGENT_SYMBOL_ROLLUP_FILES
            || u64::try_from(wire.files.len()).unwrap_or(u64::MAX) > wire.total_files
            || wire
                .files
                .windows(2)
                .any(|pair| pair[0].path >= pair[1].path)
        {
            return Err(ContractBuildError::TooManySnapshotMetadataItems);
        }
        Ok(Self {
            rollup: wire.rollup,
            status: wire.status,
            owned_nodes: wire.owned_nodes,
            attributed_edges: wire.attributed_edges,
            unattributed_edges: wire.unattributed_edges,
            total_files: wire.total_files,
            files: wire.files,
        })
    }
}

impl AgentSymbolRollup {
    /// Projects the core rollup. A file whose node ID, path, or edge kind is
    /// outside the Agent contract fails the projection rather than silently
    /// changing the counts.
    pub fn project_core(
        source: &depgraph_core::symbol_rollup::SymbolRollup,
    ) -> Result<Self, ContractBuildError> {
        use depgraph_core::symbol_rollup::{DependencyRollup, SymbolRollupStatus};
        let mut files = Vec::with_capacity(source.files.len());
        for file in &source.files {
            let edge_kinds = file
                .edge_kinds
                .iter()
                .map(|kind| {
                    Ok(AgentSymbolRollupEdgeKind {
                        kind: AgentToken::parse(&kind.kind)
                            .map_err(|_| ContractBuildError::AgentDtoValue)?,
                        edge_count: kind.edge_count,
                    })
                })
                .collect::<Result<Vec<_>, ContractBuildError>>()?;
            let edge_ids = file
                .edge_ids
                .iter()
                .map(|id| AgentId::parse(id).map_err(|_| ContractBuildError::AgentDtoValue))
                .collect::<Result<Vec<_>, _>>()?;
            files.push(AgentSymbolRollupFile::try_from(
                AgentSymbolRollupFileWire {
                    node_id: AgentId::parse(&file.node_id)
                        .map_err(|_| ContractBuildError::AgentDtoValue)?,
                    path: RepositoryRelativePath::parse(&file.path)
                        .map_err(|_| ContractBuildError::AgentDtoValue)?,
                    edge_count: file.edge_count,
                    edge_kinds,
                    edge_ids,
                    file_edge: file.file_edge,
                },
            )?);
        }
        Self::try_from(AgentSymbolRollupWire {
            rollup: match source.rollup {
                DependencyRollup::Symbols => AgentDependencyRollup::Symbols,
            },
            status: match source.status {
                SymbolRollupStatus::RolledUp => AgentSymbolRollupStatus::RolledUp,
                SymbolRollupStatus::NoSemanticEdges => AgentSymbolRollupStatus::NoSemanticEdges,
                SymbolRollupStatus::RootNotFile => AgentSymbolRollupStatus::RootNotFile,
            },
            owned_nodes: source.owned_nodes,
            attributed_edges: source.attributed_edges,
            unattributed_edges: source.unattributed_edges,
            total_files: source.total_files,
            files,
        })
    }

    #[must_use]
    pub const fn status(&self) -> AgentSymbolRollupStatus {
        self.status
    }

    #[must_use]
    pub const fn total_files(&self) -> u64 {
        self.total_files
    }

    #[must_use]
    pub fn files(&self) -> &[AgentSymbolRollupFile] {
        &self.files
    }
}

impl<'de> Deserialize<'de> for AgentSymbolRollupFile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::try_from(AgentSymbolRollupFileWire::deserialize(deserializer)?)
            .map_err(D::Error::custom)
    }
}

impl<'de> Deserialize<'de> for AgentSymbolRollup {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::try_from(AgentSymbolRollupWire::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(edge_count: u64, kinds: &[u64]) -> serde_json::Value {
        let edge_kinds = kinds
            .iter()
            .enumerate()
            .map(|(index, count)| serde_json::json!({"kind": format!("kind{index}"), "edge_count": count}))
            .collect::<Vec<_>>();
        serde_json::json!({
            "node_id": "file:model", "path": "src/model.rs", "edge_count": edge_count,
            "edge_kinds": edge_kinds, "edge_ids": [], "file_edge": false
        })
    }

    #[test]
    fn a_rollup_file_counts_its_kinds_without_overflowing() {
        assert!(serde_json::from_value::<AgentSymbolRollupFile>(file(3, &[1, 2])).is_ok());
        assert!(serde_json::from_value::<AgentSymbolRollupFile>(file(4, &[1, 2])).is_err());
        // A sum that wraps around must not match the declared count.
        assert!(serde_json::from_value::<AgentSymbolRollupFile>(file(1, &[u64::MAX, 2])).is_err());
    }
}
