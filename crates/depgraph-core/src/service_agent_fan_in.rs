//! Fan-in ranking of graph nodes by distinct dependents (Issue #566).
//!
//! The hotspot fan-in counts every edge record that targets a node, structural
//! edges and repeated edges from one source included. This ranking counts the
//! distinct source nodes instead, over the dependency edges that
//! `graph_dependents_list` follows by default, so it agrees with the number of
//! direct dependents an agent sees there.
//!
//! This module is a child of `service_agent` so it can reuse its private
//! snapshot loading.

use std::collections::{BTreeSet, HashMap};

use super::GraphNodeFields;
use crate::CancellationToken;
use crate::edge_kind_selection::EdgeKindFilter;
use crate::service::{
    DepgraphService, DepgraphServiceError, DepgraphServiceResult, ResolvedSnapshotId,
};

/// One ranked node: the distinct sources and the edge records that target it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FanInEntry {
    node: GraphNodeFields,
    fan_in: u64,
    edge_count: u64,
}

impl FanInEntry {
    #[must_use]
    pub const fn node(&self) -> &GraphNodeFields {
        &self.node
    }

    /// Distinct source nodes of the selected edges, the node itself excluded.
    #[must_use]
    pub const fn fan_in(&self) -> u64 {
        self.fan_in
    }

    /// Selected edge records from those sources.
    #[must_use]
    pub const fn edge_count(&self) -> u64 {
        self.edge_count
    }
}

/// Every node of the requested kinds with at least one dependent, ranked by
/// `fan_in` descending, then `edge_count` descending, then node ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FanInRanking {
    snapshot_id: ResolvedSnapshotId,
    entries: Vec<FanInEntry>,
}

impl FanInRanking {
    #[must_use]
    pub const fn snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.snapshot_id
    }

    #[must_use]
    pub fn entries(&self) -> &[FanInEntry] {
        &self.entries
    }
}

impl DepgraphService {
    /// Ranks the nodes of `node_kinds` (every kind when empty) by distinct
    /// dependents over the edges `edge_kinds` allows. Self-loops are ignored.
    pub fn rank_fan_in(
        &self,
        snapshot_id: &ResolvedSnapshotId,
        node_kinds: &[String],
        edge_kinds: &EdgeKindFilter,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<FanInRanking> {
        let snapshot = self.load_agent_snapshot(snapshot_id, cancellation)?;
        let nodes = snapshot
            .nodes
            .iter()
            .filter(|node| node_kinds.is_empty() || node_kinds.contains(&node.kind))
            .map(|node| (node.id.as_str(), node))
            .collect::<HashMap<_, _>>();
        let mut dependents = HashMap::<&str, (BTreeSet<&str>, u64)>::new();
        for edge in &snapshot.edges {
            if edge.source == edge.target
                || !nodes.contains_key(edge.target.as_str())
                || !edge_kinds.allows(&edge.kind)
            {
                continue;
            }
            let (sources, edges) = dependents.entry(edge.target.as_str()).or_default();
            sources.insert(edge.source.as_str());
            *edges += 1;
        }
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let mut entries = dependents
            .into_iter()
            .map(|(target, (sources, edge_count))| {
                let node = nodes.get(target).ok_or(DepgraphServiceError::Integrity)?;
                Ok(FanInEntry {
                    node: GraphNodeFields::from_record(node),
                    fan_in: u64::try_from(sources.len())
                        .map_err(|_| DepgraphServiceError::ResourceExhausted)?,
                    edge_count,
                })
            })
            .collect::<DepgraphServiceResult<Vec<_>>>()?;
        entries.sort_by(|left, right| {
            right
                .fan_in
                .cmp(&left.fan_in)
                .then(right.edge_count.cmp(&left.edge_count))
                .then_with(|| left.node.id().cmp(right.node.id()))
        });
        Ok(FanInRanking {
            snapshot_id: snapshot_id.clone(),
            entries,
        })
    }
}
