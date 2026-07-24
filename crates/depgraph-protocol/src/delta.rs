use crate::{
    CommonFields, Coverage, DependencySite, Evidence, GraphEdge, GraphNode, PROTOCOL_VERSION,
    ProtocolError, ValidatedProtocol, stable_id_from_value, validate_site_edge_invariants,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;
use std::path::{Component, Path};

/// Capability advertised by both the core and a worker before the core may
/// request a fine-grained graph delta.
pub const WORKER_DELTA_CAPABILITY: &str = "worker-delta-v1";

/// Version carried by every delta stream independently from protocol `1.0`.
pub const DELTA_CONTRACT_VERSION: &str = "worker-delta-v1";

/// The wire mode selected after core/worker capability negotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerProtocolMode {
    /// The protocol `1.0` repository-complete stream. This is the safe fallback.
    FullSnapshot,
    /// The fine-grained, base-snapshot-bound delta contract.
    DeltaV1,
}

/// Selects delta mode only when both peers explicitly advertise the exact
/// capability. Legacy workers and unknown capabilities fail closed to the
/// repository-complete protocol.
#[must_use]
pub fn negotiate_worker_protocol(
    core_capabilities: &[String],
    worker_capabilities: &[String],
) -> WorkerProtocolMode {
    let supports_delta = |capabilities: &[String]| {
        capabilities
            .iter()
            .any(|capability| capability == WORKER_DELTA_CAPABILITY)
    };
    if supports_delta(core_capabilities) && supports_delta(worker_capabilities) {
        WorkerProtocolMode::DeltaV1
    } else {
        WorkerProtocolMode::FullSnapshot
    }
}

/// Canonical ownership closure requested from one worker.
///
/// Profile declarations are deliberately not mutable in delta v1. A workspace
/// replan therefore negotiates the full-snapshot fallback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaScope {
    pub paths: Vec<String>,
    pub package_locators: Vec<String>,
    pub profile_ids: Vec<String>,
    pub artifact_node_ids: Vec<String>,
    pub adapters: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaEvidenceOwner {
    Node,
    Site,
    Edge,
}

impl DeltaEvidenceOwner {
    fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Site => "site",
            Self::Edge => "edge",
        }
    }
}

/// Stable evidence-store key. Ordinals are part of the persisted identity and
/// must remain contiguous for each owner.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DeltaEvidenceKey {
    pub owner_type: DeltaEvidenceOwner,
    pub owner_id: String,
    pub ordinal: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeltaEvidenceRecord {
    #[serde(flatten)]
    pub key: DeltaEvidenceKey,
    pub evidence: Evidence,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum DeltaCoverageKey {
    Aggregate,
    Profile { profile_id: String },
    File { adapter: String, path: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaFileCoverage {
    pub discovered_sites: u64,
    pub emitted_sites: u64,
    pub skipped_sites: u64,
    pub skipped: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum DeltaCoverage {
    Aggregate {
        value: Coverage,
    },
    Profile {
        profile_id: String,
        value: Coverage,
    },
    File {
        adapter: String,
        path: String,
        value: DeltaFileCoverage,
    },
}

impl DeltaCoverage {
    #[must_use]
    pub fn key(&self) -> DeltaCoverageKey {
        match self {
            Self::Aggregate { .. } => DeltaCoverageKey::Aggregate,
            Self::Profile { profile_id, .. } => DeltaCoverageKey::Profile {
                profile_id: profile_id.clone(),
            },
            Self::File { adapter, path, .. } => DeltaCoverageKey::File {
                adapter: adapter.clone(),
                path: path.clone(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum DeltaEvent {
    DeltaStarted(DeltaStarted),
    EvidenceDelete(EvidenceDelete),
    EdgeDelete(EdgeDelete),
    SiteDelete(SiteDelete),
    NodeDelete(NodeDelete),
    #[serde(rename = "delta_node_upsert")]
    NodeUpsert(DeltaNodeUpsert),
    SiteUpsert(SiteUpsert),
    #[serde(rename = "delta_edge_upsert")]
    EdgeUpsert(DeltaEdgeUpsert),
    EvidenceUpsert(EvidenceUpsert),
    CoverageDelete(CoverageDelete),
    CoverageUpsert(CoverageUpsert),
    DeltaCompleted(DeltaCompleted),
}

macro_rules! delta_event_struct {
    ($(#[$meta:meta])* $name:ident { $($fields:tt)* }) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
        pub struct $name {
            #[serde(flatten)]
            pub common: CommonFields,
            $($fields)*
        }
    };
}

delta_event_struct!(DeltaStarted {
    pub delta_contract_version: String,
    pub delta_id: String,
    pub base_snapshot_id: String,
    pub base_graph_digest: String,
    pub scope: DeltaScope,
});

delta_event_struct!(NodeDelete {
    pub node_id: String,
});

delta_event_struct!(DeltaNodeUpsert {
    pub node: GraphNode,
});

delta_event_struct!(SiteDelete {
    pub site_id: String,
});

delta_event_struct!(SiteUpsert {
    pub site: DependencySite,
});

delta_event_struct!(EdgeDelete {
    pub edge_id: String,
});

delta_event_struct!(DeltaEdgeUpsert {
    pub edge: GraphEdge,
});

delta_event_struct!(EvidenceDelete {
    pub evidence_key: DeltaEvidenceKey,
});

delta_event_struct!(EvidenceUpsert {
    pub evidence: DeltaEvidenceRecord,
});

delta_event_struct!(CoverageDelete {
    pub coverage_key: DeltaCoverageKey,
});

delta_event_struct!(CoverageUpsert {
    pub coverage: DeltaCoverage,
});

delta_event_struct!(DeltaCompleted {
    pub delta_contract_version: String,
    pub delta_id: String,
    pub mutation_count: u64,
    pub result_graph_digest: String,
});

impl DeltaEvent {
    #[must_use]
    pub fn common(&self) -> &CommonFields {
        match self {
            Self::DeltaStarted(event) => &event.common,
            Self::EvidenceDelete(event) => &event.common,
            Self::EdgeDelete(event) => &event.common,
            Self::SiteDelete(event) => &event.common,
            Self::NodeDelete(event) => &event.common,
            Self::NodeUpsert(event) => &event.common,
            Self::SiteUpsert(event) => &event.common,
            Self::EdgeUpsert(event) => &event.common,
            Self::EvidenceUpsert(event) => &event.common,
            Self::CoverageDelete(event) => &event.common,
            Self::CoverageUpsert(event) => &event.common,
            Self::DeltaCompleted(event) => &event.common,
        }
    }

    #[must_use]
    pub fn event_name(&self) -> &'static str {
        match self {
            Self::DeltaStarted(_) => "delta_started",
            Self::EvidenceDelete(_) => "evidence_delete",
            Self::EdgeDelete(_) => "edge_delete",
            Self::SiteDelete(_) => "site_delete",
            Self::NodeDelete(_) => "node_delete",
            Self::NodeUpsert(_) => "delta_node_upsert",
            Self::SiteUpsert(_) => "site_upsert",
            Self::EdgeUpsert(_) => "delta_edge_upsert",
            Self::EvidenceUpsert(_) => "evidence_upsert",
            Self::CoverageDelete(_) => "coverage_delete",
            Self::CoverageUpsert(_) => "coverage_upsert",
            Self::DeltaCompleted(_) => "delta_completed",
        }
    }

    fn is_mutation(&self) -> bool {
        !matches!(self, Self::DeltaStarted(_) | Self::DeltaCompleted(_))
    }

    fn mutation_sort_key(&self) -> Option<(u8, String)> {
        match self {
            Self::EvidenceDelete(event) => Some((0, evidence_key_string(&event.evidence_key))),
            Self::EdgeDelete(event) => Some((1, event.edge_id.clone())),
            Self::SiteDelete(event) => Some((2, event.site_id.clone())),
            Self::NodeDelete(event) => Some((3, event.node_id.clone())),
            Self::NodeUpsert(event) => Some((4, event.node.id.clone())),
            Self::SiteUpsert(event) => Some((5, event.site.id.clone())),
            Self::EdgeUpsert(event) => Some((6, event.edge.id.clone())),
            Self::EvidenceUpsert(event) => Some((7, evidence_key_string(&event.evidence.key))),
            Self::CoverageDelete(event) => Some((8, coverage_key_string(&event.coverage_key))),
            Self::CoverageUpsert(event) => Some((9, coverage_key_string(&event.coverage.key()))),
            Self::DeltaStarted(_) | Self::DeltaCompleted(_) => None,
        }
    }

    fn mutation_identity(&self) -> Option<String> {
        match self {
            Self::NodeDelete(event) => Some(format!("node:{}", event.node_id)),
            Self::NodeUpsert(event) => Some(format!("node:{}", event.node.id)),
            Self::SiteDelete(event) => Some(format!("site:{}", event.site_id)),
            Self::SiteUpsert(event) => Some(format!("site:{}", event.site.id)),
            Self::EdgeDelete(event) => Some(format!("edge:{}", event.edge_id)),
            Self::EdgeUpsert(event) => Some(format!("edge:{}", event.edge.id)),
            Self::EvidenceDelete(event) => Some(format!(
                "evidence:{}",
                evidence_key_string(&event.evidence_key)
            )),
            Self::EvidenceUpsert(event) => Some(format!(
                "evidence:{}",
                evidence_key_string(&event.evidence.key)
            )),
            Self::CoverageDelete(event) => Some(format!(
                "coverage:{}",
                coverage_key_string(&event.coverage_key)
            )),
            Self::CoverageUpsert(event) => Some(format!(
                "coverage:{}",
                coverage_key_string(&event.coverage.key())
            )),
            Self::DeltaStarted(_) | Self::DeltaCompleted(_) => None,
        }
    }

    fn canonical_mutation_payload(&self) -> Option<Value> {
        if !self.is_mutation() {
            return None;
        }
        let mut value = serde_json::to_value(self).expect("DeltaEvent is always serializable");
        let object = value
            .as_object_mut()
            .expect("tagged DeltaEvent serializes as an object");
        for field in [
            "protocol_version",
            "scan_id",
            "adapter",
            "adapter_version",
            "seq",
        ] {
            object.remove(field);
        }
        Some(value)
    }
}

/// Complete base state required to validate the result of a delta before any
/// store transaction mutates the current snapshot.
#[derive(Clone, Debug, Default)]
pub struct DeltaBaseGraph {
    pub snapshot_id: String,
    pub graph_digest: String,
    pub profiles: BTreeSet<String>,
    pub nodes: BTreeMap<String, GraphNode>,
    pub sites: BTreeMap<String, DependencySite>,
    pub edges: BTreeMap<String, GraphEdge>,
    pub evidence: BTreeMap<DeltaEvidenceKey, Evidence>,
    pub coverage: BTreeMap<DeltaCoverageKey, DeltaCoverage>,
}

impl DeltaBaseGraph {
    /// Converts an already validated full snapshot stream into a delta base.
    /// Evidence is normalized into the independent evidence mutation map.
    #[must_use]
    pub fn from_protocol(
        snapshot_id: impl Into<String>,
        graph_digest: impl Into<String>,
        protocol: &ValidatedProtocol,
    ) -> Self {
        let mut sites = protocol.sites.clone();
        let mut edges = protocol.edges.clone();
        let mut evidence = BTreeMap::new();
        for site in sites.values_mut() {
            for (ordinal, item) in std::mem::take(&mut site.evidence).into_iter().enumerate() {
                evidence.insert(
                    DeltaEvidenceKey {
                        owner_type: DeltaEvidenceOwner::Site,
                        owner_id: site.id.clone(),
                        ordinal: ordinal as u32,
                    },
                    item,
                );
            }
        }
        for edge in edges.values_mut() {
            for (ordinal, item) in std::mem::take(&mut edge.evidence).into_iter().enumerate() {
                evidence.insert(
                    DeltaEvidenceKey {
                        owner_type: DeltaEvidenceOwner::Edge,
                        owner_id: edge.id.clone(),
                        ordinal: ordinal as u32,
                    },
                    item,
                );
            }
        }

        let mut coverage = BTreeMap::new();
        for event in &protocol.events {
            match event {
                crate::ProtocolEvent::FileCompleted(file) => {
                    let item = DeltaCoverage::File {
                        adapter: file.common.adapter.clone(),
                        path: file.path.clone(),
                        value: DeltaFileCoverage {
                            discovered_sites: file.discovered_sites,
                            emitted_sites: file.emitted_sites,
                            skipped_sites: file.skipped_sites,
                            skipped: file.skipped,
                            reason: file.reason.clone(),
                        },
                    };
                    coverage.insert(item.key(), item);
                }
                crate::ProtocolEvent::ProfileCompleted(profile) => {
                    let item = DeltaCoverage::Profile {
                        profile_id: profile.profile_id.clone(),
                        value: profile.coverage.clone(),
                    };
                    coverage.insert(item.key(), item);
                }
                crate::ProtocolEvent::ScanCompleted(scan) => {
                    let item = DeltaCoverage::Aggregate {
                        value: scan.coverage.clone(),
                    };
                    coverage.insert(item.key(), item);
                }
                _ => {}
            }
        }

        Self {
            snapshot_id: snapshot_id.into(),
            graph_digest: graph_digest.into(),
            profiles: protocol.profiles.keys().cloned().collect(),
            nodes: protocol.nodes.clone(),
            sites,
            edges,
            evidence,
            coverage,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ValidatedDelta {
    pub events: Vec<DeltaEvent>,
    pub delta_id: String,
    pub base_snapshot_id: String,
    pub base_graph_digest: String,
    pub result_graph_digest: String,
    pub scope: DeltaScope,
    pub node_upserts: BTreeMap<String, GraphNode>,
    pub node_deletes: BTreeSet<String>,
    pub site_upserts: BTreeMap<String, DependencySite>,
    pub site_deletes: BTreeSet<String>,
    pub edge_upserts: BTreeMap<String, GraphEdge>,
    pub edge_deletes: BTreeSet<String>,
    pub evidence_upserts: BTreeMap<DeltaEvidenceKey, Evidence>,
    pub evidence_deletes: BTreeSet<DeltaEvidenceKey>,
    pub coverage_upserts: BTreeMap<DeltaCoverageKey, DeltaCoverage>,
    pub coverage_deletes: BTreeSet<DeltaCoverageKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeltaStreamState {
    AwaitingStart,
    Mutating,
    Completed,
}

#[derive(Clone, Debug)]
struct DeltaStreamIdentity {
    scan_id: String,
    adapter: String,
    adapter_version: String,
}

/// Incremental validator for a single worker delta.
#[derive(Debug)]
pub struct DeltaValidator {
    state: DeltaStreamState,
    identity: Option<DeltaStreamIdentity>,
    last_seq: Option<u64>,
    started: Option<DeltaStarted>,
    completed: Option<DeltaCompleted>,
    last_mutation_key: Option<(u8, String)>,
    mutation_identities: BTreeSet<String>,
    events: Vec<DeltaEvent>,
    profiles: BTreeSet<String>,
    nodes: BTreeMap<String, GraphNode>,
    sites: BTreeMap<String, DependencySite>,
    edges: BTreeMap<String, GraphEdge>,
    evidence: BTreeMap<DeltaEvidenceKey, Evidence>,
    coverage: BTreeMap<DeltaCoverageKey, DeltaCoverage>,
    node_upserts: BTreeMap<String, GraphNode>,
    node_deletes: BTreeSet<String>,
    site_upserts: BTreeMap<String, DependencySite>,
    site_deletes: BTreeSet<String>,
    edge_upserts: BTreeMap<String, GraphEdge>,
    edge_deletes: BTreeSet<String>,
    evidence_upserts: BTreeMap<DeltaEvidenceKey, Evidence>,
    evidence_deletes: BTreeSet<DeltaEvidenceKey>,
    coverage_upserts: BTreeMap<DeltaCoverageKey, DeltaCoverage>,
    coverage_deletes: BTreeSet<DeltaCoverageKey>,
    scoped_nodes: BTreeSet<String>,
    scoped_sites: BTreeSet<String>,
    scoped_edges: BTreeSet<String>,
    expected_snapshot_id: String,
    expected_graph_digest: String,
}

impl DeltaValidator {
    pub fn new(mut base: DeltaBaseGraph) -> Result<Self, ProtocolError> {
        validate_stable_id("base snapshot ID", &base.snapshot_id, Some("snapshot"))?;
        validate_digest("base graph digest", &base.graph_digest)?;
        for profile_id in &base.profiles {
            require_non_empty("base profile ID", profile_id)?;
        }
        for (id, node) in &base.nodes {
            validate_stable_id("base node ID", id, None)?;
            if id != &node.id {
                return invariant(format!(
                    "base node map key {id} does not match payload ID {}",
                    node.id
                ));
            }
        }
        for (id, site) in &mut base.sites {
            validate_stable_id("base site ID", id, Some("site"))?;
            if id != &site.id {
                return invariant(format!(
                    "base site map key {id} does not match payload ID {}",
                    site.id
                ));
            }
            merge_embedded_evidence(
                &mut base.evidence,
                DeltaEvidenceOwner::Site,
                id,
                std::mem::take(&mut site.evidence),
            )?;
        }
        for (id, edge) in &mut base.edges {
            validate_stable_id("base edge ID", id, Some("edge"))?;
            if id != &edge.id {
                return invariant(format!(
                    "base edge map key {id} does not match payload ID {}",
                    edge.id
                ));
            }
            merge_embedded_evidence(
                &mut base.evidence,
                DeltaEvidenceOwner::Edge,
                id,
                std::mem::take(&mut edge.evidence),
            )?;
        }
        validate_final_state(
            &base.profiles,
            &base.nodes,
            &base.sites,
            &base.edges,
            &base.evidence,
            &base.coverage,
        )?;

        Ok(Self {
            state: DeltaStreamState::AwaitingStart,
            identity: None,
            last_seq: None,
            started: None,
            completed: None,
            last_mutation_key: None,
            mutation_identities: BTreeSet::new(),
            events: Vec::new(),
            profiles: base.profiles,
            nodes: base.nodes,
            sites: base.sites,
            edges: base.edges,
            evidence: base.evidence,
            coverage: base.coverage,
            node_upserts: BTreeMap::new(),
            node_deletes: BTreeSet::new(),
            site_upserts: BTreeMap::new(),
            site_deletes: BTreeSet::new(),
            edge_upserts: BTreeMap::new(),
            edge_deletes: BTreeSet::new(),
            evidence_upserts: BTreeMap::new(),
            evidence_deletes: BTreeSet::new(),
            coverage_upserts: BTreeMap::new(),
            coverage_deletes: BTreeSet::new(),
            scoped_nodes: BTreeSet::new(),
            scoped_sites: BTreeSet::new(),
            scoped_edges: BTreeSet::new(),
            expected_snapshot_id: base.snapshot_id,
            expected_graph_digest: base.graph_digest,
        })
    }

    #[must_use]
    pub fn validated_events(&self) -> &[DeltaEvent] {
        &self.events
    }

    pub fn push(&mut self, mut event: DeltaEvent) -> Result<(), ProtocolError> {
        normalize_delta_conditions(&mut event);
        self.validate_common(&event)?;
        match self.state {
            DeltaStreamState::AwaitingStart if !matches!(&event, DeltaEvent::DeltaStarted(_)) => {
                return invariant(format!(
                    "delta stream must start with delta_started, found {}",
                    event.event_name()
                ));
            }
            DeltaStreamState::Completed => {
                return invariant(format!(
                    "event {} is not allowed after delta_completed",
                    event.event_name()
                ));
            }
            _ => {}
        }

        match &event {
            DeltaEvent::DeltaStarted(started) => self.start(started)?,
            DeltaEvent::DeltaCompleted(completed) => self.complete(completed)?,
            _ => {
                if self.state != DeltaStreamState::Mutating {
                    return invariant(format!(
                        "{} is not allowed before delta_started",
                        event.event_name()
                    ));
                }
                self.validate_mutation_order(&event)?;
                self.apply_mutation(&event)?;
            }
        }
        self.events.push(event);
        Ok(())
    }

    pub fn finish(self) -> Result<ValidatedDelta, ProtocolError> {
        if self.state != DeltaStreamState::Completed {
            return invariant("delta stream ended before delta_completed".into());
        }
        let started = self.started.expect("completed delta has a start event");
        let completed = self
            .completed
            .expect("completed delta has a completion event");
        Ok(ValidatedDelta {
            events: self.events,
            delta_id: started.delta_id,
            base_snapshot_id: started.base_snapshot_id,
            base_graph_digest: started.base_graph_digest,
            result_graph_digest: completed.result_graph_digest,
            scope: started.scope,
            node_upserts: self.node_upserts,
            node_deletes: self.node_deletes,
            site_upserts: self.site_upserts,
            site_deletes: self.site_deletes,
            edge_upserts: self.edge_upserts,
            edge_deletes: self.edge_deletes,
            evidence_upserts: self.evidence_upserts,
            evidence_deletes: self.evidence_deletes,
            coverage_upserts: self.coverage_upserts,
            coverage_deletes: self.coverage_deletes,
        })
    }

    fn validate_common(&mut self, event: &DeltaEvent) -> Result<(), ProtocolError> {
        let common = event.common();
        if common.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion {
                expected: PROTOCOL_VERSION,
                found: common.protocol_version.clone(),
            });
        }
        require_non_empty("scan_id", &common.scan_id)?;
        require_non_empty("adapter", &common.adapter)?;
        require_non_empty("adapter_version", &common.adapter_version)?;
        match self.last_seq {
            None if common.seq != 1 => {
                return invariant(format!("delta seq must start at 1, found {}", common.seq));
            }
            Some(previous) if common.seq != previous + 1 => {
                return invariant(format!(
                    "delta seq must be contiguous; previous={previous}, found={}",
                    common.seq
                ));
            }
            _ => {}
        }
        if let Some(identity) = &self.identity {
            if common.scan_id != identity.scan_id
                || common.adapter != identity.adapter
                || common.adapter_version != identity.adapter_version
            {
                return invariant("delta routing metadata changed within the stream".into());
            }
        } else {
            self.identity = Some(DeltaStreamIdentity {
                scan_id: common.scan_id.clone(),
                adapter: common.adapter.clone(),
                adapter_version: common.adapter_version.clone(),
            });
        }
        self.last_seq = Some(common.seq);
        Ok(())
    }

    fn start(&mut self, started: &DeltaStarted) -> Result<(), ProtocolError> {
        if self.state != DeltaStreamState::AwaitingStart {
            return invariant("duplicate delta_started event".into());
        }
        validate_contract_version(&started.delta_contract_version)?;
        validate_stable_id("delta ID", &started.delta_id, Some("delta"))?;
        validate_stable_id(
            "delta base snapshot ID",
            &started.base_snapshot_id,
            Some("snapshot"),
        )?;
        validate_digest("delta base graph digest", &started.base_graph_digest)?;
        if started.base_snapshot_id != self.expected_snapshot_id
            || started.base_graph_digest != self.expected_graph_digest
        {
            return invariant(
                "delta base snapshot identity or graph digest does not match the validated base"
                    .into(),
            );
        }
        validate_scope(&started.scope)?;
        let adapter = &started.common.adapter;
        if started.scope.adapters.len() != 1 || started.scope.adapters.first() != Some(adapter) {
            return invariant(format!(
                "delta scope adapters must contain exactly the producing adapter {adapter:?}"
            ));
        }
        for profile_id in &started.scope.profile_ids {
            if !self.profiles.contains(profile_id) {
                return invariant(format!(
                    "delta scope references undeclared base profile {profile_id}"
                ));
            }
        }
        (self.scoped_nodes, self.scoped_sites, self.scoped_edges) = scoped_base_entities(
            &started.scope,
            &self.nodes,
            &self.sites,
            &self.edges,
            &self.evidence,
        );
        self.started = Some(started.clone());
        self.state = DeltaStreamState::Mutating;
        Ok(())
    }

    fn validate_mutation_order(&mut self, event: &DeltaEvent) -> Result<(), ProtocolError> {
        let sort_key = event
            .mutation_sort_key()
            .expect("mutation event has a sort key");
        if self
            .last_mutation_key
            .as_ref()
            .is_some_and(|previous| previous >= &sort_key)
        {
            return invariant(format!(
                "delta mutations are not in canonical order at {}",
                event.event_name()
            ));
        }
        let identity = event
            .mutation_identity()
            .expect("mutation event has an identity");
        if !self.mutation_identities.insert(identity.clone()) {
            return invariant(format!("delta mutates {identity} more than once"));
        }
        self.last_mutation_key = Some(sort_key);
        Ok(())
    }

    fn apply_mutation(&mut self, event: &DeltaEvent) -> Result<(), ProtocolError> {
        let scope = &self
            .started
            .as_ref()
            .expect("mutating delta has a start event")
            .scope;
        match event {
            DeltaEvent::NodeDelete(event) => {
                validate_stable_id("node_delete.node_id", &event.node_id, None)?;
                require_scoped(
                    self.scoped_nodes.contains(&event.node_id),
                    "node",
                    &event.node_id,
                )?;
                require_present(self.nodes.remove(&event.node_id), "node", &event.node_id)?;
                self.node_deletes.insert(event.node_id.clone());
            }
            DeltaEvent::NodeUpsert(event) => {
                validate_stable_id("node_upsert.node.id", &event.node.id, None)?;
                require_non_empty("node.kind", &event.node.kind)?;
                require_non_empty("node.locator", &event.node.locator)?;
                if let Some(existing) = self.nodes.get(&event.node.id)
                    && (existing.kind != event.node.kind || existing.locator != event.node.locator)
                {
                    return invariant(format!(
                        "node {} changed stable kind/locator identity",
                        event.node.id
                    ));
                }
                require_scoped(
                    self.scoped_nodes.contains(&event.node.id)
                        || node_is_scoped(scope, &event.node),
                    "node",
                    &event.node.id,
                )?;
                self.scoped_nodes.insert(event.node.id.clone());
                self.nodes.insert(event.node.id.clone(), event.node.clone());
                self.node_upserts
                    .insert(event.node.id.clone(), event.node.clone());
            }
            DeltaEvent::SiteDelete(event) => {
                validate_stable_id("site_delete.site_id", &event.site_id, Some("site"))?;
                require_scoped(
                    self.scoped_sites.contains(&event.site_id),
                    "site",
                    &event.site_id,
                )?;
                require_present(self.sites.remove(&event.site_id), "site", &event.site_id)?;
                self.site_deletes.insert(event.site_id.clone());
            }
            DeltaEvent::SiteUpsert(event) => {
                validate_stable_id("site_upsert.site.id", &event.site.id, Some("site"))?;
                if !event.site.evidence.is_empty() {
                    return invariant(format!(
                        "delta site {} must emit evidence through evidence_upsert",
                        event.site.id
                    ));
                }
                if let Some(existing) = self.sites.get(&event.site.id)
                    && (existing.source != event.site.source
                        || existing.kind != event.site.kind
                        || existing.profile_id != event.site.profile_id
                        || existing.condition != event.site.condition)
                {
                    return invariant(format!(
                        "site {} changed stable identity fields",
                        event.site.id
                    ));
                }
                require_scoped(
                    self.scoped_sites.contains(&event.site.id)
                        || site_is_scoped(scope, &event.site, &self.scoped_nodes, &self.evidence),
                    "site",
                    &event.site.id,
                )?;
                self.scoped_sites.insert(event.site.id.clone());
                self.sites.insert(event.site.id.clone(), event.site.clone());
                self.site_upserts
                    .insert(event.site.id.clone(), event.site.clone());
            }
            DeltaEvent::EdgeDelete(event) => {
                validate_stable_id("edge_delete.edge_id", &event.edge_id, Some("edge"))?;
                require_scoped(
                    self.scoped_edges.contains(&event.edge_id),
                    "edge",
                    &event.edge_id,
                )?;
                require_present(self.edges.remove(&event.edge_id), "edge", &event.edge_id)?;
                self.edge_deletes.insert(event.edge_id.clone());
            }
            DeltaEvent::EdgeUpsert(event) => {
                validate_stable_id("edge_upsert.edge.id", &event.edge.id, Some("edge"))?;
                if !event.edge.evidence.is_empty() {
                    return invariant(format!(
                        "delta edge {} must emit evidence through evidence_upsert",
                        event.edge.id
                    ));
                }
                if let Some(existing) = self.edges.get(&event.edge.id)
                    && (existing.site_id != event.edge.site_id
                        || existing.source != event.edge.source
                        || existing.target != event.edge.target
                        || existing.kind != event.edge.kind)
                {
                    return invariant(format!(
                        "edge {} changed stable identity fields",
                        event.edge.id
                    ));
                }
                require_scoped(
                    self.scoped_edges.contains(&event.edge.id)
                        || edge_is_scoped(
                            scope,
                            &event.edge,
                            &self.scoped_nodes,
                            &self.scoped_sites,
                            &self.evidence,
                        ),
                    "edge",
                    &event.edge.id,
                )?;
                self.scoped_edges.insert(event.edge.id.clone());
                self.edges.insert(event.edge.id.clone(), event.edge.clone());
                self.edge_upserts
                    .insert(event.edge.id.clone(), event.edge.clone());
            }
            DeltaEvent::EvidenceDelete(event) => {
                validate_evidence_key(&event.evidence_key)?;
                let existing = self.evidence.get(&event.evidence_key);
                require_scoped(
                    evidence_is_scoped(
                        scope,
                        &event.evidence_key,
                        existing,
                        &self.scoped_nodes,
                        &self.scoped_sites,
                        &self.scoped_edges,
                    ),
                    "evidence",
                    &evidence_key_string(&event.evidence_key),
                )?;
                require_present(
                    self.evidence.remove(&event.evidence_key),
                    "evidence",
                    &evidence_key_string(&event.evidence_key),
                )?;
                self.evidence_deletes.insert(event.evidence_key.clone());
            }
            DeltaEvent::EvidenceUpsert(event) => {
                validate_evidence_key(&event.evidence.key)?;
                validate_evidence(&event.evidence.evidence)?;
                require_scoped(
                    evidence_is_scoped(
                        scope,
                        &event.evidence.key,
                        Some(&event.evidence.evidence),
                        &self.scoped_nodes,
                        &self.scoped_sites,
                        &self.scoped_edges,
                    ),
                    "evidence",
                    &evidence_key_string(&event.evidence.key),
                )?;
                self.evidence
                    .insert(event.evidence.key.clone(), event.evidence.evidence.clone());
                self.evidence_upserts
                    .insert(event.evidence.key.clone(), event.evidence.evidence.clone());
            }
            DeltaEvent::CoverageDelete(event) => {
                validate_coverage_key(&event.coverage_key)?;
                require_scoped(
                    coverage_key_is_scoped(scope, &event.coverage_key),
                    "coverage",
                    &coverage_key_string(&event.coverage_key),
                )?;
                require_present(
                    self.coverage.remove(&event.coverage_key),
                    "coverage",
                    &coverage_key_string(&event.coverage_key),
                )?;
                self.coverage_deletes.insert(event.coverage_key.clone());
            }
            DeltaEvent::CoverageUpsert(event) => {
                validate_delta_coverage(&event.coverage)?;
                let key = event.coverage.key();
                require_scoped(
                    coverage_key_is_scoped(scope, &key),
                    "coverage",
                    &coverage_key_string(&key),
                )?;
                self.coverage.insert(key.clone(), event.coverage.clone());
                self.coverage_upserts.insert(key, event.coverage.clone());
            }
            DeltaEvent::DeltaStarted(_) | DeltaEvent::DeltaCompleted(_) => {
                unreachable!("start/completion events are not mutations")
            }
        }
        Ok(())
    }

    fn complete(&mut self, completed: &DeltaCompleted) -> Result<(), ProtocolError> {
        if self.state != DeltaStreamState::Mutating {
            return invariant("delta_completed is not allowed before delta_started".into());
        }
        validate_contract_version(&completed.delta_contract_version)?;
        validate_stable_id(
            "delta_completed.delta_id",
            &completed.delta_id,
            Some("delta"),
        )?;
        validate_digest("delta result graph digest", &completed.result_graph_digest)?;
        let started = self
            .started
            .as_ref()
            .expect("mutating delta has a start event");
        if completed.delta_id != started.delta_id {
            return invariant("delta ID changed between start and completion".into());
        }
        let mutation_count = self
            .events
            .iter()
            .filter(|event| event.is_mutation())
            .count() as u64;
        if mutation_count == 0 || completed.mutation_count != mutation_count {
            return invariant(format!(
                "delta_completed mutation_count={} but observed {mutation_count}",
                completed.mutation_count
            ));
        }
        let expected_delta_id = build_delta_stable_id(
            &started.base_snapshot_id,
            &started.base_graph_digest,
            &started.scope,
            self.events.iter().filter(|event| event.is_mutation()),
        )?;
        if completed.delta_id != expected_delta_id {
            return invariant(format!(
                "delta ID {} does not match canonical mutation identity {expected_delta_id}",
                completed.delta_id
            ));
        }
        validate_final_state(
            &self.profiles,
            &self.nodes,
            &self.sites,
            &self.edges,
            &self.evidence,
            &self.coverage,
        )?;
        self.completed = Some(completed.clone());
        self.state = DeltaStreamState::Completed;
        Ok(())
    }
}

/// Reads, size-limits, deserializes, and validates a complete delta stream.
pub fn validate_delta_ndjson(
    reader: impl BufRead,
    base: DeltaBaseGraph,
) -> Result<ValidatedDelta, ProtocolError> {
    let mut validator = DeltaValidator::new(base)?;
    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line.map_err(|source| ProtocolError::Io {
            line: line_number,
            source,
        })?;
        if line.len() > crate::MAX_EVENT_LINE_BYTES {
            return Err(ProtocolError::LineTooLong {
                line: line_number,
                limit: crate::MAX_EVENT_LINE_BYTES,
            });
        }
        let event = serde_json::from_str(&line).map_err(|source| ProtocolError::Json {
            line: line_number,
            source,
        })?;
        validator.push(event)?;
    }
    validator.finish()
}

/// Builds the stable delta identity from the exact validated base, canonical
/// scope, and canonical mutation payloads. Attempt routing metadata and event
/// sequence numbers are intentionally excluded.
pub fn build_delta_stable_id<'a>(
    base_snapshot_id: &str,
    base_graph_digest: &str,
    scope: &DeltaScope,
    mutations: impl IntoIterator<Item = &'a DeltaEvent>,
) -> Result<String, ProtocolError> {
    validate_stable_id("delta base snapshot ID", base_snapshot_id, Some("snapshot"))?;
    validate_digest("delta base graph digest", base_graph_digest)?;
    validate_scope(scope)?;
    let mut payloads = Vec::new();
    let mut previous = None;
    for event in mutations {
        let key = event.mutation_sort_key().ok_or_else(|| {
            ProtocolError::Invariant("delta ID input contains a boundary event".into())
        })?;
        if previous.as_ref().is_some_and(|previous| previous >= &key) {
            return invariant("delta ID input is not in canonical mutation order".into());
        }
        previous = Some(key);
        payloads.push(
            event
                .canonical_mutation_payload()
                .expect("mutation has canonical payload"),
        );
    }
    if payloads.is_empty() {
        return invariant("delta ID requires at least one mutation".into());
    }
    Ok(stable_id_from_value(
        "delta",
        &json!({
            "contract": DELTA_CONTRACT_VERSION,
            "base_snapshot_id": base_snapshot_id,
            "base_graph_digest": base_graph_digest,
            "scope": scope,
            "mutations": payloads,
        }),
    ))
}

fn normalize_delta_conditions(event: &mut DeltaEvent) {
    match event {
        DeltaEvent::SiteUpsert(event) => {
            event.site.condition = event.site.condition.canonicalized();
        }
        DeltaEvent::EdgeUpsert(event) => {
            event.edge.condition = event.edge.condition.canonicalized();
        }
        _ => {}
    }
}

fn scoped_base_entities(
    scope: &DeltaScope,
    nodes: &BTreeMap<String, GraphNode>,
    sites: &BTreeMap<String, DependencySite>,
    edges: &BTreeMap<String, GraphEdge>,
    evidence: &BTreeMap<DeltaEvidenceKey, Evidence>,
) -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
    let scoped_nodes = nodes
        .values()
        .filter(|node| {
            node_is_scoped(scope, node)
                || owner_has_scoped_evidence(scope, DeltaEvidenceOwner::Node, &node.id, evidence)
        })
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    let scoped_sites = sites
        .values()
        .filter(|site| site_is_scoped(scope, site, &scoped_nodes, evidence))
        .map(|site| site.id.clone())
        .collect::<BTreeSet<_>>();
    let scoped_edges = edges
        .values()
        .filter(|edge| edge_is_scoped(scope, edge, &scoped_nodes, &scoped_sites, evidence))
        .map(|edge| edge.id.clone())
        .collect::<BTreeSet<_>>();
    (scoped_nodes, scoped_sites, scoped_edges)
}

fn node_is_scoped(scope: &DeltaScope, node: &GraphNode) -> bool {
    let properties = Value::Object(node.properties.clone().into_iter().collect());
    scope.artifact_node_ids.binary_search(&node.id).is_ok()
        || scope.paths.binary_search(&node.locator).is_ok()
        || (node.kind == "package_instance"
            && scope.package_locators.binary_search(&node.locator).is_ok())
        || has_named_scope_value(
            &properties,
            &[
                "path",
                "source_path",
                "manifest_path",
                "relative_path",
                "logical_path",
            ],
            &scope.paths,
        )
        || has_named_scope_value(&properties, &["package_locator"], &scope.package_locators)
        || has_named_scope_value(&properties, &["profile_id"], &scope.profile_ids)
}

fn site_is_scoped(
    scope: &DeltaScope,
    site: &DependencySite,
    scoped_nodes: &BTreeSet<String>,
    evidence: &BTreeMap<DeltaEvidenceKey, Evidence>,
) -> bool {
    scope.profile_ids.binary_search(&site.profile_id).is_ok()
        || scoped_nodes.contains(&site.source)
        || owner_has_scoped_evidence(scope, DeltaEvidenceOwner::Site, &site.id, evidence)
}

fn edge_is_scoped(
    scope: &DeltaScope,
    edge: &GraphEdge,
    scoped_nodes: &BTreeSet<String>,
    scoped_sites: &BTreeSet<String>,
    evidence: &BTreeMap<DeltaEvidenceKey, Evidence>,
) -> bool {
    scope.profile_ids.binary_search(&edge.profile_id).is_ok()
        || scoped_nodes.contains(&edge.source)
        || scoped_nodes.contains(&edge.target)
        || edge
            .site_id
            .as_ref()
            .is_some_and(|site_id| scoped_sites.contains(site_id))
        || owner_has_scoped_evidence(scope, DeltaEvidenceOwner::Edge, &edge.id, evidence)
}

fn evidence_is_scoped(
    scope: &DeltaScope,
    key: &DeltaEvidenceKey,
    evidence: Option<&Evidence>,
    scoped_nodes: &BTreeSet<String>,
    scoped_sites: &BTreeSet<String>,
    scoped_edges: &BTreeSet<String>,
) -> bool {
    let owner_is_scoped = match key.owner_type {
        DeltaEvidenceOwner::Node => scoped_nodes.contains(&key.owner_id),
        DeltaEvidenceOwner::Site => scoped_sites.contains(&key.owner_id),
        DeltaEvidenceOwner::Edge => scoped_edges.contains(&key.owner_id),
    };
    owner_is_scoped
        || evidence
            .and_then(|evidence| evidence.path.as_ref())
            .is_some_and(|path| scope.paths.binary_search(path).is_ok())
}

fn owner_has_scoped_evidence(
    scope: &DeltaScope,
    owner_type: DeltaEvidenceOwner,
    owner_id: &str,
    evidence: &BTreeMap<DeltaEvidenceKey, Evidence>,
) -> bool {
    evidence.iter().any(|(key, evidence)| {
        key.owner_type == owner_type
            && key.owner_id == owner_id
            && evidence
                .path
                .as_ref()
                .is_some_and(|path| scope.paths.binary_search(path).is_ok())
    })
}

fn coverage_key_is_scoped(scope: &DeltaScope, key: &DeltaCoverageKey) -> bool {
    match key {
        DeltaCoverageKey::Aggregate => true,
        DeltaCoverageKey::Profile { profile_id } => {
            scope.profile_ids.binary_search(profile_id).is_ok()
        }
        DeltaCoverageKey::File { adapter, path } => {
            scope.adapters.binary_search(adapter).is_ok() && scope.paths.binary_search(path).is_ok()
        }
    }
}

fn has_named_scope_value(value: &Value, keys: &[&str], candidates: &[String]) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            (keys.contains(&key.as_str())
                && value.as_str().is_some_and(|value| {
                    candidates
                        .binary_search_by(|candidate| candidate.as_str().cmp(value))
                        .is_ok()
                }))
                || has_named_scope_value(value, keys, candidates)
        }),
        Value::Array(values) => values
            .iter()
            .any(|value| has_named_scope_value(value, keys, candidates)),
        _ => false,
    }
}

fn validate_final_state(
    profiles: &BTreeSet<String>,
    nodes: &BTreeMap<String, GraphNode>,
    sites: &BTreeMap<String, DependencySite>,
    edges: &BTreeMap<String, GraphEdge>,
    evidence: &BTreeMap<DeltaEvidenceKey, Evidence>,
    coverage: &BTreeMap<DeltaCoverageKey, DeltaCoverage>,
) -> Result<(), ProtocolError> {
    for key in evidence.keys() {
        validate_evidence_key(key)?;
        let owner_exists = match key.owner_type {
            DeltaEvidenceOwner::Node => nodes.contains_key(&key.owner_id),
            DeltaEvidenceOwner::Site => sites.contains_key(&key.owner_id),
            DeltaEvidenceOwner::Edge => edges.contains_key(&key.owner_id),
        };
        if !owner_exists {
            return invariant(format!(
                "evidence {} references a missing owner",
                evidence_key_string(key)
            ));
        }
    }
    validate_evidence_ordinals(evidence)?;

    let mut hydrated_sites = Vec::with_capacity(sites.len());
    for site in sites.values() {
        if !profiles.contains(&site.profile_id) {
            return invariant(format!(
                "site {} references undeclared profile {}",
                site.id, site.profile_id
            ));
        }
        let mut site = site.clone();
        site.evidence = evidence_for_owner(evidence, DeltaEvidenceOwner::Site, &site.id);
        hydrated_sites.push(site);
    }
    let mut hydrated_edges = Vec::with_capacity(edges.len());
    for edge in edges.values() {
        if !profiles.contains(&edge.profile_id) {
            return invariant(format!(
                "edge {} references undeclared profile {}",
                edge.id, edge.profile_id
            ));
        }
        let mut edge = edge.clone();
        edge.evidence = evidence_for_owner(evidence, DeltaEvidenceOwner::Edge, &edge.id);
        hydrated_edges.push(edge);
    }
    validate_site_edge_invariants(
        &nodes.values().cloned().collect::<Vec<_>>(),
        &hydrated_edges,
        &hydrated_sites,
    )?;

    if !coverage.contains_key(&DeltaCoverageKey::Aggregate) {
        return invariant("delta result has no aggregate coverage".into());
    }
    for profile_id in profiles {
        let key = DeltaCoverageKey::Profile {
            profile_id: profile_id.clone(),
        };
        if !coverage.contains_key(&key) {
            return invariant(format!(
                "delta result has no coverage for profile {profile_id}"
            ));
        }
    }
    for (key, value) in coverage {
        validate_coverage_key(key)?;
        validate_delta_coverage(value)?;
        if &value.key() != key {
            return invariant(format!(
                "coverage map key {} does not match its payload",
                coverage_key_string(key)
            ));
        }
        if let DeltaCoverageKey::Profile { profile_id } = key
            && !profiles.contains(profile_id)
        {
            return invariant(format!(
                "coverage references undeclared profile {profile_id}"
            ));
        }
    }
    Ok(())
}

fn validate_scope(scope: &DeltaScope) -> Result<(), ProtocolError> {
    if scope.paths.is_empty()
        && scope.package_locators.is_empty()
        && scope.profile_ids.is_empty()
        && scope.artifact_node_ids.is_empty()
    {
        return invariant("delta scope must identify a non-empty graph ownership closure".into());
    }
    validate_sorted_unique("delta scope paths", &scope.paths)?;
    for path in &scope.paths {
        validate_relative_path("delta scope path", path)?;
    }
    for (field, values) in [
        ("delta scope package locators", &scope.package_locators),
        ("delta scope profile IDs", &scope.profile_ids),
        ("delta scope artifact node IDs", &scope.artifact_node_ids),
        ("delta scope adapters", &scope.adapters),
    ] {
        validate_sorted_unique(field, values)?;
        for value in values {
            require_non_empty(field, value)?;
        }
    }
    if scope.adapters.len() != 1 {
        return invariant("one worker delta must contain exactly one adapter".into());
    }
    for node_id in &scope.artifact_node_ids {
        validate_stable_id("delta scope artifact node ID", node_id, None)?;
    }
    Ok(())
}

fn validate_delta_coverage(coverage: &DeltaCoverage) -> Result<(), ProtocolError> {
    match coverage {
        DeltaCoverage::Aggregate { value } => validate_coverage(value),
        DeltaCoverage::Profile { profile_id, value } => {
            require_non_empty("coverage profile ID", profile_id)?;
            validate_coverage(value)
        }
        DeltaCoverage::File {
            adapter,
            path,
            value,
        } => {
            require_non_empty("file coverage adapter", adapter)?;
            validate_relative_path("file coverage path", path)?;
            let accounted = value
                .emitted_sites
                .checked_add(value.skipped_sites)
                .ok_or_else(|| {
                    ProtocolError::Invariant("file coverage site ledger overflowed".into())
                })?;
            if accounted != value.discovered_sites {
                return invariant(format!(
                    "file coverage {path} discovered {} sites but emitted {} and skipped {}",
                    value.discovered_sites, value.emitted_sites, value.skipped_sites
                ));
            }
            if value.skipped_sites > 0 && !value.skipped {
                return invariant(format!(
                    "file coverage {path} reports skipped sites but skipped=false"
                ));
            }
            if value.skipped && value.reason.as_deref().is_none_or(str::is_empty) {
                return invariant(format!(
                    "skipped file coverage {path} must include a non-empty reason"
                ));
            }
            Ok(())
        }
    }
}

fn validate_coverage(coverage: &Coverage) -> Result<(), ProtocolError> {
    let classified = coverage
        .resolved
        .checked_add(coverage.candidates)
        .and_then(|value| value.checked_add(coverage.external))
        .and_then(|value| value.checked_add(coverage.unresolved))
        .ok_or_else(|| ProtocolError::Invariant("coverage status counters overflowed".into()))?;
    if classified != coverage.dependency_sites {
        return invariant(format!(
            "coverage dependency_sites={} but classified statuses total {classified}",
            coverage.dependency_sites
        ));
    }
    let accounted_files = coverage
        .files_analyzed
        .checked_add(coverage.files_skipped)
        .ok_or_else(|| ProtocolError::Invariant("coverage file counters overflowed".into()))?;
    if accounted_files != coverage.files_discovered {
        return invariant(format!(
            "coverage files_discovered={} but analyzed+skipped={}",
            coverage.files_discovered, accounted_files
        ));
    }
    if !is_strictly_sorted(&coverage.completeness) {
        return invariant("delta coverage completeness must be canonical sorted and unique".into());
    }
    if !is_strictly_sorted(&coverage.reasons) {
        return invariant("delta coverage reasons must be canonical sorted and unique".into());
    }
    Ok(())
}

fn validate_coverage_key(key: &DeltaCoverageKey) -> Result<(), ProtocolError> {
    match key {
        DeltaCoverageKey::Aggregate => Ok(()),
        DeltaCoverageKey::Profile { profile_id } => {
            require_non_empty("coverage profile ID", profile_id)
        }
        DeltaCoverageKey::File { adapter, path } => {
            require_non_empty("file coverage adapter", adapter)?;
            validate_relative_path("file coverage path", path)
        }
    }
}

fn validate_evidence_key(key: &DeltaEvidenceKey) -> Result<(), ProtocolError> {
    let prefix = match key.owner_type {
        DeltaEvidenceOwner::Site => Some("site"),
        DeltaEvidenceOwner::Edge => Some("edge"),
        DeltaEvidenceOwner::Node => None,
    };
    validate_stable_id("evidence owner ID", &key.owner_id, prefix)
}

fn validate_evidence(evidence: &Evidence) -> Result<(), ProtocolError> {
    require_non_empty("evidence.extractor", &evidence.extractor)?;
    require_non_empty("evidence.extractor_version", &evidence.extractor_version)?;
    if let Some(path) = &evidence.path {
        validate_relative_path("evidence path", path)?;
    }
    let coordinates = [
        evidence.start_line,
        evidence.start_column,
        evidence.end_line,
        evidence.end_column,
    ];
    if coordinates.iter().any(Option::is_some) {
        if evidence.path.is_none() || coordinates.iter().any(Option::is_none) {
            return invariant("evidence span requires path and all four coordinates".into());
        }
        let start = (
            evidence.start_line.expect("checked"),
            evidence.start_column.expect("checked"),
        );
        let end = (
            evidence.end_line.expect("checked"),
            evidence.end_column.expect("checked"),
        );
        if [start.0, start.1, end.0, end.1].contains(&0) || end < start {
            return invariant("evidence span is invalid".into());
        }
    }
    Ok(())
}

fn validate_evidence_ordinals(
    evidence: &BTreeMap<DeltaEvidenceKey, Evidence>,
) -> Result<(), ProtocolError> {
    let mut expected = BTreeMap::<(DeltaEvidenceOwner, &str), u32>::new();
    for key in evidence.keys() {
        let owner = (key.owner_type, key.owner_id.as_str());
        let next = expected.entry(owner).or_insert(0);
        if key.ordinal != *next {
            return invariant(format!(
                "evidence owner {}:{} has non-contiguous ordinal {}; expected {}",
                key.owner_type.as_str(),
                key.owner_id,
                key.ordinal,
                *next
            ));
        }
        *next += 1;
    }
    Ok(())
}

fn evidence_for_owner(
    evidence: &BTreeMap<DeltaEvidenceKey, Evidence>,
    owner_type: DeltaEvidenceOwner,
    owner_id: &str,
) -> Vec<Evidence> {
    evidence
        .iter()
        .filter(|(key, _)| key.owner_type == owner_type && key.owner_id == owner_id)
        .map(|(_, evidence)| evidence.clone())
        .collect()
}

fn merge_embedded_evidence(
    target: &mut BTreeMap<DeltaEvidenceKey, Evidence>,
    owner_type: DeltaEvidenceOwner,
    owner_id: &str,
    evidence: Vec<Evidence>,
) -> Result<(), ProtocolError> {
    for (ordinal, item) in evidence.into_iter().enumerate() {
        let key = DeltaEvidenceKey {
            owner_type,
            owner_id: owner_id.to_owned(),
            ordinal: ordinal as u32,
        };
        if let Some(existing) = target.insert(key.clone(), item.clone())
            && existing != item
        {
            return invariant(format!(
                "base graph contains conflicting evidence {}",
                evidence_key_string(&key)
            ));
        }
    }
    Ok(())
}

fn validate_contract_version(version: &str) -> Result<(), ProtocolError> {
    if version != DELTA_CONTRACT_VERSION {
        return invariant(format!(
            "unsupported delta contract {version:?}; expected {DELTA_CONTRACT_VERSION:?}"
        ));
    }
    Ok(())
}

fn validate_stable_id(
    field: &str,
    id: &str,
    expected_namespace: Option<&str>,
) -> Result<(), ProtocolError> {
    let (namespace, digest) = id
        .split_once(":sha256:")
        .ok_or_else(|| ProtocolError::Invariant(format!("{field} is not a stable SHA-256 ID")))?;
    if namespace.is_empty()
        || expected_namespace.is_some_and(|expected| namespace != expected)
        || !is_digest(digest)
    {
        return invariant(format!("{field} is not a valid stable SHA-256 ID"));
    }
    Ok(())
}

fn validate_digest(field: &str, digest: &str) -> Result<(), ProtocolError> {
    if !is_digest(digest) {
        return invariant(format!(
            "{field} must be 64 lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_relative_path(field: &str, value: &str) -> Result<(), ProtocolError> {
    require_non_empty(field, value)?;
    let path = Path::new(value);
    if path.is_absolute()
        || value.contains('\\')
        || value.starts_with("./")
        || value.contains("//")
        || value.ends_with('/')
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir
                    | Component::CurDir
                    | Component::RootDir
                    | Component::Prefix(_)
            )
        })
    {
        return invariant(format!(
            "{field} must be a canonical repository-relative path"
        ));
    }
    Ok(())
}

fn validate_sorted_unique<T: Ord>(field: &str, values: &[T]) -> Result<(), ProtocolError> {
    if !is_strictly_sorted(values) {
        return invariant(format!("{field} must be canonical sorted and unique"));
    }
    Ok(())
}

fn is_strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn require_non_empty(field: &str, value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() {
        return invariant(format!("{field} must not be empty"));
    }
    Ok(())
}

fn require_present<T>(value: Option<T>, entity: &str, id: &str) -> Result<T, ProtocolError> {
    value.ok_or_else(|| {
        ProtocolError::Invariant(format!(
            "{entity}_delete references missing base entity {id}"
        ))
    })
}

fn require_scoped(scoped: bool, entity: &str, id: &str) -> Result<(), ProtocolError> {
    if !scoped {
        return invariant(format!(
            "delta {entity} mutation {id} is outside the declared scope"
        ));
    }
    Ok(())
}

fn evidence_key_string(key: &DeltaEvidenceKey) -> String {
    format!(
        "{}\0{}\0{:010}",
        key.owner_type.as_str(),
        key.owner_id,
        key.ordinal
    )
}

fn coverage_key_string(key: &DeltaCoverageKey) -> String {
    match key {
        DeltaCoverageKey::Aggregate => "aggregate".to_owned(),
        DeltaCoverageKey::Profile { profile_id } => format!("profile\0{profile_id}"),
        DeltaCoverageKey::File { adapter, path } => format!("file\0{adapter}\0{path}"),
    }
}

fn invariant<T>(message: String) -> Result<T, ProtocolError> {
    Err(ProtocolError::Invariant(message))
}
