use crate::{
    CompletenessLevel, Condition, DependencySite, Diagnostic, Evidence, EvidenceKind, GraphEdge,
    GraphNode, PROTOCOL_VERSION, Phase, Precision, Profile, ProtocolEvent, ResolutionStatus,
    canonical_json, stable_id_from_value,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Maximum accepted size of one NDJSON event, excluding the newline.
pub const MAX_EVENT_LINE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("failed to read protocol stream at line {line}: {source}")]
    Io {
        line: usize,
        #[source]
        source: std::io::Error,
    },
    #[error("protocol event at line {line} exceeds {limit} bytes")]
    LineTooLong { line: usize, limit: usize },
    #[error("invalid JSON protocol event at line {line}: {source}")]
    Json {
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("unsupported protocol version {found:?}; expected {expected:?}")]
    UnsupportedVersion {
        expected: &'static str,
        found: String,
    },
    #[error("protocol stream must start with scan_started, found {found}")]
    MissingScanStarted { found: &'static str },
    #[error("event {found} is not allowed after scan_completed")]
    EventAfterScanCompleted { found: &'static str },
    #[error("duplicate scan_started event")]
    DuplicateScanStarted,
    #[error("scan metadata field {field} changed from {expected:?} to {found:?}")]
    MetadataChanged {
        field: &'static str,
        expected: String,
        found: String,
    },
    #[error("event seq must increase strictly; previous={previous}, found={found}")]
    NonMonotonicSequence { previous: u64, found: u64 },
    #[error("{entity} {id:?} was upserted with conflicting content")]
    ConflictingUpsert { entity: &'static str, id: String },
    #[error("profile {profile_id:?} must be declared before {event}")]
    UndeclaredProfile {
        profile_id: String,
        event: &'static str,
    },
    #[error("profile {profile_id:?} already completed before {event}")]
    ProfileAlreadyCompleted {
        profile_id: String,
        event: &'static str,
    },
    #[error("profile {profile_id:?} completed more than once")]
    DuplicateProfileCompletion { profile_id: String },
    #[error("scan_completed arrived before profiles completed: {profile_ids:?}")]
    UncompletedProfiles { profile_ids: Vec<String> },
    #[error("protocol stream ended before scan_completed")]
    IncompleteStream,
    #[error(
        "strict safe-scan validation requires safe_mode=true and project_code_executed=false; found safe_mode={safe_mode}, project_code_executed={project_code_executed}"
    )]
    UnsafeScanMode {
        safe_mode: bool,
        project_code_executed: bool,
    },
    #[error("event {found} is not allowed after profile completion has begun")]
    PayloadAfterProfileCompletion { found: &'static str },
    #[error("protocol path {path:?} escapes scan root {root:?}")]
    UnsafePath { path: String, root: String },
    #[error("protocol invariant failed: {0}")]
    Invariant(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamState {
    AwaitingStart,
    Scanning,
    Completed,
}

/// Selects whether the validator accepts every protocol-v1 execution mode or
/// only the safe static-scan contract.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ValidationPolicy {
    #[default]
    Compatible,
    SafeScan,
}

#[derive(Clone, Debug)]
struct StreamIdentity {
    scan_id: String,
    adapter: String,
    adapter_version: String,
}

/// Incremental state-machine validator for one worker's event stream.
#[derive(Debug)]
pub struct ProtocolValidator {
    policy: ValidationPolicy,
    state: StreamState,
    identity: Option<StreamIdentity>,
    last_seq: Option<u64>,
    root: Option<PathBuf>,
    safe_mode: bool,
    project_code_executed: bool,
    payload_closed: bool,
    events: Vec<ProtocolEvent>,
    profiles: BTreeMap<String, Profile>,
    completed_profiles: BTreeSet<String>,
    profile_coverage: BTreeMap<String, crate::Coverage>,
    nodes: BTreeMap<String, GraphNode>,
    edges: BTreeMap<String, GraphEdge>,
    sites: BTreeMap<String, DependencySite>,
    diagnostics: BTreeMap<String, Diagnostic>,
}

impl Default for ProtocolValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolValidator {
    #[must_use]
    pub fn new() -> Self {
        Self::with_policy(ValidationPolicy::Compatible)
    }

    /// Creates a validator that requires the worker to declare a safe scan and
    /// to report that no project code was executed.
    #[must_use]
    pub fn for_safe_scan() -> Self {
        Self::with_policy(ValidationPolicy::SafeScan)
    }

    #[must_use]
    pub fn with_policy(policy: ValidationPolicy) -> Self {
        Self {
            policy,
            state: StreamState::AwaitingStart,
            identity: None,
            last_seq: None,
            root: None,
            safe_mode: false,
            project_code_executed: false,
            payload_closed: false,
            events: Vec::new(),
            profiles: BTreeMap::new(),
            completed_profiles: BTreeSet::new(),
            profile_coverage: BTreeMap::new(),
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
            sites: BTreeMap::new(),
            diagnostics: BTreeMap::new(),
        }
    }

    /// Returns the canonicalized prefix accepted so far. This is intended for
    /// evidence stores that retain a worker's valid output when the process
    /// crashes or the stream is truncated before `scan_completed`.
    #[must_use]
    pub fn validated_events(&self) -> &[ProtocolEvent] {
        &self.events
    }

    /// Validates and records one event. Conditions are canonicalized before
    /// conflict detection so semantically equivalent commutative expressions
    /// do not create false conflicts.
    pub fn push(&mut self, mut event: ProtocolEvent) -> Result<(), ProtocolError> {
        normalize_conditions(&mut event);
        self.validate_common(&event)?;

        match self.state {
            StreamState::AwaitingStart if !matches!(&event, ProtocolEvent::ScanStarted(_)) => {
                return Err(ProtocolError::MissingScanStarted {
                    found: event.event_name(),
                });
            }
            StreamState::Completed => {
                return Err(ProtocolError::EventAfterScanCompleted {
                    found: event.event_name(),
                });
            }
            _ => {}
        }
        if self.payload_closed && is_payload_event(&event) {
            return Err(ProtocolError::PayloadAfterProfileCompletion {
                found: event.event_name(),
            });
        }

        match &event {
            ProtocolEvent::ScanStarted(started) => {
                if self.state != StreamState::AwaitingStart {
                    return Err(ProtocolError::DuplicateScanStarted);
                }
                require_non_empty("scan_started.root", &started.root)?;
                if self.policy == ValidationPolicy::SafeScan
                    && (!started.safe_mode || started.project_code_executed)
                {
                    return Err(ProtocolError::UnsafeScanMode {
                        safe_mode: started.safe_mode,
                        project_code_executed: started.project_code_executed,
                    });
                }
                if started.safe_mode && started.project_code_executed {
                    return Err(ProtocolError::Invariant(
                        "safe-mode scan reports project_code_executed=true".into(),
                    ));
                }
                self.root = Some(PathBuf::from(&started.root));
                self.safe_mode = started.safe_mode;
                self.project_code_executed = started.project_code_executed;
                self.state = StreamState::Scanning;
            }
            ProtocolEvent::ProfileDeclared(declared) => {
                validate_profile(&declared.profile)?;
                if self.completed_profiles.contains(&declared.profile.id) {
                    return Err(ProtocolError::ProfileAlreadyCompleted {
                        profile_id: declared.profile.id.clone(),
                        event: event.event_name(),
                    });
                }
                insert_upsert(
                    &mut self.profiles,
                    declared.profile.id.clone(),
                    declared.profile.clone(),
                    "profile",
                )?;
            }
            ProtocolEvent::NodeUpsert(upsert) => {
                validate_node(&upsert.node)?;
                insert_upsert(
                    &mut self.nodes,
                    upsert.node.id.clone(),
                    upsert.node.clone(),
                    "node",
                )?;
            }
            ProtocolEvent::EdgeUpsert(upsert) => {
                validate_edge(&upsert.edge)?;
                self.require_active_profile(&upsert.edge.profile_id, event.event_name())?;
                self.validate_evidence_paths(&upsert.edge.evidence)?;
                insert_upsert(
                    &mut self.edges,
                    upsert.edge.id.clone(),
                    upsert.edge.clone(),
                    "edge",
                )?;
            }
            ProtocolEvent::DependencySite(site) => {
                validate_site(&site.site)?;
                self.require_active_profile(&site.site.profile_id, event.event_name())?;
                self.validate_evidence_paths(&site.site.evidence)?;
                insert_upsert(
                    &mut self.sites,
                    site.site.id.clone(),
                    site.site.clone(),
                    "dependency_site",
                )?;
            }
            ProtocolEvent::Diagnostic(diagnostic) => {
                validate_diagnostic(&diagnostic.diagnostic)?;
                if let Some(profile_id) = &diagnostic.diagnostic.profile_id
                    && !self.profiles.contains_key(profile_id)
                {
                    return Err(ProtocolError::UndeclaredProfile {
                        profile_id: profile_id.clone(),
                        event: event.event_name(),
                    });
                }
                if let Some(path) = &diagnostic.diagnostic.path {
                    self.validate_path(path)?;
                }
                self.validate_evidence_paths(&diagnostic.diagnostic.evidence)?;
                insert_upsert(
                    &mut self.diagnostics,
                    diagnostic.diagnostic.id.clone(),
                    diagnostic.diagnostic.clone(),
                    "diagnostic",
                )?;
            }
            ProtocolEvent::FileCompleted(completed) => {
                require_non_empty("file_completed.path", &completed.path)?;
                self.validate_path(&completed.path)?;
                let accounted = completed
                    .emitted_sites
                    .checked_add(completed.skipped_sites)
                    .ok_or_else(|| {
                        ProtocolError::Invariant(format!(
                            "file {} site ledger overflowed",
                            completed.path
                        ))
                    })?;
                if accounted != completed.discovered_sites {
                    return Err(ProtocolError::Invariant(format!(
                        "file {} discovered {} sites but emitted {} and skipped {}",
                        completed.path,
                        completed.discovered_sites,
                        completed.emitted_sites,
                        completed.skipped_sites
                    )));
                }
                if completed.skipped_sites > 0 && !completed.skipped {
                    return Err(ProtocolError::Invariant(format!(
                        "file {} reports skipped sites but skipped=false",
                        completed.path
                    )));
                }
                if completed.skipped && completed.reason.is_none() {
                    return Err(ProtocolError::Invariant(format!(
                        "skipped file {} has no reason",
                        completed.path
                    )));
                }
                if let Some(reason) = &completed.reason {
                    require_non_empty("file_completed.reason", reason)?;
                }
            }
            ProtocolEvent::ProfileCompleted(completed) => {
                self.require_declared_profile(&completed.profile_id, event.event_name())?;
                if !self.completed_profiles.insert(completed.profile_id.clone()) {
                    return Err(ProtocolError::DuplicateProfileCompletion {
                        profile_id: completed.profile_id.clone(),
                    });
                }
                if self.safe_mode && completed.coverage.project_code_executed {
                    return Err(ProtocolError::Invariant(format!(
                        "safe-mode profile {} reports project_code_executed=true",
                        completed.profile_id
                    )));
                }
                validate_coverage(&completed.coverage)?;
                validate_profile_coverage(&completed.profile_id, &completed.coverage, &self.sites)?;
                let profile = self
                    .profiles
                    .get(&completed.profile_id)
                    .expect("profile completion requires a declared profile");
                validate_profile_completeness(profile, &completed.coverage)?;
                self.profile_coverage
                    .insert(completed.profile_id.clone(), completed.coverage.clone());
                self.payload_closed = true;
            }
            ProtocolEvent::ScanCompleted(completed) => {
                let uncompleted: Vec<_> = self
                    .profiles
                    .keys()
                    .filter(|id| !self.completed_profiles.contains(*id))
                    .cloned()
                    .collect();
                if !uncompleted.is_empty() {
                    return Err(ProtocolError::UncompletedProfiles {
                        profile_ids: uncompleted,
                    });
                }
                if self.safe_mode && completed.coverage.project_code_executed {
                    return Err(ProtocolError::Invariant(
                        "safe-mode coverage reports project_code_executed=true".into(),
                    ));
                }
                validate_coverage(&completed.coverage)?;
                validate_scan_coverage(
                    &completed.coverage,
                    &self.profiles,
                    &self.sites,
                    &self.events,
                )?;
                validate_aggregate_profile_coverage(&completed.coverage, &self.profile_coverage)?;
                if completed.coverage.project_code_executed != self.project_code_executed {
                    return Err(ProtocolError::Invariant(format!(
                        "scan_started project_code_executed={} but final coverage reports {}",
                        self.project_code_executed, completed.coverage.project_code_executed
                    )));
                }
                validate_site_edge_maps(&self.nodes, &self.edges, &self.sites)?;
                self.state = StreamState::Completed;
            }
        }

        self.events.push(event);
        Ok(())
    }

    /// Finishes validation and returns the canonicalized protocol contents.
    pub fn finish(self) -> Result<ValidatedProtocol, ProtocolError> {
        if self.state != StreamState::Completed {
            return Err(ProtocolError::IncompleteStream);
        }
        Ok(ValidatedProtocol {
            events: self.events,
            profiles: self.profiles,
            nodes: self.nodes,
            edges: self.edges,
            sites: self.sites,
            diagnostics: self.diagnostics,
        })
    }

    fn validate_common(&mut self, event: &ProtocolEvent) -> Result<(), ProtocolError> {
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
        if let Some(previous) = self.last_seq
            && common.seq <= previous
        {
            return Err(ProtocolError::NonMonotonicSequence {
                previous,
                found: common.seq,
            });
        }
        if let Some(identity) = &self.identity {
            check_identity("scan_id", &identity.scan_id, &common.scan_id)?;
            check_identity("adapter", &identity.adapter, &common.adapter)?;
            check_identity(
                "adapter_version",
                &identity.adapter_version,
                &common.adapter_version,
            )?;
        } else {
            self.identity = Some(StreamIdentity {
                scan_id: common.scan_id.clone(),
                adapter: common.adapter.clone(),
                adapter_version: common.adapter_version.clone(),
            });
        }
        self.last_seq = Some(common.seq);
        Ok(())
    }

    fn require_active_profile(
        &self,
        profile_id: &str,
        event: &'static str,
    ) -> Result<(), ProtocolError> {
        self.require_declared_profile(profile_id, event)?;
        if self.completed_profiles.contains(profile_id) {
            return Err(ProtocolError::ProfileAlreadyCompleted {
                profile_id: profile_id.into(),
                event,
            });
        }
        Ok(())
    }

    fn require_declared_profile(
        &self,
        profile_id: &str,
        event: &'static str,
    ) -> Result<(), ProtocolError> {
        if !self.profiles.contains_key(profile_id) {
            return Err(ProtocolError::UndeclaredProfile {
                profile_id: profile_id.into(),
                event,
            });
        }
        Ok(())
    }

    fn validate_evidence_paths(&self, evidence: &[Evidence]) -> Result<(), ProtocolError> {
        for item in evidence {
            if let Some(path) = &item.path {
                self.validate_path(path)?;
            }
        }
        Ok(())
    }

    fn validate_path(&self, path: &str) -> Result<(), ProtocolError> {
        let root = self
            .root
            .as_deref()
            .expect("scan_started always establishes a root before payload events");
        let candidate = Path::new(path);
        let lexically_escapes = candidate
            .components()
            .any(|component| matches!(component, Component::ParentDir))
            || (candidate.is_absolute() && !candidate.starts_with(root));
        if lexically_escapes {
            return Err(ProtocolError::UnsafePath {
                path: path.into(),
                root: root.display().to_string(),
            });
        }

        // Lexical checks cannot see a symlink under the repository that points
        // outside it. When both paths exist, canonicalize them and enforce the
        // same confinement rule on their resolved locations.
        if let Ok(canonical_root) = root.canonicalize() {
            let absolute_candidate = if candidate.is_absolute() {
                candidate.to_path_buf()
            } else {
                root.join(candidate)
            };
            if let Some(canonical_candidate) = canonical_existing_ancestor(&absolute_candidate)
                && !canonical_candidate.starts_with(&canonical_root)
            {
                return Err(ProtocolError::UnsafePath {
                    path: path.into(),
                    root: canonical_root.display().to_string(),
                });
            }
        }
        Ok(())
    }
}

fn canonical_existing_ancestor(path: &Path) -> Option<PathBuf> {
    let mut candidate = path.to_path_buf();
    loop {
        if let Ok(canonical) = candidate.canonicalize() {
            return Some(canonical);
        }
        if !candidate.pop() {
            return None;
        }
    }
}

/// Fully validated, canonicalized worker output.
#[derive(Clone, Debug)]
pub struct ValidatedProtocol {
    pub events: Vec<ProtocolEvent>,
    pub profiles: BTreeMap<String, Profile>,
    pub nodes: BTreeMap<String, GraphNode>,
    pub edges: BTreeMap<String, GraphEdge>,
    pub sites: BTreeMap<String, DependencySite>,
    pub diagnostics: BTreeMap<String, Diagnostic>,
}

/// Reads, size-limits, deserializes, and validates one NDJSON stream.
pub fn validate_ndjson(reader: impl BufRead) -> Result<ValidatedProtocol, ProtocolError> {
    validate_ndjson_with(reader, ProtocolValidator::new())
}

/// Validates an NDJSON stream and additionally requires safe static-scan mode.
pub fn validate_safe_ndjson(reader: impl BufRead) -> Result<ValidatedProtocol, ProtocolError> {
    validate_ndjson_with(reader, ProtocolValidator::for_safe_scan())
}

/// Validates a protocol-v1 stream and then applies the opt-in Milestone 2
/// semantic graph contract for symbol/type nodes and semantic dependencies.
///
/// The base protocol intentionally keeps node and edge kinds as an open
/// vocabulary. Producers that emit the shared semantic graph vocabulary can
/// call this stricter validator without narrowing protocol-v1 compatibility
/// for other producers.
pub fn validate_semantic_ndjson(reader: impl BufRead) -> Result<ValidatedProtocol, ProtocolError> {
    let protocol = validate_ndjson(reader)?;
    validate_semantic_contract(&protocol)?;
    Ok(protocol)
}

/// Applies both safe static-scan validation and the opt-in Milestone 2
/// semantic graph contract.
pub fn validate_safe_semantic_ndjson(
    reader: impl BufRead,
) -> Result<ValidatedProtocol, ProtocolError> {
    let protocol = validate_safe_ndjson(reader)?;
    validate_semantic_contract(&protocol)?;
    Ok(protocol)
}

/// Validates the opt-in Milestone 2 semantic graph contract on an already
/// validated protocol stream.
pub fn validate_semantic_contract(protocol: &ValidatedProtocol) -> Result<(), ProtocolError> {
    validate_site_edge_maps(&protocol.nodes, &protocol.edges, &protocol.sites)?;
    validate_semantic_maps(&protocol.nodes, &protocol.edges, &protocol.sites)
}

fn validate_ndjson_with(
    reader: impl BufRead,
    mut validator: ProtocolValidator,
) -> Result<ValidatedProtocol, ProtocolError> {
    for (index, line) in reader.split(b'\n').enumerate() {
        let line_number = index + 1;
        let mut line = line.map_err(|source| ProtocolError::Io {
            line: line_number,
            source,
        })?;
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.len() > MAX_EVENT_LINE_BYTES {
            return Err(ProtocolError::LineTooLong {
                line: line_number,
                limit: MAX_EVENT_LINE_BYTES,
            });
        }
        let event = serde_json::from_slice(&line).map_err(|source| ProtocolError::Json {
            line: line_number,
            source,
        })?;
        validator.push(event)?;
    }
    validator.finish()
}

/// Validates the authoritative dependency-site classifications against their
/// graph nodes and edges.
pub fn validate_site_edge_invariants(
    nodes: &[GraphNode],
    edges: &[GraphEdge],
    sites: &[DependencySite],
) -> Result<(), ProtocolError> {
    let nodes = nodes
        .iter()
        .cloned()
        .map(|node| (node.id.clone(), node))
        .collect();
    let edges = edges
        .iter()
        .cloned()
        .map(|edge| (edge.id.clone(), edge))
        .collect();
    let sites = sites
        .iter()
        .cloned()
        .map(|site| (site.id.clone(), site))
        .collect();
    validate_site_edge_maps(&nodes, &edges, &sites)
}

/// Validates an in-memory graph against both the base endpoint/site contract
/// and the opt-in semantic symbol/type/dependency contract.
///
/// Workers use this before atomically merging a semantic delta with an
/// existing syntax graph, avoiding a serialize/parse round trip solely for
/// contract validation.
pub fn validate_semantic_graph(
    nodes: &[GraphNode],
    edges: &[GraphEdge],
    sites: &[DependencySite],
) -> Result<(), ProtocolError> {
    let nodes: BTreeMap<_, _> = nodes
        .iter()
        .cloned()
        .map(|node| (node.id.clone(), node))
        .collect();
    let edges: BTreeMap<_, _> = edges
        .iter()
        .cloned()
        .map(|edge| (edge.id.clone(), edge))
        .collect();
    let sites: BTreeMap<_, _> = sites
        .iter()
        .cloned()
        .map(|site| (site.id.clone(), site))
        .collect();
    validate_site_edge_maps(&nodes, &edges, &sites)?;
    validate_semantic_maps(&nodes, &edges, &sites)
}

fn validate_site_edge_maps(
    nodes: &BTreeMap<String, GraphNode>,
    edges: &BTreeMap<String, GraphEdge>,
    sites: &BTreeMap<String, DependencySite>,
) -> Result<(), ProtocolError> {
    let mut edges_by_site = BTreeMap::<&str, Vec<&GraphEdge>>::new();
    for edge in edges.values() {
        validate_edge(edge)?;
        if !nodes.contains_key(&edge.source) {
            return invariant(format!(
                "edge {} references missing source node {}",
                edge.id, edge.source
            ));
        }
        if !nodes.contains_key(&edge.target) {
            return invariant(format!(
                "edge {} references missing target node {}",
                edge.id, edge.target
            ));
        }
        if let Some(site_id) = &edge.site_id {
            if !sites.contains_key(site_id) {
                return invariant(format!(
                    "edge {} references missing dependency site {}",
                    edge.id, site_id
                ));
            }
            edges_by_site.entry(site_id).or_default().push(edge);
        }
    }

    for site in sites.values() {
        validate_site(site)?;
        if !nodes.contains_key(&site.source) {
            return invariant(format!(
                "dependency site {} references missing source node {}",
                site.id, site.source
            ));
        }
        let targets: BTreeSet<_> = site.target_ids.iter().cloned().collect();
        if targets.len() != site.target_ids.len() {
            return invariant(format!(
                "dependency site {} contains duplicate targets",
                site.id
            ));
        }
        match site.resolution_status {
            ResolutionStatus::Resolved
            | ResolutionStatus::External
            | ResolutionStatus::Unresolved
                if targets.len() != 1 =>
            {
                return invariant(format!(
                    "dependency site {} with status {:?} must have exactly one target",
                    site.id, site.resolution_status
                ));
            }
            ResolutionStatus::Candidates if targets.is_empty() => {
                return invariant(format!(
                    "candidate dependency site {} must have at least one target",
                    site.id
                ));
            }
            _ => {}
        }

        for target in &targets {
            let node = nodes.get(target).ok_or_else(|| {
                ProtocolError::Invariant(format!(
                    "dependency site {} references missing target node {}",
                    site.id, target
                ))
            })?;
            match site.resolution_status {
                ResolutionStatus::Resolved
                    if matches!(node.kind.as_str(), "external_system" | "unknown_target") =>
                {
                    return invariant(format!(
                        "resolved dependency site {} targets non-concrete node {} of kind {}",
                        site.id, node.id, node.kind
                    ));
                }
                ResolutionStatus::External if node.kind != "external_system" => {
                    return invariant(format!(
                        "external dependency site {} targets node {} of kind {}",
                        site.id, node.id, node.kind
                    ));
                }
                ResolutionStatus::Unresolved if node.kind != "unknown_target" => {
                    return invariant(format!(
                        "unresolved dependency site {} targets node {} of kind {}",
                        site.id, node.id, node.kind
                    ));
                }
                _ => {}
            }
        }
        if site.resolution_status == ResolutionStatus::Unresolved && site.reason.is_none() {
            return invariant(format!(
                "unresolved dependency site {} has no reason",
                site.id
            ));
        }

        let site_edges = edges_by_site
            .get(site.id.as_str())
            .cloned()
            .unwrap_or_default();
        if site_edges.len() != targets.len() {
            return invariant(format!(
                "dependency site {} has {} targets but {} edges",
                site.id,
                targets.len(),
                site_edges.len()
            ));
        }
        let edge_targets: BTreeSet<_> = site_edges.iter().map(|edge| edge.target.clone()).collect();
        if edge_targets != targets {
            return invariant(format!(
                "dependency site {} target set does not match its edge target set",
                site.id
            ));
        }
        for edge in site_edges {
            if edge.source != site.source {
                return invariant(format!(
                    "edge {} source does not match dependency site {}",
                    edge.id, site.id
                ));
            }
            if edge.profile_id != site.profile_id {
                return invariant(format!(
                    "edge {} profile does not match dependency site {}",
                    edge.id, site.id
                ));
            }
            if edge.resolution_status != site.resolution_status {
                return invariant(format!(
                    "edge {} status does not match dependency site {}",
                    edge.id, site.id
                ));
            }
            if edge.precision != site.precision {
                return invariant(format!(
                    "edge {} precision does not match dependency site {}",
                    edge.id, site.id
                ));
            }
            // A site condition describes when the syntax site participates at
            // all. Each concrete candidate edge may further narrow that site
            // (for example package exports' browser vs. server targets).
        }
    }
    for node in nodes.values() {
        validate_node(node)?;
    }
    Ok(())
}

fn validate_semantic_maps(
    nodes: &BTreeMap<String, GraphNode>,
    edges: &BTreeMap<String, GraphEdge>,
    sites: &BTreeMap<String, DependencySite>,
) -> Result<(), ProtocolError> {
    let strict_dependency_sites: BTreeSet<_> = sites
        .values()
        .filter(|site| is_evidence_driven_semantic_site(site))
        .map(|site| site.id.as_str())
        .collect();

    for node in nodes.values() {
        validate_semantic_node(node)?;
        if node.kind == "symbol"
            && let Some(identity) = node.properties.get("canonical_identity")
        {
            for field in ["enclosing_symbol", "generated_from"] {
                if let Some(origin) = identity.get(field).and_then(Value::as_str) {
                    let origin_node = nodes.get(origin).ok_or_else(|| {
                        ProtocolError::Invariant(format!(
                            "symbol node {} canonical_identity.{field} references missing node {origin}",
                            node.id
                        ))
                    })?;
                    if field == "enclosing_symbol" && origin_node.kind != "symbol" {
                        return invariant(format!(
                            "symbol node {} canonical_identity.enclosing_symbol references non-symbol node {} of kind {}",
                            node.id, origin_node.id, origin_node.kind
                        ));
                    }
                }
            }
        }
    }

    for edge in edges.values() {
        let linked_site = edge
            .site_id
            .as_deref()
            .and_then(|site_id| sites.get(site_id));
        let linked_to_strict_site =
            linked_site.is_some_and(|site| strict_dependency_sites.contains(site.id.as_str()));
        if let Some(expected_kind) = linked_site.and_then(source_fallback_edge_kind_for_site) {
            validate_source_fallback_edge(
                linked_site.expect("source fallback edge has a linked site"),
                edge,
                expected_kind,
            )?;
            continue;
        }
        validate_semantic_edge(edge, linked_to_strict_site)?;

        if is_semantic_definition_relation(edge) {
            validate_definition_relation_endpoints(nodes, edge)?;
        }

        let Some(site) = linked_site else {
            continue;
        };
        let expected_edge_kind = semantic_edge_kind_for_site(site, linked_to_strict_site);
        if expected_edge_kind.is_none() {
            if is_common_semantic_edge_kind(edge.kind.as_str()) {
                return invariant(format!(
                    "semantic edge {} of kind {} requires a call or type_use dependency site, found {}",
                    edge.id, edge.kind, site.kind
                ));
            }
            continue;
        }
        let expected_edge_kind = expected_edge_kind.expect("semantic site kind checked");
        if edge.kind != expected_edge_kind {
            return invariant(format!(
                "semantic dependency site {} of kind {} requires {expected_edge_kind} edges, found {}",
                site.id, site.kind, edge.kind
            ));
        }
    }

    for site in sites.values() {
        let strict_dependency_site = strict_dependency_sites.contains(site.id.as_str());
        validate_semantic_site(site, strict_dependency_site)?;
        if source_fallback_edge_kind_for_site(site).is_some() {
            validate_source_fallback_site(site)?;
            continue;
        }
        if semantic_edge_kind_for_site(site, strict_dependency_site).is_none() {
            continue;
        }
        let source_node = nodes
            .get(&site.source)
            .expect("base validation requires dependency-site sources to exist");
        let rust_semantic_site = is_rust_semantic_dependency_site(site, source_node);
        match site.kind.as_str() {
            "call" if source_node.kind != "symbol" => {
                return invariant(format!(
                    "semantic call site {} source {} must be a symbol node",
                    site.id, source_node.id
                ));
            }
            "type_use" if !matches!(source_node.kind.as_str(), "symbol" | "type") => {
                return invariant(format!(
                    "semantic type-use site {} source {} must be a symbol or type node",
                    site.id, source_node.id
                ));
            }
            "rust_use" if !matches!(source_node.kind.as_str(), "module" | "symbol") => {
                return invariant(format!(
                    "Rust semantic use site {} source {} must be a module or symbol node",
                    site.id, source_node.id
                ));
            }
            "rust_reexport" if source_node.kind != "module" => {
                return invariant(format!(
                    "Rust semantic re-export site {} source {} must be a module node",
                    site.id, source_node.id
                ));
            }
            _ => {}
        }
        if rust_semantic_site
            && source_node
                .properties
                .get("language")
                .and_then(Value::as_str)
                != Some("rust")
        {
            return invariant(format!(
                "Rust semantic dependency site {} source {} must declare language=rust",
                site.id, source_node.id
            ));
        }

        if matches!(
            site.resolution_status,
            ResolutionStatus::Resolved | ResolutionStatus::Candidates
        ) {
            for target_id in &site.target_ids {
                let target = nodes
                    .get(target_id)
                    .expect("base validation requires dependency-site targets to exist");
                match site.kind.as_str() {
                    "call" if target.kind != "symbol" => {
                        return invariant(format!(
                            "semantic call site {} concrete target {} must be a symbol node",
                            site.id, target.id
                        ));
                    }
                    "type_use" if target.kind != "type" => {
                        return invariant(format!(
                            "semantic type-use site {} concrete target {} must be a type node",
                            site.id, target.id
                        ));
                    }
                    "rust_use" | "rust_reexport"
                        if !matches!(target.kind.as_str(), "module" | "symbol" | "type") =>
                    {
                        return invariant(format!(
                            "Rust semantic {} site {} concrete target {} must be a module, symbol, or type node",
                            site.kind, site.id, target.id
                        ));
                    }
                    _ => {}
                }
                if rust_semantic_site
                    && target.properties.get("language").and_then(Value::as_str) != Some("rust")
                {
                    return invariant(format!(
                        "Rust semantic dependency site {} concrete target {} must declare language=rust",
                        site.id, target.id
                    ));
                }
            }
        }

        let expected_edge_kind = semantic_edge_kind_for_site(site, strict_dependency_site)
            .expect("semantic site kind matched above");
        let require_same_condition = rust_semantic_site;
        for edge in edges
            .values()
            .filter(|edge| edge.site_id.as_deref() == Some(site.id.as_str()))
        {
            if edge.kind != expected_edge_kind {
                return invariant(format!(
                    "semantic dependency site {} requires {expected_edge_kind} edges, found {}",
                    site.id, edge.kind
                ));
            }
            if primary_evidence_anchor(&site.evidence[0])
                != primary_evidence_anchor(&edge.evidence[0])
            {
                return invariant(format!(
                    "semantic edge {} primary evidence anchor does not match dependency site {}",
                    edge.id, site.id
                ));
            }
            if require_same_condition
                && edge.condition.canonicalized() != site.condition.canonicalized()
            {
                return invariant(format!(
                    "Rust semantic edge {} condition does not match dependency site {}",
                    edge.id, site.id
                ));
            }
        }
    }
    Ok(())
}

fn is_common_semantic_edge_kind(kind: &str) -> bool {
    matches!(kind, "type_uses" | "calls" | "may_call")
}

fn is_definition_relation_kind(kind: &str) -> bool {
    matches!(kind, "declares" | "extends" | "implements" | "instantiates")
}

fn is_semantic_definition_relation(edge: &GraphEdge) -> bool {
    is_definition_relation_kind(edge.kind.as_str())
        && (edge.phase == Phase::Semantic
            || edge
                .evidence
                .first()
                .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic))
}

fn validate_definition_relation_endpoints(
    nodes: &BTreeMap<String, GraphNode>,
    edge: &GraphEdge,
) -> Result<(), ProtocolError> {
    let source = nodes
        .get(&edge.source)
        .expect("base validation requires relation sources to exist");
    let target = nodes
        .get(&edge.target)
        .expect("base validation requires relation targets to exist");

    let valid = match edge.kind.as_str() {
        "declares" => {
            !matches!(source.kind.as_str(), "external_system" | "unknown_target")
                && !matches!(target.kind.as_str(), "external_system" | "unknown_target")
        }
        "extends" | "implements" => {
            source.kind == "type" && matches!(target.kind.as_str(), "type" | "external_system")
        }
        "instantiates" => {
            matches!(source.kind.as_str(), "symbol" | "type")
                && matches!(target.kind.as_str(), "symbol" | "type" | "external_system")
        }
        _ => true,
    };
    if !valid {
        return invariant(format!(
            "semantic definition relation {} of kind {} has incompatible endpoints {} ({}) -> {} ({})",
            edge.id, edge.kind, source.id, source.kind, target.id, target.kind
        ));
    }

    let source_language = source.properties.get("language").and_then(Value::as_str);
    let target_language = target.properties.get("language").and_then(Value::as_str);
    if let (Some(source_language), Some(target_language)) = (source_language, target_language)
        && source_language != target_language
        && !matches!(
            (source_language, target_language),
            ("typescript", "javascript") | ("javascript", "typescript")
        )
    {
        return invariant(format!(
            "semantic definition relation {} crosses languages from {source_language:?} to {target_language:?}",
            edge.id
        ));
    }
    Ok(())
}

fn is_rust_import_site_kind(kind: &str) -> bool {
    matches!(kind, "rust_use" | "rust_reexport")
}

fn is_evidence_driven_semantic_site(site: &DependencySite) -> bool {
    matches!(
        site.kind.as_str(),
        "type_use" | "rust_use" | "rust_reexport"
    ) && site
        .evidence
        .first()
        .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic)
}

fn source_fallback_edge_kind_for_site(site: &DependencySite) -> Option<&'static str> {
    if site
        .evidence
        .first()
        .is_none_or(|evidence| evidence.kind != EvidenceKind::Source)
    {
        return None;
    }
    match site.kind.as_str() {
        "type_use" => Some("type_uses"),
        "rust_use" => Some("imports"),
        "rust_reexport" => Some("reexports"),
        _ => None,
    }
}

fn validate_source_fallback_site(site: &DependencySite) -> Result<(), ProtocolError> {
    validate_primary_source_evidence(
        &format!("source fallback dependency site {}", site.id),
        &site.evidence,
    )?;
    if site.kind == "type_use"
        && (!matches!(
            site.resolution_status,
            ResolutionStatus::External | ResolutionStatus::Unresolved
        ) || site.precision != Precision::Heuristic)
    {
        return invariant(format!(
            "source fallback type-use site {} must use external or unresolved status with heuristic precision",
            site.id
        ));
    }
    Ok(())
}

fn validate_source_fallback_edge(
    site: &DependencySite,
    edge: &GraphEdge,
    expected_kind: &str,
) -> Result<(), ProtocolError> {
    if edge.kind != expected_kind {
        return invariant(format!(
            "source dependency site requires {expected_kind} edges, found {}",
            edge.kind
        ));
    }
    if edge.phase != Phase::Source {
        return invariant(format!(
            "source fallback edge {} of kind {} must use phase=source",
            edge.id, edge.kind
        ));
    }
    let site_primary = validate_primary_source_evidence(
        &format!("source fallback dependency site {}", site.id),
        &site.evidence,
    )?;
    let edge_primary = validate_primary_source_evidence(
        &format!("source fallback edge {}", edge.id),
        &edge.evidence,
    )?;
    if primary_evidence_anchor(site_primary) != primary_evidence_anchor(edge_primary) {
        return invariant(format!(
            "source fallback edge {} primary evidence anchor does not match dependency site {}",
            edge.id, site.id
        ));
    }
    if edge.condition.canonicalized() != site.condition.canonicalized() {
        return invariant(format!(
            "source fallback edge {} condition does not match dependency site {}",
            edge.id, site.id
        ));
    }
    if edge.source != site.source {
        return invariant(format!(
            "source fallback edge {} source does not match dependency site {}",
            edge.id, site.id
        ));
    }
    if edge.resolution_status != site.resolution_status {
        return invariant(format!(
            "source fallback edge {} status does not match dependency site {}",
            edge.id, site.id
        ));
    }
    if edge.precision != site.precision {
        return invariant(format!(
            "source fallback edge {} precision does not match dependency site {}",
            edge.id, site.id
        ));
    }
    Ok(())
}

fn semantic_edge_kind_for_site(
    site: &DependencySite,
    strict_dependency_site: bool,
) -> Option<&'static str> {
    match site.kind.as_str() {
        "call" if site.resolution_status == ResolutionStatus::Candidates => Some("may_call"),
        "call" => Some("calls"),
        "type_use" if strict_dependency_site => Some("type_uses"),
        "rust_use" if strict_dependency_site => Some("imports"),
        "rust_reexport" if strict_dependency_site => Some("reexports"),
        _ => None,
    }
}

fn is_rust_semantic_dependency_site(site: &DependencySite, source: &GraphNode) -> bool {
    is_rust_import_site_kind(site.kind.as_str())
        || (site.kind == "type_use"
            && source.properties.get("language").and_then(Value::as_str) == Some("rust"))
        || (site.kind == "call"
            && (source.properties.get("language").and_then(Value::as_str) == Some("rust")
                || site.evidence.first().is_some_and(|evidence| {
                    evidence.kind == EvidenceKind::Semantic
                        && evidence.extractor.starts_with("rust-analyzer")
                })))
}

fn is_payload_event(event: &ProtocolEvent) -> bool {
    matches!(
        event,
        ProtocolEvent::ProfileDeclared(_)
            | ProtocolEvent::NodeUpsert(_)
            | ProtocolEvent::EdgeUpsert(_)
            | ProtocolEvent::DependencySite(_)
            | ProtocolEvent::Diagnostic(_)
            | ProtocolEvent::FileCompleted(_)
    )
}

fn validate_profile(profile: &Profile) -> Result<(), ProtocolError> {
    require_non_empty("profile.id", &profile.id)?;
    require_non_empty("profile.language", &profile.language)?;
    if let Some(toolchain) = &profile.toolchain
        && !(toolchain.is_string() || toolchain.is_object())
    {
        return invariant("profile.toolchain must be a string or object".into());
    }
    Ok(())
}

fn validate_node(node: &GraphNode) -> Result<(), ProtocolError> {
    require_non_empty("node.id", &node.id)?;
    require_non_empty("node.kind", &node.kind)?;
    require_non_empty("node.locator", &node.locator)
}

fn validate_edge(edge: &GraphEdge) -> Result<(), ProtocolError> {
    require_non_empty("edge.id", &edge.id)?;
    require_non_empty("edge.source", &edge.source)?;
    require_non_empty("edge.target", &edge.target)?;
    require_non_empty("edge.kind", &edge.kind)?;
    require_non_empty("edge.profile_id", &edge.profile_id)?;
    if let Some(site_id) = &edge.site_id {
        require_non_empty("edge.site_id", site_id)?;
    }
    validate_condition(&edge.condition)?;
    validate_dependency_evidence(
        "edge",
        &edge.evidence,
        matches!(edge.phase, Phase::Source | Phase::Semantic),
    )
}

fn validate_site(site: &DependencySite) -> Result<(), ProtocolError> {
    require_non_empty("dependency_site.id", &site.id)?;
    require_non_empty("dependency_site.source", &site.source)?;
    require_non_empty("dependency_site.kind", &site.kind)?;
    require_non_empty("dependency_site.profile_id", &site.profile_id)?;
    for target in &site.target_ids {
        require_non_empty("dependency_site.target_ids[]", target)?;
    }
    if let Some(reason) = &site.reason {
        require_non_empty("dependency_site.reason", reason)?;
    }
    validate_condition(&site.condition)?;
    validate_dependency_evidence("dependency_site", &site.evidence, true)
}

fn validate_semantic_node(node: &GraphNode) -> Result<(), ProtocolError> {
    let kind_property = match node.kind.as_str() {
        "symbol" => "symbol_kind",
        "type" => "type_kind",
        _ => return Ok(()),
    };
    let language = required_node_property(node, "language")?;
    let package_locator = required_node_property(node, "package_locator")?;
    let semantic_kind = required_node_property(node, kind_property)?;
    let identity = node.properties.get("canonical_identity").ok_or_else(|| {
        ProtocolError::Invariant(format!(
            "{} node {} must include properties.canonical_identity",
            node.kind, node.id
        ))
    })?;
    if !identity.is_object() {
        return invariant(format!(
            "{} node {} canonical_identity must be an object",
            node.kind, node.id
        ));
    }
    for (field, expected) in [
        ("language", language),
        ("package_locator", package_locator),
        (kind_property, semantic_kind),
    ] {
        let found = required_identity_string(identity, field, &node.id)?;
        if found != expected {
            return invariant(format!(
                "{} node {} property {field}={expected:?} disagrees with canonical_identity value {found:?}",
                node.kind, node.id
            ));
        }
    }

    match node.kind.as_str() {
        "symbol" => validate_symbol_identity(identity, &node.id)?,
        "type" => {
            required_identity_string(identity, "resolver_identity", &node.id)?;
        }
        _ => unreachable!("semantic node kind matched above"),
    }

    let expected_id = stable_id_from_value(&node.kind, identity);
    if node.id != expected_id {
        return invariant(format!(
            "{} node {} does not match its canonical identity; expected {}",
            node.kind, node.id, expected_id
        ));
    }
    Ok(())
}

fn required_node_property<'a>(node: &'a GraphNode, field: &str) -> Result<&'a str, ProtocolError> {
    node.properties
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ProtocolError::Invariant(format!(
                "{} node {} must include non-empty properties.{field}",
                node.kind, node.id
            ))
        })
}

fn required_identity_string<'a>(
    identity: &'a Value,
    field: &str,
    node_id: &str,
) -> Result<&'a str, ProtocolError> {
    identity
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ProtocolError::Invariant(format!(
                "semantic node {node_id} canonical_identity.{field} must be a non-empty string"
            ))
        })
}

fn validate_symbol_identity(identity: &Value, node_id: &str) -> Result<(), ProtocolError> {
    let identity_kind = required_identity_string(identity, "identity_kind", node_id)?;
    let symbol_kind = required_identity_string(identity, "symbol_kind", node_id)?;
    if let Some(expected) = reserved_symbol_identity_kind(symbol_kind)
        && identity_kind != expected
    {
        return invariant(format!(
            "symbol node {node_id} symbol_kind {symbol_kind:?} requires canonical_identity.identity_kind={expected:?}"
        ));
    }

    match identity_kind {
        "named" => {
            required_identity_string(identity, "resolver_identity", node_id)?;
            return Ok(());
        }
        "local" | "anonymous" | "generated" => {}
        other => {
            return invariant(format!(
                "symbol node {node_id} canonical_identity.identity_kind has unsupported value {other:?}"
            ));
        }
    }

    let has_origin = ["enclosing_symbol", "generated_from"].iter().any(|field| {
        identity
            .get(*field)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
    });
    if !has_origin {
        return invariant(format!(
            "{identity_kind} symbol node {node_id} canonical_identity must include enclosing_symbol or generated_from"
        ));
    }
    let relative_path = required_identity_string(identity, "relative_path", node_id)?;
    validate_canonical_relative_path("symbol canonical_identity.relative_path", relative_path)?;
    let span = identity.get("span").ok_or_else(|| {
        ProtocolError::Invariant(format!(
            "symbol node {node_id} local canonical_identity must include span"
        ))
    })?;
    validate_identity_span(span, node_id)
}

fn reserved_symbol_identity_kind(symbol_kind: &str) -> Option<&'static str> {
    if symbol_kind.starts_with("local_") || symbol_kind == "parameter" {
        Some("local")
    } else if symbol_kind.starts_with("anonymous_") || matches!(symbol_kind, "closure" | "lambda") {
        Some("anonymous")
    } else if symbol_kind.starts_with("generated_") {
        Some("generated")
    } else {
        None
    }
}

fn validate_identity_span(span: &Value, node_id: &str) -> Result<(), ProtocolError> {
    let coordinate = |field: &str| -> Result<u32, ProtocolError> {
        let value = span.get(field).and_then(Value::as_u64).ok_or_else(|| {
            ProtocolError::Invariant(format!(
                "symbol node {node_id} canonical_identity.span.{field} must be a positive integer"
            ))
        })?;
        let value = u32::try_from(value).map_err(|_| {
            ProtocolError::Invariant(format!(
                "symbol node {node_id} canonical_identity.span.{field} exceeds u32"
            ))
        })?;
        if value == 0 {
            return invariant(format!(
                "symbol node {node_id} canonical_identity.span.{field} must be at least 1"
            ));
        }
        Ok(value)
    };
    let start = (coordinate("start_line")?, coordinate("start_column")?);
    let end = (coordinate("end_line")?, coordinate("end_column")?);
    if end < start {
        return invariant(format!(
            "symbol node {node_id} canonical identity span end precedes start"
        ));
    }
    Ok(())
}

fn validate_semantic_edge(
    edge: &GraphEdge,
    linked_to_strict_site: bool,
) -> Result<(), ProtocolError> {
    if is_semantic_definition_relation(edge) {
        return validate_semantic_definition_relation(edge);
    }
    if !is_common_semantic_edge_kind(edge.kind.as_str()) && !linked_to_strict_site {
        return Ok(());
    }
    if edge.phase != Phase::Semantic {
        return invariant(format!(
            "semantic edge {} of kind {} must use phase=semantic",
            edge.id, edge.kind
        ));
    }
    let site_id = edge.site_id.as_deref().ok_or_else(|| {
        ProtocolError::Invariant(format!(
            "semantic edge {} of kind {} must reference a dependency site",
            edge.id, edge.kind
        ))
    })?;
    let primary =
        validate_primary_semantic_evidence(&format!("semantic edge {}", edge.id), &edge.evidence)?;
    validate_semantic_resolution(
        &format!("semantic edge {}", edge.id),
        edge.resolution_status,
        edge.precision,
    )?;
    match edge.kind.as_str() {
        "calls" if edge.resolution_status == ResolutionStatus::Candidates => {
            return invariant(format!(
                "direct calls edge {} cannot use candidates; emit may_call edges",
                edge.id
            ));
        }
        "may_call"
            if edge.resolution_status != ResolutionStatus::Candidates
                || edge.precision != Precision::Overapprox =>
        {
            return invariant(format!(
                "may_call edge {} must use candidates/overapprox",
                edge.id
            ));
        }
        "may_call" => {
            validate_candidate_algorithm(&format!("may_call edge {}", edge.id), primary)?;
        }
        _ => {}
    }
    let expected_id = stable_id_from_value(
        "edge",
        &json!({
            "kind": edge.kind,
            "site_id": site_id,
            "target": edge.target,
        }),
    );
    if edge.id != expected_id {
        return invariant(format!(
            "semantic edge {} does not match its canonical identity; expected {}",
            edge.id, expected_id
        ));
    }
    Ok(())
}

fn validate_semantic_definition_relation(edge: &GraphEdge) -> Result<(), ProtocolError> {
    if edge.phase != Phase::Semantic {
        return invariant(format!(
            "semantic definition relation {} of kind {} must use phase=semantic",
            edge.id, edge.kind
        ));
    }
    if edge.site_id.is_some() {
        return invariant(format!(
            "semantic definition relation {} of kind {} must remain site-less",
            edge.id, edge.kind
        ));
    }
    if edge.resolution_status != ResolutionStatus::Resolved || edge.precision != Precision::Exact {
        return invariant(format!(
            "semantic definition relation {} of kind {} must use resolved/exact",
            edge.id, edge.kind
        ));
    }
    let primary = validate_primary_semantic_evidence(
        &format!("semantic definition relation {}", edge.id),
        &edge.evidence,
    )?;
    let expected_id = stable_id_from_value(
        "edge",
        &json!({
            "condition": edge.condition.canonicalized(),
            "kind": edge.kind,
            "path": primary.path.as_deref().expect("complete semantic evidence path"),
            "profile_id": edge.profile_id,
            "source": edge.source,
            "span": {
                "end_column": primary.end_column.expect("complete semantic evidence span"),
                "end_line": primary.end_line.expect("complete semantic evidence span"),
                "start_column": primary.start_column.expect("complete semantic evidence span"),
                "start_line": primary.start_line.expect("complete semantic evidence span"),
            },
            "target": edge.target,
        }),
    );
    if edge.id != expected_id {
        return invariant(format!(
            "semantic definition relation {} does not match its canonical identity; expected {}",
            edge.id, expected_id
        ));
    }
    Ok(())
}

fn validate_semantic_site(
    site: &DependencySite,
    strict_dependency_site: bool,
) -> Result<(), ProtocolError> {
    if semantic_edge_kind_for_site(site, strict_dependency_site).is_none() {
        return Ok(());
    }
    require_non_empty("semantic dependency_site.specifier", &site.specifier)?;
    let primary = validate_primary_semantic_evidence(
        &format!("semantic dependency site {}", site.id),
        &site.evidence,
    )?;
    validate_semantic_resolution(
        &format!("semantic dependency site {}", site.id),
        site.resolution_status,
        site.precision,
    )?;
    if site.kind == "call" && site.resolution_status == ResolutionStatus::Candidates {
        validate_candidate_algorithm(&format!("candidate call site {}", site.id), primary)?;
    }
    if site.target_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return invariant(format!(
            "semantic dependency site {} target IDs must be unique and sorted",
            site.id
        ));
    }
    if site.resolution_status == ResolutionStatus::Unresolved && site.reason.is_none() {
        return invariant(format!(
            "unresolved semantic dependency site {} must include a reason",
            site.id
        ));
    }

    let path = primary
        .path
        .as_deref()
        .expect("primary semantic evidence has a complete span");
    let expected_id = stable_id_from_value(
        "site",
        &json!({
            "condition": site.condition.canonicalized(),
            "kind": site.kind,
            "path": path,
            "profile_id": site.profile_id,
            "source": site.source,
            "span": {
                "end_column": primary.end_column.expect("complete span"),
                "end_line": primary.end_line.expect("complete span"),
                "start_column": primary.start_column.expect("complete span"),
                "start_line": primary.start_line.expect("complete span"),
            }
        }),
    );
    if site.id != expected_id {
        return invariant(format!(
            "semantic dependency site {} does not match its canonical identity; expected {}",
            site.id, expected_id
        ));
    }
    Ok(())
}

fn validate_primary_semantic_evidence<'a>(
    owner: &str,
    evidence: &'a [Evidence],
) -> Result<&'a Evidence, ProtocolError> {
    let primary = evidence.first().ok_or_else(|| {
        ProtocolError::Invariant(format!("{owner} must include primary semantic evidence"))
    })?;
    if primary.kind != EvidenceKind::Semantic || !has_complete_span(primary) {
        return invariant(format!(
            "{owner} evidence[0] must be semantic evidence with a complete source span"
        ));
    }
    validate_canonical_relative_path(
        &format!("{owner} primary evidence path"),
        primary
            .path
            .as_deref()
            .expect("complete span includes path"),
    )?;

    let supporting_keys: Vec<_> = evidence[1..]
        .iter()
        .map(|item| {
            let value = serde_json::to_value(item).expect("Evidence is always serializable");
            canonical_json(&value)
        })
        .collect();
    if supporting_keys.windows(2).any(|pair| pair[0] > pair[1]) {
        return invariant(format!(
            "{owner} supporting evidence must be in canonical JSON order"
        ));
    }
    Ok(primary)
}

fn validate_primary_source_evidence<'a>(
    owner: &str,
    evidence: &'a [Evidence],
) -> Result<&'a Evidence, ProtocolError> {
    let primary = evidence.first().ok_or_else(|| {
        ProtocolError::Invariant(format!("{owner} must include primary source evidence"))
    })?;
    if primary.kind != EvidenceKind::Source || !has_complete_span(primary) {
        return invariant(format!(
            "{owner} evidence[0] must be source evidence with a complete source span"
        ));
    }
    validate_canonical_relative_path(
        &format!("{owner} primary evidence path"),
        primary
            .path
            .as_deref()
            .expect("complete span includes path"),
    )?;
    Ok(primary)
}

fn validate_candidate_algorithm(owner: &str, primary: &Evidence) -> Result<(), ProtocolError> {
    if primary
        .properties
        .get("algorithm")
        .and_then(Value::as_str)
        .is_none_or(|algorithm| algorithm.is_empty())
    {
        return invariant(format!(
            "{owner} primary evidence must include a non-empty properties.algorithm"
        ));
    }
    Ok(())
}

fn validate_semantic_resolution(
    owner: &str,
    status: ResolutionStatus,
    precision: Precision,
) -> Result<(), ProtocolError> {
    let valid = match status {
        ResolutionStatus::Resolved => precision == Precision::Exact,
        ResolutionStatus::Candidates => precision == Precision::Overapprox,
        ResolutionStatus::External => matches!(precision, Precision::Exact | Precision::Heuristic),
        ResolutionStatus::Unresolved => precision == Precision::Heuristic,
    };
    if !valid {
        return invariant(format!(
            "{owner} has invalid semantic resolution/precision combination {status:?}/{precision:?}"
        ));
    }
    Ok(())
}

fn validate_canonical_relative_path(owner: &str, path: &str) -> Result<(), ProtocolError> {
    let has_drive_prefix = path.as_bytes().get(1) == Some(&b':');
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || has_drive_prefix
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return invariant(format!(
            "{owner} must be a normalized repository-relative path, found {path:?}"
        ));
    }
    Ok(())
}

fn validate_dependency_evidence(
    owner: &str,
    evidence: &[Evidence],
    requires_source_span: bool,
) -> Result<(), ProtocolError> {
    if evidence.is_empty() {
        return invariant(format!("{owner} must include at least one evidence item"));
    }
    validate_evidence(evidence)?;
    if requires_source_span && !evidence.iter().any(has_complete_span) {
        return invariant(format!(
            "{owner} must include at least one evidence item with a complete source span"
        ));
    }
    Ok(())
}

fn has_complete_span(evidence: &Evidence) -> bool {
    evidence.path.is_some()
        && evidence.start_line.is_some()
        && evidence.start_column.is_some()
        && evidence.end_line.is_some()
        && evidence.end_column.is_some()
}

fn primary_evidence_anchor(evidence: &Evidence) -> (&str, &str, &str, u32, u32, u32, u32) {
    (
        &evidence.extractor,
        &evidence.extractor_version,
        evidence
            .path
            .as_deref()
            .expect("primary evidence has a path"),
        evidence
            .start_line
            .expect("primary evidence has a start line"),
        evidence
            .start_column
            .expect("primary evidence has a start column"),
        evidence.end_line.expect("primary evidence has an end line"),
        evidence
            .end_column
            .expect("primary evidence has an end column"),
    )
}

fn validate_diagnostic(diagnostic: &Diagnostic) -> Result<(), ProtocolError> {
    require_non_empty("diagnostic.id", &diagnostic.id)?;
    require_non_empty("diagnostic.code", &diagnostic.code)?;
    require_non_empty("diagnostic.message", &diagnostic.message)?;
    if let Some(profile_id) = &diagnostic.profile_id {
        require_non_empty("diagnostic.profile_id", profile_id)?;
    }
    validate_span(
        "diagnostic",
        diagnostic.path.as_deref(),
        diagnostic.start_line,
        diagnostic.start_column,
        diagnostic.end_line,
        diagnostic.end_column,
    )?;
    validate_evidence(&diagnostic.evidence)
}

fn validate_evidence(evidence: &[Evidence]) -> Result<(), ProtocolError> {
    for item in evidence {
        require_non_empty("evidence.extractor", &item.extractor)?;
        require_non_empty("evidence.extractor_version", &item.extractor_version)?;
        validate_span(
            "evidence",
            item.path.as_deref(),
            item.start_line,
            item.start_column,
            item.end_line,
            item.end_column,
        )?;
    }
    Ok(())
}

fn validate_span(
    owner: &str,
    path: Option<&str>,
    start_line: Option<u32>,
    start_column: Option<u32>,
    end_line: Option<u32>,
    end_column: Option<u32>,
) -> Result<(), ProtocolError> {
    if let Some(path) = path {
        require_non_empty(&format!("{owner}.path"), path)?;
    }
    let coordinates = [start_line, start_column, end_line, end_column];
    if coordinates.iter().all(Option::is_none) {
        return Ok(());
    }
    if path.is_none() || coordinates.iter().any(Option::is_none) {
        return invariant(format!(
            "{owner} span requires path and all four line/column coordinates"
        ));
    }
    let (start_line, start_column, end_line, end_column) = (
        start_line.expect("checked"),
        start_column.expect("checked"),
        end_line.expect("checked"),
        end_column.expect("checked"),
    );
    if [start_line, start_column, end_line, end_column].contains(&0) {
        return invariant(format!("{owner} span coordinates must be at least 1"));
    }
    if (end_line, end_column) < (start_line, start_column) {
        return invariant(format!(
            "{owner} span end {end_line}:{end_column} precedes start {start_line}:{start_column}"
        ));
    }
    Ok(())
}

fn validate_condition(condition: &Condition) -> Result<(), ProtocolError> {
    match condition {
        Condition::All { conditions } | Condition::Any { conditions } => {
            for child in conditions {
                validate_condition(child)?;
            }
            Ok(())
        }
        Condition::Not { condition } => validate_condition(condition),
        Condition::Eq { key, value } => {
            require_non_empty("condition.key", key)?;
            if !is_condition_primitive(value) {
                return invariant("condition eq value must be a JSON primitive".into());
            }
            Ok(())
        }
        Condition::In { key, values } => {
            require_non_empty("condition.key", key)?;
            if values.iter().any(|value| !is_condition_primitive(value)) {
                return invariant("condition in values must be JSON primitives".into());
            }
            Ok(())
        }
        Condition::Defined { key } => require_non_empty("condition.key", key),
    }
}

fn is_condition_primitive(value: &serde_json::Value) -> bool {
    value.is_null() || value.is_boolean() || value.is_number() || value.is_string()
}

fn require_non_empty(field: &str, value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() {
        return invariant(format!("{field} must not be empty"));
    }
    Ok(())
}

fn normalize_conditions(event: &mut ProtocolEvent) {
    match event {
        ProtocolEvent::EdgeUpsert(event) => {
            event.edge.condition = event.edge.condition.canonicalized();
        }
        ProtocolEvent::DependencySite(event) => {
            event.site.condition = event.site.condition.canonicalized();
        }
        _ => {}
    }
}

fn insert_upsert<T: PartialEq>(
    collection: &mut BTreeMap<String, T>,
    id: String,
    value: T,
    entity: &'static str,
) -> Result<(), ProtocolError> {
    if let Some(existing) = collection.get(&id) {
        if existing != &value {
            return Err(ProtocolError::ConflictingUpsert { entity, id });
        }
    } else {
        collection.insert(id, value);
    }
    Ok(())
}

fn check_identity(field: &'static str, expected: &str, found: &str) -> Result<(), ProtocolError> {
    if expected != found {
        return Err(ProtocolError::MetadataChanged {
            field,
            expected: expected.into(),
            found: found.into(),
        });
    }
    Ok(())
}

fn validate_coverage(coverage: &crate::Coverage) -> Result<(), ProtocolError> {
    let classified =
        coverage.resolved + coverage.candidates + coverage.external + coverage.unresolved;
    if classified != coverage.dependency_sites {
        return invariant(format!(
            "coverage dependency_sites={} but classified statuses total {}",
            coverage.dependency_sites, classified
        ));
    }
    if coverage.files_analyzed + coverage.files_skipped != coverage.files_discovered {
        return invariant(format!(
            "coverage files_discovered={} but analyzed+skipped={}",
            coverage.files_discovered,
            coverage.files_analyzed + coverage.files_skipped
        ));
    }
    let unique_completeness: BTreeSet<_> = coverage.completeness.iter().collect();
    if unique_completeness.len() != coverage.completeness.len() {
        return invariant("coverage completeness values must be unique".into());
    }
    Ok(())
}

fn validate_profile_completeness(
    profile: &Profile,
    coverage: &crate::Coverage,
) -> Result<(), ProtocolError> {
    if profile.language != "rust"
        || !coverage
            .completeness
            .contains(&CompletenessLevel::SemanticComplete)
    {
        return Ok(());
    }

    if !coverage
        .completeness
        .contains(&CompletenessLevel::SyntaxComplete)
    {
        return invariant(format!(
            "Rust semantic-complete profile {} must also report syntax-complete",
            profile.id
        ));
    }
    if coverage
        .reasons
        .iter()
        .any(|reason| reason == "rust-hir-backend-failure")
    {
        return invariant(format!(
            "Rust semantic-complete profile {} cannot report rust-hir-backend-failure",
            profile.id
        ));
    }

    for (field, actual) in [
        ("files_skipped", coverage.files_skipped),
        ("unsupported_syntax", coverage.unsupported_syntax),
        ("unresolved", coverage.unresolved),
    ] {
        if actual != 0 {
            return invariant(format!(
                "Rust semantic-complete profile {} requires {field}=0, found {actual}",
                profile.id
            ));
        }
    }
    if coverage.project_code_executed {
        return invariant(format!(
            "Rust semantic-complete profile {} requires coverage project_code_executed=false",
            profile.id
        ));
    }

    for (property, expected) in [
        ("analysis", "syntax+hir-imports-types-calls"),
        ("analysis_backend", "static-syntax+rust-analyzer-hir"),
        ("rust_hir_backend", "rust-analyzer-hir"),
        ("rust_hir_status", "import-type-call-graph-emitted"),
        ("rust_hir_project_model", "ready"),
        ("crate_graph_source", "confined-cargo-metadata"),
        ("cargo_metadata_input", "confined-mirror"),
        ("rust_toolchain_probe_status", "compatible"),
        ("rust_hir_toolchain_status", "compatible"),
        ("proc_macro_expansion", "disabled"),
        ("build_script_policy", "disabled"),
        ("proc_macro_policy", "disabled"),
    ] {
        let actual = profile.properties.get(property).and_then(Value::as_str);
        if actual != Some(expected) {
            return invariant(format!(
                "Rust semantic-complete profile {} requires properties.{property}={expected:?}, found {actual:?}",
                profile.id
            ));
        }
    }
    let release_gate = profile
        .properties
        .get("rust_hir_enable_gate")
        .and_then(Value::as_str);
    if !matches!(
        release_gate,
        Some("release-gate-pending" | "release-gate-verified")
    ) {
        return invariant(format!(
            "Rust semantic-complete profile {} requires properties.rust_hir_enable_gate to be release-gate-pending or release-gate-verified, found {release_gate:?}",
            profile.id
        ));
    }
    let semantic_issue_count = profile
        .properties
        .get("rust_hir_semantic_issue_count")
        .and_then(Value::as_u64);
    if semantic_issue_count != Some(0) {
        return invariant(format!(
            "Rust semantic-complete profile {} requires properties.rust_hir_semantic_issue_count=0, found {semantic_issue_count:?}",
            profile.id
        ));
    }
    for property in [
        "project_code_executed",
        "project_toolchain_executed",
        "build_scripts_executed",
        "proc_macros_executed",
    ] {
        let actual = profile.properties.get(property).and_then(Value::as_bool);
        if actual != Some(false) {
            return invariant(format!(
                "Rust semantic-complete profile {} requires properties.{property}=false, found {actual:?}",
                profile.id
            ));
        }
    }
    Ok(())
}

fn validate_profile_coverage(
    profile_id: &str,
    coverage: &crate::Coverage,
    sites: &BTreeMap<String, DependencySite>,
) -> Result<(), ProtocolError> {
    if coverage.profiles != 1 {
        return invariant(format!(
            "profile {profile_id} coverage must report profiles=1, found {}",
            coverage.profiles
        ));
    }
    let profile_sites: Vec<_> = sites
        .values()
        .filter(|site| site.profile_id == profile_id)
        .collect();
    validate_site_counts(
        &format!("profile {profile_id}"),
        coverage,
        profile_sites.into_iter(),
    )
}

fn validate_aggregate_profile_coverage(
    aggregate: &crate::Coverage,
    profiles: &BTreeMap<String, crate::Coverage>,
) -> Result<(), ProtocolError> {
    let Some(first) = profiles.values().next() else {
        return Ok(());
    };

    let mut expected_completeness: BTreeSet<_> = first.completeness.iter().copied().collect();
    for profile in profiles.values().skip(1) {
        expected_completeness.retain(|level| profile.completeness.contains(level));
    }
    let aggregate_completeness: BTreeSet<_> = aggregate.completeness.iter().copied().collect();
    if aggregate_completeness != expected_completeness {
        return invariant(format!(
            "scan completeness {aggregate_completeness:?} does not equal the profile intersection {expected_completeness:?}"
        ));
    }

    let maximums = [
        (
            "files_discovered",
            aggregate.files_discovered,
            profiles
                .values()
                .map(|profile| profile.files_discovered)
                .max()
                .unwrap_or_default(),
        ),
        (
            "files_analyzed",
            aggregate.files_analyzed,
            profiles
                .values()
                .map(|profile| profile.files_analyzed)
                .max()
                .unwrap_or_default(),
        ),
        (
            "files_skipped",
            aggregate.files_skipped,
            profiles
                .values()
                .map(|profile| profile.files_skipped)
                .max()
                .unwrap_or_default(),
        ),
        (
            "unsupported_syntax",
            aggregate.unsupported_syntax,
            profiles
                .values()
                .map(|profile| profile.unsupported_syntax)
                .max()
                .unwrap_or_default(),
        ),
    ];
    for (field, reported, minimum) in maximums {
        if reported < minimum {
            return invariant(format!(
                "scan coverage {field}={reported}, below the profile maximum {minimum}"
            ));
        }
    }

    if profiles
        .values()
        .any(|profile| profile.project_code_executed)
        && !aggregate.project_code_executed
    {
        return invariant(
            "scan coverage hides project code execution reported by a profile".into(),
        );
    }

    for blocking_reason in ["rust-hir-backend-failure"] {
        if profiles.values().any(|profile| {
            profile
                .reasons
                .iter()
                .any(|reason| reason == blocking_reason)
        }) && !aggregate
            .reasons
            .iter()
            .any(|reason| reason == blocking_reason)
        {
            return invariant(format!(
                "scan coverage omits blocking profile reason {blocking_reason}"
            ));
        }
    }
    Ok(())
}

fn validate_scan_coverage(
    coverage: &crate::Coverage,
    profiles: &BTreeMap<String, Profile>,
    sites: &BTreeMap<String, DependencySite>,
    events: &[ProtocolEvent],
) -> Result<(), ProtocolError> {
    if coverage.profiles != profiles.len() as u64 {
        return invariant(format!(
            "scan coverage profiles={} but {} profiles were declared",
            coverage.profiles,
            profiles.len()
        ));
    }
    validate_site_counts("scan", coverage, sites.values())?;

    let files: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            ProtocolEvent::FileCompleted(completed) => Some(completed),
            _ => None,
        })
        .collect();
    let files_skipped = files.iter().filter(|file| file.skipped).count() as u64;
    let emitted_sites: u64 = files.iter().map(|file| file.emitted_sites).sum();
    if coverage.files_discovered != files.len() as u64 {
        return invariant(format!(
            "scan coverage files_discovered={} but {} file_completed events were emitted",
            coverage.files_discovered,
            files.len()
        ));
    }
    if coverage.files_skipped != files_skipped {
        return invariant(format!(
            "scan coverage files_skipped={} but {} file_completed events are skipped",
            coverage.files_skipped, files_skipped
        ));
    }
    // Some adapters emit package/manifest sites whose coverage is accounted at
    // profile scope rather than by a source-file completion event.
    if emitted_sites > coverage.dependency_sites {
        return invariant(format!(
            "file coverage emitted_sites total {} exceeds scan coverage's {} dependency sites",
            emitted_sites, coverage.dependency_sites
        ));
    }
    Ok(())
}

fn validate_site_counts<'a>(
    scope: &str,
    coverage: &crate::Coverage,
    sites: impl Iterator<Item = &'a DependencySite>,
) -> Result<(), ProtocolError> {
    let mut total = 0_u64;
    let mut resolved = 0_u64;
    let mut candidates = 0_u64;
    let mut external = 0_u64;
    let mut unresolved = 0_u64;
    for site in sites {
        total += 1;
        match site.resolution_status {
            ResolutionStatus::Resolved => resolved += 1,
            ResolutionStatus::Candidates => candidates += 1,
            ResolutionStatus::External => external += 1,
            ResolutionStatus::Unresolved => unresolved += 1,
        }
    }
    let actual = (total, resolved, candidates, external, unresolved);
    let reported = (
        coverage.dependency_sites,
        coverage.resolved,
        coverage.candidates,
        coverage.external,
        coverage.unresolved,
    );
    if actual != reported {
        return invariant(format!(
            "{scope} coverage site counts {:?} do not match emitted counts {:?}",
            reported, actual
        ));
    }
    Ok(())
}

fn invariant<T>(message: String) -> Result<T, ProtocolError> {
    Err(ProtocolError::Invariant(message))
}
