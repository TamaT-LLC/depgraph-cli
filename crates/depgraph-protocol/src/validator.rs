use crate::{
    Condition, DependencySite, Diagnostic, Evidence, GraphEdge, GraphNode, PROTOCOL_VERSION, Phase,
    Profile, ProtocolEvent, ResolutionStatus,
};
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
                validate_coverage(&completed.coverage)?;
                validate_profile_coverage(&completed.profile_id, &completed.coverage, &self.sites)?;
                if self.safe_mode && completed.coverage.project_code_executed {
                    return Err(ProtocolError::Invariant(format!(
                        "safe-mode profile {} reports project_code_executed=true",
                        completed.profile_id
                    )));
                }
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
                if self.safe_mode && completed.coverage.project_code_executed {
                    return Err(ProtocolError::Invariant(
                        "safe-mode coverage reports project_code_executed=true".into(),
                    ));
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
