use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::Read,
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use depgraph_protocol::stable_id_from_value;
use depgraph_store::{
    CoverageRecord, DiagnosticRecord, EdgeRecord, EvidenceRecord, GraphSnapshot, NodeRecord,
    ProfileRecord, RuntimeSessionDelta, RuntimeSessionRecord, SiteRecord,
    canonical_effective_input_id,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const RUNTIME_TRACE_SCHEMA_VERSION: &str = "1.0";
pub const RUNTIME_COLLECTOR_CONTRACT_VERSION: &str = "runtime-collector-v1";
pub const RUNTIME_TRACE_MAX_BYTES: usize = 16 * 1024 * 1024;
pub const RUNTIME_TRACE_MAX_EVENTS: usize = 100_000;
pub const RUNTIME_COLLECTOR_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/depgraph-runtime-collector-v1.schema.json"
));
pub const RUNTIME_TRACE_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/depgraph-runtime-trace-v1.schema.json"
));

const MAX_STRING_CHARS: usize = 4_096;
const MAX_ID_CHARS: usize = 512;
const MAX_NAMES: usize = 256;
const MAX_FEATURES: usize = 256;
const MAX_JSON_DEPTH: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTrace {
    pub schema_version: String,
    pub repository: RuntimeTraceRepository,
    pub session: RuntimeTraceSession,
    pub events: Vec<RuntimeTraceEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTraceRepository {
    pub identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTraceSession {
    pub id: String,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector_contract_version: Option<String>,
    pub profile: RuntimeTraceProfile,
    pub environment: RuntimeTraceEnvironment,
    #[serde(default)]
    pub redaction: RuntimeTraceRedaction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTraceProfile {
    pub language: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_profile_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTraceEnvironment {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Environment variable names observed by the collector. Values are never
    /// part of the contract and are rejected as unknown/secret-bearing input.
    #[serde(default)]
    pub environment_keys: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTraceRedaction {
    #[serde(default)]
    pub environment_keys: Vec<String>,
    #[serde(default)]
    pub header_names: Vec<String>,
    #[serde(default)]
    pub secret_names: Vec<String>,
    #[serde(default)]
    pub redacted_value_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTraceEvent {
    pub sequence: u64,
    pub timestamp: String,
    pub dependency_kind: String,
    pub source: RuntimeTraceLocator,
    pub target: RuntimeTraceLocator,
    #[serde(default = "default_event_count")]
    pub count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ns: Option<u64>,
    #[serde(default)]
    pub redaction: RuntimeTraceRedaction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeTraceLocator {
    Node {
        node_id: String,
    },
    GraphLocator {
        locator: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        node_kind: Option<String>,
    },
    RepositoryPath {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        node_kind: Option<String>,
    },
    External {
        namespace: String,
        name: String,
    },
    Unresolved {
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTraceMatchStatus {
    Resolved,
    External,
    Unresolved,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchedRuntimeTraceLocator {
    pub status: RuntimeTraceMatchStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub input: RuntimeTraceLocator,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeTraceProfileMatch {
    pub status: RuntimeTraceMatchStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatedRuntimeTraceEvent {
    pub id: String,
    pub sequence: u64,
    pub timestamp: String,
    pub dependency_kind: String,
    pub source: MatchedRuntimeTraceLocator,
    pub target: MatchedRuntimeTraceLocator,
    pub count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ns: Option<u64>,
    pub redaction: RuntimeTraceRedaction,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeTraceSummary {
    pub events: u64,
    pub resolved_targets: u64,
    pub external_targets: u64,
    pub unresolved_targets: u64,
    pub redacted_values: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatedRuntimeTrace {
    pub schema_version: String,
    pub repository: RuntimeTraceRepository,
    pub session: RuntimeTraceSession,
    pub profile_match: RuntimeTraceProfileMatch,
    pub events: Vec<ValidatedRuntimeTraceEvent>,
    pub summary: RuntimeTraceSummary,
}

fn default_event_count() -> u64 {
    1
}

/// Reads and validates an untrusted collector document without accessing the
/// repository or mutating the evidence store.
pub fn read_runtime_trace(mut reader: impl Read) -> Result<RuntimeTrace> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take((RUNTIME_TRACE_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("failed to read runtime trace")?;
    if bytes.len() > RUNTIME_TRACE_MAX_BYTES {
        bail!("runtime trace exceeds its byte limit");
    }
    let source = std::str::from_utf8(&bytes).context("runtime trace must be valid UTF-8")?;
    let value: Value =
        serde_json::from_str(source).context("runtime trace must be a valid JSON document")?;
    validate_untrusted_json(&value, 0)?;
    let mut trace: RuntimeTrace = serde_json::from_value(value)
        .map_err(|_| anyhow::anyhow!("runtime trace does not match the versioned contract"))?;
    trace.validate()?;
    Ok(trace)
}

/// Applies repository/profile/node matching to an already bounded runtime
/// document. Missing targets remain explicit external/unresolved observations;
/// this function never creates a graph node or changes the store.
pub fn validate_runtime_trace(
    reader: impl Read,
    snapshot: &GraphSnapshot,
) -> Result<ValidatedRuntimeTrace> {
    let trace = read_runtime_trace(reader)?;
    match_runtime_trace(trace, snapshot)
}

pub fn match_runtime_trace(
    trace: RuntimeTrace,
    snapshot: &GraphSnapshot,
) -> Result<ValidatedRuntimeTrace> {
    validate_repository(&trace.repository, snapshot)?;
    let profile_match = match_profile(&trace.session.profile, &snapshot.profiles);
    let node_index = RuntimeTraceNodeIndex::new(&snapshot.nodes);
    let mut events = Vec::with_capacity(trace.events.len());
    let mut summary = RuntimeTraceSummary {
        events: trace.events.len() as u64,
        redacted_values: trace.session.redaction.redacted_value_count.saturating_add(
            trace
                .events
                .iter()
                .map(|event| event.redaction.redacted_value_count)
                .fold(0_u64, u64::saturating_add),
        ),
        ..RuntimeTraceSummary::default()
    };

    for event in &trace.events {
        let source = match_locator(&event.source, &node_index);
        let target = match_locator(&event.target, &node_index);
        match target.status {
            RuntimeTraceMatchStatus::Resolved => summary.resolved_targets += 1,
            RuntimeTraceMatchStatus::External => summary.external_targets += 1,
            RuntimeTraceMatchStatus::Unresolved => summary.unresolved_targets += 1,
        }
        let id = stable_id_from_value(
            "runtime-event",
            &json!({
                "schema_version": RUNTIME_TRACE_SCHEMA_VERSION,
                "repository_identity": trace.repository.identity,
                "repository_revision": trace.repository.revision,
                "session_id": trace.session.id,
                "sequence": event.sequence,
                "timestamp": event.timestamp,
                "profile": trace.session.profile,
                "environment": trace.session.environment,
                "dependency_kind": event.dependency_kind,
                "source": event.source,
                "target": event.target,
                "count": event.count,
                "duration_ns": event.duration_ns,
            }),
        );
        events.push(ValidatedRuntimeTraceEvent {
            id,
            sequence: event.sequence,
            timestamp: event.timestamp.clone(),
            dependency_kind: event.dependency_kind.clone(),
            source,
            target,
            count: event.count,
            duration_ns: event.duration_ns,
            redaction: event.redaction.clone(),
        });
    }

    Ok(ValidatedRuntimeTrace {
        schema_version: RUNTIME_TRACE_SCHEMA_VERSION.to_owned(),
        repository: trace.repository,
        session: trace.session,
        profile_match,
        events,
        summary,
    })
}

/// Converts a validated collector document into an immutable runtime graph
/// delta. Stable graph identities deliberately exclude the collector session
/// ID, so repeated observations share nodes/sites/edges while their evidence
/// rows remain independently queryable.
pub fn runtime_session_delta(
    validated: ValidatedRuntimeTrace,
    base_snapshot_id: &str,
    snapshot: &GraphSnapshot,
) -> Result<RuntimeSessionDelta> {
    let trace_digest = stable_id_from_value("runtime-trace", &serde_json::to_value(&validated)?);
    let session_id = stable_id_from_value(
        "runtime-session",
        &json!({
            "source_session_id": validated.session.id,
            "trace_digest": trace_digest,
        }),
    );
    let parent = validated
        .profile_match
        .parent_profile_id
        .as_deref()
        .and_then(|id| snapshot.profiles.iter().find(|profile| profile.id == id));
    let effective_input_id = parent.map(canonical_effective_input_id).unwrap_or_else(|| {
        stable_id_from_value(
            "runtime-input",
            &json!({
                "profile": validated.session.profile,
                "environment": validated.session.environment,
            }),
        )
    });
    let runtime_profile_id = stable_id_from_value(
        "profile",
        &json!({
            "profile_phase": "runtime",
            "parent_profile_id": validated.profile_match.parent_profile_id,
            "effective_input_id": effective_input_id,
            "profile": validated.session.profile,
            "environment": validated.session.environment,
        }),
    );
    let profile_status = match validated.profile_match.status {
        RuntimeTraceMatchStatus::Resolved => "resolved",
        RuntimeTraceMatchStatus::External => "external",
        RuntimeTraceMatchStatus::Unresolved => "unresolved",
    }
    .to_owned();
    let profile = ProfileRecord {
        id: runtime_profile_id.clone(),
        language: validated.session.profile.language.clone(),
        toolchain: validated
            .session
            .environment
            .runtime
            .as_ref()
            .map(|runtime| json!({"runtime":runtime})),
        command: None,
        target: validated.session.profile.target.clone(),
        features: validated.session.profile.features.clone(),
        environment: serde_json::to_value(&validated.session.environment)?,
        source_revision: validated.repository.revision.clone(),
        properties: json!({
            "profile_phase":"runtime",
            "parent_profile_id":validated.profile_match.parent_profile_id,
            "effective_input_id":effective_input_id,
            "profile_status":profile_status,
            "profile_reason":validated.profile_match.reason,
        }),
        // Session-specific coverage lives on RuntimeSessionRecord. Keeping the
        // profile content stable lets independent sessions deduplicate.
        coverage: None,
    };

    let mut nodes = BTreeMap::<String, NodeRecord>::new();
    let mut grouped = BTreeMap::<RuntimeEdgeKey, RuntimeObservation>::new();
    let mut resolution_sets = BTreeMap::<(String, String), BTreeSet<String>>::new();
    let mut diagnostics = Vec::new();
    let diagnostic_context = RuntimeDiagnosticContext {
        session_id: &session_id,
        source_session_id: &validated.session.id,
        profile_id: &runtime_profile_id,
        environment: &validated.session.environment,
    };
    for event in &validated.events {
        let source = runtime_node_id(&event.source, &mut nodes)?;
        let target = runtime_node_id(&event.target, &mut nodes)?;
        append_locator_diagnostic(
            &mut diagnostics,
            &diagnostic_context,
            event,
            "source",
            &event.source,
        );
        append_locator_diagnostic(
            &mut diagnostics,
            &diagnostic_context,
            event,
            "target",
            &event.target,
        );
        let resolution_status = combined_resolution_status(&event.source, &event.target);
        resolution_sets
            .entry((source.clone(), event.dependency_kind.clone()))
            .or_default()
            .insert(resolution_status.to_owned());
        let key = RuntimeEdgeKey {
            source,
            target,
            dependency_kind: event.dependency_kind.clone(),
            resolution_status: resolution_status.to_owned(),
        };
        grouped.entry(key).or_default().observe(event);
    }
    let mut has_evidence_conflict = false;
    for ((source, dependency_kind), statuses) in resolution_sets {
        if statuses.len() > 1 && statuses.contains("resolved") {
            has_evidence_conflict = true;
            diagnostics.push(runtime_diagnostic(
                &session_id,
                "RUNTIME_EVIDENCE_CONFLICT",
                format!(
                    "runtime observations disagree on resolution for {dependency_kind} from {source}"
                ),
                None,
                json!({
                    "session_id":session_id,
                    "source_session_id":validated.session.id,
                    "phase":"runtime",
                    "profile_id":runtime_profile_id,
                    "environment":validated.session.environment,
                    "source":source,
                    "dependency_kind":dependency_kind,
                    "resolution_statuses":statuses,
                }),
            ));
        }
    }
    if validated.profile_match.status != RuntimeTraceMatchStatus::Resolved {
        diagnostics.push(runtime_diagnostic(
            &session_id,
            "RUNTIME_PROFILE_UNMATCHED",
            format!(
                "runtime profile could not be matched: {}",
                validated
                    .profile_match
                    .reason
                    .as_deref()
                    .unwrap_or("unknown")
            ),
            None,
            json!({
                "session_id":session_id,
                "source_session_id":validated.session.id,
                "phase":"runtime",
                "profile_id":runtime_profile_id,
                "environment":validated.session.environment,
                "reason":validated.profile_match.reason,
            }),
        ));
    }

    let environment = serde_json::to_value(&validated.session.environment)?;
    let mut sites = Vec::with_capacity(grouped.len());
    let mut edges = Vec::with_capacity(grouped.len());
    let mut evidence = Vec::with_capacity(grouped.len() * 2);
    for (key, observation) in grouped {
        let identity = json!({
            "profile_id":runtime_profile_id,
            "source":key.source,
            "target":key.target,
            "kind":key.dependency_kind,
            "environment":validated.session.environment,
        });
        let site_id = stable_id_from_value(
            "site",
            &json!({
                "phase":"runtime",
                "identity":identity,
            }),
        );
        let edge_id = stable_id_from_value(
            "edge",
            &json!({
                "phase":"runtime",
                "identity":identity,
            }),
        );
        let reason = observation.reasons.iter().next().cloned();
        let specifier = snapshot
            .nodes
            .iter()
            .find(|node| node.id == key.target)
            .or_else(|| nodes.get(&key.target))
            .map(|node| node.locator.clone())
            .with_context(|| format!("runtime target node {} was not materialized", key.target))?;
        let site = SiteRecord {
            id: site_id.clone(),
            source: key.source.clone(),
            kind: key.dependency_kind.clone(),
            specifier: Some(specifier),
            profile_id: runtime_profile_id.clone(),
            resolution_status: key.resolution_status.clone(),
            precision: "observed".to_owned(),
            condition: json!({"op":"true"}),
            target_ids: vec![key.target.clone()],
            reason,
        };
        let edge = EdgeRecord {
            id: edge_id.clone(),
            site_id: Some(site_id.clone()),
            source: key.source,
            target: key.target,
            kind: key.dependency_kind,
            phase: "runtime".to_owned(),
            environment: validated.session.environment.name.clone(),
            profile_id: runtime_profile_id.clone(),
            resolution_status: key.resolution_status,
            precision: "observed".to_owned(),
            condition: json!({"op":"true"}),
            generated: false,
        };
        let properties =
            observation.evidence_properties(&session_id, &validated.session.id, &environment);
        evidence.push(runtime_evidence("site", &site_id, properties.clone()));
        evidence.push(runtime_evidence("edge", &edge_id, properties));
        sites.push(site);
        edges.push(edge);
    }

    diagnostics.sort_by(|left, right| left.id.cmp(&right.id));
    diagnostics.dedup_by(|left, right| left.id == right.id);
    for (ordinal, diagnostic) in diagnostics.iter_mut().enumerate() {
        diagnostic.ordinal = ordinal as i64;
    }
    let partial = validated.profile_match.status != RuntimeTraceMatchStatus::Resolved
        || has_evidence_conflict
        || validated.events.iter().any(|event| {
            event.source.status != RuntimeTraceMatchStatus::Resolved
                || event.target.status == RuntimeTraceMatchStatus::Unresolved
        });
    let mut reasons = diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.to_ascii_lowercase())
        .collect::<Vec<_>>();
    reasons.sort();
    reasons.dedup();
    let coverage = CoverageRecord {
        profiles: 1,
        dependency_sites: sites.len() as u64,
        resolved: sites
            .iter()
            .filter(|site| site.resolution_status == "resolved")
            .count() as u64,
        external: sites
            .iter()
            .filter(|site| site.resolution_status == "external")
            .count() as u64,
        unresolved: sites
            .iter()
            .filter(|site| site.resolution_status == "unresolved")
            .count() as u64,
        project_code_executed: true,
        completeness: if partial {
            Vec::new()
        } else {
            vec!["runtime-observed".to_owned()]
        },
        reasons,
        ..CoverageRecord::default()
    };
    let first_observed_at = validated
        .events
        .iter()
        .map(|event| event.timestamp.as_str())
        .min()
        .context("validated runtime trace has no event")?
        .to_owned();
    let last_observed_at = validated
        .events
        .iter()
        .map(|event| event.timestamp.as_str())
        .max()
        .context("validated runtime trace has no event")?
        .to_owned();
    let observation_count = validated
        .events
        .iter()
        .map(|event| event.count)
        .fold(0_u64, u64::saturating_add);
    let created_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let session = RuntimeSessionRecord {
        id: session_id,
        base_snapshot_id: base_snapshot_id.to_owned(),
        source_session_id: validated.session.id,
        schema_version: validated.schema_version,
        status: if partial { "partial" } else { "completed" }.to_owned(),
        trace_digest,
        profile_id: runtime_profile_id,
        parent_profile_id: validated.profile_match.parent_profile_id,
        profile_status,
        profile_reason: validated.profile_match.reason,
        profile,
        environment,
        redaction: serde_json::to_value(&validated.session.redaction)?,
        started_at: validated.session.started_at,
        ended_at: validated.session.ended_at,
        first_observed_at,
        last_observed_at,
        event_count: validated.summary.events,
        observation_count,
        resolved_targets: validated.summary.resolved_targets,
        external_targets: validated.summary.external_targets,
        unresolved_targets: validated.summary.unresolved_targets,
        redacted_values: validated.summary.redacted_values,
        coverage,
        created_at,
    };
    Ok(RuntimeSessionDelta {
        session,
        nodes: nodes.into_values().collect(),
        sites,
        edges,
        evidence,
        diagnostics,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RuntimeEdgeKey {
    source: String,
    target: String,
    dependency_kind: String,
    resolution_status: String,
}

#[derive(Debug, Clone, Default)]
struct RuntimeObservation {
    event_ids: BTreeSet<String>,
    sequences: BTreeSet<u64>,
    source_labels: BTreeSet<String>,
    target_labels: BTreeSet<String>,
    reasons: BTreeSet<String>,
    count: u64,
    duration_ns: u64,
    redacted_values: u64,
    first_observed_at: Option<String>,
    last_observed_at: Option<String>,
}

impl RuntimeObservation {
    fn observe(&mut self, event: &ValidatedRuntimeTraceEvent) {
        self.event_ids.insert(event.id.clone());
        self.sequences.insert(event.sequence);
        self.source_labels
            .insert(locator_label(&event.source.input));
        self.target_labels
            .insert(locator_label(&event.target.input));
        if let Some(reason) = event
            .target
            .reason
            .as_ref()
            .or(event.source.reason.as_ref())
        {
            self.reasons.insert(reason.clone());
        }
        self.count = self.count.saturating_add(event.count);
        self.duration_ns = self
            .duration_ns
            .saturating_add(event.duration_ns.unwrap_or(0));
        self.redacted_values = self
            .redacted_values
            .saturating_add(event.redaction.redacted_value_count);
        update_timestamp_min(&mut self.first_observed_at, &event.timestamp);
        update_timestamp_max(&mut self.last_observed_at, &event.timestamp);
    }

    fn evidence_properties(
        self,
        session_id: &str,
        source_session_id: &str,
        environment: &Value,
    ) -> Value {
        json!({
            "session_id":session_id,
            "source_session_id":source_session_id,
            "environment":environment,
            "event_ids":self.event_ids,
            "sequences":self.sequences,
            "source_locators":self.source_labels,
            "target_locators":self.target_labels,
            "count":self.count,
            "duration_ns":self.duration_ns,
            "first_observed_at":self.first_observed_at,
            "last_observed_at":self.last_observed_at,
            "redacted_value_count":self.redacted_values,
            "reasons":self.reasons,
        })
    }
}

fn runtime_node_id(
    matched: &MatchedRuntimeTraceLocator,
    nodes: &mut BTreeMap<String, NodeRecord>,
) -> Result<String> {
    if let Some(node_id) = &matched.node_id {
        return Ok(node_id.clone());
    }
    let id = stable_id_from_value(
        "runtime-node",
        &json!({
            "status":matched.status,
            "reason":matched.reason,
            "input":matched.input,
        }),
    );
    let status = match matched.status {
        RuntimeTraceMatchStatus::Resolved => "resolved",
        RuntimeTraceMatchStatus::External => "external",
        RuntimeTraceMatchStatus::Unresolved => "unresolved",
    };
    let node = NodeRecord {
        id: id.clone(),
        kind: "runtime_sentinel".to_owned(),
        locator: format!(
            "runtime://{status}/{}",
            id.rsplit(':').next().unwrap_or("unknown")
        ),
        display_name: locator_label(&matched.input),
        properties: json!({
            "runtime_only":true,
            "match_status":status,
            "reason":matched.reason,
            "input":matched.input,
        }),
    };
    if let Some(existing) = nodes.get(&id) {
        if existing != &node {
            bail!("runtime sentinel identity collision for {id}");
        }
    } else {
        nodes.insert(id.clone(), node);
    }
    Ok(id)
}

fn combined_resolution_status(
    source: &MatchedRuntimeTraceLocator,
    target: &MatchedRuntimeTraceLocator,
) -> &'static str {
    if source.status == RuntimeTraceMatchStatus::Unresolved
        || target.status == RuntimeTraceMatchStatus::Unresolved
    {
        "unresolved"
    } else if source.status == RuntimeTraceMatchStatus::External
        || target.status == RuntimeTraceMatchStatus::External
    {
        "external"
    } else {
        "resolved"
    }
}

fn locator_label(locator: &RuntimeTraceLocator) -> String {
    match locator {
        RuntimeTraceLocator::Node { node_id } => node_id.clone(),
        RuntimeTraceLocator::GraphLocator { locator, .. } => locator.clone(),
        RuntimeTraceLocator::RepositoryPath { path, .. } => path.clone(),
        RuntimeTraceLocator::External { namespace, name } => format!("{namespace}:{name}"),
        RuntimeTraceLocator::Unresolved { reason } => format!("unresolved:{reason}"),
    }
}

struct RuntimeDiagnosticContext<'a> {
    session_id: &'a str,
    source_session_id: &'a str,
    profile_id: &'a str,
    environment: &'a RuntimeTraceEnvironment,
}

fn append_locator_diagnostic(
    diagnostics: &mut Vec<DiagnosticRecord>,
    context: &RuntimeDiagnosticContext<'_>,
    event: &ValidatedRuntimeTraceEvent,
    role: &str,
    locator: &MatchedRuntimeTraceLocator,
) {
    if locator.status == RuntimeTraceMatchStatus::Resolved {
        return;
    }
    let code = if role == "target" {
        "RUNTIME_TARGET_UNMATCHED"
    } else {
        "RUNTIME_SOURCE_UNMATCHED"
    };
    diagnostics.push(runtime_diagnostic(
        context.session_id,
        code,
        format!(
            "runtime {role} was retained as a {} sentinel: {}",
            match locator.status {
                RuntimeTraceMatchStatus::Resolved => "resolved",
                RuntimeTraceMatchStatus::External => "external",
                RuntimeTraceMatchStatus::Unresolved => "unresolved",
            },
            locator
                .reason
                .as_deref()
                .unwrap_or("collector_classification")
        ),
        Some(event.id.as_str()),
        json!({
            "session_id":context.session_id,
            "source_session_id":context.source_session_id,
            "phase":"runtime",
            "profile_id":context.profile_id,
            "environment":context.environment,
            "event_id":event.id,
            "sequence":event.sequence,
            "role":role,
            "status":locator.status,
            "reason":locator.reason,
            "input":locator.input,
        }),
    ));
}

fn runtime_diagnostic(
    session_id: &str,
    code: &str,
    message: String,
    event_id: Option<&str>,
    properties: Value,
) -> DiagnosticRecord {
    DiagnosticRecord {
        ordinal: 0,
        id: stable_id_from_value(
            "diagnostic",
            &json!({
                "session_id":session_id,
                "code":code,
                "event_id":event_id,
                "properties":properties,
            }),
        ),
        severity: "warning".to_owned(),
        code: code.to_owned(),
        message,
        path: None,
        adapter: Some("runtime-trace".to_owned()),
        start_line: None,
        start_column: None,
        end_line: None,
        end_column: None,
        properties,
    }
}

fn runtime_evidence(owner_type: &str, owner_id: &str, properties: Value) -> EvidenceRecord {
    EvidenceRecord {
        owner_type: owner_type.to_owned(),
        owner_id: owner_id.to_owned(),
        ordinal: 0,
        kind: "runtime".to_owned(),
        extractor: "runtime-trace".to_owned(),
        extractor_version: RUNTIME_TRACE_SCHEMA_VERSION.to_owned(),
        path: String::new(),
        start_line: 1,
        start_column: 1,
        end_line: 1,
        end_column: 1,
        detail: Some("runtime observation".to_owned()),
        properties,
    }
}

fn update_timestamp_min(current: &mut Option<String>, value: &str) {
    if current.as_deref().is_none_or(|current| value < current) {
        *current = Some(value.to_owned());
    }
}

fn update_timestamp_max(current: &mut Option<String>, value: &str) {
    if current.as_deref().is_none_or(|current| value > current) {
        *current = Some(value.to_owned());
    }
}

impl RuntimeTrace {
    fn validate(&mut self) -> Result<()> {
        if self.schema_version != RUNTIME_TRACE_SCHEMA_VERSION {
            bail!(
                "unsupported runtime trace schema_version; expected {RUNTIME_TRACE_SCHEMA_VERSION}"
            );
        }
        validate_bounded_string(
            &self.repository.identity,
            "repository.identity",
            MAX_ID_CHARS,
        )?;
        if let Some(revision) = &self.repository.revision {
            validate_bounded_string(revision, "repository.revision", MAX_ID_CHARS)?;
        }
        validate_bounded_string(&self.session.id, "session.id", MAX_ID_CHARS)?;
        let production_collector = match self.session.collector_contract_version.as_deref() {
            None => false,
            Some(RUNTIME_COLLECTOR_CONTRACT_VERSION) => true,
            Some(_) => bail!("unsupported runtime collector contract version"),
        };
        validate_identifier(&self.session.profile.language, "session.profile.language")?;
        if let Some(target) = &self.session.profile.target {
            validate_bounded_string(target, "session.profile.target", MAX_ID_CHARS)?;
        }
        if let Some(parent) = &self.session.profile.parent_profile_id {
            validate_bounded_string(parent, "session.profile.parent_profile_id", MAX_ID_CHARS)?;
        }
        normalize_names(
            &mut self.session.profile.features,
            "session.profile.features",
            MAX_FEATURES,
        )?;
        validate_bounded_string(
            &self.session.environment.name,
            "session.environment.name",
            MAX_ID_CHARS,
        )?;
        if let Some(runtime) = &self.session.environment.runtime {
            validate_bounded_string(runtime, "session.environment.runtime", MAX_ID_CHARS)?;
        }
        if let Some(region) = &self.session.environment.region {
            validate_bounded_string(region, "session.environment.region", MAX_ID_CHARS)?;
        }
        normalize_names(
            &mut self.session.environment.environment_keys,
            "session.environment.environment_keys",
            MAX_NAMES,
        )?;
        self.session.redaction.normalize("session.redaction")?;
        if production_collector {
            validate_collector_names(
                &self.session.environment.environment_keys,
                "session.environment.environment_keys",
            )?;
            self.session
                .redaction
                .validate_collector_names("session.redaction")?;
        }

        let started_at = normalize_timestamp(&mut self.session.started_at, "session.started_at")?;
        let ended_at = self
            .session
            .ended_at
            .as_mut()
            .map(|value| normalize_timestamp(value, "session.ended_at"))
            .transpose()?;
        if ended_at.is_some_and(|ended_at| ended_at < started_at) {
            bail!("runtime trace session.ended_at precedes session.started_at");
        }
        if self.events.is_empty() {
            bail!("runtime trace must contain at least one event");
        }
        if self.events.len() > RUNTIME_TRACE_MAX_EVENTS {
            bail!("runtime trace exceeds its event limit");
        }
        let mut previous_sequence = None;
        for event in &mut self.events {
            if event.sequence == 0
                || previous_sequence.is_some_and(|previous| event.sequence <= previous)
            {
                bail!("runtime trace event sequences must be positive and strictly increasing");
            }
            previous_sequence = Some(event.sequence);
            let timestamp = normalize_timestamp(&mut event.timestamp, "events[].timestamp")?;
            if timestamp < started_at || ended_at.is_some_and(|ended_at| timestamp > ended_at) {
                bail!("runtime trace event timestamp is outside its session bounds");
            }
            validate_identifier(&event.dependency_kind, "events[].dependency_kind")?;
            validate_locator(&event.source, "events[].source", production_collector)?;
            validate_locator(&event.target, "events[].target", production_collector)?;
            if event.count == 0 {
                bail!("runtime trace events[].count must be greater than zero");
            }
            event.redaction.normalize("events[].redaction")?;
            if production_collector {
                event
                    .redaction
                    .validate_collector_names("events[].redaction")?;
            }
        }
        Ok(())
    }
}

impl RuntimeTraceRedaction {
    fn normalize(&mut self, field: &str) -> Result<()> {
        normalize_names(
            &mut self.environment_keys,
            &format!("{field}.environment_keys"),
            MAX_NAMES,
        )?;
        normalize_names(
            &mut self.header_names,
            &format!("{field}.header_names"),
            MAX_NAMES,
        )?;
        normalize_names(
            &mut self.secret_names,
            &format!("{field}.secret_names"),
            MAX_NAMES,
        )
    }

    fn validate_collector_names(&self, field: &str) -> Result<()> {
        validate_collector_names(&self.environment_keys, &format!("{field}.environment_keys"))?;
        validate_collector_names(&self.header_names, &format!("{field}.header_names"))?;
        validate_collector_names(&self.secret_names, &format!("{field}.secret_names"))
    }
}

fn normalize_timestamp(value: &mut String, field: &str) -> Result<DateTime<Utc>> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("runtime trace {field} must be an RFC 3339 timestamp"))?
        .with_timezone(&Utc);
    *value = parsed.to_rfc3339_opts(SecondsFormat::AutoSi, true);
    Ok(parsed)
}

fn validate_locator(
    locator: &RuntimeTraceLocator,
    field: &str,
    production_collector: bool,
) -> Result<()> {
    match locator {
        RuntimeTraceLocator::Node { node_id } => {
            validate_bounded_string(node_id, &format!("{field}.node_id"), MAX_ID_CHARS)
        }
        RuntimeTraceLocator::GraphLocator { locator, node_kind } => {
            validate_graph_locator(locator, &format!("{field}.locator"))?;
            if production_collector && looks_like_http_url(locator) {
                bail!("runtime trace {field}.locator must not contain a raw URL");
            }
            if let Some(node_kind) = node_kind {
                validate_identifier(node_kind, &format!("{field}.node_kind"))?;
            }
            Ok(())
        }
        RuntimeTraceLocator::RepositoryPath { path, node_kind } => {
            validate_repository_path(path, &format!("{field}.path"))?;
            if let Some(node_kind) = node_kind {
                validate_identifier(node_kind, &format!("{field}.node_kind"))?;
            }
            Ok(())
        }
        RuntimeTraceLocator::External { namespace, name } => {
            validate_identifier(namespace, &format!("{field}.namespace"))?;
            validate_bounded_string(name, &format!("{field}.name"), MAX_STRING_CHARS)?;
            if production_collector {
                validate_external_name(namespace, name, &format!("{field}.name"))?;
            }
            Ok(())
        }
        RuntimeTraceLocator::Unresolved { reason } => {
            validate_identifier(reason, &format!("{field}.reason"))
        }
    }
}

fn validate_graph_locator(locator: &str, field: &str) -> Result<()> {
    validate_bounded_string(locator, field, MAX_STRING_CHARS)?;
    if locator.contains('\\') || locator.chars().any(char::is_whitespace) {
        bail!("runtime trace {field} is not a portable graph locator");
    }
    if strip_ascii_case_prefix(locator, "file:").is_some() && !locator.starts_with("file:") {
        bail!("runtime trace {field} uses a non-canonical file URI scheme");
    }
    if let Some(path) = strip_ascii_case_prefix(locator, "file://") {
        if path
            .split('/')
            .next()
            .is_some_and(|segment| segment.eq_ignore_ascii_case("localhost"))
        {
            bail!("runtime trace {field} must not contain a file URI host");
        }
        validate_repository_path(path, field)?;
    } else if let Some(path) = strip_ascii_case_prefix(locator, "file:") {
        validate_repository_path(path, field)?;
    }
    Ok(())
}

fn validate_external_name(namespace: &str, name: &str, field: &str) -> Result<()> {
    if looks_like_raw_url(name) {
        bail!("runtime trace {field} must contain only a redacted HTTP authority");
    }
    if matches_ignore_ascii_case(namespace, "http", "https") {
        validate_http_authority(name, field)?;
    }
    Ok(())
}

fn validate_collector_names(names: &[String], field: &str) -> Result<()> {
    if names.iter().any(|name| {
        looks_like_raw_url(name)
            || name
                .chars()
                .any(|character| matches!(character, '@' | '?' | '#' | '%' | '='))
    }) {
        bail!("runtime trace {field} must contain redacted names only");
    }
    Ok(())
}

fn looks_like_raw_url(value: &str) -> bool {
    let Some((scheme, _)) = value.split_once("://") else {
        return false;
    };
    !scheme.is_empty()
        && scheme.chars().enumerate().all(|(index, character)| {
            if index == 0 {
                character.is_ascii_alphabetic()
            } else {
                character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
            }
        })
}

fn validate_http_authority(authority: &str, field: &str) -> Result<()> {
    let invalid =
        || anyhow::anyhow!("runtime trace {field} must contain a redacted HTTP authority");
    if !authority.is_ascii() || authority != authority.to_ascii_lowercase() {
        return Err(invalid());
    }

    let (host, port) = if let Some(ipv6) = authority.strip_prefix('[') {
        let close = ipv6.find(']').ok_or_else(&invalid)?;
        let (address, suffix) = ipv6.split_at(close);
        if address.is_empty()
            || !address.contains(':')
            || !address
                .chars()
                .all(|character| character.is_ascii_hexdigit() || matches!(character, ':' | '.'))
        {
            return Err(invalid());
        }
        let suffix = &suffix[1..];
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':').ok_or_else(&invalid)?)
        };
        (address, port)
    } else {
        let mut parts = authority.split(':');
        let host = parts.next().ok_or_else(&invalid)?;
        let port = parts.next();
        if parts.next().is_some()
            || host.is_empty()
            || host.split('.').any(|label| {
                label.is_empty()
                    || !label.chars().all(|character| {
                        character.is_ascii_lowercase()
                            || character.is_ascii_digit()
                            || character == '-'
                    })
                    || !label
                        .chars()
                        .next()
                        .is_some_and(|character| character.is_ascii_alphanumeric())
                    || !label
                        .chars()
                        .next_back()
                        .is_some_and(|character| character.is_ascii_alphanumeric())
            })
        {
            return Err(invalid());
        }
        (host, port)
    };
    if host.is_empty()
        || port.is_some_and(|port| {
            port.is_empty()
                || !port.chars().all(|character| character.is_ascii_digit())
                || (port.len() > 1 && port.starts_with('0'))
                || port.parse::<u16>().is_err()
        })
    {
        return Err(invalid());
    }
    Ok(())
}

fn looks_like_http_url(value: &str) -> bool {
    strip_ascii_case_prefix(value, "http://").is_some()
        || strip_ascii_case_prefix(value, "https://").is_some()
}

fn matches_ignore_ascii_case(value: &str, first: &str, second: &str) -> bool {
    value.eq_ignore_ascii_case(first) || value.eq_ignore_ascii_case(second)
}

fn strip_ascii_case_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|candidate| candidate.eq_ignore_ascii_case(prefix))
        .map(|_| &value[prefix.len()..])
}

fn validate_repository_path(path: &str, field: &str) -> Result<()> {
    validate_bounded_string(path, field, MAX_STRING_CHARS)?;
    if path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains(':')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        bail!("runtime trace {field} must be a canonical repository-relative path");
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &str) -> Result<()> {
    validate_bounded_string(value, field, MAX_ID_CHARS)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
    }) {
        bail!("runtime trace {field} contains unsupported characters");
    }
    Ok(())
}

fn validate_bounded_string(value: &str, field: &str, max: usize) -> Result<()> {
    if value.is_empty() || value.chars().count() > max {
        bail!("runtime trace {field} must be a non-empty bounded string");
    }
    if value.chars().any(char::is_control) {
        bail!("runtime trace {field} contains control characters");
    }
    if looks_like_absolute_path(value) {
        bail!("runtime trace {field} contains an absolute path");
    }
    if looks_like_secret(value) {
        bail!("runtime trace {field} contains a secret-like value");
    }
    Ok(())
}

fn normalize_names(values: &mut Vec<String>, field: &str, max_items: usize) -> Result<()> {
    if values.len() > max_items {
        bail!("runtime trace {field} exceeds its item limit");
    }
    for value in values.iter() {
        validate_bounded_string(value, field, MAX_ID_CHARS)?;
    }
    values.sort();
    values.dedup();
    Ok(())
}

fn validate_untrusted_json(value: &Value, depth: usize) -> Result<()> {
    if depth > MAX_JSON_DEPTH {
        bail!("runtime trace exceeds its nesting limit");
    }
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if is_forbidden_sensitive_field(key) {
                    bail!("runtime trace contains a forbidden secret-bearing field");
                }
                validate_untrusted_json(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_untrusted_json(value, depth + 1)?;
            }
        }
        Value::String(value) => {
            if value.chars().count() > MAX_STRING_CHARS {
                bail!("runtime trace contains a string exceeding its length limit");
            }
            if looks_like_absolute_path(value) {
                bail!("runtime trace contains an absolute path");
            }
            if looks_like_secret(value) {
                bail!("runtime trace contains a secret-like value");
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn is_forbidden_sensitive_field(key: &str) -> bool {
    if matches!(
        key,
        "environment_keys" | "header_names" | "secret_names" | "redaction" | "redacted_value_count"
    ) {
        return false;
    }
    let normalized = key.to_ascii_lowercase().replace('-', "_");
    [
        "authorization",
        "cookie",
        "set_cookie",
        "token",
        "secret",
        "password",
        "passwd",
        "api_key",
        "private_key",
        "environment_values",
        "header_values",
        "headers",
        "env",
    ]
    .iter()
    .any(|part| normalized == *part || normalized.ends_with(&format!("_{part}")))
}

fn looks_like_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("bearer ")
        || lower.starts_with("basic ")
        || lower.starts_with("ghp_")
        || lower.starts_with("github_pat_")
        || lower.starts_with("sk-")
        || lower.starts_with("xoxb-")
        || lower.starts_with("xoxp-")
        || lower.starts_with("xoxa-")
        || lower.starts_with("xoxr-")
        || value.starts_with("AKIA")
        || value.starts_with("AIza")
        || (value.starts_with("eyJ") && value.matches('.').count() == 2)
        || (lower.contains("-----begin ") && lower.contains("private key-----"))
        || ["token=", "secret=", "password=", "api_key=", "apikey="]
            .iter()
            .any(|marker| lower.contains(marker))
}

fn looks_like_absolute_path(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    value.starts_with('/')
        || value.starts_with("\\\\")
        || is_windows_drive_path(value)
        || lowercase.starts_with("file:///")
        || lowercase == "file://localhost"
        || lowercase.starts_with("file://localhost/")
        || (lowercase.starts_with("file:/") && !lowercase.starts_with("file://"))
}

fn is_windows_drive_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn validate_repository(
    repository: &RuntimeTraceRepository,
    snapshot: &GraphSnapshot,
) -> Result<()> {
    let identities = snapshot
        .nodes
        .iter()
        .filter(|node| node.kind == "workspace")
        .flat_map(|node| {
            [
                Some(node.id.as_str()),
                Some(node.locator.as_str()),
                node.properties
                    .get("repository_identity")
                    .and_then(Value::as_str),
            ]
            .into_iter()
            .flatten()
        })
        .collect::<BTreeSet<_>>();
    if !identities.contains(repository.identity.as_str()) {
        bail!("runtime trace repository identity does not match the selected snapshot");
    }
    if let (Some(expected), Some(observed)) = (
        snapshot.scan.source_revision.as_deref(),
        repository.revision.as_deref(),
    ) && expected != observed
    {
        bail!("runtime trace repository revision does not match the selected snapshot");
    }
    Ok(())
}

fn match_profile(
    requested: &RuntimeTraceProfile,
    profiles: &[ProfileRecord],
) -> RuntimeTraceProfileMatch {
    let mut matches = if let Some(parent) = requested.parent_profile_id.as_deref() {
        profiles
            .iter()
            .filter(|profile| {
                profile
                    .properties
                    .get("profile_phase")
                    .and_then(Value::as_str)
                    != Some("runtime")
            })
            .filter(|profile| profile.id == parent)
            .filter(|profile| profile_matches_requested_axes(profile, requested))
            .collect::<Vec<_>>()
    } else {
        profiles
            .iter()
            .filter(|profile| {
                profile
                    .properties
                    .get("profile_phase")
                    .and_then(Value::as_str)
                    != Some("runtime")
            })
            .filter(|profile| profile_matches_requested_axes(profile, requested))
            .collect::<Vec<_>>()
    };
    matches.sort_by(|left, right| left.id.cmp(&right.id));
    match matches.as_slice() {
        [profile] => RuntimeTraceProfileMatch {
            status: RuntimeTraceMatchStatus::Resolved,
            parent_profile_id: Some(profile.id.clone()),
            reason: None,
        },
        [] => RuntimeTraceProfileMatch {
            status: RuntimeTraceMatchStatus::Unresolved,
            parent_profile_id: None,
            reason: Some("profile_not_found".to_owned()),
        },
        _ => RuntimeTraceProfileMatch {
            status: RuntimeTraceMatchStatus::Unresolved,
            parent_profile_id: None,
            reason: Some("profile_ambiguous".to_owned()),
        },
    }
}

fn profile_matches_requested_axes(
    profile: &ProfileRecord,
    requested: &RuntimeTraceProfile,
) -> bool {
    profile.language == requested.language
        && requested
            .target
            .as_deref()
            .is_none_or(|target| profile.target.as_deref() == Some(target))
        && (requested.features.is_empty()
            || profile.features.iter().collect::<BTreeSet<_>>()
                == requested.features.iter().collect::<BTreeSet<_>>())
}

struct RuntimeTraceNodeIndex<'a> {
    by_id: HashMap<&'a str, Vec<&'a NodeRecord>>,
    by_locator: HashMap<&'a str, Vec<&'a NodeRecord>>,
    by_repository_path: HashMap<&'a str, Vec<&'a NodeRecord>>,
}

impl<'a> RuntimeTraceNodeIndex<'a> {
    fn new(nodes: &'a [NodeRecord]) -> Self {
        let mut index = Self {
            by_id: HashMap::with_capacity(nodes.len()),
            by_locator: HashMap::with_capacity(nodes.len()),
            by_repository_path: HashMap::with_capacity(nodes.len()),
        };
        for node in nodes {
            push_indexed_node(&mut index.by_id, &node.id, node);
            push_indexed_node(&mut index.by_locator, &node.locator, node);
            if let Some(path) = node.properties.get("path").and_then(Value::as_str) {
                push_indexed_node(&mut index.by_repository_path, path, node);
            }
            if let Some(path) = node
                .locator
                .strip_prefix("file://")
                .or_else(|| node.locator.strip_prefix("file:"))
            {
                push_indexed_node(&mut index.by_repository_path, path, node);
            }
        }
        index
    }
}

fn push_indexed_node<'a>(
    index: &mut HashMap<&'a str, Vec<&'a NodeRecord>>,
    key: &'a str,
    node: &'a NodeRecord,
) {
    let matches = index.entry(key).or_default();
    if !matches.iter().any(|existing| existing.id == node.id) {
        matches.push(node);
    }
}

fn match_locator(
    locator: &RuntimeTraceLocator,
    index: &RuntimeTraceNodeIndex<'_>,
) -> MatchedRuntimeTraceLocator {
    let (matches, node_kind) = match locator {
        RuntimeTraceLocator::Node { node_id } => (index.by_id.get(node_id.as_str()), None),
        RuntimeTraceLocator::GraphLocator { locator, node_kind } => {
            (index.by_locator.get(locator.as_str()), node_kind.as_deref())
        }
        RuntimeTraceLocator::RepositoryPath { path, node_kind } => (
            index.by_repository_path.get(path.as_str()),
            node_kind.as_deref(),
        ),
        RuntimeTraceLocator::External { .. } => {
            return MatchedRuntimeTraceLocator {
                status: RuntimeTraceMatchStatus::External,
                node_id: None,
                reason: Some("collector_classified_external".to_owned()),
                input: locator.clone(),
            };
        }
        RuntimeTraceLocator::Unresolved { reason } => {
            return MatchedRuntimeTraceLocator {
                status: RuntimeTraceMatchStatus::Unresolved,
                node_id: None,
                reason: Some(reason.clone()),
                input: locator.clone(),
            };
        }
    };

    let mut matches = matches
        .into_iter()
        .flat_map(|matches| matches.iter().copied())
        .filter(|node| node_kind.is_none_or(|node_kind| node.kind == node_kind));
    let first = matches.next();
    let ambiguous = matches.next().is_some();
    match (first, ambiguous) {
        (Some(node), false) => MatchedRuntimeTraceLocator {
            status: RuntimeTraceMatchStatus::Resolved,
            node_id: Some(node.id.clone()),
            reason: None,
            input: locator.clone(),
        },
        (None, _) => MatchedRuntimeTraceLocator {
            status: RuntimeTraceMatchStatus::Unresolved,
            node_id: None,
            reason: Some("node_not_found".to_owned()),
            input: locator.clone(),
        },
        (Some(_), true) => MatchedRuntimeTraceLocator {
            status: RuntimeTraceMatchStatus::Unresolved,
            node_id: None,
            reason: Some("node_ambiguous".to_owned()),
            input: locator.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use depgraph_store::{CoverageRecord, ProfileMatrixRecord, ScanRecord};
    use std::io::Cursor;

    const GOLDEN: &str = include_str!("../tests/fixtures/runtime-trace-v1.golden.json");
    const MALFORMED: &str = include_str!("../tests/fixtures/runtime-trace-v1.malformed.json");
    const SECRET: &str = include_str!("../tests/fixtures/runtime-trace-v1.secret.json");
    const COLLECTOR_CONTRACT: &str =
        include_str!("../tests/fixtures/runtime-collector-v1.contract.json");
    const COLLECTOR_SECRET_OUTPUT: &str =
        include_str!("../tests/fixtures/runtime-collector-v1.secret-output.json");

    fn snapshot() -> GraphSnapshot {
        GraphSnapshot {
            scan: ScanRecord {
                id: "scan-runtime".to_owned(),
                root: "/fixture".to_owned(),
                status: "completed".to_owned(),
                strict: false,
                started_at: "2026-07-23T00:00:00Z".to_owned(),
                completed_at: Some("2026-07-23T00:00:01Z".to_owned()),
                project_code_executed: false,
                error: None,
                parent_snapshot_id: None,
                source_revision: Some("abc123".to_owned()),
            },
            profiles: vec![ProfileRecord {
                id: "profile:web".to_owned(),
                language: "typescript".to_owned(),
                toolchain: None,
                command: Some("scan".to_owned()),
                target: Some("server".to_owned()),
                features: vec!["next".to_owned()],
                environment: json!({"mode":"production"}),
                source_revision: Some("abc123".to_owned()),
                properties: json!({}),
                coverage: None,
            }],
            nodes: vec![
                NodeRecord {
                    id: "workspace:web".to_owned(),
                    kind: "workspace".to_owned(),
                    locator: "workspace://repository:test".to_owned(),
                    display_name: "fixture".to_owned(),
                    properties: json!({"repository_identity":"repository:test"}),
                },
                NodeRecord {
                    id: "file:server".to_owned(),
                    kind: "file".to_owned(),
                    locator: "file://src/server.ts".to_owned(),
                    display_name: "server.ts".to_owned(),
                    properties: json!({"path":"src/server.ts"}),
                },
                NodeRecord {
                    id: "route:users".to_owned(),
                    kind: "route".to_owned(),
                    locator: "framework-route:/api/users".to_owned(),
                    display_name: "/api/users".to_owned(),
                    properties: json!({}),
                },
            ],
            sites: Vec::new(),
            edges: Vec::new(),
            evidence: Vec::new(),
            diagnostics: Vec::new(),
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: CoverageRecord::default(),
            profile_matrix: ProfileMatrixRecord::default(),
        }
    }

    #[test]
    fn golden_trace_matches_nodes_redacts_values_and_has_stable_ids() -> Result<()> {
        let first = validate_runtime_trace(Cursor::new(GOLDEN), &snapshot())?;
        let second = validate_runtime_trace(Cursor::new(GOLDEN), &snapshot())?;
        assert_eq!(first, second);
        assert_eq!(
            first.profile_match.parent_profile_id.as_deref(),
            Some("profile:web")
        );
        assert_eq!(first.summary.events, 3);
        assert_eq!(first.summary.resolved_targets, 1);
        assert_eq!(first.summary.external_targets, 1);
        assert_eq!(first.summary.unresolved_targets, 1);
        assert_eq!(first.summary.redacted_values, 5);
        assert_eq!(
            first.events[0].source.node_id.as_deref(),
            Some("file:server")
        );
        assert_eq!(
            first.events[0].target.node_id.as_deref(),
            Some("route:users")
        );
        assert!(first.events[1].target.node_id.is_none());
        assert!(first.events[2].target.node_id.is_none());
        assert!(
            first
                .events
                .iter()
                .all(|event| event.id.starts_with("runtime-event:sha256:"))
        );
        let serialized = serde_json::to_string(&first)?;
        assert!(!serialized.contains("fixture-secret-value"));
        assert!(!serialized.contains("/fixture"));
        Ok(())
    }

    #[test]
    fn runtime_diagnostics_keep_all_query_dimensions() -> Result<()> {
        let snapshot = snapshot();
        let validated = validate_runtime_trace(Cursor::new(GOLDEN), &snapshot)?;
        let delta = runtime_session_delta(validated, "snapshot:base", &snapshot)?;
        assert!(!delta.diagnostics.is_empty());
        for diagnostic in &delta.diagnostics {
            assert_eq!(
                diagnostic.properties["source_session_id"],
                json!("session-001")
            );
            assert_eq!(diagnostic.properties["phase"], json!("runtime"));
            assert_eq!(
                diagnostic.properties["profile_id"],
                json!(delta.session.profile_id)
            );
            assert_eq!(
                diagnostic.properties["environment"]["name"],
                json!("production")
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_coverage_is_graph_unique_and_evidence_redaction_is_event_scoped() -> Result<()> {
        let snapshot = snapshot();
        let validated = validate_runtime_trace(Cursor::new(GOLDEN), &snapshot)?;
        let delta = runtime_session_delta(validated, "snapshot:base", &snapshot)?;
        assert_eq!(
            delta.session.coverage.dependency_sites,
            delta.sites.len() as u64
        );
        assert_eq!(delta.session.coverage.resolved, 1);
        assert_eq!(delta.session.coverage.external, 1);
        assert_eq!(delta.session.coverage.unresolved, 1);
        assert_eq!(delta.session.redacted_values, 5);
        assert_eq!(delta.session.redaction["redacted_value_count"], json!(3));
        let edge_redactions = delta
            .evidence
            .iter()
            .filter(|evidence| evidence.owner_type == "edge")
            .filter_map(|evidence| evidence.properties["redacted_value_count"].as_u64())
            .sum::<u64>();
        assert_eq!(edge_redactions, 2);
        Ok(())
    }

    #[test]
    fn conflicting_resolution_statuses_make_the_session_partial() -> Result<()> {
        let snapshot = snapshot();
        let mut value: Value = serde_json::from_str(GOLDEN)?;
        let shared_source = value["events"][0]["source"].clone();
        let events = value["events"].as_array_mut().context("events")?;
        events.truncate(2);
        events[1]["source"] = shared_source;
        events[1]["dependency_kind"] = json!("calls");
        let validated =
            validate_runtime_trace(Cursor::new(serde_json::to_vec(&value)?), &snapshot)?;
        let delta = runtime_session_delta(validated, "snapshot:base", &snapshot)?;
        assert!(
            delta
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "RUNTIME_EVIDENCE_CONFLICT")
        );
        assert_eq!(delta.session.status, "partial");
        assert!(delta.session.coverage.completeness.is_empty());
        assert!(
            delta
                .session
                .coverage
                .reasons
                .contains(&"runtime_evidence_conflict".to_owned())
        );
        Ok(())
    }

    #[test]
    fn event_identity_includes_every_environment_axis() -> Result<()> {
        let baseline = validate_runtime_trace(Cursor::new(GOLDEN), &snapshot())?;
        let mut value: Value = serde_json::from_str(GOLDEN)?;
        value["session"]["environment"]["runtime"] = json!("nodejs-25");
        value["session"]["environment"]["region"] = json!("test-region-2");
        let changed =
            validate_runtime_trace(Cursor::new(serde_json::to_vec(&value)?), &snapshot())?;
        assert_ne!(baseline.events[0].id, changed.events[0].id);
        Ok(())
    }

    #[test]
    fn golden_trace_is_accepted_by_json_schema() -> Result<()> {
        let value: Value = serde_json::from_str(GOLDEN)?;
        let schema: Value = serde_json::from_str(RUNTIME_TRACE_SCHEMA)?;
        let validator = jsonschema::validator_for(&schema)?;
        validator
            .validate(&value)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        assert!(!validator.is_valid(&serde_json::from_str(MALFORMED)?));
        assert!(!validator.is_valid(&serde_json::from_str(SECRET)?));

        let mut oversized_id = value.clone();
        oversized_id["repository"]["identity"] = json!("x".repeat(MAX_ID_CHARS + 1));
        assert!(!validator.is_valid(&oversized_id));
        assert!(
            read_runtime_trace(Cursor::new(serde_json::to_vec(&oversized_id)?))
                .unwrap_err()
                .to_string()
                .contains("bounded string")
        );

        let mut unicode_boundary = value;
        unicode_boundary["repository"]["identity"] = json!("é".repeat(MAX_ID_CHARS));
        assert!(validator.is_valid(&unicode_boundary));
        read_runtime_trace(Cursor::new(serde_json::to_vec(&unicode_boundary)?))?;
        Ok(())
    }

    #[test]
    fn production_collector_contract_is_fixed_by_json_schema() -> Result<()> {
        let contract: Value = serde_json::from_str(COLLECTOR_CONTRACT)?;
        assert_eq!(
            contract["contract_version"],
            json!(RUNTIME_COLLECTOR_CONTRACT_VERSION)
        );
        let schema: Value = serde_json::from_str(RUNTIME_COLLECTOR_SCHEMA)?;
        let validator = jsonschema::validator_for(&schema)?;
        validator
            .validate(&contract)
            .map_err(|error| anyhow::anyhow!("{error}"))?;

        for transport in ["file", "stdout", "otlp"] {
            let mut candidate = contract.clone();
            candidate["transport"]["kind"] = json!(transport);
            assert!(validator.is_valid(&candidate));
        }

        let mut unknown_version = contract.clone();
        unknown_version["contract_version"] = json!("runtime-collector-v2");
        assert!(!validator.is_valid(&unknown_version));

        let mut unsafe_transport = contract.clone();
        unsafe_transport["transport"]["authorization"] = json!("fixture-secret-value");
        assert!(!validator.is_valid(&unsafe_transport));
        let mut unsafe_name = contract.clone();
        unsafe_name["redaction"]["header_names"] = json!(["https://user@example.test/private"]);
        assert!(!validator.is_valid(&unsafe_name));

        let mut output: Value = serde_json::from_str(GOLDEN)?;
        output["session"]["collector_contract_version"] = json!(RUNTIME_COLLECTOR_CONTRACT_VERSION);
        let trace_schema: Value = serde_json::from_str(RUNTIME_TRACE_SCHEMA)?;
        let trace_validator = jsonschema::validator_for(&trace_schema)?;
        assert!(trace_validator.is_valid(&output));
        read_runtime_trace(Cursor::new(serde_json::to_vec(&output)?))?;

        output["session"]["collector_contract_version"] = json!("runtime-collector-v2");
        assert!(!trace_validator.is_valid(&output));
        assert!(
            read_runtime_trace(Cursor::new(serde_json::to_vec(&output)?))
                .unwrap_err()
                .to_string()
                .contains("collector contract version")
        );
        Ok(())
    }

    #[test]
    fn malformed_and_secret_fixtures_are_rejected_without_echoing_values() {
        let malformed = read_runtime_trace(Cursor::new(MALFORMED)).unwrap_err();
        assert!(malformed.to_string().contains("repository-relative path"));

        let secret = read_runtime_trace(Cursor::new(SECRET)).unwrap_err();
        let message = format!("{secret:#}");
        assert!(message.contains("secret"));
        assert!(!message.contains("fixture-secret-value"));

        let collector_output =
            read_runtime_trace(Cursor::new(COLLECTOR_SECRET_OUTPUT)).unwrap_err();
        let message = format!("{collector_output:#}");
        assert!(message.contains("HTTP authority"));
        assert!(!message.contains("fixture-secret-value"));

        let collector_output: Value = serde_json::from_str(COLLECTOR_SECRET_OUTPUT).unwrap();
        let schema: Value = serde_json::from_str(RUNTIME_TRACE_SCHEMA).unwrap();
        assert!(
            !jsonschema::validator_for(&schema)
                .unwrap()
                .is_valid(&collector_output)
        );
    }

    #[test]
    fn typed_shape_errors_never_echo_raw_values() -> Result<()> {
        let mut value: Value = serde_json::from_str(GOLDEN)?;
        value["events"][0]["count"] = json!("opaque-runtime-value");
        let error = read_runtime_trace(Cursor::new(serde_json::to_vec(&value)?)).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("versioned contract"));
        assert!(!message.contains("opaque-runtime-value"));
        Ok(())
    }

    #[test]
    fn input_limits_encoding_and_versions_fail_closed() -> Result<()> {
        let oversized = vec![b' '; RUNTIME_TRACE_MAX_BYTES + 1];
        assert!(
            read_runtime_trace(Cursor::new(oversized))
                .unwrap_err()
                .to_string()
                .contains("byte limit")
        );
        assert!(
            read_runtime_trace(Cursor::new([0xff]))
                .unwrap_err()
                .to_string()
                .contains("UTF-8")
        );
        let mut value: Value = serde_json::from_str(GOLDEN)?;
        value["schema_version"] = json!("2.0");
        assert!(
            read_runtime_trace(Cursor::new(serde_json::to_vec(&value)?))
                .unwrap_err()
                .to_string()
                .contains("unsupported runtime trace schema_version")
        );
        Ok(())
    }

    #[test]
    fn production_http_targets_match_the_redacted_authority_contract() -> Result<()> {
        let schema: Value = serde_json::from_str(RUNTIME_TRACE_SCHEMA)?;
        let validator = jsonschema::validator_for(&schema)?;
        let mut legacy: Value = serde_json::from_str(GOLDEN)?;
        legacy["events"][1]["target"]["name"] =
            json!("https://user@example.test/private?customer=42");
        read_runtime_trace(Cursor::new(serde_json::to_vec(&legacy)?))?;
        assert!(validator.is_valid(&legacy));

        for authority in [
            "api.example.test",
            "localhost:3000",
            "[::1]:443",
            "[:::]",
            "[0:0:0:0:0:0:0:1]:443",
        ] {
            let mut value: Value = serde_json::from_str(GOLDEN)?;
            value["session"]["collector_contract_version"] =
                json!(RUNTIME_COLLECTOR_CONTRACT_VERSION);
            value["events"][1]["target"]["name"] = json!(authority);
            read_runtime_trace(Cursor::new(serde_json::to_vec(&value)?))?;
            assert!(validator.is_valid(&value));
        }

        for unsafe_authority in [
            "HTTPS://api.example.test/private",
            "user@api.example.test",
            "api.example.test/private",
            "api.example.test?customer=42",
            "API.EXAMPLE.TEST",
            "api.example.test:secret",
            "api.example.test:0080",
            "api.example.test:00080",
            "api.example.test:65536",
            "api..example.test",
        ] {
            let mut value: Value = serde_json::from_str(GOLDEN)?;
            value["session"]["collector_contract_version"] =
                json!(RUNTIME_COLLECTOR_CONTRACT_VERSION);
            value["events"][1]["target"]["name"] = json!(unsafe_authority);
            let error = read_runtime_trace(Cursor::new(serde_json::to_vec(&value)?)).unwrap_err();
            assert!(error.to_string().contains("HTTP authority"));
            assert!(!validator.is_valid(&value));
        }

        let mut raw_url_locator: Value = serde_json::from_str(GOLDEN)?;
        raw_url_locator["session"]["collector_contract_version"] =
            json!(RUNTIME_COLLECTOR_CONTRACT_VERSION);
        raw_url_locator["events"][0]["target"] = json!({
            "kind": "graph_locator",
            "locator": "https://api.example.test/private",
            "node_kind": "route"
        });
        assert!(
            read_runtime_trace(Cursor::new(serde_json::to_vec(&raw_url_locator)?))
                .unwrap_err()
                .to_string()
                .contains("raw URL")
        );
        assert!(!validator.is_valid(&raw_url_locator));

        let mut raw_url_external: Value = serde_json::from_str(GOLDEN)?;
        raw_url_external["session"]["collector_contract_version"] =
            json!(RUNTIME_COLLECTOR_CONTRACT_VERSION);
        raw_url_external["events"][1]["target"] = json!({
            "kind": "external",
            "namespace": "url",
            "name": "https://api.example.test/private"
        });
        assert!(
            read_runtime_trace(Cursor::new(serde_json::to_vec(&raw_url_external)?))
                .unwrap_err()
                .to_string()
                .contains("HTTP authority")
        );
        assert!(!validator.is_valid(&raw_url_external));

        let mut non_http_url_external = raw_url_external.clone();
        non_http_url_external["events"][1]["target"]["name"] =
            json!("ftp://user@example.test/private");
        assert!(
            read_runtime_trace(Cursor::new(serde_json::to_vec(&non_http_url_external)?))
                .unwrap_err()
                .to_string()
                .contains("HTTP authority")
        );
        assert!(!validator.is_valid(&non_http_url_external));

        let mut leaked_name: Value = serde_json::from_str(GOLDEN)?;
        leaked_name["session"]["collector_contract_version"] =
            json!(RUNTIME_COLLECTOR_CONTRACT_VERSION);
        leaked_name["session"]["redaction"]["header_names"] =
            json!(["https://user:fixture-secret-value@example.test/private"]);
        let error = read_runtime_trace(Cursor::new(serde_json::to_vec(&leaked_name)?)).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("redacted names only"));
        assert!(!message.contains("fixture-secret-value"));
        assert!(!validator.is_valid(&leaked_name));
        Ok(())
    }

    #[test]
    fn v1_optional_fields_remain_backward_compatible_but_unknown_fields_do_not() -> Result<()> {
        let mut value: Value = serde_json::from_str(GOLDEN)?;
        value["repository"]
            .as_object_mut()
            .expect("repository object")
            .remove("revision");
        value["session"]
            .as_object_mut()
            .expect("session object")
            .remove("ended_at");
        value["session"]
            .as_object_mut()
            .expect("session object")
            .remove("redaction");
        for event in value["events"].as_array_mut().expect("events") {
            event.as_object_mut().expect("event").remove("duration_ns");
            event.as_object_mut().expect("event").remove("redaction");
        }
        let trace = read_runtime_trace(Cursor::new(serde_json::to_vec(&value)?))?;
        assert_eq!(trace.schema_version, "1.0");

        value["session"]["profile"]["collector_internal_state"] = json!("not allowed");
        assert!(
            read_runtime_trace(Cursor::new(serde_json::to_vec(&value)?))
                .unwrap_err()
                .to_string()
                .contains("versioned contract")
        );
        Ok(())
    }

    #[test]
    fn repository_mismatch_and_absolute_locator_never_reach_matching() -> Result<()> {
        let mut wrong_repository: RuntimeTrace = serde_json::from_str(GOLDEN)?;
        wrong_repository.validate()?;
        wrong_repository.repository.identity = "workspace://other".to_owned();
        assert!(
            match_runtime_trace(wrong_repository, &snapshot())
                .unwrap_err()
                .to_string()
                .contains("repository identity")
        );

        let mut value: Value = serde_json::from_str(GOLDEN)?;
        value["events"][0]["source"]["path"] = json!("/fixture/src/server.ts");
        let error = read_runtime_trace(Cursor::new(serde_json::to_vec(&value)?)).unwrap_err();
        assert!(error.to_string().contains("absolute path"));
        assert!(!format!("{error:#}").contains("/fixture"));

        value = serde_json::from_str(GOLDEN)?;
        value["events"][0]["target"] = json!({
            "kind":"graph_locator",
            "locator":"file://../outside.ts",
            "node_kind":"file"
        });
        assert!(
            read_runtime_trace(Cursor::new(serde_json::to_vec(&value)?))
                .unwrap_err()
                .to_string()
                .contains("repository-relative path")
        );

        for unsafe_path in [
            "C:/outside.ts",
            "C:outside.ts",
            "src/C:/outside.ts",
            "a//b.ts",
            "a/",
        ] {
            value = serde_json::from_str(GOLDEN)?;
            value["events"][0]["source"]["path"] = json!(unsafe_path);
            assert!(
                read_runtime_trace(Cursor::new(serde_json::to_vec(&value)?))
                    .unwrap_err()
                    .to_string()
                    .contains("path")
            );
            let schema: Value = serde_json::from_str(RUNTIME_TRACE_SCHEMA)?;
            assert!(
                !jsonschema::validator_for(&schema)?.is_valid(&value),
                "schema accepted unsafe repository path"
            );
        }

        for unsafe_locator in ["FILE://../outside.ts", "File://C:/outside.ts"] {
            value = serde_json::from_str(GOLDEN)?;
            value["events"][0]["target"] = json!({
                "kind":"graph_locator",
                "locator":unsafe_locator,
                "node_kind":"file"
            });
            assert!(
                read_runtime_trace(Cursor::new(serde_json::to_vec(&value)?))
                    .unwrap_err()
                    .to_string()
                    .contains("file URI scheme")
            );
            let schema: Value = serde_json::from_str(RUNTIME_TRACE_SCHEMA)?;
            assert!(
                !jsonschema::validator_for(&schema)?.is_valid(&value),
                "schema accepted a non-canonical file URI scheme"
            );
        }

        for unsafe_locator in ["framework route:/api/users", "framework\\route:/api/users"] {
            value = serde_json::from_str(GOLDEN)?;
            value["events"][0]["target"] = json!({
                "kind":"graph_locator",
                "locator":unsafe_locator,
                "node_kind":"route"
            });
            assert!(
                read_runtime_trace(Cursor::new(serde_json::to_vec(&value)?))
                    .unwrap_err()
                    .to_string()
                    .contains("portable graph locator")
            );
            let schema: Value = serde_json::from_str(RUNTIME_TRACE_SCHEMA)?;
            assert!(
                !jsonschema::validator_for(&schema)?.is_valid(&value),
                "schema accepted whitespace or backslash in a graph locator"
            );
        }

        for unsafe_locator in [
            "file://localhost/C:/Windows",
            "file://localhost/etc/passwd",
            "file://src/C:/Windows",
        ] {
            value = serde_json::from_str(GOLDEN)?;
            value["events"][0]["target"] = json!({
                "kind":"graph_locator",
                "locator":unsafe_locator,
                "node_kind":"file"
            });
            assert!(read_runtime_trace(Cursor::new(serde_json::to_vec(&value)?)).is_err());
            let schema: Value = serde_json::from_str(RUNTIME_TRACE_SCHEMA)?;
            assert!(
                !jsonschema::validator_for(&schema)?.is_valid(&value),
                "schema accepted a file host or embedded drive path"
            );
        }
        Ok(())
    }

    #[test]
    fn node_index_deduplicates_equivalent_path_keys() {
        let snapshot = snapshot();
        let index = RuntimeTraceNodeIndex::new(&snapshot.nodes);
        assert_eq!(index.by_repository_path["src/server.ts"].len(), 1);
    }

    #[test]
    fn explicit_parent_profile_must_match_all_declared_axes() -> Result<()> {
        let mut value: Value = serde_json::from_str(GOLDEN)?;
        value["session"]["profile"]["language"] = json!("rust");
        let validated =
            validate_runtime_trace(Cursor::new(serde_json::to_vec(&value)?), &snapshot())?;
        assert_eq!(
            validated.profile_match.status,
            RuntimeTraceMatchStatus::Unresolved
        );
        assert_eq!(
            validated.profile_match.reason.as_deref(),
            Some("profile_not_found")
        );
        Ok(())
    }
}
