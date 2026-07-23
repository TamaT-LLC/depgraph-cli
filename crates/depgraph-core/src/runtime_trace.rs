use std::{
    collections::{BTreeSet, HashMap},
    io::Read,
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use depgraph_protocol::stable_id_from_value;
use depgraph_store::{GraphSnapshot, NodeRecord, ProfileRecord};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const RUNTIME_TRACE_SCHEMA_VERSION: &str = "1.0";
pub const RUNTIME_TRACE_MAX_BYTES: usize = 16 * 1024 * 1024;
pub const RUNTIME_TRACE_MAX_EVENTS: usize = 100_000;
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
                "environment": trace.session.environment.name,
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
            validate_locator(&event.source, "events[].source")?;
            validate_locator(&event.target, "events[].target")?;
            if event.count == 0 {
                bail!("runtime trace events[].count must be greater than zero");
            }
            event.redaction.normalize("events[].redaction")?;
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
}

fn normalize_timestamp(value: &mut String, field: &str) -> Result<DateTime<Utc>> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("runtime trace {field} must be an RFC 3339 timestamp"))?
        .with_timezone(&Utc);
    *value = parsed.to_rfc3339_opts(SecondsFormat::AutoSi, true);
    Ok(parsed)
}

fn validate_locator(locator: &RuntimeTraceLocator, field: &str) -> Result<()> {
    match locator {
        RuntimeTraceLocator::Node { node_id } => {
            validate_bounded_string(node_id, &format!("{field}.node_id"), MAX_ID_CHARS)
        }
        RuntimeTraceLocator::GraphLocator { locator, node_kind } => {
            validate_graph_locator(locator, &format!("{field}.locator"))?;
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
            validate_bounded_string(name, &format!("{field}.name"), MAX_STRING_CHARS)
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
            .filter(|profile| profile.id == parent)
            .filter(|profile| profile_matches_requested_axes(profile, requested))
            .collect::<Vec<_>>()
    } else {
        profiles
            .iter()
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
    fn malformed_and_secret_fixtures_are_rejected_without_echoing_values() {
        let malformed = read_runtime_trace(Cursor::new(MALFORMED)).unwrap_err();
        assert!(malformed.to_string().contains("repository-relative path"));

        let secret = read_runtime_trace(Cursor::new(SECRET)).unwrap_err();
        let message = format!("{secret:#}");
        assert!(message.contains("secret"));
        assert!(!message.contains("fixture-secret-value"));
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
