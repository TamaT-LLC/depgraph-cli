use std::borrow::Cow;

use depgraph_core::{
    DaemonAttempt, DaemonIncrementalTrace, DaemonPhase, DaemonStatus, DoctorResponse,
    IncrementalChangeKind, IncrementalFileChange, IncrementalInvalidationMode,
    IncrementalInvalidationPlan, RepositoryProfilePlanPreview,
};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;

use crate::{
    AgentId, AgentLabel, AgentToken, ContractBuildError, RepositoryRelativePath, SnapshotId,
};

const MAX_DAEMON_CHANGES: usize = 100_000;
const MAX_LIFECYCLE_ITEMS: usize = 1_024;

/// Exact, typed profile-plan result. The wrapped core type is already a closed Serde contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AgentProfilePlan(RepositoryProfilePlanPreview);

impl From<RepositoryProfilePlanPreview> for AgentProfilePlan {
    fn from(plan: RepositoryProfilePlanPreview) -> Self {
        Self(plan)
    }
}

impl JsonSchema for AgentProfilePlan {
    fn schema_name() -> Cow<'static, str> {
        "AgentProfilePlan".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::AgentProfilePlan").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        let plan: Value = serde_json::from_str(depgraph_core::DEFAULT_PROFILE_SELECTION_SCHEMA)
            .expect("checked-in profile plan schema is valid JSON");
        let plan = inline_local_definitions(plan);
        json_schema!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "plan": plan,
                "config_migration": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "source_schema_version": {"type": "integer", "format": "uint32", "minimum": 0},
                        "status": {"enum": ["default_equivalent", "normalized_candidates", "explicit_selection_required"]},
                        "normalized_axes": bounded_text_array(1024),
                        "explicit_only_axes": bounded_text_array(1024),
                        "diagnostics": bounded_text_array(1024)
                    },
                    "required": ["source_schema_version", "status", "normalized_axes", "explicit_only_axes", "diagnostics"]
                },
                "toolchain_guidance": {
                    "type": "array",
                    "maxItems": 3,
                    "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "language": {"enum": ["rust", "go", "web"]},
                            "required_baseline": lifecycle_text_schema(),
                            "selection": lifecycle_text_schema(),
                            "remediation": lifecycle_text_schema()
                        },
                        "required": ["language", "required_baseline", "selection", "remediation"]
                    }
                }
            },
            "required": ["plan", "config_migration", "toolchain_guidance"]
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentDaemonPhase {
    Idle,
    Debouncing,
    Scanning,
    Cancelling,
    Stopping,
    Stopped,
}

impl From<DaemonPhase> for AgentDaemonPhase {
    fn from(phase: DaemonPhase) -> Self {
        match phase {
            DaemonPhase::Idle => Self::Idle,
            DaemonPhase::Debouncing => Self::Debouncing,
            DaemonPhase::Scanning => Self::Scanning,
            DaemonPhase::Cancelling => Self::Cancelling,
            DaemonPhase::Stopping => Self::Stopping,
            DaemonPhase::Stopped => Self::Stopped,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentDaemonChangeKind {
    Added,
    Modified,
    Deleted,
    Renamed,
}

impl From<IncrementalChangeKind> for AgentDaemonChangeKind {
    fn from(kind: IncrementalChangeKind) -> Self {
        match kind {
            IncrementalChangeKind::Added => Self::Added,
            IncrementalChangeKind::Modified => Self::Modified,
            IncrementalChangeKind::Deleted => Self::Deleted,
            IncrementalChangeKind::Renamed => Self::Renamed,
        }
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDaemonChange {
    kind: AgentDaemonChangeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    old_path: Option<RepositoryRelativePath>,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_path: Option<RepositoryRelativePath>,
}

impl TryFrom<IncrementalFileChange> for AgentDaemonChange {
    type Error = ContractBuildError;

    fn try_from(change: IncrementalFileChange) -> Result<Self, Self::Error> {
        Ok(Self {
            kind: change.kind.into(),
            old_path: change
                .old_path
                .map(RepositoryRelativePath::parse)
                .transpose()
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            new_path: change
                .new_path
                .map(RepositoryRelativePath::parse)
                .transpose()
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDaemonTrace {
    schema_version: AgentToken,
    mode: AgentToken,
    base_projection_milliseconds: u64,
    worker_capability_milliseconds: u64,
    worker_analysis_milliseconds: u64,
    store_commit_milliseconds: u64,
    total_milliseconds: u64,
}

impl TryFrom<DaemonIncrementalTrace> for AgentDaemonTrace {
    type Error = ContractBuildError;

    fn try_from(trace: DaemonIncrementalTrace) -> Result<Self, Self::Error> {
        Ok(Self {
            schema_version: parse_value(trace.schema_version)?,
            mode: parse_value(trace.mode)?,
            base_projection_milliseconds: trace.base_projection_milliseconds,
            worker_capability_milliseconds: trace.worker_capability_milliseconds,
            worker_analysis_milliseconds: trace.worker_analysis_milliseconds,
            store_commit_milliseconds: trace.store_commit_milliseconds,
            total_milliseconds: trace.total_milliseconds,
        })
    }
}

/// Bounded, path-free evidence that an incremental attempt used a planned invalidation.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDaemonInvalidationSummary {
    schema_version: AgentToken,
    mode: AgentToken,
    #[serde(skip_serializing_if = "Option::is_none")]
    base_profile_plan_id: Option<AgentId>,
    affected_profile_count: u64,
}

impl TryFrom<IncrementalInvalidationPlan> for AgentDaemonInvalidationSummary {
    type Error = ContractBuildError;

    fn try_from(plan: IncrementalInvalidationPlan) -> Result<Self, Self::Error> {
        let mode = match plan.mode {
            IncrementalInvalidationMode::ScopedReplacement => "scoped_replacement",
            IncrementalInvalidationMode::WorkspaceReplan => "workspace_replan",
        };
        Ok(Self {
            schema_version: parse_value(plan.schema_version)?,
            mode: parse_value(mode.to_owned())?,
            base_profile_plan_id: plan.base_profile_plan_id.map(parse_value).transpose()?,
            affected_profile_count: u64::try_from(plan.affected_profile_ids.len())
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDaemonAttempt {
    attempt_id: AgentId,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_id: Option<AgentId>,
    status: AgentToken,
    started_at: AgentLabel,
    finished_at: AgentLabel,
    #[schemars(length(max = 100000))]
    #[serde(deserialize_with = "deserialize_daemon_changes")]
    changes: Vec<AgentDaemonChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    base_snapshot_id: Option<SnapshotId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_snapshot_id: Option<SnapshotId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    invalidation_summary: Option<AgentDaemonInvalidationSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    incremental_trace: Option<AgentDaemonTrace>,
}

impl TryFrom<DaemonAttempt> for AgentDaemonAttempt {
    type Error = ContractBuildError;

    fn try_from(attempt: DaemonAttempt) -> Result<Self, Self::Error> {
        if attempt.changes.len() > MAX_DAEMON_CHANGES {
            return Err(ContractBuildError::TooManySnapshotMetadataItems);
        }
        Ok(Self {
            attempt_id: parse_value(attempt.attempt_id)?,
            scan_id: attempt.scan_id.map(parse_value).transpose()?,
            status: parse_value(attempt.status)?,
            started_at: parse_value(attempt.started_at)?,
            finished_at: parse_value(attempt.finished_at)?,
            changes: attempt
                .changes
                .into_iter()
                .map(AgentDaemonChange::try_from)
                .collect::<Result<_, _>>()?,
            base_snapshot_id: attempt.base_snapshot_id.map(parse_value).transpose()?,
            completed_snapshot_id: attempt.completed_snapshot_id.map(parse_value).transpose()?,
            invalidation_summary: attempt
                .invalidation_plan
                .map(AgentDaemonInvalidationSummary::try_from)
                .transpose()?,
            incremental_trace: attempt
                .incremental_trace
                .map(AgentDaemonTrace::try_from)
                .transpose()?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRecoveredAttempts {
    #[schemars(length(max = 1024))]
    #[serde(deserialize_with = "deserialize_lifecycle_ids")]
    scan_attempt_ids: Vec<AgentId>,
    #[schemars(length(max = 1024))]
    #[serde(deserialize_with = "deserialize_lifecycle_ids")]
    build_attempt_ids: Vec<AgentId>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDaemonStatus {
    schema_version: AgentToken,
    phase: AgentDaemonPhase,
    started_at: AgentLabel,
    #[serde(skip_serializing_if = "Option::is_none")]
    stopped_at: Option<AgentLabel>,
    debounce_milliseconds: u64,
    pending_change_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    active_attempt_id: Option<AgentId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_completed_attempt: Option<AgentDaemonAttempt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_failed_attempt: Option<AgentDaemonAttempt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_cancelled_attempt: Option<AgentDaemonAttempt>,
    recovered_attempts: AgentRecoveredAttempts,
}

/// Closed, path-free terminal decision for a durable daemon control operation.
/// Full lifecycle status remains available only through `daemon_get`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDaemonControlOutcome {
    action: AgentDaemonControlAction,
    phase: AgentDaemonControlPhase,
}

impl AgentDaemonControlOutcome {
    #[must_use]
    pub const fn running() -> Self {
        Self {
            action: AgentDaemonControlAction::Start,
            phase: AgentDaemonControlPhase::Running,
        }
    }

    #[must_use]
    pub const fn stopped() -> Self {
        Self {
            action: AgentDaemonControlAction::Stop,
            phase: AgentDaemonControlPhase::Stopped,
        }
    }

    #[must_use]
    pub const fn action(self) -> AgentDaemonControlAction {
        self.action
    }

    #[must_use]
    pub const fn phase(self) -> AgentDaemonControlPhase {
        self.phase
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        matches!(
            (self.action, self.phase),
            (
                AgentDaemonControlAction::Start,
                AgentDaemonControlPhase::Running
            ) | (
                AgentDaemonControlAction::Stop,
                AgentDaemonControlPhase::Stopped
            )
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentDaemonControlAction {
    Start,
    Stop,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentDaemonControlPhase {
    Running,
    Stopped,
}

fn deserialize_daemon_changes<'de, D>(deserializer: D) -> Result<Vec<AgentDaemonChange>, D::Error>
where
    D: Deserializer<'de>,
{
    let changes = Vec::deserialize(deserializer)?;
    if changes.len() > MAX_DAEMON_CHANGES {
        return Err(D::Error::custom("too many daemon changes"));
    }
    Ok(changes)
}

fn deserialize_lifecycle_ids<'de, D>(deserializer: D) -> Result<Vec<AgentId>, D::Error>
where
    D: Deserializer<'de>,
{
    let ids = Vec::deserialize(deserializer)?;
    if ids.len() > MAX_LIFECYCLE_ITEMS {
        return Err(D::Error::custom("too many lifecycle identifiers"));
    }
    Ok(ids)
}

impl TryFrom<DaemonStatus> for AgentDaemonStatus {
    type Error = ContractBuildError;

    fn try_from(status: DaemonStatus) -> Result<Self, Self::Error> {
        if status.recovered_attempts.scan_attempt_ids.len() > MAX_LIFECYCLE_ITEMS
            || status.recovered_attempts.build_attempt_ids.len() > MAX_LIFECYCLE_ITEMS
        {
            return Err(ContractBuildError::TooManySnapshotMetadataItems);
        }
        Ok(Self {
            schema_version: parse_value(status.schema_version)?,
            phase: status.phase.into(),
            started_at: parse_value(status.started_at)?,
            stopped_at: status.stopped_at.map(parse_value).transpose()?,
            debounce_milliseconds: status.debounce_milliseconds,
            pending_change_count: u64::try_from(status.pending_change_count)
                .map_err(|_| ContractBuildError::AgentDtoValue)?,
            active_attempt_id: status.active_attempt_id.map(parse_value).transpose()?,
            last_completed_attempt: status
                .last_completed_attempt
                .map(AgentDaemonAttempt::try_from)
                .transpose()?,
            last_failed_attempt: status
                .last_failed_attempt
                .map(AgentDaemonAttempt::try_from)
                .transpose()?,
            last_cancelled_attempt: status
                .last_cancelled_attempt
                .map(AgentDaemonAttempt::try_from)
                .transpose()?,
            recovered_attempts: AgentRecoveredAttempts {
                scan_attempt_ids: status
                    .recovered_attempts
                    .scan_attempt_ids
                    .into_iter()
                    .map(parse_value)
                    .collect::<Result<_, _>>()?,
                build_attempt_ids: status
                    .recovered_attempts
                    .build_attempt_ids
                    .into_iter()
                    .map(parse_value)
                    .collect::<Result<_, _>>()?,
            },
        })
    }
}

/// Doctor output is already a closed, allowlisted core projection. This transparent wrapper is
/// the only way that projection enters a public MCP success envelope.
#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub struct AgentDoctor(DoctorResponse);

impl From<DoctorResponse> for AgentDoctor {
    fn from(doctor: DoctorResponse) -> Self {
        Self(doctor)
    }
}

impl JsonSchema for AgentDoctor {
    fn schema_name() -> Cow<'static, str> {
        "AgentDoctor".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::AgentDoctor").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        generator.subschema_for::<doctor_schema::Doctor>()
    }
}

fn parse_value<T>(value: String) -> Result<T, ContractBuildError>
where
    T: std::str::FromStr,
{
    value.parse().map_err(|_| ContractBuildError::AgentDtoValue)
}

fn lifecycle_text_schema() -> Value {
    serde_json::json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 256,
        "pattern": "^[^\\u0000-\\u001f\\u007f]+$"
    })
}

fn bounded_text_array(maximum: usize) -> Value {
    serde_json::json!({
        "type": "array",
        "maxItems": maximum,
        "items": lifecycle_text_schema()
    })
}

fn inline_local_definitions(mut schema: Value) -> Value {
    let definitions = schema
        .get("$defs")
        .and_then(Value::as_object)
        .cloned()
        .expect("profile plan schema has definitions");
    inline_schema_node(&mut schema, &definitions);
    if let Some(object) = schema.as_object_mut() {
        object.remove("$schema");
        object.remove("$id");
        object.remove("title");
        object.remove("$defs");
    }
    schema
}

fn inline_schema_node(node: &mut Value, definitions: &serde_json::Map<String, Value>) {
    if let Some(reference) = node
        .as_object()
        .and_then(|object| object.get("$ref"))
        .and_then(Value::as_str)
        .and_then(|reference| reference.strip_prefix("#/$defs/"))
    {
        *node = definitions
            .get(reference)
            .cloned()
            .expect("profile plan schema reference resolves");
        inline_schema_node(node, definitions);
        return;
    }
    match node {
        Value::Object(object) => {
            object.remove("$defs");
            for child in object.values_mut() {
                inline_schema_node(child, definitions);
            }
        }
        Value::Array(array) => {
            for child in array {
                inline_schema_node(child, definitions);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[allow(dead_code)]
mod doctor_schema {
    use schemars::JsonSchema;

    use super::{LifecycleText, RepositoryRelativePath};

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    pub(super) struct Doctor {
        report_kind: ReportKind,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail_command: Option<LifecycleText>,
        diagnostic_root_source: LifecycleText,
        protocol_version: LifecycleText,
        graph_schema_version: LifecycleText,
        store_schema_version: i64,
        cache_contract_version: u32,
        cache_entries: CacheEntries,
        impact_query_cache_contract_version: u32,
        impact_query_cache_entries: u64,
        #[schemars(length(max = 1024))]
        recent_cache_events: Vec<CacheEvent>,
        #[schemars(length(max = 1024))]
        toolchains: Vec<NamedValue>,
        #[schemars(length(max = 1024))]
        supported_baselines: Vec<NamedValue>,
        #[schemars(length(max = 3))]
        workers: Vec<Worker>,
        compiler_pack: CompilerPack,
        #[serde(skip_serializing_if = "Option::is_none")]
        latest_attempt: Option<Attempt>,
        #[serde(skip_serializing_if = "Option::is_none")]
        latest_successful_scan_id: Option<LifecycleText>,
        #[serde(skip_serializing_if = "Option::is_none")]
        release: Option<Release>,
    }

    #[derive(JsonSchema)]
    #[serde(rename_all = "snake_case")]
    enum ReportKind {
        Summary,
        Details,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct CacheEntries {
        syntax: u64,
        semantic: u64,
        build: u64,
        compiler_precise: u64,
    }

    #[derive(JsonSchema)]
    #[serde(rename_all = "snake_case")]
    enum CacheLayer {
        Syntax,
        Semantic,
        Build,
        CompilerPrecise,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct CacheEvent {
        layer: CacheLayer,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_key: Option<LifecycleText>,
        outcome: LifecycleText,
        reason: LifecycleText,
        created_at: LifecycleText,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct NamedValue {
        name: LifecycleText,
        value: LifecycleText,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct NamedCount {
        name: LifecycleText,
        count: u64,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct Worker {
        adapter: LifecycleText,
        available: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<LifecycleText>,
        #[serde(skip_serializing_if = "Option::is_none")]
        protocol: Option<LifecycleText>,
        integrity: LifecycleText,
        root_launch_allowed: bool,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct CompilerPack {
        status: LifecycleText,
        #[serde(skip_serializing_if = "Option::is_none")]
        host_target: Option<LifecycleText>,
        #[serde(skip_serializing_if = "Option::is_none")]
        manifest_sha256: Option<LifecycleText>,
        #[serde(skip_serializing_if = "Option::is_none")]
        archive_asset: Option<LifecycleText>,
        #[serde(skip_serializing_if = "Option::is_none")]
        checksum_asset: Option<LifecycleText>,
        #[serde(skip_serializing_if = "Option::is_none")]
        requirement_asset: Option<LifecycleText>,
        #[serde(skip_serializing_if = "Option::is_none")]
        smoke_asset: Option<LifecycleText>,
        release_page: LifecycleText,
        fallback_policy: LifecycleText,
        diagnostic: LifecycleText,
        remediation: LifecycleText,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct Attempt {
        scan_id: LifecycleText,
        status: LifecycleText,
        project_code_executed: bool,
        coverage: Coverage,
        #[serde(skip_serializing_if = "Option::is_none")]
        profile_count: Option<u64>,
        #[schemars(length(max = 1024))]
        #[serde(skip_serializing_if = "Option::is_none")]
        profiles_by_language: Option<Vec<NamedCount>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        package_instance_count: Option<u64>,
        #[schemars(length(max = 1000000))]
        file_coverage: Vec<FileCoverage>,
        #[serde(skip_serializing_if = "Option::is_none")]
        diagnostic_summary: Option<DiagnosticSummary>,
        #[schemars(length(max = 1024))]
        profiles: Vec<Profile>,
        #[schemars(length(max = 1024))]
        diagnostics: Vec<Diagnostic>,
        #[schemars(length(max = 1024))]
        cache_events: Vec<CacheEvent>,
        #[serde(skip_serializing_if = "Option::is_none")]
        profile_matrix: Option<ProfileMatrix>,
        #[serde(skip_serializing_if = "Option::is_none")]
        compiler_precise: Option<CompilerPrecise>,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct Coverage {
        profiles: u64,
        files_discovered: u64,
        files_analyzed: u64,
        files_skipped: u64,
        dependency_sites: u64,
        resolved: u64,
        candidates: u64,
        external: u64,
        unresolved: u64,
        unsupported_syntax: u64,
        project_code_executed: bool,
        #[schemars(length(max = 1024))]
        completeness: Vec<LifecycleText>,
        #[schemars(length(max = 1024))]
        reasons: Vec<LifecycleText>,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct FileCoverage {
        adapter: LifecycleText,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<RepositoryRelativePath>,
        files: u64,
        skipped_files: u64,
        discovered_sites: u64,
        emitted_sites: u64,
        skipped_sites: u64,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct DiagnosticSummary {
        total: u64,
        #[schemars(length(max = 64))]
        groups: Vec<DiagnosticGroup>,
        omitted_groups: u64,
        omitted_diagnostics: u64,
        #[schemars(length(max = 5))]
        samples: Vec<DiagnosticSample>,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct DiagnosticGroup {
        severity: LifecycleText,
        code: LifecycleText,
        #[serde(skip_serializing_if = "Option::is_none")]
        adapter: Option<LifecycleText>,
        count: u64,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct DiagnosticSample {
        id: LifecycleText,
        severity: LifecycleText,
        code: LifecycleText,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<RepositoryRelativePath>,
        #[serde(skip_serializing_if = "Option::is_none")]
        adapter: Option<LifecycleText>,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct Profile {
        id: LifecycleText,
        language: LifecycleText,
        #[serde(skip_serializing_if = "Option::is_none")]
        target: Option<LifecycleText>,
        #[schemars(length(max = 1024))]
        features: Vec<LifecycleText>,
        #[serde(skip_serializing_if = "Option::is_none")]
        coverage: Option<Coverage>,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct ProfileMatrix {
        schema_version: LifecycleText,
        #[schemars(length(max = 1024))]
        entries: Vec<ProfileMatrixEntry>,
        phase_coverage: PhaseCoverageByPhase,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct ProfileMatrixEntry {
        id: LifecycleText,
        effective_input_id: LifecycleText,
        language: LifecycleText,
        #[schemars(length(max = 1024))]
        profile_ids: Vec<LifecycleText>,
        #[schemars(length(max = 1024))]
        parent_profile_ids: Vec<LifecycleText>,
        #[schemars(length(max = 1024))]
        phases: Vec<LifecycleText>,
        phase_coverage: PhaseCoverageByPhase,
        #[schemars(length(max = 1024))]
        selection_reasons: Vec<LifecycleText>,
        #[schemars(length(max = 1024))]
        axis_conflicts: Vec<ProfileAxisConflict>,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct PhaseCoverageByPhase {
        #[serde(rename = "static", skip_serializing_if = "Option::is_none")]
        static_phase: Option<PhaseCoverage>,
        #[serde(skip_serializing_if = "Option::is_none")]
        build: Option<PhaseCoverage>,
        #[serde(skip_serializing_if = "Option::is_none")]
        runtime: Option<PhaseCoverage>,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct PhaseCoverage {
        #[schemars(length(max = 1024))]
        profile_ids: Vec<LifecycleText>,
        sites: u64,
        edges: u64,
        evidence: u64,
        resolved: u64,
        candidates: u64,
        external: u64,
        unresolved: u64,
        #[schemars(length(max = 1024))]
        completeness: Vec<LifecycleText>,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct ProfileAxisConflict {
        profile_id: LifecycleText,
        parent_profile_id: LifecycleText,
        #[schemars(length(max = 1024))]
        fields: Vec<LifecycleText>,
        diagnostic_id: LifecycleText,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct Diagnostic {
        id: LifecycleText,
        severity: LifecycleText,
        code: LifecycleText,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<RepositoryRelativePath>,
        #[serde(skip_serializing_if = "Option::is_none")]
        adapter: Option<LifecycleText>,
        #[serde(skip_serializing_if = "Option::is_none")]
        start_line: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        start_column: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        end_line: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        end_column: Option<u64>,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct CompilerPrecise {
        status: LifecycleText,
        phase: LifecycleText,
        precision: LifecycleText,
        #[schemars(length(max = 1024))]
        profiles: Vec<CompilerPreciseProfile>,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct CompilerPreciseProfile {
        profile_id: LifecycleText,
        #[serde(skip_serializing_if = "Option::is_none")]
        target: Option<LifecycleText>,
        #[serde(skip_serializing_if = "Option::is_none")]
        compiler_pack_manifest_sha256: Option<LifecycleText>,
        #[serde(skip_serializing_if = "Option::is_none")]
        unit_graph_digest: Option<LifecycleText>,
        #[serde(skip_serializing_if = "Option::is_none")]
        invocation_ledger_digest: Option<LifecycleText>,
        #[serde(skip_serializing_if = "Option::is_none")]
        mir_ledger_digest: Option<LifecycleText>,
        cargo_units: u64,
        typed_mir_bodies: u64,
        compiler_instances: u64,
        compiler_calls: u64,
    }

    #[derive(JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct Release {
        version: LifecycleText,
        target: LifecycleText,
        schema_version: LifecycleText,
        compatibility_integrity: LifecycleText,
        license_expression: LifecycleText,
        core_integrity: LifecycleText,
        schema_integrity: LifecycleText,
    }
}

#[allow(dead_code)]
struct LifecycleText(String);

impl JsonSchema for LifecycleText {
    fn schema_name() -> Cow<'static, str> {
        "LifecycleText".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::LifecycleText").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        lifecycle_text_schema()
            .try_into()
            .expect("text schema is valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_plan_schema_has_no_unresolved_local_references() {
        let schema = serde_json::to_value(AgentProfilePlan::json_schema(
            &mut SchemaGenerator::default(),
        ))
        .unwrap();
        assert!(!schema.to_string().contains("#/$defs/"));
    }

    #[test]
    fn daemon_attempt_projects_only_bounded_invalidation_evidence() {
        let plan_id = format!("profile-selection-plan:sha256:{}", "3".repeat(64));
        let profile_id = format!("profile:sha256:{}", "4".repeat(64));
        let attempt: DaemonAttempt = serde_json::from_value(serde_json::json!({
            "attempt_id": "attempt:fixture",
            "scan_id": "scan:fixture",
            "status": "completed",
            "started_at": "2026-08-13T00:00:00.000Z",
            "finished_at": "2026-08-13T00:00:01.000Z",
            "changes": [{"kind": "modified", "new_path": "src/index.ts"}],
            "base_snapshot_id": format!("snapshot:sha256:{}", "1".repeat(64)),
            "completed_snapshot_id": format!("snapshot:sha256:{}", "2".repeat(64)),
            "invalidation_plan": {
                "schema_version": "incremental-plan-v2",
                "base_snapshot_id": format!("snapshot:sha256:{}", "1".repeat(64)),
                "base_profile_plan_id": plan_id,
                "mode": "scoped_replacement",
                "changes": [{"kind": "modified", "new_path": "src/index.ts"}],
                "reasons": ["source_changed"],
                "affected_package_locators": ["npm:workspace:fixture@1.0.0#."],
                "affected_profile_ids": [profile_id.clone()],
                "affected_generated_artifact_ids": [],
                "replacement_scope": {
                    "paths": ["src/index.ts"],
                    "package_locators": ["npm:workspace:fixture@1.0.0#."],
                    "profile_ids": [profile_id],
                    "replanned_profile_ids": [],
                    "artifact_node_ids": [],
                    "adapters": ["web"]
                }
            },
            "invalidation_error": "private invalidation diagnostic /outside/repository",
            "incremental_trace": {
                "schema_version": "daemon-incremental-trace-v1",
                "mode": "semantic_noop",
                "base_projection_milliseconds": 1,
                "worker_capability_milliseconds": 2,
                "worker_analysis_milliseconds": 3,
                "store_commit_milliseconds": 4,
                "total_milliseconds": 10
            },
            "error": null
        }))
        .unwrap();

        let projected = AgentDaemonAttempt::try_from(attempt).unwrap();
        let mut value = serde_json::to_value(projected).unwrap();
        assert_eq!(
            value["invalidation_summary"],
            serde_json::json!({
                "schema_version": "incremental-plan-v2",
                "mode": "scoped_replacement",
                "base_profile_plan_id": format!(
                    "profile-selection-plan:sha256:{}",
                    "3".repeat(64)
                ),
                "affected_profile_count": 1
            })
        );
        let encoded = value.to_string();
        assert!(!encoded.contains("invalidation_plan"));
        assert!(!encoded.contains("private invalidation diagnostic"));
        assert!(value["invalidation_summary"].get("paths").is_none());

        value["invalidation_summary"]["paths"] = serde_json::json!(["src/index.ts"]);
        assert!(serde_json::from_value::<AgentDaemonAttempt>(value).is_err());
    }
}
