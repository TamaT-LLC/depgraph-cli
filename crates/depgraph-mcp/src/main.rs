use std::{
    borrow::Cow,
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use chrono::{DateTime, Utc};
use clap::{Parser, ValueEnum};
use depgraph_core::service::{
    BoundedQueryMode, BoundedQueryRequest, ClosedRecordDiff, CyclesRequest,
    DEFAULT_GRAPH_EXPORT_MAX_EDGES, DEFAULT_GRAPH_EXPORT_MAX_NODES, DependenciesRequest,
    DependencyDirection, DoctorRequest, EdgeDirection, ExplainPathRequest, GraphExportFormat,
    GraphExportRequest, GraphExportResult, HealthAuditRequest, HealthFindingGetRequest,
    HealthFindingsRequest, HealthHotspotsRequest, HealthSummaryRequest, ImpactRequest,
    MAX_HEALTH_CHURN_COMMITS, MAX_HEALTH_FILTER_ITEMS, MAX_HEALTH_FINDINGS, NodeMatchMode,
    PolicyEvaluateRequest, PolicyEvaluationResult, ProfilePlanRequest, RepositoryInitRequest,
    RepositoryOutputPrecondition, RuntimeValidateRequest, ServiceSnapshotSelector,
    SnapshotDiffFilters, SnapshotDiffRequest, SnapshotDiffResult, SnapshotNameCreateRequest,
    UnresolvedRequest,
};
use depgraph_core::{
    CancellationToken, Confidence, CycleLevel, DEFAULT_HOTSPOT_WEIGHTS, DepgraphCapability,
    DepgraphCapabilitySet, DepgraphService, DepgraphServiceConfig, DepgraphServiceError,
    DepgraphServiceLimits, FindingKind, GraphQueryFilter, HealthFinding, HotspotWeights,
    ImpactFilters, MAX_INTERACTIVE_QUERY_TRAVERSAL, Severity, SnapshotLocator,
    VerifiedCompilerPack, read_compiler_pack_requirement, verify_compiler_pack,
};
use depgraph_mcp::runtime::{AuditLogger, RuntimeClass, RuntimeConfig, RuntimeController};
use depgraph_mcp_tools::{
    AgentCompletedSnapshot, AgentContext, AgentCycleLevel, AgentDaemonStatus,
    AgentDependencyDirection, AgentDoctor, AgentEdge, AgentError, AgentErrorCode,
    AgentErrorDetails, AgentEvidence, AgentGraphExportFormat, AgentGraphExportMediaType,
    AgentGraphExportResponse, AgentHealthAudit, AgentHealthFinding, AgentHealthFindingDetail,
    AgentHealthFindingsPage, AgentHealthHotspots, AgentHealthSummary, AgentId, AgentLocator,
    AgentNamedSnapshot, AgentNode, AgentNodeSummary, AgentOperation, AgentOperationStatus,
    AgentPathResponse, AgentPolicyAnnotation, AgentPolicyAnnotationLevel, AgentPolicyApiChange,
    AgentPolicyApiChangeKind, AgentPolicyEvaluationResponse, AgentPolicySeverity,
    AgentPolicySummary, AgentPolicyViolation, AgentProfilePlan, AgentRemediation,
    AgentRepositoryInitOutcome, AgentResourceLimit, AgentRuntimeTraceEvent,
    AgentRuntimeValidationResponse, AgentSite, AgentSnapshotDiffChange,
    AgentSnapshotDiffChangeType, AgentSnapshotDiffRecordType, AgentSnapshotDiffResponse,
    AgentToken, BoundedQueryProjectionFailure, CanonicalResponseMapper, ContractBuildError,
    ContractVersion, Cursor, CursorKey, DurableSubmitResult, ErrorEnvelope, IdempotencyKey,
    LogicalRepositoryId, MAX_AGENT_CONDITION_BYTES, MAX_PAGE_BYTES, MappedToolResult,
    OperationAccepted, OperationId, Page, PageByteLimit, PageRequest, PageSize, PaginationContext,
    PortableTerminalOutputContract, RepositoryRelativePath, ResponseMappingError, SnapshotId,
    SnapshotName, SuccessEnvelope, TASK_POLL_INTERVAL_MS, ToolCatalog,
    project_bounded_query_rows_cancellable, project_cycles_page_cancellable,
    project_dependencies_page_cancellable, project_impact_response_cancellable,
    project_unresolved_page_cancellable,
};
use depgraph_operation::{
    DEADLINE_EXCEEDED_ERROR_JSON, EXECUTION_STATE_UNKNOWN_ERROR_JSON, JournalError,
    OperationHandle, OperationKind, OperationManager, OperationOutcome, OperationResultView,
    OperationRunnerLauncher, OperationStatus, OperationView, RunnerStartupConfig, SubmitRequest,
    UNSUPPORTED_OPERATION_ERROR_JSON,
};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, Service, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResponse, CancelTaskParams, ClientRequest, CreateTaskResult,
        DetailedTask, ErrorCode, GetTaskParams, GetTaskResult, Implementation,
        InitializeRequestParams, InitializeResult, ListToolsResult, PaginatedRequestParams,
        ProtocolVersion, ServerCapabilities, ServerInfo, Task, TaskPayload, TaskStatus, Tool,
        ToolsCapability, UpdateTaskParams,
    },
    service::{
        NotificationContext, RequestContext, RxJsonRpcMessage, ServiceRole, TxJsonRpcMessage,
    },
    transport::Transport,
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex as AsyncMutex,
};
use tracing_subscriber::fmt::MakeWriter as _;

const MAX_INBOUND_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_STDERR_RECORD_BYTES: usize = 1024;
const MAX_STDERR_TOTAL_BYTES: usize = 16 * 1024;
const STARTUP_ERROR: &str = "depgraph-mcp: invalid startup configuration\n";
const INBOUND_ERROR: &str = "depgraph-mcp: inbound message rejected\n";
const SCAN_EXECUTION_DEADLINE_MS: i64 = 60 * 60 * 1_000;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CapabilityArg {
    #[value(name = "read")]
    Read,
    #[value(name = "store-write")]
    StoreWrite,
    #[value(name = "repository-write")]
    RepositoryWrite,
    #[value(name = "daemon-control")]
    DaemonControl,
    #[value(name = "project-exec")]
    ProjectExec,
}

impl From<CapabilityArg> for DepgraphCapability {
    fn from(value: CapabilityArg) -> Self {
        match value {
            CapabilityArg::Read => Self::Read,
            CapabilityArg::StoreWrite => Self::StoreWrite,
            CapabilityArg::RepositoryWrite => Self::RepositoryWrite,
            CapabilityArg::DaemonControl => Self::DaemonControl,
            CapabilityArg::ProjectExec => Self::ProjectExec,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for tracing::level_filters::LevelFilter {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Error => Self::ERROR,
            LogLevel::Warn => Self::WARN,
            LogLevel::Info => Self::INFO,
            LogLevel::Debug => Self::DEBUG,
            LogLevel::Trace => Self::TRACE,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "depgraph-mcp",
    version,
    about = "depgraph MCP server over stdio"
)]
struct Args {
    /// Existing repository directory to analyze.
    #[arg(long)]
    root: PathBuf,

    /// Absolute fixed path to the depgraph store file.
    #[arg(long)]
    store: PathBuf,

    /// Explicitly granted service capabilities. Repeat for every capability.
    #[arg(long, required = true)]
    capability: Vec<CapabilityArg>,

    /// Regular, non-symlink compiler-pack requirement JSON file (at most 1 MiB).
    #[arg(long)]
    compiler_pack_requirement: PathBuf,

    /// Bounded stderr log severity.
    #[arg(long, value_enum, default_value_t = LogLevel::Warn)]
    log_level: LogLevel,
}

struct DepgraphMcpServer {
    // Retained as immutable server state so tool handlers share one validated setup and runtime.
    service: DepgraphService,
    operation_config: DepgraphServiceConfig,
    compiler_pack: VerifiedCompilerPack,
    compiler_pack_requirement: PathBuf,
    runtime: RuntimeController,
    audit: AuditLogger,
    repository_id: LogicalRepositoryId,
    cursor_key: CursorKey,
    tools: Arc<[Tool]>,
}

struct RequestScopedDepgraphMcpServer {
    inner: DepgraphMcpServer,
}

tokio::task_local! {
    static EFFECTIVE_PROTOCOL_VERSION: ProtocolVersion;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    operation_id: OperationId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanSubmitArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    idempotency_key: IdempotencyKey,
    #[serde(default)]
    strict: bool,
    #[serde(default)]
    no_cache: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DaemonStartSubmitArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    idempotency_key: IdempotencyKey,
    #[serde(default)]
    strict: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DaemonStopArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    idempotency_key: IdempotencyKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveBuildSubmitArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    idempotency_key: IdempotencyKey,
    acknowledgement: bool,
    rust_compiler_precise: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryInitArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    #[serde(default)]
    force: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeImportSubmitArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    idempotency_key: IdempotencyKey,
    #[serde(default)]
    trace: Option<String>,
    #[serde(default)]
    trace_file: Option<RepositoryRelativePath>,
    #[serde(default)]
    snapshot: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotNameCreateArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    name: SnapshotName,
    #[serde(default)]
    snapshot: Option<String>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum NodeMatchArgument {
    Exact,
    Prefix,
    Contains,
}

impl From<NodeMatchArgument> for NodeMatchMode {
    fn from(value: NodeMatchArgument) -> Self {
        match value {
            NodeMatchArgument::Exact => Self::Exact,
            NodeMatchArgument::Prefix => Self::Prefix,
            NodeMatchArgument::Contains => Self::Contains,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FindNodesArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    query: String,
    match_mode: NodeMatchArgument,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default)]
    kinds: Vec<String>,
    #[serde(default)]
    cursor: Option<Cursor>,
    #[serde(default)]
    limit: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentNodeGetArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    node_id: String,
    #[serde(default)]
    snapshot: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSitesListArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default)]
    node_id: Option<String>,
    #[serde(default)]
    cursor: Option<Cursor>,
    #[serde(default)]
    limit: Option<u16>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum AgentEdgesDirection {
    Incoming,
    Outgoing,
    Both,
}
impl From<AgentEdgesDirection> for EdgeDirection {
    fn from(value: AgentEdgesDirection) -> Self {
        match value {
            AgentEdgesDirection::Incoming => Self::Incoming,
            AgentEdgesDirection::Outgoing => Self::Outgoing,
            AgentEdgesDirection::Both => Self::Both,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentEdgesListArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    node_id: String,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default = "default_agent_edges_direction")]
    direction: AgentEdgesDirection,
    #[serde(default)]
    cursor: Option<Cursor>,
    #[serde(default)]
    limit: Option<u16>,
}
fn default_agent_edges_direction() -> AgentEdgesDirection {
    AgentEdgesDirection::Both
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentEvidenceListArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    site_id: String,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default)]
    cursor: Option<Cursor>,
    #[serde(default)]
    limit: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotListArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    #[serde(default)]
    cursor: Option<Cursor>,
    #[serde(default)]
    limit: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotGetArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    snapshot: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfilesPlanArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    #[serde(default)]
    profile_budget: Option<u32>,
    #[serde(default)]
    profiles_document: Option<String>,
    #[serde(default)]
    profiles_file: Option<RepositoryRelativePath>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DoctorArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    #[serde(default)]
    details: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DaemonStatusArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphDependenciesArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    selector: AgentLocator,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default)]
    transitive: bool,
    #[serde(default)]
    phases: Vec<String>,
    #[serde(default)]
    profiles: Vec<String>,
    #[serde(default)]
    sessions: Vec<String>,
    #[serde(default)]
    environments: Vec<String>,
    #[serde(default)]
    max_traversal: Option<usize>,
    #[serde(default)]
    cursor: Option<Cursor>,
    #[serde(default)]
    limit: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphPathArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    from: AgentLocator,
    to: AgentLocator,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default)]
    phases: Vec<String>,
    #[serde(default)]
    profiles: Vec<String>,
    #[serde(default)]
    sessions: Vec<String>,
    #[serde(default)]
    environments: Vec<String>,
    #[serde(default)]
    max_traversal: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphImpactArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    selector: AgentLocator,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default)]
    changed_since: Option<String>,
    #[serde(default)]
    depth: Option<usize>,
    #[serde(default)]
    profiles: Vec<String>,
    #[serde(default)]
    conditions: Vec<String>,
    #[serde(default)]
    phases: Vec<String>,
    #[serde(default)]
    sessions: Vec<String>,
    #[serde(default)]
    environments: Vec<String>,
    #[serde(default)]
    max_nodes: Option<usize>,
    #[serde(default)]
    max_edges: Option<usize>,
    #[serde(default)]
    cursor: Option<Cursor>,
    #[serde(default)]
    limit: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphCyclesArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default = "default_cycle_level")]
    level: AgentCycleLevel,
    #[serde(default)]
    max_traversal: Option<usize>,
    #[serde(default)]
    cursor: Option<Cursor>,
    #[serde(default)]
    limit: Option<u16>,
}

const fn default_cycle_level() -> AgentCycleLevel {
    AgentCycleLevel::File
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphUnresolvedArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default)]
    kinds: Vec<String>,
    #[serde(default)]
    max_traversal: Option<usize>,
    #[serde(default)]
    cursor: Option<Cursor>,
    #[serde(default)]
    limit: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphQueryArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    query_file: Option<RepositoryRelativePath>,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default)]
    cursor: Option<Cursor>,
    #[serde(default)]
    limit: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeValidateArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    #[serde(default)]
    trace: Option<String>,
    #[serde(default)]
    trace_file: Option<RepositoryRelativePath>,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default)]
    cursor: Option<Cursor>,
    #[serde(default)]
    limit: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotDiffArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    from: String,
    to: String,
    #[serde(default)]
    kinds: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyEvaluateArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    from: String,
    to: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthSummaryArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default)]
    kinds: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthFindingsArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default)]
    kinds: Vec<String>,
    #[serde(default)]
    severities: Vec<String>,
    #[serde(default)]
    confidences: Vec<String>,
    #[serde(default)]
    cursor: Option<Cursor>,
    #[serde(default)]
    limit: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthFindingGetArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    #[serde(default)]
    snapshot: Option<String>,
    finding_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthAuditArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    #[serde(default)]
    snapshot: Option<String>,
    changed: String,
    #[serde(default)]
    base_snapshot: Option<String>,
    #[serde(default)]
    cursor: Option<Cursor>,
    #[serde(default)]
    limit: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthHotspotsArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default)]
    churn_commit_limit: Option<u32>,
    #[serde(default)]
    churn_path_filter: Vec<String>,
    #[serde(default)]
    weight_fan_in: Option<u32>,
    #[serde(default)]
    weight_fan_out: Option<u32>,
    #[serde(default)]
    weight_reverse_impact: Option<u32>,
    #[serde(default)]
    weight_git_churn: Option<u32>,
    #[serde(default)]
    weight_runtime: Option<u32>,
    #[serde(default)]
    cursor: Option<Cursor>,
    #[serde(default)]
    limit: Option<u16>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GraphExportFormatArgument {
    Json,
    Dot,
    Mermaid,
    Graphml,
}

impl From<GraphExportFormatArgument> for GraphExportFormat {
    fn from(value: GraphExportFormatArgument) -> Self {
        match value {
            GraphExportFormatArgument::Json => Self::Json,
            GraphExportFormatArgument::Dot => Self::Dot,
            GraphExportFormatArgument::Mermaid => Self::Mermaid,
            GraphExportFormatArgument::Graphml => Self::Graphml,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphExportArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    format: GraphExportFormatArgument,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default)]
    selector: Option<AgentLocator>,
    #[serde(default)]
    max_nodes: Option<usize>,
    #[serde(default)]
    max_edges: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportFileSubmitArguments {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    idempotency_key: IdempotencyKey,
    output_path: RepositoryRelativePath,
    #[serde(default)]
    overwrite: bool,
    format: GraphExportFormatArgument,
    #[serde(default)]
    snapshot: Option<String>,
    #[serde(default)]
    selector: Option<AgentLocator>,
    #[serde(default)]
    max_nodes: Option<usize>,
    #[serde(default)]
    max_edges: Option<usize>,
}

fn append_closed_diff<T>(
    output: &mut Vec<AgentSnapshotDiffChange>,
    record_type: AgentSnapshotDiffRecordType,
    records: &ClosedRecordDiff<T>,
    id: impl Fn(&T) -> String + Copy,
) -> Result<(), ContractBuildError> {
    for record in &records.added {
        output.push(AgentSnapshotDiffChange::try_new(
            record_type,
            AgentSnapshotDiffChangeType::Added,
            id(record),
            Vec::new(),
        )?);
    }
    for record in &records.removed {
        output.push(AgentSnapshotDiffChange::try_new(
            record_type,
            AgentSnapshotDiffChangeType::Removed,
            id(record),
            Vec::new(),
        )?);
    }
    for record in &records.changed {
        output.push(AgentSnapshotDiffChange::try_new(
            record_type,
            AgentSnapshotDiffChangeType::Changed,
            record.id.clone(),
            record.changed_fields.clone(),
        )?);
    }
    Ok(())
}

fn project_snapshot_diff(
    result: SnapshotDiffResult,
) -> Result<AgentSnapshotDiffResponse, ContractBuildError> {
    let mut changes = Vec::with_capacity(result.item_count());
    append_closed_diff(
        &mut changes,
        AgentSnapshotDiffRecordType::Node,
        &result.nodes,
        |record| record.id.clone(),
    )?;
    append_closed_diff(
        &mut changes,
        AgentSnapshotDiffRecordType::Site,
        &result.sites,
        |record| record.id.clone(),
    )?;
    append_closed_diff(
        &mut changes,
        AgentSnapshotDiffRecordType::Edge,
        &result.edges,
        |record| record.id.clone(),
    )?;
    append_closed_diff(
        &mut changes,
        AgentSnapshotDiffRecordType::Evidence,
        &result.evidence,
        |record| record.id(),
    )?;
    append_closed_diff(
        &mut changes,
        AgentSnapshotDiffRecordType::Profile,
        &result.profiles,
        |record| record.id.clone(),
    )?;
    if let Some(coverage) = &result.coverage {
        changes.push(AgentSnapshotDiffChange::try_new(
            AgentSnapshotDiffRecordType::Coverage,
            AgentSnapshotDiffChangeType::Changed,
            coverage.id.clone(),
            coverage.changed_fields.clone(),
        )?);
    }
    for rename in &result.renames {
        changes.push(AgentSnapshotDiffChange::try_new(
            AgentSnapshotDiffRecordType::Node,
            AgentSnapshotDiffChangeType::Renamed,
            format!("{}->{}", rename.old_id, rename.new_id),
            rename.changed_fields.clone(),
        )?);
    }
    for rename in &result.rename_candidates {
        changes.push(AgentSnapshotDiffChange::try_new(
            AgentSnapshotDiffRecordType::Node,
            AgentSnapshotDiffChangeType::RenameCandidate,
            format!("{}->{}", rename.old_id, rename.new_id),
            rename.changed_fields.clone(),
        )?);
    }
    changes.sort_by(|left, right| {
        (&left.record_type, &left.change_type, &left.id).cmp(&(
            &right.record_type,
            &right.change_type,
            &right.id,
        ))
    });
    AgentSnapshotDiffResponse::try_new(
        &result.schema_version,
        &result.from_snapshot_id,
        &result.to_snapshot_id,
        result.summary.total_changes,
        result.summary.empty,
        changes,
        &result.collection_digest,
    )
}

fn project_policy_result(
    result: PolicyEvaluationResult,
) -> Result<AgentPolicyEvaluationResponse, ContractBuildError> {
    let api_changes = result
        .result
        .api_changes
        .iter()
        .map(|change| {
            AgentPolicyApiChange::try_new(
                &change.id,
                &change.rule_id,
                match change.kind {
                    depgraph_core::policy::PublicApiChangeKind::Added => {
                        AgentPolicyApiChangeKind::Added
                    }
                    depgraph_core::policy::PublicApiChangeKind::Removed => {
                        AgentPolicyApiChangeKind::Removed
                    }
                    depgraph_core::policy::PublicApiChangeKind::Changed => {
                        AgentPolicyApiChangeKind::Changed
                    }
                },
                change.breaking,
                change.changed_fields.clone(),
                change.before.as_ref().map(|entity| entity.id.as_str()),
                change.after.as_ref().map(|entity| entity.id.as_str()),
                change.profile_id.as_deref(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let violations = result
        .result
        .violations
        .iter()
        .map(|violation| {
            AgentPolicyViolation::try_new(
                &violation.id,
                &violation.rule_id,
                match violation.severity {
                    depgraph_core::policy::PolicySeverity::Warning => AgentPolicySeverity::Warning,
                    depgraph_core::policy::PolicySeverity::Error => AgentPolicySeverity::Error,
                },
                &violation.message,
                &violation.source.id,
                &violation.target.id,
                violation.profile_id.as_deref(),
                violation.change_id.as_deref(),
                violation.suppression.is_some(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let annotations = result
        .annotations
        .iter()
        .map(|annotation| {
            AgentPolicyAnnotation::try_new(
                &annotation.violation_id,
                &annotation.rule_id,
                match annotation.level {
                    depgraph_core::policy::PolicyAnnotationLevel::Warning => {
                        AgentPolicyAnnotationLevel::Warning
                    }
                    depgraph_core::policy::PolicyAnnotationLevel::Error => {
                        AgentPolicyAnnotationLevel::Error
                    }
                },
                &annotation.path,
                annotation.start_line,
                annotation.start_column,
                annotation.end_line,
                annotation.end_column,
                &annotation.title,
                &annotation.message,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    AgentPolicyEvaluationResponse::try_new(
        &result.from_snapshot_id,
        &result.to_snapshot_id,
        &result.result.result_id,
        &result.result.policy_config_digest,
        result.result.exit_code == 0,
        result.result.exit_code,
        api_changes,
        violations,
        annotations,
        AgentPolicySummary {
            errors: result.result.summary.errors,
            warnings: result.result.summary.warnings,
            suppressed: result.result.summary.suppressed,
        },
        &result.collection_digest,
    )
}

fn project_graph_export(
    result: GraphExportResult,
) -> Result<AgentGraphExportResponse, ContractBuildError> {
    let format = match result.format {
        GraphExportFormat::Json => AgentGraphExportFormat::Json,
        GraphExportFormat::Dot => AgentGraphExportFormat::Dot,
        GraphExportFormat::Mermaid => AgentGraphExportFormat::Mermaid,
        GraphExportFormat::Graphml => AgentGraphExportFormat::Graphml,
    };
    let media_type = match result.media_type.as_str() {
        "application/json" => AgentGraphExportMediaType::Json,
        "text/vnd.graphviz" => AgentGraphExportMediaType::Graphviz,
        "text/vnd.mermaid" => AgentGraphExportMediaType::Mermaid,
        "application/graphml+xml" => AgentGraphExportMediaType::Graphml,
        _ => return Err(ContractBuildError::AgentDtoValue),
    };
    AgentGraphExportResponse::try_new(
        &result.schema_version,
        &result.snapshot_id,
        format,
        media_type,
        result.content,
        &result.content_sha256,
        result.output_bytes,
        result.node_count,
        result.edge_count,
    )
}

#[derive(Debug)]
enum ToolExecutionFailure {
    Service(DepgraphServiceError),
    Agent(AgentError),
    Journal {
        error: JournalError,
        operation_id: Option<OperationId>,
    },
    Response(ResponseMappingError),
}

impl From<DepgraphServiceError> for ToolExecutionFailure {
    fn from(error: DepgraphServiceError) -> Self {
        Self::Service(error)
    }
}

impl From<ResponseMappingError> for ToolExecutionFailure {
    fn from(error: ResponseMappingError) -> Self {
        Self::Response(error)
    }
}

fn request_protocol_version(
    server: &DepgraphMcpServer,
    request: &ClientRequest,
    context: &RequestContext<RoleServer>,
) -> ProtocolVersion {
    let requested = match request {
        ClientRequest::InitializeRequest(request) => Some(request.params.protocol_version.clone()),
        _ => context.protocol_version(),
    };
    requested
        .filter(|version| ServerHandler::supported_protocol_versions(server).contains(version))
        .unwrap_or_else(|| ServerHandler::get_info(server).protocol_version)
}

impl Service<RoleServer> for RequestScopedDepgraphMcpServer {
    fn handle_request(
        &self,
        request: <RoleServer as ServiceRole>::PeerReq,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<<RoleServer as ServiceRole>::Resp, McpError>> + '_ {
        let protocol = request_protocol_version(&self.inner, &request, &context);
        async move {
            EFFECTIVE_PROTOCOL_VERSION
                .scope(
                    protocol,
                    Service::<RoleServer>::handle_request(&self.inner, request, context),
                )
                .await
        }
    }

    fn handle_notification(
        &self,
        notification: <RoleServer as ServiceRole>::PeerNot,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = Result<(), McpError>> + '_ {
        Service::<RoleServer>::handle_notification(&self.inner, notification, context)
    }

    fn get_info(&self) -> <RoleServer as ServiceRole>::Info {
        ServerHandler::get_info(&self.inner)
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        ServerHandler::supported_protocol_versions(&self.inner)
    }
}

impl ServerHandler for DepgraphMcpServer {
    fn get_info(&self) -> ServerInfo {
        let _ = (
            &self.service,
            &self.compiler_pack,
            &self.runtime,
            &self.audit,
        );
        let mut tools = ToolsCapability::default();
        tools.list_changed = Some(false);
        let mut capabilities = ServerCapabilities::default();
        capabilities.tools = Some(tools);
        if EFFECTIVE_PROTOCOL_VERSION
            .try_with(|version| *version == ProtocolVersion::V_2026_07_28)
            .unwrap_or(false)
        {
            capabilities.extensions = ServerCapabilities::builder()
                .enable_tasks()
                .build()
                .extensions;
        }
        ServerInfo::new(capabilities).with_server_info(
            Implementation::new("depgraph-mcp", env!("CARGO_PKG_VERSION"))
                .with_description("depgraph MCP server"),
        )
    }

    fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<InitializeResult, McpError>> + '_ {
        context.peer.set_peer_info(request.clone());
        let requested = request.protocol_version;
        let fallback = ServerHandler::get_info(self).protocol_version;
        let negotiated = if ServerHandler::supported_protocol_versions(self).contains(&requested) {
            requested
        } else {
            fallback
        };
        let mut info = ServerHandler::get_info(self);
        info.protocol_version = negotiated;
        std::future::ready(Ok(info))
    }

    fn get_task(
        &self,
        request: GetTaskParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<GetTaskResult, McpError>> + '_ {
        let config = self.operation_config.clone();
        let repository_id = self.repository_id.clone();
        let runtime = self.runtime.clone();
        let client_tasks_capability = context
            .client_capabilities()
            .is_some_and(|capabilities| capabilities.supports_tasks());
        async move {
            require_client_tasks_capability(client_tasks_capability)?;
            let cancellation = CancellationToken::new();
            let request_cancellation = context.ct;
            if request_cancellation.is_cancelled() {
                cancellation.cancel();
            }
            let cancellation_bridge = tokio::spawn({
                let cancellation = cancellation.clone();
                async move {
                    request_cancellation.cancelled().await;
                    cancellation.cancel();
                }
            });
            let execution = runtime
                .execute_blocking(RuntimeClass::Read, cancellation, move |cancellation| {
                    if cancellation.is_cancelled() {
                        return Err(task_request_cancelled());
                    }
                    let result = task_get(&config, &repository_id, &request.task_id);
                    if cancellation.is_cancelled() {
                        Err(task_request_cancelled())
                    } else {
                        result
                    }
                })
                .await;
            cancellation_bridge.abort();
            execution.unwrap_or_else(|_| Err(task_request_unavailable()))
        }
    }

    fn cancel_task(
        &self,
        request: CancelTaskParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), McpError>> + '_ {
        let config = self.operation_config.clone();
        let runtime = self.runtime.clone();
        let client_tasks_capability = context
            .client_capabilities()
            .is_some_and(|capabilities| capabilities.supports_tasks());
        async move {
            require_client_tasks_capability(client_tasks_capability)?;
            let cancellation = CancellationToken::new();
            let request_cancellation = context.ct;
            if request_cancellation.is_cancelled() {
                cancellation.cancel();
            }
            let cancellation_bridge = tokio::spawn({
                let cancellation = cancellation.clone();
                async move {
                    request_cancellation.cancelled().await;
                    cancellation.cancel();
                }
            });
            let execution = runtime
                .execute_mutation_blocking(cancellation, move |cancellation| {
                    if cancellation.is_cancelled() {
                        return Err(task_request_cancelled());
                    }
                    task_cancel(&config, &request.task_id, &cancellation)
                })
                .await;
            cancellation_bridge.abort();
            execution.unwrap_or_else(|_| Err(task_request_unavailable()))
        }
    }

    fn update_task(
        &self,
        request: UpdateTaskParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), McpError>> + '_ {
        let config = self.operation_config.clone();
        let repository_id = self.repository_id.clone();
        let runtime = self.runtime.clone();
        let client_tasks_capability = context
            .client_capabilities()
            .is_some_and(|capabilities| capabilities.supports_tasks());
        async move {
            require_client_tasks_capability(client_tasks_capability)?;
            let cancellation = CancellationToken::new();
            let request_cancellation = context.ct;
            if request_cancellation.is_cancelled() {
                cancellation.cancel();
            }
            let cancellation_bridge = tokio::spawn({
                let cancellation = cancellation.clone();
                async move {
                    request_cancellation.cancelled().await;
                    cancellation.cancel();
                }
            });
            let execution = runtime
                .execute_blocking(RuntimeClass::Read, cancellation, move |cancellation| {
                    if cancellation.is_cancelled() {
                        return Err(task_request_cancelled());
                    }
                    // v1 tools never request mid-task input. Unknown response keys are ignored,
                    // but durable identity and current read authorization are still revalidated.
                    let result = task_get(&config, &repository_id, &request.task_id).map(|_| ());
                    if cancellation.is_cancelled() {
                        Err(task_request_cancelled())
                    } else {
                        result
                    }
                })
                .await;
            cancellation_bridge.abort();
            execution.unwrap_or_else(|_| Err(task_request_unavailable()))
        }
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, McpError>> + '_ {
        std::future::ready(Ok(ListToolsResult::with_all_items(self.tools.to_vec())))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tools
            .binary_search_by(|tool| tool.name.as_ref().cmp(name))
            .ok()
            .map(|index| self.tools[index].clone())
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let tool = request.name.into_owned();
        if self.get_tool(&tool).is_none() {
            return Err(McpError::invalid_params(
                "tool handler is unavailable",
                None,
            ));
        }
        if matches!(
            tool.as_str(),
            "scan_submit"
                | "runtime_trace_import_submit"
                | "export_file"
                | "daemon_start_submit"
                | "daemon_stop"
                | "resolve_build_submit"
        ) {
            let tasks_negotiated = EFFECTIVE_PROTOCOL_VERSION
                .try_with(|version| *version == ProtocolVersion::V_2026_07_28)
                .unwrap_or(false)
                && context
                    .client_capabilities()
                    .is_some_and(|capabilities| capabilities.supports_tasks());
            let arguments = request.arguments.unwrap_or_default();
            let operation_config = self.operation_config.clone();
            let repository_id = self.repository_id.clone();
            let compiler_pack_requirement = self.compiler_pack_requirement.clone();
            let submit_tool = tool.clone();
            let cancellation = CancellationToken::new();
            let request_cancellation = context.ct;
            if request_cancellation.is_cancelled() {
                cancellation.cancel();
            }
            let cancellation_bridge = tokio::spawn({
                let cancellation = cancellation.clone();
                async move {
                    request_cancellation.cancelled().await;
                    cancellation.cancel();
                }
            });
            let execution = self
                .runtime
                .execute_mutation_blocking(cancellation, move |cancellation| {
                    match submit_tool.as_str() {
                        "scan_submit" => execute_scan_submit(
                            &operation_config,
                            &repository_id,
                            arguments,
                            &cancellation,
                        ),
                        "runtime_trace_import_submit" => execute_runtime_import_submit(
                            &operation_config,
                            &repository_id,
                            arguments,
                            &cancellation,
                        ),
                        "export_file" => execute_export_file_submit(
                            &operation_config,
                            &repository_id,
                            arguments,
                            &cancellation,
                        ),
                        "daemon_start_submit" => execute_daemon_start_submit(
                            &operation_config,
                            &repository_id,
                            arguments,
                            &cancellation,
                        ),
                        "daemon_stop" => execute_daemon_stop_submit(
                            &operation_config,
                            &repository_id,
                            arguments,
                            &cancellation,
                        ),
                        "resolve_build_submit" => execute_resolve_build_submit(
                            &operation_config,
                            &repository_id,
                            &compiler_pack_requirement,
                            arguments,
                            &cancellation,
                        ),
                        _ => unreachable!("durable submit branch is closed"),
                    }
                })
                .await;
            cancellation_bridge.abort();

            let handle = match execution {
                Ok(Ok(handle)) => handle,
                Ok(Err(failure)) => {
                    return Ok(map_tool_failure(&self.repository_id, failure)?
                        .into_result()
                        .into());
                }
                Err(error) => {
                    let mapped = CanonicalResponseMapper::error(&ErrorEnvelope::new(
                        self.repository_id.clone(),
                        error.agent_error(self.runtime.deadline(RuntimeClass::Submit)),
                    ))
                    .map_err(internal_mapping_error)?;
                    return Ok(mapped.into_result().into());
                }
            };
            if tasks_negotiated {
                return Ok(CallToolResponse::Task(create_task_result(
                    handle.operation(),
                )?));
            }
            let accepted = DurableSubmitResult::baseline(OperationAccepted::new(
                handle.operation_id().clone(),
            ));
            let mapped = CanonicalResponseMapper::durable_submit(&accepted)
                .map_err(internal_mapping_error)?;
            return Ok(mapped.into_result().into());
        }
        if !matches!(
            tool.as_str(),
            "get_context"
                | "agent_nodes_list"
                | "agent_node_get"
                | "agent_sites_list"
                | "agent_edges_list"
                | "agent_evidence_list"
                | "snapshot_list"
                | "snapshot_get"
                | "profile_plan_get"
                | "daemon_get"
                | "doctor_get"
                | "graph_dependencies_list"
                | "graph_dependents_list"
                | "graph_path_get"
                | "graph_impact_get"
                | "graph_cycles_list"
                | "graph_unresolved_list"
                | "snapshot_diff_get"
                | "policy_evaluate"
                | "graph_export"
                | "graph_query"
                | "health_summary_get"
                | "health_findings_list"
                | "health_finding_get"
                | "health_audit_get"
                | "health_hotspots_list"
                | "runtime_trace_validate"
                | "operation_get"
                | "operation_result"
                | "operation_cancel"
                | "snapshot_name_create"
                | "repository_init"
        ) {
            return Err(McpError::invalid_params(
                "tool handler is unavailable",
                None,
            ));
        }
        let mutation_settlement = tool_uses_mutation_settlement(tool.as_str());
        let runtime_class = if mutation_settlement {
            RuntimeClass::Submit
        } else {
            RuntimeClass::Read
        };
        let arguments = request.arguments.unwrap_or_default();
        let service = self.service.clone();
        let operation_config = self.operation_config.clone();
        let repository_id = self.repository_id.clone();
        let compiler_pack_requirement = self.compiler_pack_requirement.clone();
        let cursor_key = self.cursor_key.clone();
        let cancellation = CancellationToken::new();
        let request_cancellation = context.ct;
        if request_cancellation.is_cancelled() {
            cancellation.cancel();
        }
        let cancellation_bridge = tokio::spawn({
            let cancellation = cancellation.clone();
            async move {
                request_cancellation.cancelled().await;
                cancellation.cancel();
            }
        });
        let operation = move |cancellation: CancellationToken| {
            if cancellation.is_cancelled() {
                return Err(ToolExecutionFailure::Service(
                    DepgraphServiceError::Cancelled,
                ));
            }
            let result = if matches!(
                tool.as_str(),
                "operation_get" | "operation_result" | "operation_cancel"
            ) {
                execute_operation_tool(&operation_config, &repository_id, &tool, arguments)
            } else if tool == "snapshot_name_create" {
                execute_snapshot_name_create(&service, &repository_id, arguments, &cancellation)
            } else if tool == "repository_init" {
                execute_repository_init(&service, &repository_id, arguments, &cancellation)
            } else {
                execute_catalog_read_tool(
                    &service,
                    &repository_id,
                    &cursor_key,
                    &compiler_pack_requirement,
                    &tool,
                    arguments,
                    &cancellation,
                )
            };
            finalize_completed_tool_call(&cancellation, result)
        };
        let execution = if mutation_settlement {
            self.runtime
                .execute_mutation_blocking(cancellation, operation)
                .await
        } else {
            self.runtime
                .execute_blocking(runtime_class, cancellation, operation)
                .await
        };
        cancellation_bridge.abort();

        let mapped = match execution {
            Ok(Ok(mapped)) => mapped,
            Ok(Err(failure)) => map_tool_failure(&self.repository_id, failure)?,
            Err(error) => CanonicalResponseMapper::error(&ErrorEnvelope::new(
                self.repository_id.clone(),
                error.agent_error(self.runtime.deadline(runtime_class)),
            ))
            .map_err(internal_mapping_error)?,
        };
        Ok(mapped.into_result().into())
    }
}

fn internal_mapping_error(_error: ResponseMappingError) -> McpError {
    McpError::internal_error("canonical tool response mapping failed", None)
}

fn tool_uses_mutation_settlement(tool: &str) -> bool {
    matches!(
        tool,
        "scan_submit"
            | "runtime_trace_import_submit"
            | "export_file"
            | "daemon_start_submit"
            | "daemon_stop"
            | "operation_cancel"
            | "snapshot_name_create"
            | "repository_init"
    )
}

fn finalize_completed_tool_call<T>(
    _cancellation: &CancellationToken,
    result: Result<T, ToolExecutionFailure>,
) -> Result<T, ToolExecutionFailure> {
    result
}

fn map_tool_failure(
    repository_id: &LogicalRepositoryId,
    failure: ToolExecutionFailure,
) -> Result<MappedToolResult, McpError> {
    match failure {
        ToolExecutionFailure::Service(error) => {
            CanonicalResponseMapper::service_error(repository_id.clone(), &error)
                .map_err(internal_mapping_error)
        }
        ToolExecutionFailure::Agent(error) => {
            CanonicalResponseMapper::error(&ErrorEnvelope::new(repository_id.clone(), error))
                .map_err(internal_mapping_error)
        }
        ToolExecutionFailure::Journal {
            error,
            operation_id,
        } => CanonicalResponseMapper::error(&ErrorEnvelope::new(
            repository_id.clone(),
            map_journal_error(&error, operation_id),
        ))
        .map_err(internal_mapping_error),
        ToolExecutionFailure::Response(error) => Err(internal_mapping_error(error)),
    }
}

/// Resolve a durable operation through the MCP Tasks wire contract. Task IDs are
/// deliberately identical to operation IDs so polling survives process restart.
fn task_get(
    config: &DepgraphServiceConfig,
    repository_id: &LogicalRepositoryId,
    task_id: &str,
) -> Result<GetTaskResult, McpError> {
    let operation_id = OperationId::parse(task_id)
        .map_err(|_| McpError::invalid_params("invalid taskId", None))?;
    let now_ms = system_now_ms().map_err(|_| McpError::internal_error("clock failure", None))?;
    let manager = OperationManager::open(config).map_err(task_journal_error)?;
    let operation = manager
        .get_with_clock(&operation_id, || system_now_ms().unwrap_or(now_ms))
        .map_err(task_journal_error)?;
    let payload = match operation.status() {
        OperationStatus::Queued | OperationStatus::Running | OperationStatus::Cancelling => {
            TaskPayload::Working
        }
        OperationStatus::Cancelled => TaskPayload::Cancelled,
        OperationStatus::Completed | OperationStatus::Failed => {
            let terminal = manager
                .result_with_clock(&operation_id, || system_now_ms().unwrap_or(now_ms))
                .map_err(task_journal_error)?;
            let mapped = map_terminal_operation_result(repository_id, &terminal)
                .map_err(task_mapping_error)?;
            TaskPayload::Completed {
                result: call_tool_result_object(mapped)?,
            }
        }
    };
    Ok(GetTaskResult::new(task_from_operation(
        &operation, payload,
    )?))
}

/// `tasks/cancel` intentionally delegates to the same sealed operation manager
/// used by `operation_cancel`; terminal and repeated cancellation are no-ops.
fn task_cancel(
    config: &DepgraphServiceConfig,
    task_id: &str,
    cancellation: &CancellationToken,
) -> Result<(), McpError> {
    let operation_id = OperationId::parse(task_id)
        .map_err(|_| McpError::invalid_params("invalid taskId", None))?;
    let now_ms = system_now_ms().map_err(|_| McpError::internal_error("clock failure", None))?;
    let mut manager = OperationManager::open(config).map_err(task_journal_error)?;
    if cancellation.is_cancelled() {
        return Err(task_request_cancelled());
    }
    manager
        .cancel_if_with_clock(
            &operation_id,
            || system_now_ms().unwrap_or(now_ms),
            || !cancellation.is_cancelled(),
        )
        .map_err(task_journal_error)?;
    Ok(())
}

fn create_task_result(operation: &OperationView) -> Result<CreateTaskResult, McpError> {
    let (status, polling) = create_task_status(operation.status());
    Ok(CreateTaskResult::new(task_metadata(
        operation, status, polling,
    )?))
}

fn create_task_status(status: OperationStatus) -> (TaskStatus, bool) {
    match status {
        OperationStatus::Queued | OperationStatus::Running | OperationStatus::Cancelling => {
            (TaskStatus::Working, true)
        }
        OperationStatus::Cancelled => (TaskStatus::Cancelled, false),
        OperationStatus::Completed | OperationStatus::Failed => (TaskStatus::Completed, false),
    }
}

fn task_from_operation(
    operation: &OperationView,
    payload: TaskPayload,
) -> Result<DetailedTask, McpError> {
    let task = if matches!(payload, TaskPayload::Working) {
        create_task_result(operation)?.task
    } else {
        task_metadata(operation, payload.status(), false)?
    };
    Ok(DetailedTask::new(task, payload))
}

fn task_metadata(
    operation: &OperationView,
    status: TaskStatus,
    polling: bool,
) -> Result<Task, McpError> {
    let timestamps = operation.timestamps();
    let retention = operation.retention();
    let created_at = task_timestamp(timestamps.created_at_ms())?;
    let updated_at = task_timestamp(timestamps.updated_at_ms())?;
    let ttl_ms = retention
        .retain_until_ms()
        .checked_sub(timestamps.created_at_ms())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| McpError::internal_error("invalid operation retention", None))?;
    let mut task = Task::new(
        operation.operation_id().as_str(),
        status,
        created_at,
        updated_at,
    )
    .with_ttl_ms(ttl_ms);
    if polling {
        task = task.with_poll_interval_ms(u64::from(TASK_POLL_INTERVAL_MS));
    }
    Ok(task)
}

fn call_tool_result_object(
    mapped: MappedToolResult,
) -> Result<serde_json::Map<String, serde_json::Value>, McpError> {
    serde_json::to_value(mapped.into_result())
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or_else(|| McpError::internal_error("canonical task result mapping failed", None))
}

fn task_timestamp(timestamp_ms: i64) -> Result<String, McpError> {
    DateTime::<Utc>::from_timestamp_millis(timestamp_ms)
        .map(|timestamp| timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .ok_or_else(|| McpError::internal_error("invalid operation timestamp", None))
}

fn task_journal_error(error: JournalError) -> McpError {
    match error {
        JournalError::RequestCancelled => task_request_cancelled(),
        JournalError::NotFound | JournalError::Expired => {
            McpError::invalid_params("unknown taskId", None)
        }
        JournalError::RepositoryMismatch | JournalError::CapabilityDenied => {
            McpError::invalid_request("task access denied", None)
        }
        _ => McpError::internal_error("durable operation journal failure", None),
    }
}

fn task_mapping_error(_error: ToolExecutionFailure) -> McpError {
    McpError::internal_error("canonical task result mapping failed", None)
}

fn task_request_cancelled() -> McpError {
    McpError::internal_error("task request cancelled", None)
}

fn task_request_unavailable() -> McpError {
    McpError::internal_error("task request unavailable", None)
}

fn require_client_tasks_capability(declared: bool) -> Result<(), McpError> {
    if declared {
        Ok(())
    } else {
        Err(McpError::new(
            ErrorCode::MISSING_REQUIRED_CLIENT_CAPABILITY,
            "missing required client capability",
            None,
        ))
    }
}

fn decode_arguments<T>(
    arguments: serde_json::Map<String, serde_json::Value>,
) -> Result<T, ToolExecutionFailure>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(serde_json::Value::Object(arguments))
        .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::InvalidInput))
}

fn validate_array_argument_lengths(
    arguments: &serde_json::Map<String, serde_json::Value>,
    names: &[&str],
) -> Result<(), ToolExecutionFailure> {
    if names.iter().any(|name| {
        arguments
            .get(*name)
            .and_then(serde_json::Value::as_array)
            .is_some_and(|items| items.len() > MAX_HEALTH_FILTER_ITEMS)
    }) {
        return Err(ToolExecutionFailure::Service(
            DepgraphServiceError::InvalidInput,
        ));
    }
    Ok(())
}

fn authorize_repository(
    contract_version: ContractVersion,
    requested: &LogicalRepositoryId,
    actual: &LogicalRepositoryId,
) -> Result<(), ToolExecutionFailure> {
    let _ = contract_version;
    if requested != actual {
        return Err(ToolExecutionFailure::Service(
            DepgraphServiceError::InvalidInput,
        ));
    }
    Ok(())
}

fn page_request(
    limit: Option<u16>,
    cursor: Option<Cursor>,
) -> Result<PageRequest, ToolExecutionFailure> {
    let max_items = limit
        .map(PageSize::new)
        .transpose()
        .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::InvalidInput))?
        .unwrap_or_default();
    Ok(PageRequest::new(
        max_items,
        PageByteLimit::default(),
        cursor,
    ))
}

fn execute_scan_submit(
    config: &DepgraphServiceConfig,
    repository_id: &LogicalRepositoryId,
    arguments: serde_json::Map<String, serde_json::Value>,
    cancellation: &CancellationToken,
) -> Result<OperationHandle, ToolExecutionFailure> {
    let arguments = decode_arguments::<ScanSubmitArguments>(arguments)?;
    authorize_repository(
        arguments.contract_version,
        &arguments.repository_id,
        repository_id,
    )?;
    if cancellation.is_cancelled() {
        return Err(ToolExecutionFailure::Service(
            DepgraphServiceError::Cancelled,
        ));
    }

    let normalized_input = serde_json::json!({
        "no_cache": arguments.no_cache,
        "strict": arguments.strict,
    });
    submit_durable_operation(
        config,
        OperationKind::ScanSubmit,
        &normalized_input,
        &arguments.idempotency_key,
        cancellation,
    )
}

fn execute_daemon_start_submit(
    config: &DepgraphServiceConfig,
    repository_id: &LogicalRepositoryId,
    arguments: serde_json::Map<String, serde_json::Value>,
    cancellation: &CancellationToken,
) -> Result<OperationHandle, ToolExecutionFailure> {
    let arguments = decode_arguments::<DaemonStartSubmitArguments>(arguments)?;
    authorize_repository(
        arguments.contract_version,
        &arguments.repository_id,
        repository_id,
    )?;
    if cancellation.is_cancelled() {
        return Err(ToolExecutionFailure::Service(
            DepgraphServiceError::Cancelled,
        ));
    }
    submit_durable_operation(
        config,
        OperationKind::DaemonStartSubmit,
        &serde_json::json!({"strict": arguments.strict}),
        &arguments.idempotency_key,
        cancellation,
    )
}

fn execute_daemon_stop_submit(
    config: &DepgraphServiceConfig,
    repository_id: &LogicalRepositoryId,
    arguments: serde_json::Map<String, serde_json::Value>,
    cancellation: &CancellationToken,
) -> Result<OperationHandle, ToolExecutionFailure> {
    let arguments = decode_arguments::<DaemonStopArguments>(arguments)?;
    authorize_repository(
        arguments.contract_version,
        &arguments.repository_id,
        repository_id,
    )?;
    if cancellation.is_cancelled() {
        return Err(ToolExecutionFailure::Service(
            DepgraphServiceError::Cancelled,
        ));
    }
    submit_durable_operation(
        config,
        OperationKind::DaemonStop,
        &serde_json::json!({}),
        &arguments.idempotency_key,
        cancellation,
    )
}

fn execute_resolve_build_submit(
    config: &DepgraphServiceConfig,
    repository_id: &LogicalRepositoryId,
    compiler_pack_requirement: &Path,
    arguments: serde_json::Map<String, serde_json::Value>,
    cancellation: &CancellationToken,
) -> Result<OperationHandle, ToolExecutionFailure> {
    let arguments = decode_arguments::<ResolveBuildSubmitArguments>(arguments)?;
    authorize_repository(
        arguments.contract_version,
        &arguments.repository_id,
        repository_id,
    )?;
    // False acknowledgement and non-exact modes fail before journal, store
    // mutation, runner resolution, probes, or project child creation.
    if !arguments.acknowledgement || !arguments.rust_compiler_precise {
        return Err(ToolExecutionFailure::Service(
            DepgraphServiceError::InvalidInput,
        ));
    }
    if cancellation.is_cancelled() {
        return Err(ToolExecutionFailure::Service(
            DepgraphServiceError::Cancelled,
        ));
    }
    let requirement = read_compiler_pack_requirement(compiler_pack_requirement)
        .and_then(|requirement| verify_compiler_pack(&requirement).map(|pack| (requirement, pack)))
        .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::Integrity))?;
    let normalized_input = serde_json::json!({
        "acknowledgement": true,
        "compiler_pack_manifest_sha256": requirement.1.attestation.manifest_sha256,
        "rust_compiler_precise": true,
    });
    submit_durable_operation_with_compiler_pack(
        config,
        OperationKind::ResolveBuildSubmit,
        &normalized_input,
        &arguments.idempotency_key,
        compiler_pack_requirement,
        cancellation,
    )
}

fn execute_export_file_submit(
    config: &DepgraphServiceConfig,
    repository_id: &LogicalRepositoryId,
    arguments: serde_json::Map<String, serde_json::Value>,
    cancellation: &CancellationToken,
) -> Result<OperationHandle, ToolExecutionFailure> {
    let arguments = decode_arguments::<ExportFileSubmitArguments>(arguments)?;
    authorize_repository(
        arguments.contract_version,
        &arguments.repository_id,
        repository_id,
    )?;
    if cancellation.is_cancelled() {
        return Err(ToolExecutionFailure::Service(
            DepgraphServiceError::Cancelled,
        ));
    }

    let service = DepgraphService::new(config.clone());
    let confined_output_path =
        depgraph_core::service::RepositoryRelativePath::parse(arguments.output_path.as_str())?;
    let selector = arguments.selector.map(|value| value.as_str().to_owned());
    let format: GraphExportFormat = arguments.format.into();
    let requested_snapshot =
        SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
    let existing_input = existing_export_file_submission_input(config, &arguments.idempotency_key)?;
    let replay_snapshot;
    let snapshot_to_resolve = match (&requested_snapshot, existing_input.as_ref()) {
        (SnapshotLocator::Current, Some(input)) => {
            replay_snapshot = retained_stable_snapshot_locator(input)?;
            &replay_snapshot
        }
        _ => &requested_snapshot,
    };
    let resolved_snapshot =
        service.resolve_snapshot_id_cancellable(snapshot_to_resolve, cancellation)?;
    let snapshot_id = parse_snapshot_id(resolved_snapshot.as_str())?;
    let max_nodes = arguments
        .max_nodes
        .unwrap_or(DEFAULT_GRAPH_EXPORT_MAX_NODES);
    let max_edges = arguments
        .max_edges
        .unwrap_or(DEFAULT_GRAPH_EXPORT_MAX_EDGES);
    GraphExportRequest::try_new(
        SnapshotLocator::StableId(resolved_snapshot.as_str().to_owned()),
        format,
        selector.clone(),
        GraphQueryFilter::default(),
        max_nodes,
        max_edges,
    )?;
    let destination_precondition = match existing_input.as_ref() {
        Some(input) => match input.get("destination_precondition") {
            Some(value) => Some(
                serde_json::from_value::<RepositoryOutputPrecondition>(value.clone()).map_err(
                    |_| ToolExecutionFailure::Journal {
                        error: JournalError::IntegrityFailure,
                        operation_id: None,
                    },
                )?,
            ),
            None if !arguments.overwrite => None,
            None => {
                return Err(ToolExecutionFailure::Journal {
                    error: JournalError::IntegrityFailure,
                    operation_id: None,
                });
            }
        },
        None => Some(service.repository_output_precondition(&confined_output_path, cancellation)?),
    };
    let mut normalized_input = serde_json::json!({
        "output_path": arguments.output_path.as_str(),
        "overwrite": arguments.overwrite,
        "format": format,
        "snapshot_id": snapshot_id,
        "selector": selector,
        "max_nodes": max_nodes,
        "max_edges": max_edges,
    });
    if let Some(destination_precondition) = destination_precondition {
        normalized_input["destination_precondition"] =
            serde_json::to_value(destination_precondition)
                .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::Internal))?;
    }
    submit_export_file_with_conflict_recovery(
        &normalized_input,
        &requested_snapshot,
        || existing_export_file_submission_input(config, &arguments.idempotency_key),
        |input| {
            submit_durable_operation(
                config,
                OperationKind::ExportFile,
                input,
                &arguments.idempotency_key,
                cancellation,
            )
        },
    )
}

fn submit_export_file_with_conflict_recovery<T>(
    normalized_input: &serde_json::Value,
    requested_snapshot: &SnapshotLocator,
    mut existing_input: impl FnMut() -> Result<Option<serde_json::Value>, ToolExecutionFailure>,
    mut submit: impl FnMut(&serde_json::Value) -> Result<T, ToolExecutionFailure>,
) -> Result<T, ToolExecutionFailure> {
    let conflict = match submit(normalized_input) {
        Ok(handle) => return Ok(handle),
        Err(
            error @ ToolExecutionFailure::Journal {
                error: JournalError::IdempotencyConflict,
                ..
            },
        ) => error,
        Err(error) => return Err(error),
    };
    let Some(winner_input) = existing_input()? else {
        return Err(conflict);
    };
    if !export_file_inputs_are_exact_replay(normalized_input, &winner_input, requested_snapshot) {
        return Err(conflict);
    }
    submit(&winner_input)
}

fn export_file_inputs_are_exact_replay(
    candidate: &serde_json::Value,
    winner: &serde_json::Value,
    requested_snapshot: &SnapshotLocator,
) -> bool {
    const STATIC_FIELDS: [&str; 7] = [
        "output_path",
        "overwrite",
        "format",
        "selector",
        "max_nodes",
        "max_edges",
        "destination_precondition",
    ];
    if STATIC_FIELDS
        .iter()
        .any(|field| candidate.get(field) != winner.get(field))
    {
        return false;
    }
    if !matches!(requested_snapshot, SnapshotLocator::Current)
        && candidate.get("snapshot_id") != winner.get("snapshot_id")
    {
        return false;
    }
    matches!(
        winner.get("snapshot_id").and_then(serde_json::Value::as_str),
        Some(snapshot_id) if SnapshotLocator::parse(snapshot_id).is_ok_and(|locator| {
            matches!(locator, SnapshotLocator::StableId(_))
        })
    ) && winner.get("destination_precondition").is_some()
}

fn existing_export_file_submission_input(
    config: &DepgraphServiceConfig,
    idempotency_key: &IdempotencyKey,
) -> Result<Option<serde_json::Value>, ToolExecutionFailure> {
    let now_ms = system_now_ms()?;
    OperationManager::existing_submission_binding_read_only_with_clock(
        config,
        OperationKind::ExportFile,
        idempotency_key.as_str().as_bytes(),
        || system_now_ms().unwrap_or(now_ms),
    )
    .map_err(|error| ToolExecutionFailure::Journal {
        error,
        operation_id: None,
    })
    .map(|binding| binding.map(|binding| binding.normalized_input().value().clone()))
}

fn execute_runtime_import_submit(
    config: &DepgraphServiceConfig,
    repository_id: &LogicalRepositoryId,
    arguments: serde_json::Map<String, serde_json::Value>,
    cancellation: &CancellationToken,
) -> Result<OperationHandle, ToolExecutionFailure> {
    let arguments = decode_arguments::<RuntimeImportSubmitArguments>(arguments)?;
    authorize_repository(
        arguments.contract_version,
        &arguments.repository_id,
        repository_id,
    )?;
    if cancellation.is_cancelled() {
        return Err(ToolExecutionFailure::Service(
            DepgraphServiceError::Cancelled,
        ));
    }

    let requested_locator =
        SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
    let trace_file = arguments.trace_file.map(TryInto::try_into).transpose()?;
    let source = depgraph_core::service::RuntimeTraceSourceRequest {
        trace: arguments.trace,
        trace_file,
    };
    let service = DepgraphService::new(config.clone());
    // This entire source boundary is mutation-free. In particular, an existing
    // older journal cannot be opened (and migrated) by malformed, secret-bearing,
    // oversized, or unconfined trace input.
    let prevalidated = service.prevalidate_runtime_trace_source(&source, cancellation)?;

    // Only a valid raw trace may inspect an existing binding before resolving a
    // dynamic current selector.
    let existing_input =
        existing_runtime_import_submission_input(config, &arguments.idempotency_key)?;

    // Authenticate a known replay completely against the migration-compatible
    // read-only store. A conflicting valid request must not gain authority to
    // migrate the evidence store merely by reusing an existing key.
    if let Some(existing_input) = existing_input.as_ref() {
        prepare_runtime_import_replay_candidate_read_only(
            &service,
            &source,
            prevalidated.clone(),
            &requested_locator,
            existing_input,
            cancellation,
        )?;
    }

    // The complete existing runtime-validation boundary still runs before a
    // new journal submission. Replays pin default/current to the immutable
    // snapshot retained by the original operation, while explicit selectors
    // continue to resolve and must reproduce that same binding.
    let normalized_input = prepare_runtime_import_submission_input(
        &service,
        &source,
        prevalidated.clone(),
        &requested_locator,
        existing_input.as_ref(),
        RuntimeBindingResolution::Requested,
        cancellation,
    )?;
    submit_runtime_import_with_conflict_recovery(
        RuntimeImportSubmissionContext {
            config,
            service: &service,
            source: &source,
            initial_prevalidation: &prevalidated,
            requested_locator: &requested_locator,
            idempotency_key: &arguments.idempotency_key,
            cancellation,
        },
        normalized_input,
        |input| {
            submit_durable_operation(
                config,
                OperationKind::RuntimeTraceImportSubmit,
                input,
                &arguments.idempotency_key,
                cancellation,
            )
        },
    )
}

#[derive(Clone, Copy)]
enum RuntimeBindingResolution {
    Requested,
    RetainedStable,
}

fn existing_runtime_import_submission_input(
    config: &DepgraphServiceConfig,
    idempotency_key: &IdempotencyKey,
) -> Result<Option<serde_json::Value>, ToolExecutionFailure> {
    let now_ms = system_now_ms()?;
    OperationManager::existing_submission_binding_read_only_with_clock(
        config,
        OperationKind::RuntimeTraceImportSubmit,
        idempotency_key.as_str().as_bytes(),
        || system_now_ms().unwrap_or(now_ms),
    )
    .map_err(|error| ToolExecutionFailure::Journal {
        error,
        operation_id: None,
    })
    .map(|binding| binding.map(|binding| binding.normalized_input().value().clone()))
}

fn retained_stable_snapshot_locator(
    input: &serde_json::Value,
) -> Result<SnapshotLocator, ToolExecutionFailure> {
    let snapshot_id = input
        .get("snapshot_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ToolExecutionFailure::Journal {
            error: JournalError::IntegrityFailure,
            operation_id: None,
        })?;
    match SnapshotLocator::parse(snapshot_id) {
        Ok(SnapshotLocator::StableId(snapshot_id)) => Ok(SnapshotLocator::StableId(snapshot_id)),
        _ => Err(ToolExecutionFailure::Journal {
            error: JournalError::IntegrityFailure,
            operation_id: None,
        }),
    }
}

fn prepare_runtime_import_submission_input(
    service: &DepgraphService,
    source: &depgraph_core::service::RuntimeTraceSourceRequest,
    mut prevalidated: depgraph_core::service::RuntimeTraceSourcePrevalidation,
    requested_locator: &SnapshotLocator,
    existing_input: Option<&serde_json::Value>,
    binding_resolution: RuntimeBindingResolution,
    cancellation: &CancellationToken,
) -> Result<serde_json::Value, ToolExecutionFailure> {
    // Reopen after every journal inspection. Stable file reads reject identity
    // changes during the read, and this comparison rejects content drift from
    // the request's original raw prevalidation.
    if source.trace_file.is_some() {
        prevalidated =
            service.revalidate_runtime_trace_source(source, &prevalidated, cancellation)?;
    }
    let locator = match (binding_resolution, requested_locator, existing_input) {
        (RuntimeBindingResolution::RetainedStable, _, Some(input))
        | (RuntimeBindingResolution::Requested, SnapshotLocator::Current, Some(input)) => {
            retained_stable_snapshot_locator(input)?
        }
        (RuntimeBindingResolution::RetainedStable, _, None) => {
            return Err(ToolExecutionFailure::Journal {
                error: JournalError::IdempotencyConflict,
                operation_id: None,
            });
        }
        (RuntimeBindingResolution::Requested, locator, _) => locator.clone(),
    };
    let prepared = service.prepare_runtime_import_prevalidated(
        prevalidated,
        &ServiceSnapshotSelector::Locator(locator),
        source.trace_file.clone(),
        cancellation,
    )?;
    match existing_input {
        Some(existing_input) => {
            runtime_import_replay_input(prepared.durable_input(), existing_input)
        }
        None => Ok(prepared.durable_input()),
    }
}

fn prepare_runtime_import_replay_candidate_read_only(
    service: &DepgraphService,
    source: &depgraph_core::service::RuntimeTraceSourceRequest,
    mut prevalidated: depgraph_core::service::RuntimeTraceSourcePrevalidation,
    requested_locator: &SnapshotLocator,
    existing_input: &serde_json::Value,
    cancellation: &CancellationToken,
) -> Result<serde_json::Value, ToolExecutionFailure> {
    if source.trace_file.is_some() {
        prevalidated =
            service.revalidate_runtime_trace_source(source, &prevalidated, cancellation)?;
    }
    let locator = if matches!(requested_locator, SnapshotLocator::Current) {
        retained_stable_snapshot_locator(existing_input)?
    } else {
        requested_locator.clone()
    };
    let binding = service.prepare_runtime_import_durable_binding_prevalidated(
        prevalidated,
        &ServiceSnapshotSelector::Locator(locator),
        source.trace_file.clone(),
        cancellation,
    )?;
    runtime_import_replay_input(binding.durable_input(), existing_input)
}

fn runtime_import_replay_input(
    mut candidate: serde_json::Value,
    existing_input: &serde_json::Value,
) -> Result<serde_json::Value, ToolExecutionFailure> {
    // Journals created by the initial Issue #313 implementation did not retain
    // session_id or runtime_trace_digest. Revalidate every retained identity,
    // then submit their exact old normalized input unchanged.
    if existing_input.get("session_id").is_none()
        && let Some(object) = candidate.as_object_mut()
    {
        object.remove("session_id");
        object.remove("runtime_trace_digest");
    }
    if &candidate != existing_input {
        return Err(ToolExecutionFailure::Journal {
            error: JournalError::IdempotencyConflict,
            operation_id: None,
        });
    }
    Ok(existing_input.clone())
}

struct RuntimeImportSubmissionContext<'a> {
    config: &'a DepgraphServiceConfig,
    service: &'a DepgraphService,
    source: &'a depgraph_core::service::RuntimeTraceSourceRequest,
    initial_prevalidation: &'a depgraph_core::service::RuntimeTraceSourcePrevalidation,
    requested_locator: &'a SnapshotLocator,
    idempotency_key: &'a IdempotencyKey,
    cancellation: &'a CancellationToken,
}

fn submit_runtime_import_with_conflict_recovery(
    context: RuntimeImportSubmissionContext<'_>,
    normalized_input: serde_json::Value,
    mut submit: impl FnMut(&serde_json::Value) -> Result<OperationHandle, ToolExecutionFailure>,
) -> Result<OperationHandle, ToolExecutionFailure> {
    let conflict = match submit(&normalized_input) {
        Ok(handle) => return Ok(handle),
        Err(
            failure @ ToolExecutionFailure::Journal {
                error: JournalError::IdempotencyConflict,
                ..
            },
        ) => failure,
        Err(failure) => return Err(failure),
    };

    // A concurrent submit may establish the key after this request's first
    // lookup. Re-fetch that binding and re-open the original trace. Only a
    // dynamic current selector may adopt the winner's retained stable snapshot;
    // explicit selectors must resolve as requested and pass the same exact
    // durable-input comparison as ordinary replays.
    let Some(existing_input) =
        existing_runtime_import_submission_input(context.config, context.idempotency_key)?
    else {
        return Err(conflict);
    };
    let binding_resolution = if matches!(context.requested_locator, SnapshotLocator::Current) {
        RuntimeBindingResolution::RetainedStable
    } else {
        RuntimeBindingResolution::Requested
    };
    let replay_input = prepare_runtime_import_submission_input(
        context.service,
        context.source,
        context.initial_prevalidation.clone(),
        context.requested_locator,
        Some(&existing_input),
        binding_resolution,
        context.cancellation,
    )?;
    let handle = submit(&replay_input)?;
    if handle.created() {
        return Err(ToolExecutionFailure::Journal {
            error: JournalError::IntegrityFailure,
            operation_id: Some(handle.operation_id().clone()),
        });
    }
    Ok(handle)
}

fn submit_durable_operation(
    config: &DepgraphServiceConfig,
    kind: OperationKind,
    normalized_input: &serde_json::Value,
    idempotency_key: &IdempotencyKey,
    cancellation: &CancellationToken,
) -> Result<OperationHandle, ToolExecutionFailure> {
    submit_durable_operation_with_optional_compiler_pack(
        config,
        kind,
        normalized_input,
        idempotency_key,
        None,
        cancellation,
    )
}

fn submit_durable_operation_with_compiler_pack(
    config: &DepgraphServiceConfig,
    kind: OperationKind,
    normalized_input: &serde_json::Value,
    idempotency_key: &IdempotencyKey,
    compiler_pack_requirement: &Path,
    cancellation: &CancellationToken,
) -> Result<OperationHandle, ToolExecutionFailure> {
    submit_durable_operation_with_optional_compiler_pack(
        config,
        kind,
        normalized_input,
        idempotency_key,
        Some(compiler_pack_requirement),
        cancellation,
    )
}

fn submit_durable_operation_with_optional_compiler_pack(
    config: &DepgraphServiceConfig,
    kind: OperationKind,
    normalized_input: &serde_json::Value,
    idempotency_key: &IdempotencyKey,
    compiler_pack_requirement: Option<&Path>,
    cancellation: &CancellationToken,
) -> Result<OperationHandle, ToolExecutionFailure> {
    let now_ms = system_now_ms()?;
    let deadline_ms = now_ms
        .checked_add(SCAN_EXECUTION_DEADLINE_MS)
        .ok_or_else(|| ToolExecutionFailure::Agent(internal_agent_error()))?;
    let request = SubmitRequest::new(
        config,
        kind,
        normalized_input,
        idempotency_key.as_str().as_bytes(),
        deadline_ms,
    )
    .map_err(|error| ToolExecutionFailure::Journal {
        error,
        operation_id: None,
    })?;
    // Resolve and validate the executable before the durable commit. Once the
    // record and handoff are visible, launch failure is reported without ever
    // returning an accepted handle for work that was not handed to a runner.
    let launcher = OperationRunnerLauncher::resolve()
        .map_err(|_| ToolExecutionFailure::Agent(internal_agent_error()))?;
    let startup = match compiler_pack_requirement {
        Some(path) => RunnerStartupConfig::new_with_compiler_pack_requirement(config.clone(), path),
        None => RunnerStartupConfig::new(config.clone()),
    }
    .map_err(|_| ToolExecutionFailure::Agent(internal_agent_error()))?;
    let mut manager =
        OperationManager::open(config).map_err(|error| ToolExecutionFailure::Journal {
            error,
            operation_id: None,
        })?;
    let handle = manager
        .submit_with_clock(&request, || system_now_ms().unwrap_or(now_ms))
        .map_err(|error| ToolExecutionFailure::Journal {
            error,
            operation_id: None,
        })?;

    // A fresh manager proves that the committed operation/handoff is already
    // reconnect-visible before the transport receives its durable identity.
    let observer =
        OperationManager::open(config).map_err(|error| ToolExecutionFailure::Journal {
            error,
            operation_id: Some(handle.operation_id().clone()),
        })?;
    let visible = observer
        .get_with_clock(handle.operation_id(), || system_now_ms().unwrap_or(now_ms))
        .map_err(|error| ToolExecutionFailure::Journal {
            error,
            operation_id: Some(handle.operation_id().clone()),
        })?;
    if visible.operation_id() != handle.operation_id() {
        return Err(ToolExecutionFailure::Journal {
            error: JournalError::IntegrityFailure,
            operation_id: Some(handle.operation_id().clone()),
        });
    }
    handoff_submitted_scan(&mut manager, &startup, &handle, cancellation, |startup| {
        launcher
            .launch(startup)
            .map(|_| ())
            .map_err(|_| ToolExecutionFailure::Agent(internal_agent_error()))
    })?;
    Ok(handle)
}

fn handoff_submitted_scan(
    manager: &mut OperationManager,
    startup: &RunnerStartupConfig,
    handle: &OperationHandle,
    cancellation: &CancellationToken,
    launch: impl FnOnce(&RunnerStartupConfig) -> Result<(), ToolExecutionFailure>,
) -> Result<(), ToolExecutionFailure> {
    if handle.status().is_terminal() {
        return if handle.status() == OperationStatus::Cancelled {
            Err(ToolExecutionFailure::Service(
                DepgraphServiceError::Cancelled,
            ))
        } else {
            Ok(())
        };
    }
    let Some(launch) = cancellation.run_if_active(|| launch(startup)) else {
        // Only this request's newly-created handoff may be terminalized here.
        // A replay observes pre-existing durable work; cancelling the transport
        // retry must not mutate that operation.
        if handle.created() {
            let now_ms = system_now_ms()?;
            manager
                .cancel_before_launch_with_clock(handle.operation_id(), || {
                    system_now_ms().unwrap_or(now_ms)
                })
                .map_err(|error| ToolExecutionFailure::Journal {
                    error,
                    operation_id: Some(handle.operation_id().clone()),
                })?;
        }
        return Err(ToolExecutionFailure::Service(
            DepgraphServiceError::Cancelled,
        ));
    };
    match launch {
        Ok(()) => Ok(()),
        Err(error) => {
            // A fresh operation whose runner failed to launch has not been
            // handed off and its ID will not reach the client. Terminalize it
            // so a later runner cannot claim and execute orphaned work.
            if handle.created() {
                let now_ms = system_now_ms()?;
                manager
                    .cancel_before_launch_with_clock(handle.operation_id(), || {
                        system_now_ms().unwrap_or(now_ms)
                    })
                    .map_err(|journal_error| ToolExecutionFailure::Journal {
                        error: journal_error,
                        operation_id: Some(handle.operation_id().clone()),
                    })?;
            }
            Err(error)
        }
    }
}

fn execute_repository_init(
    service: &DepgraphService,
    repository_id: &LogicalRepositoryId,
    arguments: serde_json::Map<String, serde_json::Value>,
    cancellation: &CancellationToken,
) -> Result<MappedToolResult, ToolExecutionFailure> {
    let arguments = decode_arguments::<RepositoryInitArguments>(arguments)?;
    authorize_repository(
        arguments.contract_version,
        &arguments.repository_id,
        repository_id,
    )?;
    let initialized =
        service.repository_init(&RepositoryInitRequest::new(arguments.force), cancellation)?;
    let result =
        AgentRepositoryInitOutcome::try_from(&initialized).map_err(contract_mapping_error)?;
    CanonicalResponseMapper::success(&SuccessEnvelope::new(repository_id.clone(), None, result))
        .map_err(Into::into)
}

fn execute_snapshot_name_create(
    service: &DepgraphService,
    repository_id: &LogicalRepositoryId,
    arguments: serde_json::Map<String, serde_json::Value>,
    cancellation: &CancellationToken,
) -> Result<MappedToolResult, ToolExecutionFailure> {
    let arguments = decode_arguments::<SnapshotNameCreateArguments>(arguments)?;
    authorize_repository(
        arguments.contract_version,
        &arguments.repository_id,
        repository_id,
    )?;
    let selector = SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
    let named = service.snapshot_name_create(
        &SnapshotNameCreateRequest::new(arguments.name.as_str(), selector),
        cancellation,
    )?;
    let snapshot_id = parse_snapshot_id(named.snapshot().id())?;
    let result = AgentNamedSnapshot::try_from(&named)
        .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::Integrity))?;
    CanonicalResponseMapper::success(&SuccessEnvelope::new(
        repository_id.clone(),
        Some(snapshot_id),
        result,
    ))
    .map_err(Into::into)
}

fn execute_operation_tool(
    config: &DepgraphServiceConfig,
    repository_id: &LogicalRepositoryId,
    tool: &str,
    arguments: serde_json::Map<String, serde_json::Value>,
) -> Result<MappedToolResult, ToolExecutionFailure> {
    let arguments = decode_arguments::<OperationArguments>(arguments)?;
    let _ = arguments.contract_version;
    if &arguments.repository_id != repository_id {
        return Err(ToolExecutionFailure::Agent(AgentError::new(
            AgentErrorCode::CapabilityDenied,
            false,
            AgentRemediation::EnableRequiredCapability,
            None,
        )));
    }
    let operation_id = arguments.operation_id;
    let now_ms = system_now_ms()?;
    let journal_failure = |error| ToolExecutionFailure::Journal {
        error,
        operation_id: Some(operation_id.clone()),
    };

    match tool {
        "operation_get" => {
            let manager = OperationManager::open(config).map_err(&journal_failure)?;
            let operation = manager
                .get_with_clock(&operation_id, || system_now_ms().unwrap_or(now_ms))
                .map_err(&journal_failure)?;
            map_operation_success(repository_id, &operation)
        }
        "operation_result" => {
            let manager = OperationManager::open(config).map_err(&journal_failure)?;
            let result = manager
                .result_with_clock(&operation_id, || system_now_ms().unwrap_or(now_ms))
                .map_err(&journal_failure)?;
            map_terminal_operation_result(repository_id, &result)
        }
        "operation_cancel" => {
            let mut manager = OperationManager::open(config).map_err(&journal_failure)?;
            manager
                .cancel_with_clock(&operation_id, || system_now_ms().unwrap_or(now_ms))
                .map_err(&journal_failure)?;
            let operation = manager
                .get_with_clock(&operation_id, || system_now_ms().unwrap_or(now_ms))
                .map_err(&journal_failure)?;
            map_operation_success(repository_id, &operation)
        }
        _ => Err(ToolExecutionFailure::Service(
            DepgraphServiceError::NotFound,
        )),
    }
}

fn map_terminal_operation_result(
    repository_id: &LogicalRepositoryId,
    result: &OperationResultView,
) -> Result<MappedToolResult, ToolExecutionFailure> {
    let operation_id = result.operation().operation_id();
    let journal_failure = || ToolExecutionFailure::Journal {
        error: JournalError::IntegrityFailure,
        operation_id: Some(operation_id.clone()),
    };
    match result.outcome() {
        OperationOutcome::Completed(payload) => {
            let contract = PortableTerminalOutputContract::for_originating_tool(
                result.operation_kind().as_str(),
            )
            .ok_or_else(&journal_failure)?;
            let output = contract
                .deserialize(payload.value().clone())
                .map_err(|_| journal_failure())?;
            if output.repository_id() != repository_id {
                return Err(journal_failure());
            }
            CanonicalResponseMapper::terminal_output(&output).map_err(Into::into)
        }
        OperationOutcome::Failed(payload) => {
            map_stored_operation_error(repository_id, operation_id, payload.as_str())
        }
        OperationOutcome::Cancelled => CanonicalResponseMapper::error(&ErrorEnvelope::new(
            repository_id.clone(),
            AgentError::new(
                AgentErrorCode::Cancelled,
                false,
                AgentRemediation::Retry,
                Some(AgentErrorDetails::Operation {
                    operation_id: operation_id.clone(),
                }),
            ),
        ))
        .map_err(Into::into),
    }
}

fn map_operation_success(
    repository_id: &LogicalRepositoryId,
    operation: &OperationView,
) -> Result<MappedToolResult, ToolExecutionFailure> {
    let operation = project_operation(operation)?;
    CanonicalResponseMapper::success(&SuccessEnvelope::new(
        repository_id.clone(),
        None,
        operation,
    ))
    .map_err(Into::into)
}

fn project_operation(operation: &OperationView) -> Result<AgentOperation, ToolExecutionFailure> {
    let timestamps = operation.timestamps();
    let retention = operation.retention();
    let to_u64 = |value: i64| {
        u64::try_from(value).map_err(|_| ToolExecutionFailure::Journal {
            error: JournalError::IntegrityFailure,
            operation_id: Some(operation.operation_id().clone()),
        })
    };
    AgentOperation::new(
        operation.operation_id().clone(),
        match operation.status() {
            OperationStatus::Queued => AgentOperationStatus::Queued,
            OperationStatus::Running => AgentOperationStatus::Running,
            OperationStatus::Cancelling => AgentOperationStatus::Cancelling,
            OperationStatus::Completed => AgentOperationStatus::Completed,
            OperationStatus::Failed => AgentOperationStatus::Failed,
            OperationStatus::Cancelled => AgentOperationStatus::Cancelled,
        },
        operation.progress().completed_units(),
        operation.progress().total_units(),
        to_u64(timestamps.created_at_ms())?,
        to_u64(timestamps.updated_at_ms())?,
        timestamps.terminal_at_ms().map(to_u64).transpose()?,
        to_u64(retention.execution_deadline_ms())?,
        to_u64(retention.retain_until_ms())?,
    )
    .map_err(|_| ToolExecutionFailure::Journal {
        error: JournalError::IntegrityFailure,
        operation_id: Some(operation.operation_id().clone()),
    })
}

fn map_stored_operation_error(
    repository_id: &LogicalRepositoryId,
    operation_id: &OperationId,
    payload: &str,
) -> Result<MappedToolResult, ToolExecutionFailure> {
    let error = match payload {
        DEADLINE_EXCEEDED_ERROR_JSON => AgentError::new(
            AgentErrorCode::ResourceExhausted,
            false,
            AgentRemediation::Retry,
            Some(AgentErrorDetails::Operation {
                operation_id: operation_id.clone(),
            }),
        ),
        EXECUTION_STATE_UNKNOWN_ERROR_JSON => AgentError::new(
            AgentErrorCode::IntegrityFailure,
            false,
            AgentRemediation::ContactOperator,
            Some(AgentErrorDetails::Operation {
                operation_id: operation_id.clone(),
            }),
        ),
        UNSUPPORTED_OPERATION_ERROR_JSON => AgentError::new(
            AgentErrorCode::Internal,
            false,
            AgentRemediation::ContactOperator,
            Some(AgentErrorDetails::Operation {
                operation_id: operation_id.clone(),
            }),
        ),
        _ => {
            let envelope = serde_json::from_str::<ErrorEnvelope>(payload).map_err(|_| {
                ToolExecutionFailure::Journal {
                    error: JournalError::IntegrityFailure,
                    operation_id: Some(operation_id.clone()),
                }
            })?;
            if envelope.repository_id() != repository_id {
                return Err(ToolExecutionFailure::Journal {
                    error: JournalError::IntegrityFailure,
                    operation_id: Some(operation_id.clone()),
                });
            }
            if matches!(
                envelope.error().details(),
                Some(AgentErrorDetails::Operation {
                    operation_id: stored_operation_id,
                }) if stored_operation_id != operation_id
            ) {
                return Err(ToolExecutionFailure::Journal {
                    error: JournalError::IntegrityFailure,
                    operation_id: Some(operation_id.clone()),
                });
            }
            return CanonicalResponseMapper::error(&envelope).map_err(Into::into);
        }
    };
    CanonicalResponseMapper::error(&ErrorEnvelope::new(repository_id.clone(), error))
        .map_err(Into::into)
}

fn map_journal_error(error: &JournalError, operation_id: Option<OperationId>) -> AgentError {
    let operation_details = || {
        operation_id
            .clone()
            .map(|operation_id| AgentErrorDetails::Operation { operation_id })
    };
    match error {
        JournalError::InvalidArgument => AgentError::new(
            AgentErrorCode::InvalidArgument,
            false,
            AgentRemediation::CorrectInput,
            None,
        ),
        JournalError::NotFound | JournalError::Expired => AgentError::new(
            AgentErrorCode::NotFound,
            false,
            AgentRemediation::CorrectInput,
            operation_details(),
        ),
        JournalError::RepositoryMismatch | JournalError::CapabilityDenied => AgentError::new(
            AgentErrorCode::CapabilityDenied,
            false,
            AgentRemediation::EnableRequiredCapability,
            None,
        ),
        JournalError::IdempotencyConflict => AgentError::new(
            AgentErrorCode::IdempotencyConflict,
            false,
            AgentRemediation::CorrectInput,
            operation_details(),
        ),
        JournalError::OperationNotReady | JournalError::DeadlineExceeded => AgentError::new(
            AgentErrorCode::OperationNotReady,
            true,
            AgentRemediation::PollOperation,
            operation_details(),
        ),
        JournalError::UnsupportedSchemaVersion
        | JournalError::IntegrityFailure
        | JournalError::InvalidTransition
        | JournalError::LeaseHeld
        | JournalError::LeaseMismatch
        | JournalError::LeaseExpired => AgentError::new(
            AgentErrorCode::IntegrityFailure,
            false,
            AgentRemediation::ContactOperator,
            operation_details(),
        ),
        JournalError::RequestCancelled => AgentError::new(
            AgentErrorCode::Internal,
            true,
            AgentRemediation::Retry,
            None,
        ),
        JournalError::Storage(_) | JournalError::Io(_) | JournalError::EntropyUnavailable => {
            AgentError::new(
                AgentErrorCode::Internal,
                true,
                AgentRemediation::ContactOperator,
                operation_details(),
            )
        }
    }
}

fn system_now_ms() -> Result<i64, ToolExecutionFailure> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ToolExecutionFailure::Agent(internal_agent_error()))?
        .as_millis();
    i64::try_from(milliseconds).map_err(|_| ToolExecutionFailure::Agent(internal_agent_error()))
}

const fn internal_agent_error() -> AgentError {
    AgentError::new(
        AgentErrorCode::Internal,
        false,
        AgentRemediation::ContactOperator,
        None,
    )
}

fn execute_catalog_read_tool(
    service: &DepgraphService,
    repository_id: &LogicalRepositoryId,
    cursor_key: &CursorKey,
    compiler_pack_requirement: &Path,
    tool: &str,
    arguments: serde_json::Map<String, serde_json::Value>,
    cancellation: &CancellationToken,
) -> Result<MappedToolResult, ToolExecutionFailure> {
    match tool {
        "get_context" => {
            let arguments = decode_arguments::<ContextArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            let context = service.get_context_cancellable(cancellation)?;
            let snapshot_id = context
                .current_snapshot()
                .details()
                .map(|details| parse_snapshot_id(details.id()))
                .transpose()?;
            let result = AgentContext::try_from(&context)
                .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::Integrity))?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                snapshot_id,
                result,
            ))
            .map_err(Into::into)
        }
        "agent_nodes_list" => {
            let arguments = decode_arguments::<FindNodesArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            if arguments.kinds.len() > 1_024 {
                return Err(ToolExecutionFailure::Service(
                    DepgraphServiceError::InvalidInput,
                ));
            }
            let kinds = arguments
                .kinds
                .iter()
                .map(AgentToken::parse)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::InvalidInput))?;
            let snapshot =
                SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
            let resolved_snapshot_id =
                service.resolve_snapshot_id_cancellable(&snapshot, cancellation)?;
            let snapshot_id = parse_snapshot_id(resolved_snapshot_id.as_str())?;
            let normalized = serde_json::json!({
                "kinds": &kinds,
                "match_mode": arguments.match_mode,
                "query": &arguments.query,
            });
            let pagination = PaginationContext::new(
                cursor_key,
                "agent_nodes_list",
                repository_id.clone(),
                snapshot_id.clone(),
                &normalized,
            )?;
            let request = page_request(arguments.limit, arguments.cursor)?;
            let offset = pagination
                .cursor_offset(&request)
                .map_err(ToolExecutionFailure::Agent)?;
            let kind_values = kinds
                .iter()
                .map(|kind| kind.as_str().to_owned())
                .collect::<Vec<_>>();
            let found = service.find_nodes_page(
                &resolved_snapshot_id,
                &arguments.query,
                arguments.match_mode.into(),
                &kind_values,
                offset,
                usize::from(request.max_items().get()),
                cancellation,
            )?;
            let items = found
                .nodes()
                .iter()
                .map(AgentNodeSummary::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::Integrity))?;
            let page = pagination
                .paginate_window(&items, offset, found.total_items(), &request)
                .map_err(ToolExecutionFailure::Agent)?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                page,
            ))
            .map_err(Into::into)
        }
        "agent_node_get" => {
            let arguments = decode_arguments::<AgentNodeGetArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            let node_id = AgentId::parse(&arguments.node_id)
                .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::InvalidInput))?;
            let snapshot =
                SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
            let resolved_snapshot_id =
                service.resolve_snapshot_id_cancellable(&snapshot, cancellation)?;
            let snapshot_id = parse_snapshot_id(resolved_snapshot_id.as_str())?;
            let found = service.find_nodes_page(
                &resolved_snapshot_id,
                node_id.as_str(),
                NodeMatchMode::Exact,
                &[],
                0,
                service.config().limits().max_page_items(),
                cancellation,
            )?;
            let matches = found
                .nodes()
                .iter()
                .filter(|node| node.id() == node_id.as_str())
                .collect::<Vec<_>>();
            let node = match matches.as_slice() {
                [node] => AgentNode::try_from(*node)
                    .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::Integrity))?,
                [] => {
                    return Err(ToolExecutionFailure::Service(
                        DepgraphServiceError::NotFound,
                    ));
                }
                _ => {
                    return Err(ToolExecutionFailure::Service(
                        DepgraphServiceError::Integrity,
                    ));
                }
            };
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                node,
            ))
            .map_err(Into::into)
        }
        "agent_sites_list" => {
            let arguments = decode_arguments::<AgentSitesListArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            if let Some(node_id) = arguments.node_id.as_deref() {
                AgentId::parse(node_id).map_err(|_| {
                    ToolExecutionFailure::Service(DepgraphServiceError::InvalidInput)
                })?;
            }
            let snapshot =
                SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
            let resolved_snapshot_id =
                service.resolve_snapshot_id_cancellable(&snapshot, cancellation)?;
            let snapshot_id = parse_snapshot_id(resolved_snapshot_id.as_str())?;
            let normalized = serde_json::json!({"node_id": arguments.node_id});
            let pagination = PaginationContext::new(
                cursor_key,
                "agent_sites_list",
                repository_id.clone(),
                snapshot_id.clone(),
                &normalized,
            )?;
            let request = page_request(arguments.limit, arguments.cursor)?;
            let offset = pagination
                .cursor_offset(&request)
                .map_err(ToolExecutionFailure::Agent)?;
            let found = service.list_sites_page(
                &resolved_snapshot_id,
                arguments.node_id.as_deref(),
                offset,
                usize::from(request.max_items().get()),
                cancellation,
            )?;
            let items = found
                .items()
                .iter()
                .map(AgentSite::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::Integrity))?;
            let page = pagination
                .paginate_window(&items, offset, found.total_items(), &request)
                .map_err(ToolExecutionFailure::Agent)?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                page,
            ))
            .map_err(Into::into)
        }
        "agent_edges_list" => {
            let arguments = decode_arguments::<AgentEdgesListArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            AgentId::parse(&arguments.node_id)
                .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::InvalidInput))?;
            let snapshot =
                SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
            let resolved_snapshot_id =
                service.resolve_snapshot_id_cancellable(&snapshot, cancellation)?;
            let snapshot_id = parse_snapshot_id(resolved_snapshot_id.as_str())?;
            let normalized =
                serde_json::json!({"node_id": arguments.node_id, "direction": arguments.direction});
            let pagination = PaginationContext::new(
                cursor_key,
                "agent_edges_list",
                repository_id.clone(),
                snapshot_id.clone(),
                &normalized,
            )?;
            let request = page_request(arguments.limit, arguments.cursor)?;
            let offset = pagination
                .cursor_offset(&request)
                .map_err(ToolExecutionFailure::Agent)?;
            let found = service.list_edges_page(
                &resolved_snapshot_id,
                &arguments.node_id,
                arguments.direction.into(),
                offset,
                usize::from(request.max_items().get()),
                cancellation,
            )?;
            validate_agent_condition_projection(found.items().iter().map(|edge| edge.condition()))?;
            let items = found
                .items()
                .iter()
                .map(AgentEdge::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(contract_mapping_error)?;
            let page = pagination
                .paginate_window(&items, offset, found.total_items(), &request)
                .map_err(ToolExecutionFailure::Agent)?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                page,
            ))
            .map_err(Into::into)
        }
        "agent_evidence_list" => {
            let arguments = decode_arguments::<AgentEvidenceListArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            AgentId::parse(&arguments.site_id)
                .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::InvalidInput))?;
            let snapshot =
                SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
            let resolved_snapshot_id =
                service.resolve_snapshot_id_cancellable(&snapshot, cancellation)?;
            let snapshot_id = parse_snapshot_id(resolved_snapshot_id.as_str())?;
            let normalized = serde_json::json!({"site_id": arguments.site_id});
            let pagination = PaginationContext::new(
                cursor_key,
                "agent_evidence_list",
                repository_id.clone(),
                snapshot_id.clone(),
                &normalized,
            )?;
            let request = page_request(arguments.limit, arguments.cursor)?;
            let offset = pagination
                .cursor_offset(&request)
                .map_err(ToolExecutionFailure::Agent)?;
            let found = service.list_site_evidence_page(
                &resolved_snapshot_id,
                &arguments.site_id,
                offset,
                usize::from(request.max_items().get()),
                cancellation,
            )?;
            let items = found
                .items()
                .iter()
                .map(AgentEvidence::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::Integrity))?;
            let page = pagination
                .paginate_window(&items, offset, found.total_items(), &request)
                .map_err(ToolExecutionFailure::Agent)?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                page,
            ))
            .map_err(Into::into)
        }
        "snapshot_list" => {
            let arguments = decode_arguments::<SnapshotListArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            let context = service.get_context_cancellable(cancellation)?;
            let binding_snapshot_id = context
                .current_snapshot()
                .details()
                .map(|details| parse_snapshot_id(details.id()))
                .transpose()?
                .unwrap_or_else(empty_snapshot_id);
            let pagination = PaginationContext::new(
                cursor_key,
                "snapshot_list",
                repository_id.clone(),
                binding_snapshot_id,
                &serde_json::json!({}),
            )?;
            let request = page_request(arguments.limit, arguments.cursor)?;
            let offset = pagination
                .cursor_offset(&request)
                .map_err(ToolExecutionFailure::Agent)?;
            let found = service.list_completed_snapshots_page(
                offset,
                usize::from(request.max_items().get()),
                cancellation,
            )?;
            let items = found
                .snapshots()
                .iter()
                .map(AgentNamedSnapshot::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::Integrity))?;
            let page = pagination
                .paginate_window(&items, offset, found.total_items(), &request)
                .map_err(ToolExecutionFailure::Agent)?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                None,
                page,
            ))
            .map_err(Into::into)
        }
        "snapshot_get" => {
            let arguments = decode_arguments::<SnapshotGetArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            let snapshot = SnapshotLocator::parse(arguments.snapshot)?;
            let shown = service.show_completed_snapshot_cancellable(&snapshot, cancellation)?;
            let snapshot_id = parse_snapshot_id(shown.id())?;
            let result = AgentCompletedSnapshot::try_from(&shown)
                .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::Integrity))?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                result,
            ))
            .map_err(Into::into)
        }
        "profile_plan_get" => {
            let arguments = decode_arguments::<ProfilesPlanArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            let result = service.profile_plan_cancellable(
                &ProfilePlanRequest {
                    profile_budget: arguments.profile_budget,
                    profiles_document: arguments.profiles_document,
                    profiles_file: arguments.profiles_file.map(TryInto::try_into).transpose()?,
                },
                cancellation,
            )?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                None,
                AgentProfilePlan::from(result),
            ))
            .map_err(Into::into)
        }
        "daemon_get" => {
            let arguments = decode_arguments::<DaemonStatusArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            let result =
                AgentDaemonStatus::try_from(service.daemon_status_cancellable(cancellation)?)
                    .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::Integrity))?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                None,
                result,
            ))
            .map_err(Into::into)
        }
        "doctor_get" => {
            let arguments = decode_arguments::<DoctorArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            let result = service.doctor_cancellable(
                &DoctorRequest {
                    details: arguments.details,
                    use_service_root: true,
                    compiler_pack_requirement: Some(compiler_pack_requirement.to_path_buf()),
                },
                cancellation,
            )?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                None,
                AgentDoctor::from(result),
            ))
            .map_err(Into::into)
        }
        "graph_dependencies_list" | "graph_dependents_list" => {
            let arguments = decode_arguments::<GraphDependenciesArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            validate_graph_filter_lengths(
                &arguments.phases,
                &arguments.profiles,
                &arguments.sessions,
                &arguments.environments,
            )?;
            let filter = GraphQueryFilter::new(
                arguments.phases,
                arguments.profiles,
                arguments.sessions,
                arguments.environments,
            )
            .map_err(|source| {
                ToolExecutionFailure::Service(DepgraphServiceError::graph_query(source))
            })?;
            let max_traversal = graph_max_traversal(arguments.max_traversal)?;
            let locator =
                SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
            let mut snapshot_request =
                service.start_snapshot_request_at_cancellable(&locator, cancellation)?;
            let snapshot_id = parse_snapshot_id(snapshot_request.snapshot_id().as_str())?;
            let direction = if tool == "graph_dependents_list" {
                DependencyDirection::Incoming
            } else {
                DependencyDirection::Outgoing
            };
            let request = DependenciesRequest::try_new(
                arguments.selector.as_str(),
                direction,
                arguments.transitive,
                filter,
                max_traversal,
            )?;
            let normalized = serde_json::json!({
                "direction": match direction {
                    DependencyDirection::Outgoing => "outgoing",
                    DependencyDirection::Incoming => "incoming",
                },
                "filter": request.filter(),
                "max_traversal": request.max_traversal(),
                "selector": request.selector(),
                "transitive": request.transitive(),
            });
            let pagination = PaginationContext::new(
                cursor_key,
                tool,
                repository_id.clone(),
                snapshot_id.clone(),
                &normalized,
            )?;
            let page_request = page_request(arguments.limit, arguments.cursor)?;
            let found = service.dependencies(&mut snapshot_request, &request, cancellation)?;
            let result = project_dependencies_page_cancellable(
                &found,
                match direction {
                    DependencyDirection::Outgoing => AgentDependencyDirection::Outgoing,
                    DependencyDirection::Incoming => AgentDependencyDirection::Incoming,
                },
                request.transitive(),
                &pagination,
                &page_request,
                cancellation,
            )
            .map_err(ToolExecutionFailure::Agent)?;
            if cancellation.is_cancelled() {
                return Err(ToolExecutionFailure::Service(
                    DepgraphServiceError::Cancelled,
                ));
            }
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                result,
            ))
            .map_err(Into::into)
        }
        "graph_path_get" => {
            let arguments = decode_arguments::<GraphPathArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            validate_graph_filter_lengths(
                &arguments.phases,
                &arguments.profiles,
                &arguments.sessions,
                &arguments.environments,
            )?;
            let filter = GraphQueryFilter::new(
                arguments.phases,
                arguments.profiles,
                arguments.sessions,
                arguments.environments,
            )
            .map_err(|source| {
                ToolExecutionFailure::Service(DepgraphServiceError::graph_query(source))
            })?;
            let request = ExplainPathRequest::try_new(
                arguments.from.as_str(),
                arguments.to.as_str(),
                filter,
                graph_max_traversal(arguments.max_traversal)?,
            )?;
            let locator =
                SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
            let mut snapshot_request =
                service.start_snapshot_request_at_cancellable(&locator, cancellation)?;
            let snapshot_id = parse_snapshot_id(snapshot_request.snapshot_id().as_str())?;
            let found = service.explain_path(&mut snapshot_request, &request, cancellation)?;
            validate_agent_condition_projection(
                found
                    .items()
                    .iter()
                    .map(|item| item.step.condition_text.as_str()),
            )?;
            let result = AgentPathResponse::try_from(&found).map_err(contract_mapping_error)?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                result,
            ))
            .map_err(Into::into)
        }
        "graph_impact_get" => {
            let arguments = decode_arguments::<GraphImpactArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            validate_graph_filter_lengths(
                &arguments.phases,
                &arguments.profiles,
                &arguments.sessions,
                &arguments.environments,
            )?;
            if arguments.conditions.len() > 1_024 {
                return Err(ToolExecutionFailure::Service(
                    DepgraphServiceError::InvalidInput,
                ));
            }
            let filters = ImpactFilters::new(
                arguments.depth,
                arguments.profiles,
                arguments.conditions,
                arguments.max_nodes.unwrap_or(10_000),
                arguments.max_edges.unwrap_or(50_000),
            )
            .and_then(|filters| {
                filters.with_runtime_filters(
                    arguments.phases,
                    arguments.sessions,
                    arguments.environments,
                )
            })
            .map_err(|source| {
                ToolExecutionFailure::Service(DepgraphServiceError::graph_query(source))
            })?;
            let request = ImpactRequest::try_new(
                arguments.selector.as_str(),
                arguments.changed_since,
                filters,
            )?;
            let locator =
                SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
            let mut snapshot_request =
                service.start_snapshot_request_at_cancellable(&locator, cancellation)?;
            let snapshot_id = parse_snapshot_id(snapshot_request.snapshot_id().as_str())?;
            let normalized = serde_json::json!({
                "changed_since": request.changed_since(),
                "filters": request.filters(),
                "selector": request.selector(),
            });
            let pagination = PaginationContext::new(
                cursor_key,
                tool,
                repository_id.clone(),
                snapshot_id.clone(),
                &normalized,
            )?;
            let page_request = page_request(arguments.limit, arguments.cursor)?;
            let found = service.impact(&mut snapshot_request, &request, cancellation)?;
            let result = project_impact_response_cancellable(
                &found,
                &pagination,
                &page_request,
                cancellation,
            )
            .map_err(ToolExecutionFailure::Agent)?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                result,
            ))
            .map_err(Into::into)
        }
        "graph_cycles_list" => {
            let arguments = decode_arguments::<GraphCyclesArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            let level = match arguments.level {
                AgentCycleLevel::Package => CycleLevel::Package,
                AgentCycleLevel::File => CycleLevel::File,
                AgentCycleLevel::Symbol => CycleLevel::Symbol,
                AgentCycleLevel::Type => CycleLevel::Type,
                AgentCycleLevel::Route => CycleLevel::Route,
            };
            let request =
                CyclesRequest::try_new(level, graph_max_traversal(arguments.max_traversal)?)?;
            let locator =
                SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
            let mut snapshot_request =
                service.start_snapshot_request_at_cancellable(&locator, cancellation)?;
            let snapshot_id = parse_snapshot_id(snapshot_request.snapshot_id().as_str())?;
            let normalized = serde_json::json!({
                "level": arguments.level,
                "max_traversal": request.max_traversal(),
            });
            let pagination = PaginationContext::new(
                cursor_key,
                tool,
                repository_id.clone(),
                snapshot_id.clone(),
                &normalized,
            )?;
            let page_request = page_request(arguments.limit, arguments.cursor)?;
            let found = service.cycles(&mut snapshot_request, &request, cancellation)?;
            let page =
                project_cycles_page_cancellable(&found, &pagination, &page_request, cancellation)
                    .map_err(ToolExecutionFailure::Agent)?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                page,
            ))
            .map_err(Into::into)
        }
        "graph_unresolved_list" => {
            let arguments = decode_arguments::<GraphUnresolvedArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            if arguments.kinds.len() > 1_024 {
                return Err(ToolExecutionFailure::Service(
                    DepgraphServiceError::InvalidInput,
                ));
            }
            let request = UnresolvedRequest::try_new(
                arguments.kinds,
                graph_max_traversal(arguments.max_traversal)?,
            )?;
            let locator =
                SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
            let mut snapshot_request =
                service.start_snapshot_request_at_cancellable(&locator, cancellation)?;
            let snapshot_id = parse_snapshot_id(snapshot_request.snapshot_id().as_str())?;
            let normalized = serde_json::json!({
                "kinds": request.kinds(),
                "max_traversal": request.max_traversal(),
            });
            let pagination = PaginationContext::new(
                cursor_key,
                tool,
                repository_id.clone(),
                snapshot_id.clone(),
                &normalized,
            )?;
            let page_request = page_request(arguments.limit, arguments.cursor)?;
            let found = service.unresolved(&mut snapshot_request, &request, cancellation)?;
            let page = project_unresolved_page_cancellable(
                &found,
                &pagination,
                &page_request,
                cancellation,
            )
            .map_err(ToolExecutionFailure::Agent)?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                page,
            ))
            .map_err(Into::into)
        }
        "snapshot_diff_get" => {
            let arguments = decode_arguments::<SnapshotDiffArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            let request = SnapshotDiffRequest::new(
                SnapshotLocator::parse(&arguments.from)?,
                SnapshotLocator::parse(&arguments.to)?,
                SnapshotDiffFilters::try_new(arguments.kinds, Vec::new(), Vec::new(), Vec::new())?,
            );
            let result = project_snapshot_diff(service.snapshot_diff(&request, cancellation)?)
                .map_err(contract_mapping_error)?;
            let snapshot_id = result.to_snapshot_id.clone();
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                result,
            ))
            .map_err(Into::into)
        }
        "policy_evaluate" => {
            let arguments = decode_arguments::<PolicyEvaluateArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            let request = PolicyEvaluateRequest::new(
                SnapshotLocator::parse(&arguments.from)?,
                SnapshotLocator::parse(&arguments.to)?,
            );
            let result = project_policy_result(service.policy_evaluate(&request, cancellation)?)
                .map_err(contract_mapping_error)?;
            let snapshot_id = result.to_snapshot_id.clone();
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                result,
            ))
            .map_err(Into::into)
        }
        "health_summary_get" => {
            validate_array_argument_lengths(&arguments, &["kinds"])?;
            let arguments = decode_arguments::<HealthSummaryArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            let kinds = if arguments.kinds.is_empty() {
                None
            } else {
                Some(parse_snapshot_scoped_kinds(&arguments.kinds)?)
            };
            let request = HealthSummaryRequest::try_new(kinds)?;
            let locator =
                SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
            let mut snapshot_request =
                service.start_snapshot_request_at_cancellable(&locator, cancellation)?;
            let snapshot_id = parse_snapshot_id(snapshot_request.snapshot_id().as_str())?;
            let found = service.health_summary(&mut snapshot_request, &request, cancellation)?;
            let result = AgentHealthSummary::try_new(
                found.collection_digest(),
                found.counts_by_kind().clone(),
                found.counts_by_confidence().clone(),
                &found.coverage().completeness,
                found.coverage().files_skipped,
                found.coverage().unresolved,
                found.coverage().candidates,
            )
            .map_err(contract_mapping_error)?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                result,
            ))
            .map_err(Into::into)
        }
        "health_findings_list" => {
            validate_array_argument_lengths(&arguments, &["kinds", "severities", "confidences"])?;
            let arguments = decode_arguments::<HealthFindingsArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            let request = HealthFindingsRequest::try_new(
                parse_snapshot_scoped_kinds(&arguments.kinds)?,
                parse_health_severities(&arguments.severities)?,
                parse_health_confidences(&arguments.confidences)?,
                MAX_HEALTH_FINDINGS,
            )?;
            let locator =
                SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
            let mut snapshot_request =
                service.start_snapshot_request_at_cancellable(&locator, cancellation)?;
            let snapshot_id = parse_snapshot_id(snapshot_request.snapshot_id().as_str())?;
            let found = service.health_findings(&mut snapshot_request, &request, cancellation)?;
            let normalized = serde_json::json!({
                "kinds": request.kinds().iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
                "severities": request.severities().iter().map(|severity| severity.as_str()).collect::<Vec<_>>(),
                "confidences": request.confidences().iter().map(|confidence| confidence.as_str()).collect::<Vec<_>>(),
                "manifest_digest": found.manifest_digest(),
                "collection_digest": found.collection_digest(),
            });
            let pagination = PaginationContext::new(
                cursor_key,
                tool,
                repository_id.clone(),
                snapshot_id.clone(),
                &normalized,
            )?;
            let page_request = page_request(arguments.limit, arguments.cursor)?;
            let page = project_health_findings_page(
                found.findings(),
                &pagination,
                &page_request,
                cancellation,
            )?;
            let result = AgentHealthFindingsPage::try_new(found.collection_digest(), page)
                .map_err(contract_mapping_error)?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                result,
            ))
            .map_err(Into::into)
        }
        "health_finding_get" => {
            let arguments = decode_arguments::<HealthFindingGetArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            let request = HealthFindingGetRequest::try_new(arguments.finding_id)?;
            let locator =
                SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
            let mut snapshot_request =
                service.start_snapshot_request_at_cancellable(&locator, cancellation)?;
            let snapshot_id = parse_snapshot_id(snapshot_request.snapshot_id().as_str())?;
            let found =
                service.health_finding_get(&mut snapshot_request, &request, cancellation)?;
            let result =
                AgentHealthFindingDetail::try_from_core(&found).map_err(contract_mapping_error)?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                result,
            ))
            .map_err(Into::into)
        }
        "health_audit_get" => {
            let arguments = decode_arguments::<HealthAuditArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            let request = HealthAuditRequest::try_new(arguments.changed, arguments.base_snapshot)?;
            let locator =
                SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
            let mut snapshot_request =
                service.start_snapshot_request_at_cancellable(&locator, cancellation)?;
            let scope =
                service.start_health_audit_scope(&mut snapshot_request, &request, cancellation)?;
            let found = service.health_audit(&scope, cancellation)?;
            let snapshot_id = parse_snapshot_id(found.after_snapshot_id().as_str())?;
            let normalized = serde_json::json!({
                "after_snapshot_id": found.after_snapshot_id().as_str(),
                "before_snapshot_id": found.before_snapshot_id().map(|id| id.as_str()),
                "changed_oid": found.changed_oid(),
                "collection_digest": found.collection_digest(),
            });
            let pagination = PaginationContext::new(
                cursor_key,
                tool,
                repository_id.clone(),
                snapshot_id.clone(),
                &normalized,
            )?;
            let page_request = page_request(arguments.limit, arguments.cursor)?;
            let page = project_health_findings_page(
                found.findings(),
                &pagination,
                &page_request,
                cancellation,
            )?;
            let result = AgentHealthAudit::try_new(
                found.after_snapshot_id().as_str(),
                found.before_snapshot_id().map(|id| id.as_str()),
                found.changed_oid(),
                found.collection_digest(),
                page,
            )
            .map_err(contract_mapping_error)?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                result,
            ))
            .map_err(Into::into)
        }
        "health_hotspots_list" => {
            validate_array_argument_lengths(&arguments, &["churn_path_filter"])?;
            let arguments = decode_arguments::<HealthHotspotsArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            let defaults = DEFAULT_HOTSPOT_WEIGHTS;
            let weights = HotspotWeights::try_new(
                arguments.weight_fan_in.unwrap_or(defaults.fan_in),
                arguments.weight_fan_out.unwrap_or(defaults.fan_out),
                arguments
                    .weight_reverse_impact
                    .unwrap_or(defaults.reverse_impact),
                arguments.weight_git_churn.unwrap_or(defaults.git_churn),
                arguments.weight_runtime.unwrap_or(defaults.runtime),
            )
            .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::InvalidInput))?;
            let request = HealthHotspotsRequest::try_new(
                arguments
                    .churn_commit_limit
                    .unwrap_or(MAX_HEALTH_CHURN_COMMITS),
                arguments.churn_path_filter,
                weights,
            )?;
            let locator =
                SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
            let mut snapshot_request =
                service.start_snapshot_request_at_cancellable(&locator, cancellation)?;
            let snapshot_id = parse_snapshot_id(snapshot_request.snapshot_id().as_str())?;
            let found = service.health_hotspots(&mut snapshot_request, &request, cancellation)?;
            let normalized = serde_json::json!({
                "churn_commit_limit": request.churn_commit_limit(),
                "churn_path_filter": request.churn_path_filter(),
                "weights": request.weights().as_map(),
                "collection_digest": found.collection_digest(),
            });
            let pagination = PaginationContext::new(
                cursor_key,
                tool,
                repository_id.clone(),
                snapshot_id.clone(),
                &normalized,
            )?;
            let page_request = page_request(arguments.limit, arguments.cursor)?;
            let page = project_health_findings_page(
                found.findings(),
                &pagination,
                &page_request,
                cancellation,
            )?;
            let result = AgentHealthHotspots::try_new(found.collection_digest(), page)
                .map_err(contract_mapping_error)?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                result,
            ))
            .map_err(Into::into)
        }
        "graph_export" => {
            let arguments = decode_arguments::<GraphExportArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            let request = GraphExportRequest::try_new(
                SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?,
                arguments.format.into(),
                arguments
                    .selector
                    .map(|selector| selector.as_str().to_owned()),
                GraphQueryFilter::default(),
                arguments
                    .max_nodes
                    .unwrap_or(DEFAULT_GRAPH_EXPORT_MAX_NODES),
                arguments
                    .max_edges
                    .unwrap_or(DEFAULT_GRAPH_EXPORT_MAX_EDGES),
            )?;
            let result = project_graph_export(service.graph_export(&request, cancellation)?)
                .map_err(contract_mapping_error)?;
            let snapshot_id = result.snapshot_id.clone();
            CanonicalResponseMapper::export_success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                result,
            ))
            .map_err(Into::into)
        }
        "graph_query" => {
            let arguments = decode_arguments::<GraphQueryArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            let locator =
                SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
            let request = BoundedQueryRequest {
                query: arguments.query,
                query_file: arguments.query_file.map(TryInto::try_into).transpose()?,
                snapshot: ServiceSnapshotSelector::Locator(locator),
                mode: BoundedQueryMode::Execute,
            };
            let found = service.bounded_query(&request, cancellation)?;
            let snapshot_id = parse_snapshot_id(found.resolved_snapshot_id().as_str())?;
            let normalized = serde_json::json!({
                "query_digest": found.input_digest(),
            });
            let pagination = PaginationContext::new(
                cursor_key,
                tool,
                repository_id.clone(),
                snapshot_id.clone(),
                &normalized,
            )?;
            let request = page_request(arguments.limit, arguments.cursor)?;
            let rows =
                project_bounded_query_rows_cancellable(&found, &mut || cancellation.is_cancelled())
                    .map_err(|error| match error {
                        BoundedQueryProjectionFailure::Cancelled => {
                            ToolExecutionFailure::Service(DepgraphServiceError::Cancelled)
                        }
                        BoundedQueryProjectionFailure::Contract(error) => {
                            contract_mapping_error(error)
                        }
                    })?;
            let page = pagination
                .paginate_cancellable(&rows, &request, cancellation)
                .map_err(ToolExecutionFailure::Agent)?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                page,
            ))
            .map_err(Into::into)
        }
        "runtime_trace_validate" => {
            let arguments = decode_arguments::<RuntimeValidateArguments>(arguments)?;
            authorize_repository(
                arguments.contract_version,
                &arguments.repository_id,
                repository_id,
            )?;
            let locator =
                SnapshotLocator::parse(arguments.snapshot.as_deref().unwrap_or("current"))?;
            let request = RuntimeValidateRequest {
                trace: arguments.trace,
                trace_file: arguments.trace_file.map(TryInto::try_into).transpose()?,
                snapshot: ServiceSnapshotSelector::Locator(locator),
            };
            let found = service.runtime_validate(&request, cancellation)?;
            let snapshot_id = parse_snapshot_id(found.resolved_snapshot_id().as_str())?;
            let normalized = serde_json::json!({
                "trace_digest": found.input_digest(),
            });
            let pagination = PaginationContext::new(
                cursor_key,
                tool,
                repository_id.clone(),
                snapshot_id.clone(),
                &normalized,
            )?;
            let request = page_request(arguments.limit, arguments.cursor)?;
            let mut events = Vec::with_capacity(found.trace().events.len());
            for event in &found.trace().events {
                if cancellation.is_cancelled() {
                    return Err(ToolExecutionFailure::Service(
                        DepgraphServiceError::Cancelled,
                    ));
                }
                events.push(AgentRuntimeTraceEvent::try_from(event).map_err(|error| {
                    if cancellation.is_cancelled() {
                        ToolExecutionFailure::Service(DepgraphServiceError::Cancelled)
                    } else {
                        contract_mapping_error(error)
                    }
                })?);
            }
            let page = pagination
                .paginate_cancellable(&events, &request, cancellation)
                .map_err(ToolExecutionFailure::Agent)?;
            let result = AgentRuntimeValidationResponse::try_new(found.trace(), page)
                .map_err(contract_mapping_error)?;
            CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id.clone(),
                Some(snapshot_id),
                result,
            ))
            .map_err(Into::into)
        }
        _ => Err(ToolExecutionFailure::Service(
            DepgraphServiceError::NotFound,
        )),
    }
}

fn validate_graph_filter_lengths(
    phases: &[String],
    profiles: &[String],
    sessions: &[String],
    environments: &[String],
) -> Result<(), ToolExecutionFailure> {
    if [phases, profiles, sessions, environments]
        .into_iter()
        .any(|values| values.len() > 1_024)
    {
        return Err(ToolExecutionFailure::Service(
            DepgraphServiceError::InvalidInput,
        ));
    }
    Ok(())
}

fn graph_max_traversal(value: Option<usize>) -> Result<usize, ToolExecutionFailure> {
    let value = value.unwrap_or(depgraph_core::DEFAULT_INTERACTIVE_QUERY_MAX_TRAVERSAL);
    if !(1..=MAX_INTERACTIVE_QUERY_TRAVERSAL).contains(&value) {
        return Err(ToolExecutionFailure::Service(
            DepgraphServiceError::InvalidInput,
        ));
    }
    Ok(value)
}

fn validate_agent_condition_projection<'a>(
    conditions: impl IntoIterator<Item = &'a str>,
) -> Result<(), ToolExecutionFailure> {
    let mut total = 0_usize;
    for condition in conditions {
        if condition.len() > MAX_AGENT_CONDITION_BYTES {
            return Err(agent_condition_limit_error(
                MAX_AGENT_CONDITION_BYTES as u64,
            ));
        }
        total = total
            .checked_add(condition.len())
            .ok_or_else(|| agent_condition_limit_error(u64::from(MAX_PAGE_BYTES)))?;
        if total > MAX_PAGE_BYTES as usize {
            return Err(agent_condition_limit_error(u64::from(MAX_PAGE_BYTES)));
        }
    }
    Ok(())
}

fn agent_condition_limit_error(maximum: u64) -> ToolExecutionFailure {
    ToolExecutionFailure::Agent(AgentError::new(
        AgentErrorCode::ResourceExhausted,
        false,
        AgentRemediation::NarrowQuery,
        Some(AgentErrorDetails::ResourceLimit {
            limit: AgentResourceLimit::OutputBytes,
            maximum,
        }),
    ))
}

fn parse_snapshot_scoped_kinds(
    values: &[String],
) -> Result<Vec<FindingKind>, ToolExecutionFailure> {
    values
        .iter()
        .map(|value| {
            FindingKind::parse(value)
                .filter(|kind| kind.is_snapshot_scoped())
                .ok_or_else(|| ToolExecutionFailure::Service(DepgraphServiceError::InvalidInput))
        })
        .collect()
}

fn parse_health_severities(values: &[String]) -> Result<Vec<Severity>, ToolExecutionFailure> {
    values
        .iter()
        .map(|value| {
            Severity::parse(value)
                .ok_or_else(|| ToolExecutionFailure::Service(DepgraphServiceError::InvalidInput))
        })
        .collect()
}

fn parse_health_confidences(values: &[String]) -> Result<Vec<Confidence>, ToolExecutionFailure> {
    values
        .iter()
        .map(|value| {
            Confidence::parse(value)
                .ok_or_else(|| ToolExecutionFailure::Service(DepgraphServiceError::InvalidInput))
        })
        .collect()
}

fn project_health_findings_page(
    findings: &[HealthFinding],
    pagination: &PaginationContext,
    request: &PageRequest,
    cancellation: &CancellationToken,
) -> Result<Page<AgentHealthFinding>, ToolExecutionFailure> {
    let mut items = Vec::with_capacity(findings.len());
    for finding in findings {
        if cancellation.is_cancelled() {
            return Err(ToolExecutionFailure::Service(
                DepgraphServiceError::Cancelled,
            ));
        }
        items.push(AgentHealthFinding::try_from_core(finding).map_err(contract_mapping_error)?);
    }
    pagination
        .paginate_cancellable(&items, request, cancellation)
        .map_err(ToolExecutionFailure::Agent)
}

fn contract_mapping_error(error: ContractBuildError) -> ToolExecutionFailure {
    ToolExecutionFailure::Service(match error {
        ContractBuildError::PageByteLimit
        | ContractBuildError::TooManyPathSteps
        | ContractBuildError::TooManyCycleNodes
        | ContractBuildError::TooManyCorrelationReasons
        | ContractBuildError::TooManyPhases
        | ContractBuildError::TooManyEvidenceItems
        | ContractBuildError::TooManyTargetItems
        | ContractBuildError::TooManyQueryValues
        | ContractBuildError::TooManyArtifactItems
        | ContractBuildError::TooManyChangedFields => DepgraphServiceError::ResourceExhausted,
        _ => DepgraphServiceError::Integrity,
    })
}

fn parse_snapshot_id(value: &str) -> Result<SnapshotId, ToolExecutionFailure> {
    SnapshotId::parse(value)
        .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::Integrity))
}

fn empty_snapshot_id() -> SnapshotId {
    SnapshotId::parse(format!("snapshot:sha256:{}", "0".repeat(64)))
        .expect("fixed empty snapshot cursor binding is valid")
}

#[derive(Clone)]
struct BoundedStderr {
    written: Arc<Mutex<usize>>,
}

impl BoundedStderr {
    fn new() -> Self {
        Self {
            written: Arc::new(Mutex::new(0)),
        }
    }

    fn write_message(&self, message: &str) {
        let mut writer = self.make_writer();
        let _ = writer.write_all(message.as_bytes());
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BoundedStderr {
    type Writer = BoundedStderrWriter;

    fn make_writer(&'a self) -> Self::Writer {
        BoundedStderrWriter {
            written: Arc::clone(&self.written),
            record_remaining: MAX_STDERR_RECORD_BYTES,
        }
    }
}

struct BoundedStderrWriter {
    written: Arc<Mutex<usize>>,
    record_remaining: usize,
}

fn bounded_write_len(total_written: usize, record_remaining: usize, input_len: usize) -> usize {
    input_len
        .min(record_remaining)
        .min(MAX_STDERR_TOTAL_BYTES.saturating_sub(total_written))
}

impl io::Write for BoundedStderrWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let allowed = {
            let mut written = self.written.lock().expect("stderr bound mutex poisoned");
            let allowed = bounded_write_len(*written, self.record_remaining, buffer.len());
            if allowed != 0 {
                io::stderr().lock().write_all(&buffer[..allowed])?;
                *written += allowed;
                self.record_remaining -= allowed;
            }
            allowed
        };
        // Logging must never turn an exhausted diagnostic budget into a failure path.
        Ok(if allowed == buffer.len() {
            allowed
        } else {
            buffer.len()
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct TransportState {
    inbound_rejected: std::sync::atomic::AtomicBool,
    eof: std::sync::atomic::AtomicBool,
}

struct BoundedStdioTransport<R, W> {
    reader: R,
    writer: Arc<AsyncMutex<W>>,
    frame: Vec<u8>,
    pending: Vec<u8>,
    pending_offset: usize,
    state: Arc<TransportState>,
}

impl<R, W> BoundedStdioTransport<R, W> {
    fn new(reader: R, writer: W, state: Arc<TransportState>) -> Self {
        Self {
            reader,
            writer: Arc::new(AsyncMutex::new(writer)),
            frame: Vec::with_capacity(8192),
            pending: Vec::with_capacity(8192),
            pending_offset: 0,
            state,
        }
    }
}

impl<R, W> Transport<RoleServer> for BoundedStdioTransport<R, W>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin + 'static,
{
    type Error = io::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let writer = Arc::clone(&self.writer);
        async move {
            let encoded = serde_json::to_vec(&item).map_err(io::Error::other)?;
            let mut writer = writer.lock().await;
            writer.write_all(&encoded).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await
        }
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        loop {
            if self.pending_offset == self.pending.len() {
                self.pending.clear();
                self.pending_offset = 0;
                let mut chunk = [0_u8; 8192];
                let read = match self.reader.read(&mut chunk).await {
                    Ok(read) => read,
                    Err(_) => return None,
                };
                if read == 0 {
                    if self.frame.len() > MAX_INBOUND_MESSAGE_BYTES {
                        self.state
                            .inbound_rejected
                            .store(true, std::sync::atomic::Ordering::Release);
                        return None;
                    }
                    self.state
                        .eof
                        .store(true, std::sync::atomic::Ordering::Release);
                    return None;
                }
                self.pending.extend_from_slice(&chunk[..read]);
            }

            let byte = self.pending[self.pending_offset];
            self.pending_offset += 1;
            if byte == b'\n' {
                let frame = std::mem::take(&mut self.frame);
                let frame = frame.strip_suffix(b"\r").unwrap_or(&frame);
                if frame.is_empty() {
                    continue;
                }
                match serde_json::from_slice(frame) {
                    Ok(message) => return Some(message),
                    // Unparseable peer input is intentionally ignored without logging it.
                    Err(_) => continue,
                }
            }
            let may_be_crlf_terminator =
                self.frame.len() == MAX_INBOUND_MESSAGE_BYTES && byte == b'\r';
            if self.frame.len() >= MAX_INBOUND_MESSAGE_BYTES && !may_be_crlf_terminator {
                self.state
                    .inbound_rejected
                    .store(true, std::sync::atomic::Ordering::Release);
                return None;
            }
            self.frame.push(byte);
        }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.writer.lock().await.shutdown().await
    }
}

fn build_server(args: &Args) -> Result<DepgraphMcpServer> {
    let capabilities =
        DepgraphCapabilitySet::try_new(args.capability.iter().copied().map(Into::into))
            .context("invalid capability set")?;
    let compiler_pack_requirement = read_compiler_pack_requirement(&args.compiler_pack_requirement)
        .context("invalid compiler pack requirement")?;
    let compiler_pack = verify_compiler_pack(&compiler_pack_requirement)
        .context("compiler pack verification failed")?;
    let catalog = ToolCatalog::for_capabilities(&capabilities)
        .map_err(anyhow::Error::msg)
        .context("invalid tool catalog")?;
    let tools = catalog
        .tools()
        .iter()
        .map(|definition| {
            let mut tool = Tool::default();
            tool.name = Cow::Owned(definition.name().to_owned());
            tool.description = Some(Cow::Owned(definition.description().to_owned()));
            tool.input_schema = Arc::new(definition.input_schema().clone());
            tool.output_schema = Some(Arc::new(definition.output_schema().clone()));
            tool
        })
        .collect::<Vec<_>>()
        .into();
    let config = DepgraphServiceConfig::new(
        &args.root,
        &args.store,
        capabilities,
        DepgraphServiceLimits::default(),
    )
    .context("invalid server configuration")?;
    let repository_id = LogicalRepositoryId::parse(config.logical_repository_id())
        .map_err(anyhow::Error::msg)
        .context("invalid logical repository identity")?;

    let runtime = RuntimeController::new(RuntimeConfig::default())
        .context("invalid MCP runtime configuration")?;
    Ok(DepgraphMcpServer {
        operation_config: config.clone(),
        service: DepgraphService::new(config),
        compiler_pack,
        compiler_pack_requirement: args.compiler_pack_requirement.clone(),
        runtime,
        audit: AuditLogger::default(),
        repository_id,
        cursor_key: CursorKey::generate(),
        tools,
    })
}

async fn run(args: Args) -> Result<()> {
    let server = RequestScopedDepgraphMcpServer {
        inner: build_server(&args)?,
    };
    let state = Arc::new(TransportState::default());
    let transport =
        BoundedStdioTransport::new(tokio::io::stdin(), tokio::io::stdout(), Arc::clone(&state));
    let running = match server.serve(transport).await {
        Ok(running) => running,
        Err(_)
            if state
                .inbound_rejected
                .load(std::sync::atomic::Ordering::Acquire) =>
        {
            bail!("inbound message rejected")
        }
        Err(_) if state.eof.load(std::sync::atomic::Ordering::Acquire) => return Ok(()),
        Err(_) => bail!("MCP stdio initialization failed"),
    };
    match running.waiting().await {
        Ok(_)
            if state
                .inbound_rejected
                .load(std::sync::atomic::Ordering::Acquire) =>
        {
            bail!("inbound message rejected")
        }
        Ok(_) => Ok(()),
        Err(_)
            if state
                .inbound_rejected
                .load(std::sync::atomic::Ordering::Acquire) =>
        {
            bail!("inbound message rejected")
        }
        Err(_) => bail!("MCP server task failed"),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let stderr = BoundedStderr::new();
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayVersion => {
            let version = format!("depgraph-mcp {}\n", env!("CARGO_PKG_VERSION"));
            if io::stdout().write_all(version.as_bytes()).is_err() {
                return ExitCode::FAILURE;
            }
            return ExitCode::SUCCESS;
        }
        Err(_) => {
            stderr.write_message(STARTUP_ERROR);
            return ExitCode::FAILURE;
        }
    };
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::level_filters::LevelFilter::OFF.into())
        .parse_lossy(format!(
            "depgraph_mcp={}",
            tracing::level_filters::LevelFilter::from(args.log_level)
        ));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(stderr.clone())
        .without_time()
        .init();

    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if error.to_string() == "inbound message rejected" => {
            stderr.write_message(INBOUND_ERROR);
            ExitCode::FAILURE
        }
        Err(_) => {
            stderr.write_message(STARTUP_ERROR);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
    };

    use super::*;
    use depgraph_operation::OperationJournal;
    use depgraph_store::Store;
    use serde_json::json;

    #[test]
    fn completed_tool_result_survives_late_cancellation() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        assert!(finalize_completed_tool_call(&cancellation, Ok(())).is_ok());
    }

    #[test]
    fn irreversible_tools_require_mutation_worker_settlement() {
        for tool in [
            "scan_submit",
            "runtime_trace_import_submit",
            "export_file",
            "operation_cancel",
            "snapshot_name_create",
            "repository_init",
        ] {
            assert!(tool_uses_mutation_settlement(tool), "{tool}");
        }
        for tool in ["get_context", "snapshot_get", "graph_query"] {
            assert!(!tool_uses_mutation_settlement(tool), "{tool}");
        }
    }

    #[test]
    fn concurrent_current_export_submission_adopts_a_winner_with_the_exact_precondition() {
        let initial = json!({
            "output_path":"artifacts/current.json",
            "overwrite":false,
            "format":"json",
            "snapshot_id":"snapshot:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "selector":null,
            "max_nodes":100,
            "max_edges":100,
            "destination_precondition":{"kind":"missing"}
        });
        let winner = json!({
            "output_path":"artifacts/current.json",
            "overwrite":false,
            "format":"json",
            "snapshot_id":"snapshot:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "selector":null,
            "max_nodes":100,
            "max_edges":100,
            "destination_precondition":{"kind":"missing"}
        });
        let attempts = Cell::new(0_u8);

        let result = submit_export_file_with_conflict_recovery(
            &initial,
            &SnapshotLocator::Current,
            || Ok(Some(winner.clone())),
            |input| {
                attempts.set(attempts.get() + 1);
                if attempts.get() == 1 {
                    Err(ToolExecutionFailure::Journal {
                        error: JournalError::IdempotencyConflict,
                        operation_id: None,
                    })
                } else {
                    assert_eq!(input, &winner);
                    Ok("winning-operation")
                }
            },
        )
        .expect("an exact concurrent replay adopts the winning binding");

        assert_eq!(result, "winning-operation");
        assert_eq!(attempts.get(), 2);
    }

    #[test]
    fn concurrent_current_export_submission_rejects_a_different_destination_precondition() {
        let initial = json!({
            "output_path":"artifacts/current.json",
            "overwrite":false,
            "format":"json",
            "snapshot_id":"snapshot:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "selector":null,
            "max_nodes":100,
            "max_edges":100,
            "destination_precondition":{"kind":"missing"}
        });
        let winner = json!({
            "output_path":"artifacts/current.json",
            "overwrite":false,
            "format":"json",
            "snapshot_id":"snapshot:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "selector":null,
            "max_nodes":100,
            "max_edges":100,
            "destination_precondition":{
                "kind":"regular",
                "identity_sha256":"c".repeat(64),
                "output_bytes":1,
                "content_sha256":"d".repeat(64)
            }
        });
        let attempts = Cell::new(0_u8);

        let error = submit_export_file_with_conflict_recovery(
            &initial,
            &SnapshotLocator::Current,
            || Ok(Some(winner.clone())),
            |_| {
                attempts.set(attempts.get() + 1);
                if attempts.get() == 1 {
                    Err(ToolExecutionFailure::Journal {
                        error: JournalError::IdempotencyConflict,
                        operation_id: None,
                    })
                } else {
                    Ok("wrong-precondition-operation")
                }
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ToolExecutionFailure::Journal {
                error: JournalError::IdempotencyConflict,
                ..
            }
        ));
        assert_eq!(attempts.get(), 1);
    }

    #[test]
    fn named_export_submission_conflict_rejects_a_different_resolved_snapshot_binding() {
        let initial = json!({
            "output_path":"artifacts/named.json",
            "overwrite":false,
            "format":"json",
            "snapshot_id":"snapshot:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "selector":null,
            "max_nodes":100,
            "max_edges":100,
            "destination_precondition":{"kind":"missing"}
        });
        let winner = json!({
            "output_path":"artifacts/named.json",
            "overwrite":false,
            "format":"json",
            "snapshot_id":"snapshot:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "selector":null,
            "max_nodes":100,
            "max_edges":100,
            "destination_precondition":{"kind":"missing"}
        });
        let attempts = Cell::new(0_u8);

        let error = submit_export_file_with_conflict_recovery(
            &initial,
            &SnapshotLocator::Name("release-a".to_owned()),
            || Ok(Some(winner.clone())),
            |_| {
                attempts.set(attempts.get() + 1);
                if attempts.get() == 1 {
                    Err(ToolExecutionFailure::Journal {
                        error: JournalError::IdempotencyConflict,
                        operation_id: None,
                    })
                } else {
                    Ok("wrong-snapshot-operation")
                }
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ToolExecutionFailure::Journal {
                error: JournalError::IdempotencyConflict,
                ..
            }
        ));
        assert_eq!(attempts.get(), 1);
    }

    fn operation_test_config(root: &Path) -> DepgraphServiceConfig {
        let repository = root.join("repository");
        std::fs::create_dir_all(&repository).unwrap();
        DepgraphServiceConfig::new(
            repository,
            root.join("graph.sqlite"),
            DepgraphCapabilitySet::try_new([
                DepgraphCapability::Read,
                DepgraphCapability::StoreWrite,
            ])
            .unwrap(),
            DepgraphServiceLimits::default(),
        )
        .unwrap()
    }

    fn seed_runtime_submit_store(config: &DepgraphServiceConfig) -> String {
        let coverage = json!({
            "profiles":1,
            "files_discovered":0,
            "files_analyzed":0,
            "files_skipped":0,
            "dependency_sites":0,
            "resolved":0,
            "candidates":0,
            "external":0,
            "unresolved":0,
            "unsupported_syntax":0,
            "project_code_executed":false,
            "completeness":["syntax-complete"],
            "reasons":[]
        });
        let common = |event: &str, seq: u64| {
            json!({
                "event":event,
                "protocol_version":"1.0",
                "scan_id":"runtime-submit-base",
                "adapter":"fixture",
                "adapter_version":"1.0",
                "seq":seq
            })
        };
        let mut store = Store::open(config.store_path()).unwrap();
        store
            .start_scan_with_revision(
                "runtime-submit-base",
                config.canonical_root(),
                false,
                Some("runtime-submit-revision"),
            )
            .unwrap();
        let mut started = common("scan_started", 1);
        started["root"] = json!(config.canonical_root());
        started["project_code_executed"] = json!(false);
        started["safe_mode"] = json!(true);
        store.ingest_event(&started).unwrap();
        let mut profile = common("profile_declared", 2);
        profile["profile"] = json!({
            "id":"profile:runtime-submit",
            "language":"runtime-fixture",
            "features":[],
            "environment":{},
            "properties":{}
        });
        store.ingest_event(&profile).unwrap();
        let mut workspace = common("node_upsert", 3);
        workspace["node"] = json!({
            "id":"workspace:runtime-submit",
            "kind":"workspace",
            "locator":"repo://runtime-submit",
            "display_name":"runtime-submit",
            "properties":{
                "path":"workspace",
                "repository_identity":"workspace:runtime-submit"
            }
        });
        store.ingest_event(&workspace).unwrap();
        let mut profile_completed = common("profile_completed", 4);
        profile_completed["profile_id"] = json!("profile:runtime-submit");
        profile_completed["coverage"] = coverage.clone();
        store.ingest_event(&profile_completed).unwrap();
        let mut completed = common("scan_completed", 5);
        completed["coverage"] = coverage;
        store.ingest_event(&completed).unwrap();
        store
            .finish_scan("runtime-submit-base", "completed", None, true)
            .unwrap();
        store.current_snapshot_id().unwrap().unwrap()
    }

    fn runtime_submit_trace(source_session_id: &str) -> String {
        json!({
            "schema_version":"1.0",
            "repository":{
                "identity":"workspace:runtime-submit",
                "revision":"runtime-submit-revision"
            },
            "session":{
                "id":source_session_id,
                "started_at":"2026-08-09T00:00:00Z",
                "ended_at":"2026-08-09T00:00:01Z",
                "profile":{"language":"runtime-fixture","features":[]},
                "environment":{"name":"test"},
                "redaction":{"redacted_value_count":0}
            },
            "events":[{
                "sequence":1,
                "timestamp":"2026-08-09T00:00:00Z",
                "dependency_kind":"imports",
                "source":{"kind":"node","node_id":"workspace:runtime-submit"},
                "target":{"kind":"external","namespace":"fixture","name":"dependency"},
                "count":1
            }]
        })
        .to_string()
    }

    fn maximum_expanding_runtime_submit_trace(source_session_id: &str) -> String {
        let events = (1_u64..=4_903)
            .map(|sequence| {
                json!({
                    "sequence":sequence,
                    "timestamp":"2026-08-09T00:00:00Z",
                    "dependency_kind":"imports",
                    "source":{"kind":"node","node_id":"workspace:runtime-submit"},
                    "target":{"kind":"external","namespace":"fixture","name":"dependency"}
                })
            })
            .collect::<Vec<_>>();
        let mut trace = json!({
            "schema_version":"1.0",
            "repository":{
                "identity":"workspace:runtime-submit",
                "revision":"runtime-submit-revision"
            },
            "session":{
                "id":source_session_id,
                "started_at":"2026-08-09T00:00:00Z",
                "profile":{"language":"runtime-fixture"},
                "environment":{"name":"test"}
            },
            "events":events
        })
        .to_string();
        let maximum = depgraph_core::service::DEFAULT_SERVICE_MAX_INLINE_INPUT_BYTES;
        assert!(trace.len() <= maximum);
        assert!(maximum - trace.len() < 512);
        trace.push_str(&" ".repeat(maximum - trace.len()));
        trace
    }

    fn submit_runtime_test_operation(
        config: &DepgraphServiceConfig,
        input: &serde_json::Value,
        idempotency_key: &str,
    ) -> Result<OperationHandle, ToolExecutionFailure> {
        let now_ms = system_now_ms()?;
        let request = SubmitRequest::new(
            config,
            OperationKind::RuntimeTraceImportSubmit,
            input,
            idempotency_key.as_bytes(),
            now_ms + SCAN_EXECUTION_DEADLINE_MS,
        )
        .map_err(|error| ToolExecutionFailure::Journal {
            error,
            operation_id: None,
        })?;
        OperationManager::open(config)
            .and_then(|mut manager| manager.submit(&request, now_ms))
            .map_err(|error| ToolExecutionFailure::Journal {
                error,
                operation_id: None,
            })
    }

    fn downgrade_runtime_submit_store_to_v15(config: &DepgraphServiceConfig) {
        let connection = rusqlite::Connection::open(config.store_path()).unwrap();
        connection
            .execute_batch(
                "PRAGMA wal_checkpoint(TRUNCATE);
                 PRAGMA journal_mode=DELETE;
                 DROP TABLE scan_operation_staging;
                 DROP TABLE runtime_import_operation_owners;
                 PRAGMA user_version=15;
                 VACUUM;",
            )
            .unwrap();
    }

    #[test]
    fn concurrent_default_current_runtime_submit_recovers_the_original_binding() {
        let root = tempfile::tempdir().unwrap();
        let config = operation_test_config(root.path());
        let base_snapshot_id = seed_runtime_submit_store(&config);
        let trace = runtime_submit_trace("concurrent-default-current");
        let source = depgraph_core::service::RuntimeTraceSourceRequest {
            trace: Some(trace.clone()),
            trace_file: None,
        };
        let requested_locator = SnapshotLocator::Current;
        let idempotency_key = IdempotencyKey::parse("concurrent-default-current").unwrap();
        let cancellation = CancellationToken::new();
        let service = DepgraphService::new(config.clone());
        let winner_prevalidated = service
            .prevalidate_runtime_trace_source(&source, &cancellation)
            .unwrap();
        assert!(
            existing_runtime_import_submission_input(&config, &idempotency_key)
                .unwrap()
                .is_none()
        );
        let winner_input = prepare_runtime_import_submission_input(
            &service,
            &source,
            winner_prevalidated,
            &requested_locator,
            None,
            RuntimeBindingResolution::Requested,
            &cancellation,
        )
        .unwrap();
        assert_eq!(winner_input["snapshot_id"], base_snapshot_id);

        let (loser_missed, wait_for_loser_miss) = mpsc::sync_channel(0);
        let (current_advanced, wait_for_current_advance) = mpsc::sync_channel(0);
        let loser_config = config.clone();
        let loser_source = source.clone();
        let loser_idempotency_key = idempotency_key.clone();
        let loser = std::thread::spawn(move || {
            let service = DepgraphService::new(loser_config.clone());
            let cancellation = CancellationToken::new();
            let prevalidated = service
                .prevalidate_runtime_trace_source(&loser_source, &cancellation)
                .unwrap();
            assert!(
                existing_runtime_import_submission_input(&loser_config, &loser_idempotency_key,)
                    .unwrap()
                    .is_none()
            );
            loser_missed.send(()).unwrap();
            let advanced_snapshot_id = wait_for_current_advance.recv().unwrap();
            let initial_input = prepare_runtime_import_submission_input(
                &service,
                &loser_source,
                prevalidated.clone(),
                &SnapshotLocator::Current,
                None,
                RuntimeBindingResolution::Requested,
                &cancellation,
            )
            .unwrap();
            assert_eq!(initial_input["snapshot_id"], advanced_snapshot_id);
            let mut submit_attempts = 0;
            let handle = match submit_runtime_import_with_conflict_recovery(
                RuntimeImportSubmissionContext {
                    config: &loser_config,
                    service: &service,
                    source: &loser_source,
                    initial_prevalidation: &prevalidated,
                    requested_locator: &SnapshotLocator::Current,
                    idempotency_key: &loser_idempotency_key,
                    cancellation: &cancellation,
                },
                initial_input,
                |input| {
                    submit_attempts += 1;
                    submit_runtime_test_operation(
                        &loser_config,
                        input,
                        "concurrent-default-current",
                    )
                },
            ) {
                Ok(handle) => handle,
                Err(_) => panic!("lost-race recovery rejected the exact original request"),
            };
            assert_eq!(submit_attempts, 2);
            handle
        });

        wait_for_loser_miss.recv().unwrap();
        let winner =
            submit_runtime_test_operation(&config, &winner_input, "concurrent-default-current")
                .unwrap();
        assert!(winner.created());
        let advanced = service
            .runtime_import(
                &RuntimeValidateRequest {
                    trace: Some(trace),
                    trace_file: None,
                    snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                        base_snapshot_id.clone(),
                    )),
                },
                &cancellation,
            )
            .unwrap();
        assert_ne!(advanced.completed_snapshot_id().as_str(), base_snapshot_id);
        current_advanced
            .send(advanced.completed_snapshot_id().as_str().to_owned())
            .unwrap();

        let replay = loser.join().unwrap();
        assert!(!replay.created());
        assert_eq!(replay.operation_id(), winner.operation_id());
        let established = existing_runtime_import_submission_input(&config, &idempotency_key)
            .unwrap()
            .unwrap();
        assert_eq!(established, winner_input);

        let mut old_journal_input = winner_input.clone();
        old_journal_input
            .as_object_mut()
            .unwrap()
            .remove("session_id");
        old_journal_input
            .as_object_mut()
            .unwrap()
            .remove("runtime_trace_digest");
        assert_eq!(
            runtime_import_replay_input(winner_input, &old_journal_input).unwrap(),
            old_journal_input
        );
    }

    #[test]
    fn concurrent_explicit_name_runtime_submit_keeps_the_requested_binding() {
        let root = tempfile::tempdir().unwrap();
        let config = operation_test_config(root.path());
        let snapshot_a = seed_runtime_submit_store(&config);
        let trace = runtime_submit_trace("concurrent-explicit-name");
        let source = depgraph_core::service::RuntimeTraceSourceRequest {
            trace: Some(trace.clone()),
            trace_file: None,
        };
        let service = DepgraphService::new(config.clone());
        let cancellation = CancellationToken::new();
        let snapshot_b = service
            .runtime_import(
                &RuntimeValidateRequest {
                    trace: Some(trace),
                    trace_file: None,
                    snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                        snapshot_a.clone(),
                    )),
                },
                &cancellation,
            )
            .unwrap()
            .completed_snapshot_id()
            .as_str()
            .to_owned();
        service
            .snapshot_name_create(
                &SnapshotNameCreateRequest::new(
                    "runtime-snapshot-b",
                    SnapshotLocator::StableId(snapshot_b.clone()),
                ),
                &cancellation,
            )
            .unwrap();

        let idempotency_key = IdempotencyKey::parse("concurrent-explicit-name").unwrap();
        assert!(
            existing_runtime_import_submission_input(&config, &idempotency_key)
                .unwrap()
                .is_none()
        );
        let prevalidated = service
            .prevalidate_runtime_trace_source(&source, &cancellation)
            .unwrap();
        let requested_locator = SnapshotLocator::parse("runtime-snapshot-b").unwrap();
        let loser_input = prepare_runtime_import_submission_input(
            &service,
            &source,
            prevalidated.clone(),
            &requested_locator,
            None,
            RuntimeBindingResolution::Requested,
            &cancellation,
        )
        .unwrap();
        assert_eq!(loser_input["snapshot_id"], snapshot_b);
        let winner_input = prepare_runtime_import_submission_input(
            &service,
            &source,
            prevalidated.clone(),
            &SnapshotLocator::StableId(snapshot_a.clone()),
            None,
            RuntimeBindingResolution::Requested,
            &cancellation,
        )
        .unwrap();
        assert_eq!(winner_input["snapshot_id"], snapshot_a);
        submit_runtime_test_operation(&config, &winner_input, "concurrent-explicit-name").unwrap();

        let mut submit_attempts = 0;
        let rejected = submit_runtime_import_with_conflict_recovery(
            RuntimeImportSubmissionContext {
                config: &config,
                service: &service,
                source: &source,
                initial_prevalidation: &prevalidated,
                requested_locator: &requested_locator,
                idempotency_key: &idempotency_key,
                cancellation: &cancellation,
            },
            loser_input,
            |input| {
                submit_attempts += 1;
                submit_runtime_test_operation(&config, input, "concurrent-explicit-name")
            },
        );
        assert!(matches!(
            rejected,
            Err(ToolExecutionFailure::Journal {
                error: JournalError::IdempotencyConflict,
                ..
            })
        ));
        assert_eq!(submit_attempts, 1);
        assert_eq!(
            existing_runtime_import_submission_input(&config, &idempotency_key)
                .unwrap()
                .unwrap(),
            winner_input
        );
    }

    #[test]
    fn concurrent_explicit_stable_runtime_submit_replays_the_same_binding() {
        let root = tempfile::tempdir().unwrap();
        let config = operation_test_config(root.path());
        let snapshot_a = seed_runtime_submit_store(&config);
        let trace = runtime_submit_trace("concurrent-explicit-stable");
        let source = depgraph_core::service::RuntimeTraceSourceRequest {
            trace: Some(trace.clone()),
            trace_file: None,
        };
        let service = DepgraphService::new(config.clone());
        let cancellation = CancellationToken::new();
        let snapshot_b = service
            .runtime_import(
                &RuntimeValidateRequest {
                    trace: Some(trace),
                    trace_file: None,
                    snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                        snapshot_a.clone(),
                    )),
                },
                &cancellation,
            )
            .unwrap()
            .completed_snapshot_id()
            .as_str()
            .to_owned();
        assert_ne!(snapshot_a, snapshot_b);

        let idempotency_key = IdempotencyKey::parse("concurrent-explicit-stable").unwrap();
        assert!(
            existing_runtime_import_submission_input(&config, &idempotency_key)
                .unwrap()
                .is_none()
        );
        let prevalidated = service
            .prevalidate_runtime_trace_source(&source, &cancellation)
            .unwrap();
        let requested_locator = SnapshotLocator::StableId(snapshot_a.clone());
        let input = prepare_runtime_import_submission_input(
            &service,
            &source,
            prevalidated.clone(),
            &requested_locator,
            None,
            RuntimeBindingResolution::Requested,
            &cancellation,
        )
        .unwrap();
        let winner =
            submit_runtime_test_operation(&config, &input, "concurrent-explicit-stable").unwrap();
        assert!(winner.created());

        let mut submit_attempts = 0;
        let replay = submit_runtime_import_with_conflict_recovery(
            RuntimeImportSubmissionContext {
                config: &config,
                service: &service,
                source: &source,
                initial_prevalidation: &prevalidated,
                requested_locator: &requested_locator,
                idempotency_key: &idempotency_key,
                cancellation: &cancellation,
            },
            input.clone(),
            |candidate| {
                submit_attempts += 1;
                if submit_attempts == 1 {
                    return Err(ToolExecutionFailure::Journal {
                        error: JournalError::IdempotencyConflict,
                        operation_id: None,
                    });
                }
                submit_runtime_test_operation(&config, candidate, "concurrent-explicit-stable")
            },
        )
        .unwrap();
        assert_eq!(submit_attempts, 2);
        assert!(!replay.created());
        assert_eq!(replay.operation_id(), winner.operation_id());
        assert_eq!(
            existing_runtime_import_submission_input(&config, &idempotency_key)
                .unwrap()
                .unwrap(),
            input
        );
    }

    #[test]
    fn runtime_submit_conflict_recovery_rejects_mismatched_trace() {
        let root = tempfile::tempdir().unwrap();
        let config = operation_test_config(root.path());
        let base_snapshot_id = seed_runtime_submit_store(&config);
        let original_trace = runtime_submit_trace("conflict-original");
        let original_source = depgraph_core::service::RuntimeTraceSourceRequest {
            trace: Some(original_trace.clone()),
            trace_file: None,
        };
        let service = DepgraphService::new(config.clone());
        let idempotency_key = IdempotencyKey::parse("mismatched-trace").unwrap();
        let cancellation = CancellationToken::new();
        let original_prevalidated = service
            .prevalidate_runtime_trace_source(&original_source, &cancellation)
            .unwrap();
        let original_input = prepare_runtime_import_submission_input(
            &service,
            &original_source,
            original_prevalidated,
            &SnapshotLocator::Current,
            None,
            RuntimeBindingResolution::Requested,
            &cancellation,
        )
        .unwrap();
        submit_runtime_test_operation(&config, &original_input, "mismatched-trace").unwrap();
        service
            .runtime_import(
                &RuntimeValidateRequest {
                    trace: Some(original_trace),
                    trace_file: None,
                    snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                        base_snapshot_id,
                    )),
                },
                &cancellation,
            )
            .unwrap();

        let mismatched_source = depgraph_core::service::RuntimeTraceSourceRequest {
            trace: Some(runtime_submit_trace("conflict-mismatch")),
            trace_file: None,
        };
        let mismatched_prevalidated = service
            .prevalidate_runtime_trace_source(&mismatched_source, &cancellation)
            .unwrap();
        let mismatched_input = prepare_runtime_import_submission_input(
            &service,
            &mismatched_source,
            mismatched_prevalidated.clone(),
            &SnapshotLocator::Current,
            None,
            RuntimeBindingResolution::Requested,
            &cancellation,
        )
        .unwrap();
        let mut submit_attempts = 0;
        let rejected = submit_runtime_import_with_conflict_recovery(
            RuntimeImportSubmissionContext {
                config: &config,
                service: &service,
                source: &mismatched_source,
                initial_prevalidation: &mismatched_prevalidated,
                requested_locator: &SnapshotLocator::Current,
                idempotency_key: &idempotency_key,
                cancellation: &cancellation,
            },
            mismatched_input,
            |input| {
                submit_attempts += 1;
                submit_runtime_test_operation(&config, input, "mismatched-trace")
            },
        );
        assert!(matches!(
            rejected,
            Err(ToolExecutionFailure::Journal {
                error: JournalError::IdempotencyConflict,
                ..
            })
        ));
        assert_eq!(submit_attempts, 1);
        assert_eq!(
            existing_runtime_import_submission_input(&config, &idempotency_key)
                .unwrap()
                .unwrap(),
            original_input
        );
    }

    #[test]
    fn runtime_submit_conflict_recovery_rejects_file_drift() {
        let root = tempfile::tempdir().unwrap();
        let config = operation_test_config(root.path());
        let base_snapshot_id = seed_runtime_submit_store(&config);
        let trace_path = config.canonical_root().join("runtime.json");
        let original_trace = runtime_submit_trace("file-drift-original");
        std::fs::write(&trace_path, &original_trace).unwrap();
        let source = depgraph_core::service::RuntimeTraceSourceRequest {
            trace: None,
            trace_file: Some(
                depgraph_core::service::RepositoryRelativePath::parse("runtime.json").unwrap(),
            ),
        };
        let service = DepgraphService::new(config.clone());
        let idempotency_key = IdempotencyKey::parse("file-drift").unwrap();
        let cancellation = CancellationToken::new();
        let prevalidated = service
            .prevalidate_runtime_trace_source(&source, &cancellation)
            .unwrap();
        let original_input = prepare_runtime_import_submission_input(
            &service,
            &source,
            prevalidated.clone(),
            &SnapshotLocator::Current,
            None,
            RuntimeBindingResolution::Requested,
            &cancellation,
        )
        .unwrap();
        submit_runtime_test_operation(&config, &original_input, "file-drift").unwrap();
        service
            .runtime_import(
                &RuntimeValidateRequest {
                    trace: Some(original_trace),
                    trace_file: None,
                    snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                        base_snapshot_id,
                    )),
                },
                &cancellation,
            )
            .unwrap();
        let initial_input = prepare_runtime_import_submission_input(
            &service,
            &source,
            prevalidated.clone(),
            &SnapshotLocator::Current,
            None,
            RuntimeBindingResolution::Requested,
            &cancellation,
        )
        .unwrap();
        std::fs::write(&trace_path, runtime_submit_trace("file-drift-changed")).unwrap();

        let mut submit_attempts = 0;
        let rejected = submit_runtime_import_with_conflict_recovery(
            RuntimeImportSubmissionContext {
                config: &config,
                service: &service,
                source: &source,
                initial_prevalidation: &prevalidated,
                requested_locator: &SnapshotLocator::Current,
                idempotency_key: &idempotency_key,
                cancellation: &cancellation,
            },
            initial_input,
            |input| {
                submit_attempts += 1;
                submit_runtime_test_operation(&config, input, "file-drift")
            },
        );
        assert!(matches!(
            rejected,
            Err(ToolExecutionFailure::Service(
                DepgraphServiceError::Conflict
            ))
        ));
        assert_eq!(submit_attempts, 1);
        assert_eq!(
            existing_runtime_import_submission_input(&config, &idempotency_key)
                .unwrap()
                .unwrap(),
            original_input
        );
    }

    #[test]
    fn valid_runtime_trace_drift_cannot_create_a_journal_or_migrate_the_store() {
        let root = tempfile::tempdir().unwrap();
        let config = operation_test_config(root.path());
        seed_runtime_submit_store(&config);
        let trace_path = config.canonical_root().join("runtime.json");
        std::fs::write(&trace_path, runtime_submit_trace("drift-before-open")).unwrap();
        let source = depgraph_core::service::RuntimeTraceSourceRequest {
            trace: None,
            trace_file: Some(
                depgraph_core::service::RepositoryRelativePath::parse("runtime.json").unwrap(),
            ),
        };
        let service = DepgraphService::new(config.clone());
        let cancellation = CancellationToken::new();
        let prevalidated = service
            .prevalidate_runtime_trace_source(&source, &cancellation)
            .unwrap();
        let connection = rusqlite::Connection::open(config.store_path()).unwrap();
        connection
            .execute_batch(
                "PRAGMA journal_mode=DELETE;
                 DROP TABLE scan_operation_staging;
                 DROP TABLE runtime_import_operation_owners;
                 PRAGMA user_version=15;
                 VACUUM;",
            )
            .unwrap();
        drop(connection);
        let before_store = std::fs::read(config.store_path()).unwrap();
        let key = IdempotencyKey::parse("drift-before-open").unwrap();
        assert!(
            existing_runtime_import_submission_input(&config, &key)
                .unwrap()
                .is_none()
        );
        assert!(
            !depgraph_operation::operation_journal_path(&config)
                .as_path()
                .exists()
        );

        std::fs::write(&trace_path, runtime_submit_trace("drift-after-open")).unwrap();
        assert!(matches!(
            prepare_runtime_import_submission_input(
                &service,
                &source,
                prevalidated,
                &SnapshotLocator::Current,
                None,
                RuntimeBindingResolution::Requested,
                &cancellation,
            ),
            Err(ToolExecutionFailure::Service(
                DepgraphServiceError::Conflict
            ))
        ));

        assert!(
            !depgraph_operation::operation_journal_path(&config)
                .as_path()
                .exists()
        );
        assert_eq!(std::fs::read(config.store_path()).unwrap(), before_store);
        assert_eq!(
            rusqlite::Connection::open_with_flags(
                config.store_path(),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .unwrap()
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
            15
        );
    }

    #[test]
    fn conflicting_valid_v15_runtime_replay_is_rejected_before_store_migration() {
        let root = tempfile::tempdir().unwrap();
        let config = operation_test_config(root.path());
        seed_runtime_submit_store(&config);
        let service = DepgraphService::new(config.clone());
        let cancellation = CancellationToken::new();
        let original_source = depgraph_core::service::RuntimeTraceSourceRequest {
            trace: Some(runtime_submit_trace("v15-original-replay")),
            trace_file: None,
        };
        let original_prevalidated = service
            .prevalidate_runtime_trace_source(&original_source, &cancellation)
            .unwrap();
        let original_input = prepare_runtime_import_submission_input(
            &service,
            &original_source,
            original_prevalidated,
            &SnapshotLocator::Current,
            None,
            RuntimeBindingResolution::Requested,
            &cancellation,
        )
        .unwrap();
        submit_runtime_test_operation(&config, &original_input, "v15-conflicting-replay").unwrap();
        downgrade_runtime_submit_store_to_v15(&config);
        let before_bytes = std::fs::read(config.store_path()).unwrap();
        let before_rows = rusqlite::Connection::open_with_flags(
            config.store_path(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM completed_snapshots),
                    (SELECT COUNT(*) FROM runtime_sessions),
                    (SELECT COUNT(*) FROM snapshot_sources)",
            [],
            |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            },
        )
        .unwrap();
        let existing_input = existing_runtime_import_submission_input(
            &config,
            &IdempotencyKey::parse("v15-conflicting-replay").unwrap(),
        )
        .unwrap()
        .unwrap();
        let conflicting_source = depgraph_core::service::RuntimeTraceSourceRequest {
            trace: Some(runtime_submit_trace("v15-conflicting-replay")),
            trace_file: None,
        };
        let conflicting_prevalidated = service
            .prevalidate_runtime_trace_source(&conflicting_source, &cancellation)
            .unwrap();

        assert!(matches!(
            prepare_runtime_import_replay_candidate_read_only(
                &service,
                &conflicting_source,
                conflicting_prevalidated,
                &SnapshotLocator::Current,
                &existing_input,
                &cancellation,
            ),
            Err(ToolExecutionFailure::Journal {
                error: JournalError::IdempotencyConflict,
                ..
            })
        ));
        assert_eq!(std::fs::read(config.store_path()).unwrap(), before_bytes);
        let connection = rusqlite::Connection::open_with_flags(
            config.store_path(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            15
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM completed_snapshots),
                            (SELECT COUNT(*) FROM runtime_sessions),
                            (SELECT COUNT(*) FROM snapshot_sources)",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, u64>(0)?,
                            row.get::<_, u64>(1)?,
                            row.get::<_, u64>(2)?,
                        ))
                    },
                )
                .unwrap(),
            before_rows
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                      WHERE name IN ('runtime_import_operation_owners',
                                     'scan_operation_staging')",
                    [],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn exact_v15_runtime_replay_migrates_and_reuses_the_journal_binding() {
        let root = tempfile::tempdir().unwrap();
        let config = operation_test_config(root.path());
        seed_runtime_submit_store(&config);
        let service = DepgraphService::new(config.clone());
        let cancellation = CancellationToken::new();
        let source = depgraph_core::service::RuntimeTraceSourceRequest {
            trace: Some(runtime_submit_trace("v15-exact-replay")),
            trace_file: None,
        };
        let prevalidated = service
            .prevalidate_runtime_trace_source(&source, &cancellation)
            .unwrap();
        let original_input = prepare_runtime_import_submission_input(
            &service,
            &source,
            prevalidated.clone(),
            &SnapshotLocator::Current,
            None,
            RuntimeBindingResolution::Requested,
            &cancellation,
        )
        .unwrap();
        let original =
            submit_runtime_test_operation(&config, &original_input, "v15-exact-replay").unwrap();
        downgrade_runtime_submit_store_to_v15(&config);
        let existing_input = existing_runtime_import_submission_input(
            &config,
            &IdempotencyKey::parse("v15-exact-replay").unwrap(),
        )
        .unwrap()
        .unwrap();

        let candidate = prepare_runtime_import_replay_candidate_read_only(
            &service,
            &source,
            prevalidated.clone(),
            &SnapshotLocator::Current,
            &existing_input,
            &cancellation,
        )
        .unwrap();
        assert_eq!(candidate, original_input);
        assert_eq!(
            rusqlite::Connection::open(config.store_path())
                .unwrap()
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            15
        );

        let replay_input = prepare_runtime_import_submission_input(
            &service,
            &source,
            prevalidated,
            &SnapshotLocator::Current,
            Some(&existing_input),
            RuntimeBindingResolution::Requested,
            &cancellation,
        )
        .unwrap();
        let replay =
            submit_runtime_test_operation(&config, &replay_input, "v15-exact-replay").unwrap();
        assert!(!replay.created());
        assert_eq!(replay.operation_id(), original.operation_id());
        assert_eq!(
            rusqlite::Connection::open(config.store_path())
                .unwrap()
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            depgraph_store::STORE_SCHEMA_VERSION
        );
    }

    #[test]
    fn maximum_inline_runtime_trace_normalization_fits_the_operation_journal() {
        let root = tempfile::tempdir().unwrap();
        let config = operation_test_config(root.path());
        seed_runtime_submit_store(&config);
        let trace = maximum_expanding_runtime_submit_trace("maximum-inline-normalization");
        assert_eq!(
            trace.len(),
            depgraph_core::service::DEFAULT_SERVICE_MAX_INLINE_INPUT_BYTES
        );
        let source = depgraph_core::service::RuntimeTraceSourceRequest {
            trace: Some(trace),
            trace_file: None,
        };
        let service = DepgraphService::new(config.clone());
        let cancellation = CancellationToken::new();
        let prevalidated = service
            .prevalidate_runtime_trace_source(&source, &cancellation)
            .unwrap();
        let connection = rusqlite::Connection::open(config.store_path()).unwrap();
        connection
            .execute_batch(
                "PRAGMA journal_mode=DELETE;
                 DROP TABLE scan_operation_staging;
                 DROP TABLE runtime_import_operation_owners;
                 PRAGMA user_version=15;
                 VACUUM;",
            )
            .unwrap();
        drop(connection);

        let input = prepare_runtime_import_submission_input(
            &service,
            &source,
            prevalidated,
            &SnapshotLocator::Current,
            None,
            RuntimeBindingResolution::Requested,
            &cancellation,
        )
        .unwrap();
        let normalized_bytes = depgraph_mcp_tools::canonical_json_bytes(&input)
            .unwrap()
            .len();
        assert!(normalized_bytes > 1024 * 1024);
        assert!(normalized_bytes <= depgraph_operation::MAX_OPERATION_INPUT_BYTES);
        let request = SubmitRequest::new(
            &config,
            OperationKind::RuntimeTraceImportSubmit,
            &input,
            b"maximum-inline-normalization",
            system_now_ms().unwrap() + SCAN_EXECUTION_DEADLINE_MS,
        )
        .unwrap();
        assert_eq!(request.normalized_input().as_str().len(), normalized_bytes);
        assert_eq!(
            rusqlite::Connection::open(config.store_path())
                .unwrap()
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            17
        );
    }

    #[test]
    fn bounded_stderr_limits_each_record_and_total_output() {
        assert_eq!(
            bounded_write_len(0, MAX_STDERR_RECORD_BYTES, usize::MAX),
            MAX_STDERR_RECORD_BYTES
        );
        assert_eq!(bounded_write_len(MAX_STDERR_TOTAL_BYTES - 2, 10, 99), 2);
        assert_eq!(bounded_write_len(MAX_STDERR_TOTAL_BYTES, 10, 99), 0);
    }

    #[test]
    fn dto_collection_caps_map_to_service_resource_exhaustion() {
        for error in [
            ContractBuildError::PageByteLimit,
            ContractBuildError::TooManyEvidenceItems,
            ContractBuildError::TooManyCorrelationReasons,
            ContractBuildError::TooManyPhases,
            ContractBuildError::TooManyCycleNodes,
        ] {
            assert!(matches!(
                contract_mapping_error(error),
                ToolExecutionFailure::Service(DepgraphServiceError::ResourceExhausted)
            ));
        }
        assert!(matches!(
            contract_mapping_error(ContractBuildError::CycleTopology),
            ToolExecutionFailure::Service(DepgraphServiceError::Integrity)
        ));
    }

    #[test]
    fn journal_errors_map_exhaustively_without_reflecting_sources() {
        let operation_id = OperationId::parse("op_0123456789abcdef0123456789abcdef").unwrap();
        for (error, code, remediation, retryable) in [
            (
                JournalError::InvalidArgument,
                AgentErrorCode::InvalidArgument,
                AgentRemediation::CorrectInput,
                false,
            ),
            (
                JournalError::UnsupportedSchemaVersion,
                AgentErrorCode::IntegrityFailure,
                AgentRemediation::ContactOperator,
                false,
            ),
            (
                JournalError::IntegrityFailure,
                AgentErrorCode::IntegrityFailure,
                AgentRemediation::ContactOperator,
                false,
            ),
            (
                JournalError::NotFound,
                AgentErrorCode::NotFound,
                AgentRemediation::CorrectInput,
                false,
            ),
            (
                JournalError::Expired,
                AgentErrorCode::NotFound,
                AgentRemediation::CorrectInput,
                false,
            ),
            (
                JournalError::RepositoryMismatch,
                AgentErrorCode::CapabilityDenied,
                AgentRemediation::EnableRequiredCapability,
                false,
            ),
            (
                JournalError::CapabilityDenied,
                AgentErrorCode::CapabilityDenied,
                AgentRemediation::EnableRequiredCapability,
                false,
            ),
            (
                JournalError::IdempotencyConflict,
                AgentErrorCode::IdempotencyConflict,
                AgentRemediation::CorrectInput,
                false,
            ),
            (
                JournalError::OperationNotReady,
                AgentErrorCode::OperationNotReady,
                AgentRemediation::PollOperation,
                true,
            ),
            (
                JournalError::InvalidTransition,
                AgentErrorCode::IntegrityFailure,
                AgentRemediation::ContactOperator,
                false,
            ),
            (
                JournalError::LeaseHeld,
                AgentErrorCode::IntegrityFailure,
                AgentRemediation::ContactOperator,
                false,
            ),
            (
                JournalError::LeaseMismatch,
                AgentErrorCode::IntegrityFailure,
                AgentRemediation::ContactOperator,
                false,
            ),
            (
                JournalError::LeaseExpired,
                AgentErrorCode::IntegrityFailure,
                AgentRemediation::ContactOperator,
                false,
            ),
            (
                JournalError::DeadlineExceeded,
                AgentErrorCode::OperationNotReady,
                AgentRemediation::PollOperation,
                true,
            ),
            (
                JournalError::EntropyUnavailable,
                AgentErrorCode::Internal,
                AgentRemediation::ContactOperator,
                true,
            ),
        ] {
            let mapped = map_journal_error(&error, Some(operation_id.clone()));
            assert_eq!(mapped.code(), code);
            assert_eq!(mapped.remediation(), remediation);
            assert_eq!(mapped.retryable(), retryable);
        }

        for source in [
            JournalError::Io(io::Error::other("TOP_SECRET_IO")),
            JournalError::Storage(rusqlite::Error::InvalidParameterName(
                "TOP_SECRET_SQL".to_owned(),
            )),
        ] {
            let mapped = map_journal_error(&source, Some(operation_id.clone()));
            assert_eq!(mapped.code(), AgentErrorCode::Internal);
            let encoded = serde_json::to_string(&ErrorEnvelope::new(
                LogicalRepositoryId::parse("repository").unwrap(),
                mapped,
            ))
            .unwrap();
            assert!(!encoded.contains("TOP_SECRET"));
        }
    }

    #[test]
    fn task_creation_projects_replayed_operation_status_without_regressing_to_working() {
        for status in [
            OperationStatus::Queued,
            OperationStatus::Running,
            OperationStatus::Cancelling,
        ] {
            assert_eq!(create_task_status(status), (TaskStatus::Working, true));
        }
        assert_eq!(
            create_task_status(OperationStatus::Cancelled),
            (TaskStatus::Cancelled, false)
        );
        for status in [OperationStatus::Completed, OperationStatus::Failed] {
            assert_eq!(create_task_status(status), (TaskStatus::Completed, false));
        }
    }

    #[test]
    fn cancellation_after_durable_scan_submit_cancels_without_launching() {
        let root = tempfile::tempdir().unwrap();
        let config = operation_test_config(root.path());
        let repository_id = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let now_ms = system_now_ms().ok().unwrap();
        let request = SubmitRequest::new(
            &config,
            OperationKind::ScanSubmit,
            &serde_json::json!({"no_cache": true, "strict": false}),
            b"cancel-after-durable-submit",
            now_ms + SCAN_EXECUTION_DEADLINE_MS,
        )
        .unwrap();
        let mut manager = OperationManager::open(&config).unwrap();
        let handle = manager.submit(&request, now_ms).unwrap();
        let startup = RunnerStartupConfig::new(config.clone()).unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let launches = Arc::new(AtomicUsize::new(0));

        let result = handoff_submitted_scan(&mut manager, &startup, &handle, &cancellation, {
            let launches = Arc::clone(&launches);
            move |_| {
                launches.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        });

        assert!(matches!(
            result,
            Err(ToolExecutionFailure::Service(
                DepgraphServiceError::Cancelled
            ))
        ));
        assert_eq!(launches.load(Ordering::SeqCst), 0);
        let journal = OperationJournal::open(&config).unwrap();
        assert_eq!(
            journal
                .get(
                    &repository_id,
                    handle.operation_id(),
                    system_now_ms().ok().unwrap(),
                )
                .unwrap()
                .status(),
            OperationStatus::Cancelled
        );
    }

    #[test]
    fn launch_failure_after_durable_scan_submit_cancels_orphaned_work() {
        let root = tempfile::tempdir().unwrap();
        let config = operation_test_config(root.path());
        let repository_id = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let now_ms = system_now_ms().ok().unwrap();
        let request = SubmitRequest::new(
            &config,
            OperationKind::ScanSubmit,
            &serde_json::json!({"no_cache": true, "strict": false}),
            b"launch-failure-after-durable-submit",
            now_ms + SCAN_EXECUTION_DEADLINE_MS,
        )
        .unwrap();
        let mut manager = OperationManager::open(&config).unwrap();
        let handle = manager.submit(&request, now_ms).unwrap();
        let startup = RunnerStartupConfig::new(config.clone()).unwrap();
        let cancellation = CancellationToken::new();
        let launches = Arc::new(AtomicUsize::new(0));

        let result = handoff_submitted_scan(&mut manager, &startup, &handle, &cancellation, {
            let launches = Arc::clone(&launches);
            move |_| {
                launches.fetch_add(1, Ordering::SeqCst);
                Err(ToolExecutionFailure::Agent(internal_agent_error()))
            }
        });

        assert!(matches!(result, Err(ToolExecutionFailure::Agent(_))));
        assert_eq!(launches.load(Ordering::SeqCst), 1);
        assert_eq!(
            OperationJournal::open(&config)
                .unwrap()
                .get(
                    &repository_id,
                    handle.operation_id(),
                    system_now_ms().ok().unwrap(),
                )
                .unwrap()
                .status(),
            OperationStatus::Cancelled
        );

        let replay = manager
            .submit(&request, system_now_ms().ok().unwrap())
            .unwrap();
        assert!(!replay.created());
        assert_eq!(replay.status(), OperationStatus::Cancelled);
        let replay_result =
            handoff_submitted_scan(&mut manager, &startup, &replay, &cancellation, {
                let launches = Arc::clone(&launches);
                move |_| {
                    launches.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            });
        assert!(matches!(
            replay_result,
            Err(ToolExecutionFailure::Service(
                DepgraphServiceError::Cancelled
            ))
        ));
        assert_eq!(launches.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancelled_scan_submit_retry_does_not_cancel_existing_durable_work() {
        let root = tempfile::tempdir().unwrap();
        let config = operation_test_config(root.path());
        let repository_id = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let now_ms = system_now_ms().ok().unwrap();
        let request = SubmitRequest::new(
            &config,
            OperationKind::ScanSubmit,
            &serde_json::json!({"no_cache": true, "strict": false}),
            b"cancelled-idempotent-retry",
            now_ms + SCAN_EXECUTION_DEADLINE_MS,
        )
        .unwrap();
        let mut manager = OperationManager::open(&config).unwrap();
        let original = manager.submit(&request, now_ms).unwrap();
        assert!(original.created());
        let replay = manager.submit(&request, now_ms).unwrap();
        assert!(!replay.created());
        let startup = RunnerStartupConfig::new(config.clone()).unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let launches = Arc::new(AtomicUsize::new(0));

        let result = handoff_submitted_scan(&mut manager, &startup, &replay, &cancellation, {
            let launches = Arc::clone(&launches);
            move |_| {
                launches.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        });

        assert!(matches!(
            result,
            Err(ToolExecutionFailure::Service(
                DepgraphServiceError::Cancelled
            ))
        ));
        assert_eq!(launches.load(Ordering::SeqCst), 0);
        assert_eq!(
            OperationJournal::open(&config)
                .unwrap()
                .get(
                    &repository_id,
                    original.operation_id(),
                    system_now_ms().ok().unwrap(),
                )
                .unwrap()
                .status(),
            OperationStatus::Queued
        );
    }
}
