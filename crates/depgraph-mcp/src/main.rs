use std::{
    borrow::Cow,
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, ValueEnum};
use depgraph_core::service::{
    BoundedQueryMode, BoundedQueryRequest, ClosedRecordDiff, CyclesRequest,
    DEFAULT_GRAPH_EXPORT_MAX_EDGES, DEFAULT_GRAPH_EXPORT_MAX_NODES, DependenciesRequest,
    DependencyDirection, DoctorRequest, EdgeDirection, ExplainPathRequest, GraphExportFormat,
    GraphExportRequest, GraphExportResult, ImpactRequest, NodeMatchMode, PolicyEvaluateRequest,
    PolicyEvaluationResult, ProfilePlanRequest, RuntimeValidateRequest, ServiceSnapshotSelector,
    SnapshotDiffFilters, SnapshotDiffRequest, SnapshotDiffResult, UnresolvedRequest,
};
use depgraph_core::{
    CancellationToken, CycleLevel, DepgraphCapability, DepgraphCapabilitySet, DepgraphService,
    DepgraphServiceConfig, DepgraphServiceError, DepgraphServiceLimits, GraphQueryFilter,
    ImpactFilters, MAX_INTERACTIVE_QUERY_TRAVERSAL, SnapshotLocator, VerifiedCompilerPack,
    read_compiler_pack_requirement, verify_compiler_pack,
};
use depgraph_mcp::runtime::{AuditLogger, RuntimeClass, RuntimeConfig, RuntimeController};
use depgraph_mcp_tools::{
    AgentCompletedSnapshot, AgentContext, AgentCycleLevel, AgentDaemonStatus,
    AgentDependencyDirection, AgentDoctor, AgentEdge, AgentError, AgentErrorCode,
    AgentErrorDetails, AgentEvidence, AgentGraphExportFormat, AgentGraphExportMediaType,
    AgentGraphExportResponse, AgentId, AgentLocator, AgentNamedSnapshot, AgentNode,
    AgentNodeSummary, AgentOperation, AgentOperationStatus, AgentPathResponse,
    AgentPolicyAnnotation, AgentPolicyAnnotationLevel, AgentPolicyApiChange,
    AgentPolicyApiChangeKind, AgentPolicyEvaluationResponse, AgentPolicySeverity,
    AgentPolicySummary, AgentPolicyViolation, AgentProfilePlan, AgentRemediation,
    AgentResourceLimit, AgentRuntimeTraceEvent, AgentRuntimeValidationResponse, AgentSite,
    AgentSnapshotDiffChange, AgentSnapshotDiffChangeType, AgentSnapshotDiffRecordType,
    AgentSnapshotDiffResponse, AgentToken, BoundedQueryProjectionFailure, CanonicalResponseMapper,
    ContractBuildError, ContractVersion, Cursor, CursorKey, ErrorEnvelope, LogicalRepositoryId,
    MAX_AGENT_CONDITION_BYTES, MAX_PAGE_BYTES, MappedToolResult, OperationId, PageByteLimit,
    PageRequest, PageSize, PaginationContext, PortableTerminalOutputContract,
    RepositoryRelativePath, ResponseMappingError, SnapshotId, SuccessEnvelope, ToolCatalog,
    project_bounded_query_rows_cancellable, project_cycles_page_cancellable,
    project_dependencies_page_cancellable, project_impact_response_cancellable,
    project_unresolved_page_cancellable,
};
use depgraph_operation::{
    DEADLINE_EXCEEDED_ERROR_JSON, EXECUTION_STATE_UNKNOWN_ERROR_JSON, JournalError,
    OperationManager, OperationOutcome, OperationStatus, OperationView,
    UNSUPPORTED_OPERATION_ERROR_JSON,
};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResponse, Implementation, ListToolsResult,
        PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool, ToolsCapability,
    },
    service::{RequestContext, RxJsonRpcMessage, TxJsonRpcMessage},
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
#[command(name = "depgraph-mcp", about = "depgraph MCP server over stdio")]
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
        ServerInfo::new(capabilities).with_server_info(
            Implementation::new("depgraph-mcp", env!("CARGO_PKG_VERSION"))
                .with_description("depgraph MCP server"),
        )
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
                | "runtime_trace_validate"
                | "operation_get"
                | "operation_result"
                | "operation_cancel"
        ) {
            return Err(McpError::invalid_params(
                "tool handler is unavailable",
                None,
            ));
        }
        let runtime_class = if tool == "operation_cancel" {
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
        let execution = self
            .runtime
            .execute_blocking(runtime_class, cancellation, move |cancellation| {
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
                if cancellation.is_cancelled() {
                    Err(ToolExecutionFailure::Service(
                        DepgraphServiceError::Cancelled,
                    ))
                } else {
                    result
                }
            })
            .await;
        cancellation_bridge.abort();

        let mapped = match execution {
            Ok(Ok(mapped)) => mapped,
            Ok(Err(ToolExecutionFailure::Service(error))) => {
                CanonicalResponseMapper::service_error(self.repository_id.clone(), &error)
                    .map_err(internal_mapping_error)?
            }
            Ok(Err(ToolExecutionFailure::Agent(error))) => CanonicalResponseMapper::error(
                &ErrorEnvelope::new(self.repository_id.clone(), error),
            )
            .map_err(internal_mapping_error)?,
            Ok(Err(ToolExecutionFailure::Journal {
                error,
                operation_id,
            })) => CanonicalResponseMapper::error(&ErrorEnvelope::new(
                self.repository_id.clone(),
                map_journal_error(&error, operation_id),
            ))
            .map_err(internal_mapping_error)?,
            Ok(Err(ToolExecutionFailure::Response(error))) => {
                return Err(internal_mapping_error(error));
            }
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

fn decode_arguments<T>(
    arguments: serde_json::Map<String, serde_json::Value>,
) -> Result<T, ToolExecutionFailure>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(serde_json::Value::Object(arguments))
        .map_err(|_| ToolExecutionFailure::Service(DepgraphServiceError::InvalidInput))
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
                .get(&operation_id, now_ms)
                .map_err(&journal_failure)?;
            map_operation_success(repository_id, &operation)
        }
        "operation_result" => {
            let manager = OperationManager::open(config).map_err(&journal_failure)?;
            let result = manager
                .result(&operation_id, now_ms)
                .map_err(&journal_failure)?;
            match result.outcome() {
                OperationOutcome::Completed(payload) => {
                    let contract = PortableTerminalOutputContract::for_originating_tool(
                        result.operation_kind().as_str(),
                    )
                    .ok_or_else(|| journal_failure(JournalError::IntegrityFailure))?;
                    let output = contract
                        .deserialize(payload.value().clone())
                        .map_err(|_| journal_failure(JournalError::IntegrityFailure))?;
                    if output.repository_id() != repository_id {
                        return Err(journal_failure(JournalError::IntegrityFailure));
                    }
                    CanonicalResponseMapper::terminal_output(&output).map_err(Into::into)
                }
                OperationOutcome::Failed(payload) => {
                    map_stored_operation_error(repository_id, &operation_id, payload.as_str())
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
        "operation_cancel" => {
            let mut manager = OperationManager::open(config).map_err(&journal_failure)?;
            manager
                .cancel(&operation_id, now_ms)
                .map_err(&journal_failure)?;
            let operation = manager
                .get(&operation_id, now_ms)
                .map_err(&journal_failure)?;
            map_operation_success(repository_id, &operation)
        }
        _ => Err(ToolExecutionFailure::Service(
            DepgraphServiceError::NotFound,
        )),
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
    let server = build_server(&args)?;
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
    use super::*;

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
}
