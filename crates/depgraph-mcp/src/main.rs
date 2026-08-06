use std::{
    borrow::Cow,
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, Mutex},
};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, ValueEnum};
use depgraph_core::service::{
    CyclesRequest, DependenciesRequest, DependencyDirection, DoctorRequest, ExplainPathRequest,
    ImpactRequest, NodeMatchMode, ProfilePlanRequest, UnresolvedRequest,
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
    AgentDependenciesResponse, AgentDependencyDirection, AgentDoctor, AgentError, AgentLocator,
    AgentNamedSnapshot, AgentNode, AgentNodeSummary, AgentPathResponse, AgentProfilePlan,
    AgentToken, CanonicalResponseMapper, ContractBuildError, ContractVersion, Cursor, CursorKey,
    ErrorEnvelope, LogicalRepositoryId, MappedToolResult, PageByteLimit, PageRequest, PageSize,
    PaginationContext, RepositoryRelativePath, ResponseMappingError, SnapshotId, SuccessEnvelope,
    ToolCatalog, project_cycles_page_cancellable, project_dependencies_page_cancellable,
    project_impact_response_cancellable, project_unresolved_page_cancellable,
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

enum ToolExecutionFailure {
    Service(DepgraphServiceError),
    Agent(AgentError),
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
        ) {
            return Err(McpError::invalid_params(
                "tool handler is unavailable",
                None,
            ));
        }
        let arguments = request.arguments.unwrap_or_default();
        let service = self.service.clone();
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
            .execute_blocking(RuntimeClass::Read, cancellation, move |cancellation| {
                if cancellation.is_cancelled() {
                    return Err(ToolExecutionFailure::Service(
                        DepgraphServiceError::Cancelled,
                    ));
                }
                let result = execute_catalog_read_tool(
                    &service,
                    &repository_id,
                    &cursor_key,
                    &compiler_pack_requirement,
                    &tool,
                    arguments,
                    &cancellation,
                );
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
            Ok(Err(ToolExecutionFailure::Response(error))) => {
                return Err(internal_mapping_error(error));
            }
            Err(error) => CanonicalResponseMapper::error(&ErrorEnvelope::new(
                self.repository_id.clone(),
                error.agent_error(self.runtime.deadline(RuntimeClass::Read)),
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
            let page = project_dependencies_page_cancellable(
                &found,
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
            let result = AgentDependenciesResponse::new(
                AgentNode::try_from(&found).map_err(contract_mapping_error)?,
                match direction {
                    DependencyDirection::Outgoing => AgentDependencyDirection::Outgoing,
                    DependencyDirection::Incoming => AgentDependencyDirection::Incoming,
                },
                request.transitive(),
                found.complete(),
                found.traversed_edges(),
                page,
            )
            .map_err(contract_mapping_error)?;
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

fn contract_mapping_error(error: ContractBuildError) -> ToolExecutionFailure {
    ToolExecutionFailure::Service(match error {
        ContractBuildError::TooManyPathSteps
        | ContractBuildError::TooManyCycleNodes
        | ContractBuildError::TooManyCorrelationReasons
        | ContractBuildError::TooManyPhases
        | ContractBuildError::TooManyEvidenceItems
        | ContractBuildError::TooManyTargetItems => DepgraphServiceError::ResourceExhausted,
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
}
