//! Closed, versioned Agent-facing data contracts for depgraph MCP tools.

mod catalog;
mod contract;
mod dto;
mod host_config;
mod lifecycle;
mod operation;
mod response;
mod scalar;
mod schema;

pub use catalog::{
    ALL_CLI_ACTIONS, CapabilityProfile, CliAction, OperationBehavior, ToolAuthorization,
    ToolCatalog, ToolDefinition,
};

pub use contract::{
    AgentCapability, AgentError, AgentErrorCategory, AgentErrorCode, AgentErrorDetails,
    AgentRemediation, AgentResourceLimit, CommonRequest, ContractBuildError, ContractVersion,
    DEFAULT_PAGE_BYTES, DEFAULT_PAGE_ITEMS, ErrorEnvelope, MAX_PAGE_BYTES, MAX_PAGE_ITEMS,
    MCP_TOOLS_CONTRACT_VERSION, Page, PageByteLimit, PageRequest, PageSize, SnapshotSelector,
    SuccessEnvelope,
};
pub use dto::{
    AgentBuildHostRisk, AgentBuildIsolationStrength, AgentBuildMutationDiagnostic,
    AgentBuildNetworkIsolation, AgentBuildOutcome, AgentBuildStatus, AgentChangedSince,
    AgentCompletedSnapshot, AgentContext, AgentCorrelationDifference, AgentCorrelationStatus,
    AgentCoverage, AgentCurrentSnapshot, AgentCycle, AgentCycleLevel, AgentDependenciesResponse,
    AgentDependencyDirection, AgentEdge, AgentEvidence, AgentEvidenceKind, AgentExportOutcome,
    AgentGraphExportFormat, AgentGraphExportMediaType, AgentGraphExportResponse,
    AgentGraphExportSchemaVersion, AgentImpact, AgentImpactResponse, AgentNamedSnapshot, AgentNode,
    AgentNodeSummary, AgentPathResponse, AgentPathStep, AgentPhase, AgentPolicyAnnotation,
    AgentPolicyAnnotationLevel, AgentPolicyApiChange, AgentPolicyApiChangeKind,
    AgentPolicyEvaluationResponse, AgentPolicySeverity, AgentPolicySummary, AgentPolicyViolation,
    AgentPrecision, AgentProjectExecution, AgentQueryDirection, AgentQueryRow, AgentQueryValue,
    AgentRepositoryInitOutcome, AgentResolutionStatus, AgentRuntimeLocatorMatch,
    AgentRuntimeMatchStatus, AgentRuntimeOutcome, AgentRuntimeProfileMatch, AgentRuntimeStatus,
    AgentRuntimeTraceEvent, AgentRuntimeTraceSummary, AgentRuntimeValidationResponse,
    AgentScanOutcome, AgentScanStatus, AgentSite, AgentSnapshot, AgentSnapshotAvailability,
    AgentSnapshotDiffChange, AgentSnapshotDiffChangeType, AgentSnapshotDiffRecordType,
    AgentSnapshotDiffResponse, AgentSnapshotDiffSchemaVersion, AgentSourcePosition,
    AgentSourceSpan, AgentUnresolved, BoundedQueryProjectionFailure, MAX_AGENT_ARTIFACT_ITEMS,
    MAX_AGENT_BUILD_MUTATION_DIAGNOSTICS, MAX_AGENT_CHANGED_FIELDS, MAX_AGENT_CORRELATION_REASONS,
    MAX_AGENT_CYCLE_NODES, MAX_AGENT_EVIDENCE_ITEMS, MAX_AGENT_PATH_STEPS, MAX_AGENT_PHASES,
    MAX_AGENT_QUERY_TEXT_BYTES, MAX_AGENT_QUERY_VALUES, MAX_AGENT_SNAPSHOT_METADATA_ITEMS,
    MAX_AGENT_TARGET_ITEMS, project_bounded_query_rows, project_bounded_query_rows_cancellable,
};
pub use host_config::{
    AGENT_HOST_CONFIG_CONTRACT_VERSION, AgentHostCapabilityProfile, AgentHostFormat,
    MCP_PROTOCOL_REVISION, MCP_SDK_NAME, MCP_SDK_VERSION, agent_host_capability_name,
    agent_host_launch_arguments, render_agent_host_configuration,
};
pub use lifecycle::{
    AgentDaemonAttempt, AgentDaemonChange, AgentDaemonChangeKind, AgentDaemonControlAction,
    AgentDaemonControlOutcome, AgentDaemonControlPhase, AgentDaemonInvalidationSummary,
    AgentDaemonPhase, AgentDaemonStatus, AgentDaemonTrace, AgentDoctor, AgentProfilePlan,
    AgentRecoveredAttempts,
};
pub use operation::{
    AcceptedOperationStatus, AcceptedTaskStatus, AgentOperation, AgentOperationProgress,
    AgentOperationRetention, AgentOperationStatus, AgentOperationTimestamps, BaselineOperationTool,
    DurableSubmitResult, MAX_TASK_TTL_MS, MIN_TASK_TTL_MS, OperationAccepted,
    OperationAcceptedResultType, OperationRecoveryTools, PortableTerminalOutput,
    PortableTerminalOutputContract, PortableTerminalOutputError, TASK_POLL_INTERVAL_MS,
    TaskAccepted, TaskResultType, TasksNegotiation,
};
pub use response::{
    CanonicalResponseMapper, CursorKey, MappedToolResult, PaginationContext, PublicPageItem,
    PublicToolResult, ResponseMappingError, project_cycles_page_cancellable,
    project_dependencies_page_cancellable, project_impact_response_cancellable,
    project_unresolved_page_cancellable,
};
pub use scalar::{
    AgentArtifactId, AgentCondition, AgentFieldName, AgentGraphExportContent, AgentId, AgentLabel,
    AgentLocator, AgentPolicyText, AgentToken, ContractValueError, Cursor, IdempotencyKey,
    LogicalRepositoryId, MAX_AGENT_ARTIFACT_ID_BYTES, MAX_AGENT_CONDITION_BYTES,
    MAX_AGENT_FIELD_NAME_BYTES, MAX_AGENT_GRAPH_EXPORT_CONTENT_BYTES, MAX_AGENT_ID_BYTES,
    MAX_AGENT_LABEL_BYTES, MAX_AGENT_LOCATOR_BYTES, MAX_AGENT_POLICY_TEXT_BYTES,
    MAX_AGENT_TOKEN_BYTES, MAX_CURSOR_BYTES, MAX_IDEMPOTENCY_KEY_CHARS,
    MAX_LOGICAL_REPOSITORY_ID_BYTES, MAX_OPERATION_ID_HEX_BYTES, OperationId, PolicyApiChangeId,
    PolicyConfigDigest, PolicyEvaluationCollectionDigest, PolicyEvaluationId, PolicyViolationId,
    RepositoryRelativePath, Sha256Digest, SnapshotDiffCollectionDigest, SnapshotId, SnapshotName,
    TaskId,
};
pub use schema::{
    CanonicalJsonError, MCP_TOOLS_SCHEMA_ID, canonical_json_bytes, canonical_json_sha256,
    canonical_schema_bytes, canonical_schema_sha256, mcp_tools_v1_schema,
};
