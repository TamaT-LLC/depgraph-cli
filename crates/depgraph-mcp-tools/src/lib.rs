//! Closed, versioned Agent-facing data contracts for depgraph MCP tools.

mod catalog;
mod contract;
mod dto;
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
    AgentCompletedSnapshot, AgentContext, AgentCoverage, AgentCurrentSnapshot, AgentEdge,
    AgentEvidence, AgentEvidenceKind, AgentNamedSnapshot, AgentNode, AgentNodeSummary, AgentPhase,
    AgentPrecision, AgentResolutionStatus, AgentSite, AgentSnapshot, AgentSnapshotAvailability,
    AgentSourcePosition, AgentSourceSpan, MAX_AGENT_EVIDENCE_ITEMS,
    MAX_AGENT_SNAPSHOT_METADATA_ITEMS, MAX_AGENT_TARGET_ITEMS,
};
pub use operation::{
    AcceptedOperationStatus, AcceptedTaskStatus, BaselineOperationTool, DurableSubmitResult,
    MAX_TASK_TTL_MS, MIN_TASK_TTL_MS, OperationAccepted, OperationAcceptedResultType,
    OperationRecoveryTools, TASK_POLL_INTERVAL_MS, TaskAccepted, TaskResultType, TasksNegotiation,
};
pub use response::{
    CanonicalResponseMapper, CursorKey, MappedToolResult, PaginationContext, PublicPageItem,
    PublicToolResult, ResponseMappingError,
};
pub use scalar::{
    AgentId, AgentLabel, AgentLocator, AgentToken, ContractValueError, Cursor, LogicalRepositoryId,
    MAX_AGENT_ID_BYTES, MAX_AGENT_LABEL_BYTES, MAX_AGENT_LOCATOR_BYTES, MAX_AGENT_TOKEN_BYTES,
    MAX_CURSOR_BYTES, MAX_LOGICAL_REPOSITORY_ID_BYTES, MAX_OPERATION_ID_HEX_BYTES, OperationId,
    RepositoryRelativePath, SnapshotId, SnapshotName, TaskId,
};
pub use schema::{
    CanonicalJsonError, MCP_TOOLS_SCHEMA_ID, canonical_json_bytes, canonical_json_sha256,
    canonical_schema_bytes, canonical_schema_sha256, mcp_tools_v1_schema,
};
