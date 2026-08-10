use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;

use crate::{
    AgentDaemonStatus, AgentRuntimeOutcome, AgentScanOutcome, ContractBuildError, ContractVersion,
    LogicalRepositoryId, OperationId, SuccessEnvelope, TaskId,
};

/// Closed terminal output contracts registered for durable submit tools.
///
/// This enum is intentionally separate from the journal's operation kind so
/// `depgraph-mcp-tools` remains the owner of public tool shapes. Callers must
/// derive it from the validated journal kind's stable tool name. Kinds whose
/// future domain outcome DTO is not frozen are deliberately absent and fail
/// closed until that originating tool registers its exact output contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortableTerminalOutputContract {
    ScanSubmit,
    RuntimeTraceImportSubmit,
    DaemonStartSubmit,
    DaemonStop,
}

impl PortableTerminalOutputContract {
    #[must_use]
    pub fn for_originating_tool(tool_name: &str) -> Option<Self> {
        match tool_name {
            "scan_submit" => Some(Self::ScanSubmit),
            "runtime_trace_import_submit" => Some(Self::RuntimeTraceImportSubmit),
            "daemon_start_submit" => Some(Self::DaemonStartSubmit),
            "daemon_stop" => Some(Self::DaemonStop),
            _ => None,
        }
    }

    /// Deserialize only the closed envelope shape assigned to the originating
    /// submit tool. Unknown fields, another tool's output, and arbitrary JSON
    /// are rejected before the value can reach the canonical response mapper.
    pub fn deserialize(
        self,
        value: Value,
    ) -> Result<PortableTerminalOutput, PortableTerminalOutputError> {
        match self {
            Self::ScanSubmit => {
                let envelope = serde_json::from_value::<SuccessEnvelope<AgentScanOutcome>>(value)
                    .map_err(|_| PortableTerminalOutputError)?;
                if envelope.snapshot_id().is_none() {
                    return Err(PortableTerminalOutputError);
                }
                Ok(PortableTerminalOutput(
                    PortableTerminalOutputEnvelope::Scan(Box::new(envelope)),
                ))
            }
            Self::RuntimeTraceImportSubmit => {
                let envelope =
                    serde_json::from_value::<SuccessEnvelope<AgentRuntimeOutcome>>(value)
                        .map_err(|_| PortableTerminalOutputError)?;
                if envelope.snapshot_id() != Some(envelope.result().snapshot_id()) {
                    return Err(PortableTerminalOutputError);
                }
                Ok(PortableTerminalOutput(
                    PortableTerminalOutputEnvelope::RuntimeImport(Box::new(envelope)),
                ))
            }
            Self::DaemonStartSubmit | Self::DaemonStop => {
                let envelope = serde_json::from_value::<SuccessEnvelope<AgentDaemonStatus>>(value)
                    .map_err(|_| PortableTerminalOutputError)?;
                if envelope.snapshot_id().is_some() {
                    return Err(PortableTerminalOutputError);
                }
                Ok(PortableTerminalOutput(
                    PortableTerminalOutputEnvelope::DaemonStatus(Box::new(envelope)),
                ))
            }
        }
    }
}

/// A validated terminal success envelope. Serde is intentionally one-way:
/// journal JSON can enter this type only through a kind-specific contract.
#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub struct PortableTerminalOutput(PortableTerminalOutputEnvelope);

#[derive(Clone, Debug, JsonSchema, Serialize)]
#[serde(untagged)]
enum PortableTerminalOutputEnvelope {
    Scan(Box<SuccessEnvelope<AgentScanOutcome>>),
    RuntimeImport(Box<SuccessEnvelope<AgentRuntimeOutcome>>),
    DaemonStatus(Box<SuccessEnvelope<AgentDaemonStatus>>),
}

impl JsonSchema for PortableTerminalOutput {
    fn schema_name() -> Cow<'static, str> {
        "PortableTerminalOutput".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::PortableTerminalOutput").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        PortableTerminalOutputEnvelope::json_schema(generator)
    }
}

impl PortableTerminalOutput {
    #[must_use]
    pub const fn repository_id(&self) -> &LogicalRepositoryId {
        match &self.0 {
            PortableTerminalOutputEnvelope::Scan(envelope) => envelope.repository_id(),
            PortableTerminalOutputEnvelope::RuntimeImport(envelope) => envelope.repository_id(),
            PortableTerminalOutputEnvelope::DaemonStatus(envelope) => envelope.repository_id(),
        }
    }
}

/// Closed failure for a stored terminal payload that does not satisfy its
/// originating tool contract. The error deliberately carries no source JSON.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("terminal operation output does not match its closed tool contract")]
pub struct PortableTerminalOutputError;

/// Portable, agent-safe state of a durable operation. Journal input, digests,
/// capability sets, leases, and runner handoff data are intentionally absent.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentOperation {
    operation_id: OperationId,
    status: AgentOperationStatus,
    progress: AgentOperationProgress,
    timestamps: AgentOperationTimestamps,
    retention: AgentOperationRetention,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentOperationStatus {
    Queued,
    Running,
    Cancelling,
    Completed,
    Failed,
    Cancelled,
}

impl AgentOperationStatus {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentOperationProgress {
    completed_units: u64,
    total_units: u64,
}

impl AgentOperationProgress {
    #[must_use]
    pub const fn completed_units(self) -> u64 {
        self.completed_units
    }

    #[must_use]
    pub const fn total_units(self) -> u64 {
        self.total_units
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentOperationTimestamps {
    created_at_ms: u64,
    updated_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    terminal_at_ms: Option<u64>,
}

impl AgentOperationTimestamps {
    #[must_use]
    pub const fn created_at_ms(self) -> u64 {
        self.created_at_ms
    }

    #[must_use]
    pub const fn updated_at_ms(self) -> u64 {
        self.updated_at_ms
    }

    #[must_use]
    pub const fn terminal_at_ms(self) -> Option<u64> {
        self.terminal_at_ms
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentOperationRetention {
    execution_deadline_ms: u64,
    retain_until_ms: u64,
}

impl AgentOperationRetention {
    #[must_use]
    pub const fn execution_deadline_ms(self) -> u64 {
        self.execution_deadline_ms
    }

    #[must_use]
    pub const fn retain_until_ms(self) -> u64 {
        self.retain_until_ms
    }
}

impl AgentOperation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: OperationId,
        status: AgentOperationStatus,
        completed_units: u64,
        total_units: u64,
        created_at_ms: u64,
        updated_at_ms: u64,
        terminal_at_ms: Option<u64>,
        execution_deadline_ms: u64,
        retain_until_ms: u64,
    ) -> Result<Self, ContractBuildError> {
        let terminal_timing_is_valid = match terminal_at_ms {
            Some(terminal_at_ms) => {
                status.is_terminal()
                    && terminal_at_ms == updated_at_ms
                    && terminal_at_ms <= execution_deadline_ms
            }
            None => !status.is_terminal(),
        };
        if total_units == 0
            || completed_units > total_units
            || (status == AgentOperationStatus::Completed && completed_units != total_units)
            || created_at_ms > updated_at_ms
            || updated_at_ms > execution_deadline_ms
            || execution_deadline_ms <= created_at_ms
            || retain_until_ms < execution_deadline_ms
            || retain_until_ms < terminal_at_ms.unwrap_or(0)
            || !terminal_timing_is_valid
        {
            return Err(ContractBuildError::AgentDtoValue);
        }
        Ok(Self {
            operation_id,
            status,
            progress: AgentOperationProgress {
                completed_units,
                total_units,
            },
            timestamps: AgentOperationTimestamps {
                created_at_ms,
                updated_at_ms,
                terminal_at_ms,
            },
            retention: AgentOperationRetention {
                execution_deadline_ms,
                retain_until_ms,
            },
        })
    }

    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    #[must_use]
    pub const fn status(&self) -> AgentOperationStatus {
        self.status
    }

    #[must_use]
    pub const fn progress(&self) -> AgentOperationProgress {
        self.progress
    }

    #[must_use]
    pub const fn timestamps(&self) -> AgentOperationTimestamps {
        self.timestamps
    }

    #[must_use]
    pub const fn retention(&self) -> AgentOperationRetention {
        self.retention
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentOperationWire {
    operation_id: OperationId,
    status: AgentOperationStatus,
    progress: AgentOperationProgress,
    timestamps: AgentOperationTimestamps,
    retention: AgentOperationRetention,
}

impl<'de> Deserialize<'de> for AgentOperation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentOperationWire::deserialize(deserializer)?;
        Self::new(
            wire.operation_id,
            wire.status,
            wire.progress.completed_units,
            wire.progress.total_units,
            wire.timestamps.created_at_ms,
            wire.timestamps.updated_at_ms,
            wire.timestamps.terminal_at_ms,
            wire.retention.execution_deadline_ms,
            wire.retention.retain_until_ms,
        )
        .map_err(D::Error::custom)
    }
}

pub const TASK_POLL_INTERVAL_MS: u32 = 1_000;
pub const MIN_TASK_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
pub const MAX_TASK_TTL_MS: u64 = 365 * 24 * 60 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum OperationAcceptedResultType {
    #[serde(rename = "operation_accepted")]
    OperationAccepted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptedOperationStatus {
    Queued,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineOperationTool {
    OperationGet,
    OperationResult,
    OperationCancel,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecoveryTools {
    status: BaselineOperationTool,
    result: BaselineOperationTool,
    cancel: BaselineOperationTool,
}

impl JsonSchema for OperationRecoveryTools {
    fn schema_name() -> Cow<'static, str> {
        "OperationRecoveryTools".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::OperationRecoveryTools").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "status": { "const": "operation_get" },
                "result": { "const": "operation_result" },
                "cancel": { "const": "operation_cancel" }
            },
            "required": ["status", "result", "cancel"]
        })
    }
}

impl OperationRecoveryTools {
    #[must_use]
    pub const fn baseline() -> Self {
        Self {
            status: BaselineOperationTool::OperationGet,
            result: BaselineOperationTool::OperationResult,
            cancel: BaselineOperationTool::OperationCancel,
        }
    }

    #[must_use]
    pub const fn status(&self) -> BaselineOperationTool {
        self.status
    }

    #[must_use]
    pub const fn result(&self) -> BaselineOperationTool {
        self.result
    }

    #[must_use]
    pub const fn cancel(&self) -> BaselineOperationTool {
        self.cancel
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationRecoveryToolsWire {
    status: BaselineOperationTool,
    result: BaselineOperationTool,
    cancel: BaselineOperationTool,
}

impl<'de> Deserialize<'de> for OperationRecoveryTools {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = OperationRecoveryToolsWire::deserialize(deserializer)?;
        let expected = Self::baseline();
        if wire.status != expected.status
            || wire.result != expected.result
            || wire.cancel != expected.cancel
        {
            return Err(D::Error::custom(
                "baseline recovery tool names are immutable",
            ));
        }
        Ok(expected)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationAccepted {
    contract_version: ContractVersion,
    result_type: OperationAcceptedResultType,
    operation_id: OperationId,
    status: AcceptedOperationStatus,
    recovery: OperationRecoveryTools,
}

impl OperationAccepted {
    #[must_use]
    pub const fn new(operation_id: OperationId) -> Self {
        Self {
            contract_version: ContractVersion::V1,
            result_type: OperationAcceptedResultType::OperationAccepted,
            operation_id,
            status: AcceptedOperationStatus::Queued,
            recovery: OperationRecoveryTools::baseline(),
        }
    }

    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    #[must_use]
    pub const fn recovery(&self) -> &OperationRecoveryTools {
        &self.recovery
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum TaskResultType {
    #[serde(rename = "task")]
    Task,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptedTaskStatus {
    Working,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskAccepted {
    result_type: TaskResultType,
    task_id: TaskId,
    status: AcceptedTaskStatus,
    created_at_ms: u64,
    updated_at_ms: u64,
    #[schemars(range(min = 1000, max = 1000))]
    poll_interval_ms: u32,
    #[schemars(range(min = 604800000, max = 31536000000_u64))]
    ttl_ms: u64,
}

impl TaskAccepted {
    pub fn from_operation(
        operation: &OperationAccepted,
        created_at_ms: u64,
        updated_at_ms: u64,
        ttl_ms: u64,
    ) -> Result<Self, ContractBuildError> {
        validate_task_timing(created_at_ms, updated_at_ms, ttl_ms)?;
        Ok(Self {
            result_type: TaskResultType::Task,
            task_id: TaskId::from_operation_id(operation.operation_id()),
            status: AcceptedTaskStatus::Working,
            created_at_ms,
            updated_at_ms,
            poll_interval_ms: TASK_POLL_INTERVAL_MS,
            ttl_ms,
        })
    }

    #[must_use]
    pub const fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        self.task_id.operation_id()
    }

    #[must_use]
    pub const fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    #[must_use]
    pub const fn updated_at_ms(&self) -> u64 {
        self.updated_at_ms
    }

    #[must_use]
    pub const fn ttl_ms(&self) -> u64 {
        self.ttl_ms
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TaskAcceptedWire {
    result_type: TaskResultType,
    task_id: TaskId,
    status: AcceptedTaskStatus,
    created_at_ms: u64,
    updated_at_ms: u64,
    poll_interval_ms: u32,
    ttl_ms: u64,
}

impl<'de> Deserialize<'de> for TaskAccepted {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = TaskAcceptedWire::deserialize(deserializer)?;
        validate_task_timing(wire.created_at_ms, wire.updated_at_ms, wire.ttl_ms)
            .map_err(D::Error::custom)?;
        if wire.poll_interval_ms != TASK_POLL_INTERVAL_MS {
            return Err(D::Error::custom(ContractBuildError::TaskTiming));
        }
        Ok(Self {
            result_type: wire.result_type,
            task_id: wire.task_id,
            status: wire.status,
            created_at_ms: wire.created_at_ms,
            updated_at_ms: wire.updated_at_ms,
            poll_interval_ms: wire.poll_interval_ms,
            ttl_ms: wire.ttl_ms,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TasksNegotiation {
    Baseline,
    Tasks,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum DurableSubmitResult {
    Baseline(OperationAccepted),
    Task(TaskAccepted),
}

impl DurableSubmitResult {
    #[must_use]
    pub const fn baseline(operation: OperationAccepted) -> Self {
        Self::Baseline(operation)
    }

    pub fn negotiated(
        operation: OperationAccepted,
        negotiation: TasksNegotiation,
        created_at_ms: u64,
        updated_at_ms: u64,
        ttl_ms: u64,
    ) -> Result<Self, ContractBuildError> {
        match negotiation {
            TasksNegotiation::Baseline => Ok(Self::Baseline(operation)),
            TasksNegotiation::Tasks => Ok(Self::Task(TaskAccepted::from_operation(
                &operation,
                created_at_ms,
                updated_at_ms,
                ttl_ms,
            )?)),
        }
    }

    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        match self {
            Self::Baseline(operation) => operation.operation_id(),
            Self::Task(task) => task.operation_id(),
        }
    }
}

fn validate_task_timing(
    created_at_ms: u64,
    updated_at_ms: u64,
    ttl_ms: u64,
) -> Result<(), ContractBuildError> {
    if updated_at_ms < created_at_ms
        || !(MIN_TASK_TTL_MS..=MAX_TASK_TTL_MS).contains(&ttl_ms)
        || created_at_ms
            .checked_add(ttl_ms)
            .is_none_or(|expires_at_ms| updated_at_ms > expires_at_ms)
    {
        return Err(ContractBuildError::TaskTiming);
    }
    Ok(())
}
