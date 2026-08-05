use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::{ContractBuildError, ContractVersion, OperationId, TaskId};

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
