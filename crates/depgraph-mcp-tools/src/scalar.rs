use std::{borrow::Cow, convert::Infallible, fmt, str::FromStr};

use depgraph_core::{
    DepgraphServiceError, RepositoryRelativePath as CoreRepositoryRelativePath,
    SnapshotLocator as CoreSnapshotLocator, service::MAX_REPOSITORY_PATH_BYTES,
};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

pub const MAX_LOGICAL_REPOSITORY_ID_BYTES: usize = 128;
pub const MAX_IDEMPOTENCY_KEY_CHARS: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 4_096;
pub const MAX_OPERATION_ID_HEX_BYTES: usize = 128;
pub const MAX_AGENT_ID_BYTES: usize = 256;
pub const MAX_AGENT_TOKEN_BYTES: usize = 64;
pub const MAX_AGENT_LOCATOR_BYTES: usize = 1_024;
pub const MAX_AGENT_LABEL_BYTES: usize = 256;
pub const MAX_AGENT_CONDITION_BYTES: usize = 64 * 1024;
pub const MAX_AGENT_ARTIFACT_ID_BYTES: usize = 1_024;
pub const MAX_AGENT_FIELD_NAME_BYTES: usize = 256;
pub const MAX_AGENT_POLICY_TEXT_BYTES: usize = 4_096;
pub const MAX_AGENT_GRAPH_EXPORT_CONTENT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContractValueError {
    #[error("logical repository id is outside the closed contract")]
    LogicalRepositoryId,
    #[error("cursor is outside the closed contract")]
    Cursor,
    #[error("operation id is outside the closed contract")]
    OperationId,
    #[error("idempotency key is outside the closed contract")]
    IdempotencyKey,
    #[error("snapshot name is outside the closed contract")]
    SnapshotName,
    #[error("snapshot id is outside the closed contract")]
    SnapshotId,
    #[error("repository-relative path is outside the repository boundary")]
    RepositoryRelativePath,
    #[error("Agent identifier is outside the closed contract")]
    AgentId,
    #[error("Agent token is outside the closed contract")]
    AgentToken,
    #[error("Agent locator is outside the closed contract")]
    AgentLocator,
    #[error("Agent label is outside the closed contract")]
    AgentLabel,
    #[error("Agent artifact identifier is outside the closed contract")]
    AgentArtifactId,
    #[error("Agent field name is outside the closed contract")]
    AgentFieldName,
    #[error("Agent policy text is outside the closed contract")]
    AgentPolicyText,
    #[error("snapshot diff collection digest is outside the closed contract")]
    SnapshotDiffCollectionDigest,
    #[error("policy configuration digest is outside the closed contract")]
    PolicyConfigDigest,
    #[error("policy evaluation identifier is outside the closed contract")]
    PolicyEvaluationId,
    #[error("policy evaluation collection digest is outside the closed contract")]
    PolicyEvaluationCollectionDigest,
    #[error("policy violation identifier is outside the closed contract")]
    PolicyViolationId,
    #[error("policy API change identifier is outside the closed contract")]
    PolicyApiChangeId,
    #[error("SHA-256 digest is outside the closed contract")]
    Sha256Digest,
    #[error("Agent graph export content is outside the closed contract")]
    AgentGraphExportContent,
}

macro_rules! string_newtype {
    ($name:ident, $error:expr, $validator:ident, $schema:expr) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl AsRef<str>) -> Result<Self, ContractValueError> {
                let value = value.as_ref();
                if !$validator(value) {
                    return Err($error);
                }
                Ok(Self(value.to_owned()))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ContractValueError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(D::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                stringify!($name).into()
            }

            fn schema_id() -> Cow<'static, str> {
                concat!(module_path!(), "::", stringify!($name)).into()
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                $schema
            }
        }
    };
}

string_newtype!(
    LogicalRepositoryId,
    ContractValueError::LogicalRepositoryId,
    valid_logical_repository_id,
    json_schema!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_LOGICAL_REPOSITORY_ID_BYTES,
        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:+-]*$"
    })
);

string_newtype!(
    Cursor,
    ContractValueError::Cursor,
    valid_cursor,
    json_schema!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_CURSOR_BYTES,
        "pattern": r"^[A-Za-z0-9_~.-]+$"
    })
);

string_newtype!(
    OperationId,
    ContractValueError::OperationId,
    valid_operation_id,
    json_schema!({
        "type": "string",
        "pattern": r"^op_[0-9a-f]{32,128}$"
    })
);

string_newtype!(
    IdempotencyKey,
    ContractValueError::IdempotencyKey,
    valid_idempotency_key,
    json_schema!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_IDEMPOTENCY_KEY_CHARS,
        "pattern": r"^[^\u0000-\u001f\u007f-\u009f]+$"
    })
);

string_newtype!(
    SnapshotName,
    ContractValueError::SnapshotName,
    valid_snapshot_name,
    json_schema!({
        "allOf": [
            {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
            },
            { "not": { "pattern": r"^[Cc][Uu][Rr][Rr][Ee][Nn][Tt]$" } },
            { "not": { "pattern": r"^[Ll][Aa][Tt][Ee][Ss][Tt]$" } },
            {
                "not": {
                    "pattern": r"^[Ss][Nn][Aa][Pp][Ss][Hh][Oo][Tt]:[Ss][Hh][Aa]256:"
                }
            }
        ]
    })
);

string_newtype!(
    SnapshotId,
    ContractValueError::SnapshotId,
    valid_snapshot_id,
    json_schema!({
        "type": "string",
        "pattern": r"^snapshot:sha256:[0-9a-f]{64}$"
    })
);

string_newtype!(
    RepositoryRelativePath,
    ContractValueError::RepositoryRelativePath,
    valid_repository_relative_path,
    json_schema!({
        "allOf": [
            {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_REPOSITORY_PATH_BYTES,
                "pattern": r"^[^/\\:\u0000]+(?:/[^/\\:\u0000]+){0,255}$"
            },
            { "not": { "pattern": r"(?:^|/)[^/\\:\u0000]{256}" } },
            { "not": { "pattern": r"(?:^|/)\.{1,2}(?:/|$)" } },
            { "not": { "pattern": r"(?:^|/)[^/]*[. ](?:/|$)" } },
            { "not": { "pattern": r"^[A-Za-z]:" } },
            {
                "not": {
                    "pattern": concat!(
                        r"(?:^|/)(?:[Cc][Oo][Nn]|[Pp][Rr][Nn]|[Aa][Uu][Xx]|",
                        r"[Nn][Uu][Ll]|[Cc][Ll][Oo][Cc][Kk]\$|[Cc][Oo][Nn][Ii][Nn]\$|",
                        r"[Cc][Oo][Nn][Oo][Uu][Tt]\$|[Cc][Oo][Mm](?:[1-9]|[¹²³])|",
                        r"[Ll][Pp][Tt](?:[1-9]|[¹²³]))(?:\.[^/]*)?(?:/|$)"
                    )
                }
            }
        ]
    })
);

string_newtype!(
    AgentId,
    ContractValueError::AgentId,
    valid_agent_id,
    json_schema!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_AGENT_ID_BYTES,
        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:@+-]*$"
    })
);

string_newtype!(
    AgentToken,
    ContractValueError::AgentToken,
    valid_agent_token,
    json_schema!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_AGENT_TOKEN_BYTES,
        "pattern": r"^[a-z][a-z0-9._:-]*$"
    })
);

string_newtype!(
    AgentLocator,
    ContractValueError::AgentLocator,
    valid_agent_locator,
    json_schema!({
        "oneOf": [
            {
                "allOf": [
                    {
                        "type": "string",
                        "minLength": 8,
                        "maxLength": MAX_AGENT_LOCATOR_BYTES,
                        "pattern": r"^repo://[^/\\:\u0000-\u001F\u007F]+(?:/[^/\\:\u0000-\u001F\u007F]+){0,255}$"
                    },
                    { "not": { "pattern": r"(?:^repo://|/)[^/\\:\u0000]{256}" } },
                    { "not": { "pattern": r"(?:^repo://|/)\.{1,2}(?:/|$)" } },
                    { "not": { "pattern": r"(?:^repo://|/)[^/]*[. ](?:/|$)" } },
                    {
                        "not": {
                            "pattern": concat!(
                                r"(?:^repo://|/)(?:[Cc][Oo][Nn]|[Pp][Rr][Nn]|[Aa][Uu][Xx]|",
                                r"[Nn][Uu][Ll]|[Cc][Ll][Oo][Cc][Kk]\$|[Cc][Oo][Nn][Ii][Nn]\$|",
                                r"[Cc][Oo][Nn][Oo][Uu][Tt]\$|[Cc][Oo][Mm](?:[1-9]|[¹²³])|",
                                r"[Ll][Pp][Tt](?:[1-9]|[¹²³]))(?:\.[^/]*)?(?:/|$)"
                            )
                        }
                    }
                ]
            },
            {
                "allOf": [
                    {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_AGENT_LOCATOR_BYTES,
                        "pattern": r"^[^/\\\u0000-\u001F\u007F][^\\\u0000-\u001F\u007F]*$"
                    },
                    { "not": { "pattern": r":/" } },
                    { "not": { "pattern": r"//" } },
                    { "not": { "pattern": r"(?:^|:)[A-Za-z]:" } },
                    { "not": { "pattern": r"^[Ff][Ii][Ll][Ee]:" } }
                ]
            }
        ]
    })
);

string_newtype!(
    AgentLabel,
    ContractValueError::AgentLabel,
    valid_agent_label,
    json_schema!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_AGENT_LABEL_BYTES,
        "pattern": r"^[^\u0000-\u001f\u007f]+$"
    })
);

string_newtype!(
    AgentCondition,
    ContractValueError::AgentLabel,
    valid_agent_condition,
    json_schema!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_AGENT_CONDITION_BYTES,
        "description": "Rendered edge conditions are limited to 65536 UTF-8 bytes so a maximally sized condition remains routable within the fixed 1 MiB MCP page budget; maxLength is a conservative character cap while x-depgraph-maxUtf8Bytes carries the exact byte contract.",
        "x-depgraph-maxUtf8Bytes": MAX_AGENT_CONDITION_BYTES,
        "pattern": r"^[^\u0000-\u001f\u007f-\u009f]+$"
    })
);

impl From<AgentLabel> for AgentCondition {
    fn from(value: AgentLabel) -> Self {
        Self(value.0)
    }
}

string_newtype!(
    AgentArtifactId,
    ContractValueError::AgentArtifactId,
    valid_agent_artifact_id,
    json_schema!({
        "type": "string",
        "minLength": 1,
        "description": "Artifact identifiers are limited to 1024 UTF-8 bytes by the contract; JSON Schema maxLength is intentionally omitted because it counts Unicode characters.",
        "x-depgraph-maxUtf8Bytes": MAX_AGENT_ARTIFACT_ID_BYTES,
        "pattern": r"^[^\u0000-\u001f\u007f]+$"
    })
);

string_newtype!(
    AgentFieldName,
    ContractValueError::AgentFieldName,
    valid_agent_field_name,
    json_schema!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_AGENT_FIELD_NAME_BYTES,
        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"
    })
);

string_newtype!(
    AgentPolicyText,
    ContractValueError::AgentPolicyText,
    valid_agent_policy_text,
    json_schema!({
        "type": "string",
        "minLength": 1,
        "description": "Policy text is limited to 4096 UTF-8 bytes by the contract; JSON Schema maxLength is intentionally omitted because it counts Unicode characters.",
        "x-depgraph-maxUtf8Bytes": MAX_AGENT_POLICY_TEXT_BYTES,
        "pattern": r"^[^\u0000-\u001f\u007f]+$"
    })
);

string_newtype!(
    SnapshotDiffCollectionDigest,
    ContractValueError::SnapshotDiffCollectionDigest,
    valid_snapshot_diff_collection_digest,
    json_schema!({
        "type": "string",
        "pattern": r"^snapshot-diff-collection:sha256:[0-9a-f]{64}$"
    })
);

string_newtype!(
    PolicyConfigDigest,
    ContractValueError::PolicyConfigDigest,
    valid_policy_config_digest,
    json_schema!({
        "type": "string",
        "pattern": r"^policy-config:sha256:[0-9a-f]{64}$"
    })
);

string_newtype!(
    PolicyEvaluationId,
    ContractValueError::PolicyEvaluationId,
    valid_policy_evaluation_id,
    json_schema!({
        "type": "string",
        "pattern": r"^policy-evaluation:sha256:[0-9a-f]{64}$"
    })
);

string_newtype!(
    PolicyEvaluationCollectionDigest,
    ContractValueError::PolicyEvaluationCollectionDigest,
    valid_policy_evaluation_collection_digest,
    json_schema!({
        "type": "string",
        "pattern": r"^policy-evaluation-collection:sha256:[0-9a-f]{64}$"
    })
);

string_newtype!(
    PolicyViolationId,
    ContractValueError::PolicyViolationId,
    valid_policy_violation_id,
    json_schema!({
        "type": "string",
        "pattern": r"^policy-violation:sha256:[0-9a-f]{64}$"
    })
);

string_newtype!(
    PolicyApiChangeId,
    ContractValueError::PolicyApiChangeId,
    valid_policy_api_change_id,
    json_schema!({
        "type": "string",
        "pattern": r"^policy-api-change:sha256:[0-9a-f]{64}$"
    })
);

string_newtype!(
    Sha256Digest,
    ContractValueError::Sha256Digest,
    valid_sha256_digest,
    json_schema!({
        "type": "string",
        "pattern": r"^[0-9a-f]{64}$"
    })
);

string_newtype!(
    AgentGraphExportContent,
    ContractValueError::AgentGraphExportContent,
    valid_agent_graph_export_content,
    json_schema!({
        "type": "string",
        "minLength": 1,
        "description": "Inline graph export content is limited to 16777216 UTF-8 bytes by the contract; JSON Schema maxLength is intentionally omitted because it counts Unicode characters.",
        "x-depgraph-maxUtf8Bytes": MAX_AGENT_GRAPH_EXPORT_CONTENT_BYTES
    })
);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TaskId(OperationId);

impl TaskId {
    #[must_use]
    pub fn from_operation_id(operation_id: &OperationId) -> Self {
        Self(operation_id.clone())
    }

    pub fn parse(value: impl AsRef<str>) -> Result<Self, ContractValueError> {
        OperationId::parse(value).map(Self)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.0
    }
}

impl fmt::Display for TaskId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for TaskId {
    type Err = ContractValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl<'de> Deserialize<'de> for TaskId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let operation_id = OperationId::deserialize(deserializer)?;
        Ok(Self(operation_id))
    }
}

impl JsonSchema for TaskId {
    fn schema_name() -> Cow<'static, str> {
        "TaskId".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::TaskId").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        OperationId::json_schema(generator)
    }
}

impl From<CoreRepositoryRelativePath> for RepositoryRelativePath {
    fn from(path: CoreRepositoryRelativePath) -> Self {
        Self(path.as_str().to_owned())
    }
}

impl TryFrom<&RepositoryRelativePath> for CoreRepositoryRelativePath {
    type Error = DepgraphServiceError;

    fn try_from(path: &RepositoryRelativePath) -> Result<Self, Self::Error> {
        Self::parse(path.as_str())
    }
}

impl TryFrom<RepositoryRelativePath> for CoreRepositoryRelativePath {
    type Error = DepgraphServiceError;

    fn try_from(path: RepositoryRelativePath) -> Result<Self, Self::Error> {
        Self::parse(path.as_str())
    }
}

impl TryFrom<CoreSnapshotLocator> for SnapshotName {
    type Error = ContractValueError;

    fn try_from(locator: CoreSnapshotLocator) -> Result<Self, Self::Error> {
        match locator {
            CoreSnapshotLocator::Name(name) => Self::parse(name),
            CoreSnapshotLocator::Current | CoreSnapshotLocator::StableId(_) => {
                Err(ContractValueError::SnapshotName)
            }
        }
    }
}

impl TryFrom<CoreSnapshotLocator> for SnapshotId {
    type Error = ContractValueError;

    fn try_from(locator: CoreSnapshotLocator) -> Result<Self, Self::Error> {
        match locator {
            CoreSnapshotLocator::StableId(snapshot_id) => Self::parse(snapshot_id),
            CoreSnapshotLocator::Current | CoreSnapshotLocator::Name(_) => {
                Err(ContractValueError::SnapshotId)
            }
        }
    }
}

impl From<TaskId> for OperationId {
    fn from(task_id: TaskId) -> Self {
        task_id.0
    }
}

impl From<Infallible> for ContractValueError {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

fn valid_logical_repository_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LOGICAL_REPOSITORY_ID_BYTES
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'+' | b'-')
        })
}

fn valid_cursor(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CURSOR_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'~' | b'.' | b'-'))
}

fn valid_operation_id(value: &str) -> bool {
    value.strip_prefix("op_").is_some_and(|identifier| {
        (32..=MAX_OPERATION_ID_HEX_BYTES).contains(&identifier.len())
            && identifier
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_IDEMPOTENCY_KEY_CHARS
        && !value.chars().any(char::is_control)
}

fn valid_snapshot_name(value: &str) -> bool {
    matches!(
        CoreSnapshotLocator::parse(value),
        Ok(CoreSnapshotLocator::Name(_))
    )
}

fn valid_snapshot_id(value: &str) -> bool {
    matches!(
        CoreSnapshotLocator::parse(value),
        Ok(CoreSnapshotLocator::StableId(_))
    )
}

fn valid_repository_relative_path(value: &str) -> bool {
    CoreRepositoryRelativePath::parse(value).is_ok()
}

fn valid_agent_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AGENT_ID_BYTES
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'@' | b'+' | b'-')
        })
}

fn valid_agent_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AGENT_TOKEN_BYTES
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
}

fn valid_agent_locator(value: &str) -> bool {
    if value.len() > MAX_AGENT_LOCATOR_BYTES || value.bytes().any(|byte| byte.is_ascii_control()) {
        return false;
    }
    if let Some(path) = value.strip_prefix("repo://") {
        return CoreRepositoryRelativePath::parse(path).is_ok();
    }
    !value.is_empty()
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.contains('\\')
        && !value.contains(":/")
        && !value.contains("//")
        && !value
            .as_bytes()
            .windows(2)
            .enumerate()
            .any(|(index, pair)| {
                pair[0].is_ascii_alphabetic()
                    && pair[1] == b':'
                    && (index == 0 || value.as_bytes()[index - 1] == b':')
            })
        && !value
            .get(..5)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("file:"))
}

fn valid_agent_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AGENT_LABEL_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_agent_condition(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AGENT_CONDITION_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_agent_artifact_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AGENT_ARTIFACT_ID_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_agent_field_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AGENT_FIELD_NAME_BYTES
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_agent_policy_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AGENT_POLICY_TEXT_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_snapshot_diff_collection_digest(value: &str) -> bool {
    valid_prefixed_sha256(value, "snapshot-diff-collection")
}

fn valid_policy_config_digest(value: &str) -> bool {
    valid_prefixed_sha256(value, "policy-config")
}

fn valid_policy_evaluation_id(value: &str) -> bool {
    valid_prefixed_sha256(value, "policy-evaluation")
}

fn valid_policy_evaluation_collection_digest(value: &str) -> bool {
    valid_prefixed_sha256(value, "policy-evaluation-collection")
}

fn valid_policy_violation_id(value: &str) -> bool {
    valid_prefixed_sha256(value, "policy-violation")
}

fn valid_policy_api_change_id(value: &str) -> bool {
    valid_prefixed_sha256(value, "policy-api-change")
}

fn valid_prefixed_sha256(value: &str, namespace: &str) -> bool {
    value
        .strip_prefix(namespace)
        .and_then(|value| value.strip_prefix(":sha256:"))
        .is_some_and(valid_sha256_digest)
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_agent_graph_export_content(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_AGENT_GRAPH_EXPORT_CONTENT_BYTES
}
