use std::fmt;

use depgraph_core::SnapshotLocator as CoreSnapshotLocator;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::{
    AgentRepositoryIds, AgentToken, ContractValueError, Cursor, LogicalRepositoryId, OperationId,
    SnapshotId, SnapshotName,
};

pub const MCP_TOOLS_CONTRACT_VERSION: &str = "depgraph-mcp-tools-v1";
pub const DEFAULT_PAGE_ITEMS: u16 = 100;
pub const MAX_PAGE_ITEMS: u16 = 1_000;
pub const DEFAULT_PAGE_BYTES: u32 = 1024 * 1024;
pub const MAX_PAGE_BYTES: u32 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum ContractVersion {
    #[default]
    #[serde(rename = "depgraph-mcp-tools-v1")]
    V1,
}

impl ContractVersion {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => MCP_TOOLS_CONTRACT_VERSION,
        }
    }
}

impl fmt::Display for ContractVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommonRequest {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
}

impl CommonRequest {
    #[must_use]
    pub const fn new(repository_id: LogicalRepositoryId) -> Self {
        Self {
            contract_version: ContractVersion::V1,
            repository_id,
        }
    }

    #[must_use]
    pub const fn contract_version(&self) -> ContractVersion {
        self.contract_version
    }

    #[must_use]
    pub const fn repository_id(&self) -> &LogicalRepositoryId {
        &self.repository_id
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SnapshotSelector {
    Current,
    Name { name: SnapshotName },
    Id { snapshot_id: SnapshotId },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum SnapshotSelectorWire {
    Current {},
    Name { name: SnapshotName },
    Id { snapshot_id: SnapshotId },
}

impl<'de> Deserialize<'de> for SnapshotSelector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match SnapshotSelectorWire::deserialize(deserializer)? {
            SnapshotSelectorWire::Current {} => Ok(Self::Current),
            SnapshotSelectorWire::Name { name } => Ok(Self::Name { name }),
            SnapshotSelectorWire::Id { snapshot_id } => Ok(Self::Id { snapshot_id }),
        }
    }
}

impl SnapshotSelector {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, ContractValueError> {
        match CoreSnapshotLocator::parse(value.as_ref()) {
            Ok(CoreSnapshotLocator::Current) => Ok(Self::Current),
            Ok(CoreSnapshotLocator::Name(name)) => Ok(Self::Name {
                name: SnapshotName::parse(name)?,
            }),
            Ok(CoreSnapshotLocator::StableId(snapshot_id)) => Ok(Self::Id {
                snapshot_id: SnapshotId::parse(snapshot_id)?,
            }),
            Ok(CoreSnapshotLocator::Attempt(_)) => Err(ContractValueError::SnapshotName),
            Err(_) => Err(ContractValueError::SnapshotName),
        }
    }

    pub fn to_core(&self) -> Result<CoreSnapshotLocator, depgraph_core::DepgraphServiceError> {
        match self {
            Self::Current => CoreSnapshotLocator::parse("current"),
            Self::Name { name } => CoreSnapshotLocator::parse(name.as_str()),
            Self::Id { snapshot_id } => CoreSnapshotLocator::parse(snapshot_id.as_str()),
        }
    }
}

impl TryFrom<CoreSnapshotLocator> for SnapshotSelector {
    type Error = ContractValueError;

    fn try_from(locator: CoreSnapshotLocator) -> Result<Self, Self::Error> {
        match locator {
            CoreSnapshotLocator::Current => Ok(Self::Current),
            CoreSnapshotLocator::Name(name) => Ok(Self::Name {
                name: SnapshotName::parse(name)?,
            }),
            CoreSnapshotLocator::StableId(snapshot_id) => Ok(Self::Id {
                snapshot_id: SnapshotId::parse(snapshot_id)?,
            }),
            CoreSnapshotLocator::Attempt(_) => Err(ContractValueError::SnapshotName),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PageSize(#[schemars(range(min = 1, max = 1000))] u16);

impl PageSize {
    pub fn new(value: u16) -> Result<Self, ContractBuildError> {
        if !(1..=MAX_PAGE_ITEMS).contains(&value) {
            return Err(ContractBuildError::PageSize);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl Default for PageSize {
    fn default() -> Self {
        Self(DEFAULT_PAGE_ITEMS)
    }
}

impl<'de> Deserialize<'de> for PageSize {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PageByteLimit(#[schemars(range(min = 1, max = 16777216))] u32);

impl PageByteLimit {
    pub fn new(value: u32) -> Result<Self, ContractBuildError> {
        if !(1..=MAX_PAGE_BYTES).contains(&value) {
            return Err(ContractBuildError::PageByteLimit);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl Default for PageByteLimit {
    fn default() -> Self {
        Self(DEFAULT_PAGE_BYTES)
    }
}

impl<'de> Deserialize<'de> for PageByteLimit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PageRequest {
    max_items: PageSize,
    max_bytes: PageByteLimit,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cursor: Option<Cursor>,
}

impl PageRequest {
    #[must_use]
    pub const fn new(
        max_items: PageSize,
        max_bytes: PageByteLimit,
        cursor: Option<Cursor>,
    ) -> Self {
        Self {
            max_items,
            max_bytes,
            cursor,
        }
    }

    #[must_use]
    pub const fn max_items(&self) -> PageSize {
        self.max_items
    }

    #[must_use]
    pub const fn max_bytes(&self) -> PageByteLimit {
        self.max_bytes
    }

    #[must_use]
    pub const fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Page<T> {
    #[schemars(length(max = 1000))]
    items: Vec<T>,
    returned_items: u16,
    total_items: u64,
    complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_cursor: Option<Cursor>,
}

impl<T> Page<T> {
    pub fn new(
        items: Vec<T>,
        total_items: u64,
        complete: bool,
        next_cursor: Option<Cursor>,
    ) -> Result<Self, ContractBuildError> {
        let returned_items =
            u16::try_from(items.len()).map_err(|_| ContractBuildError::TooManyPageItems)?;
        if returned_items > MAX_PAGE_ITEMS {
            return Err(ContractBuildError::TooManyPageItems);
        }
        if total_items < u64::from(returned_items) {
            return Err(ContractBuildError::PageTotal);
        }
        if complete && next_cursor.is_some() {
            return Err(ContractBuildError::CompletePageCursor);
        }
        if !complete && next_cursor.is_none() {
            return Err(ContractBuildError::IncompletePageCursor);
        }
        Ok(Self {
            items,
            returned_items,
            total_items,
            complete,
            next_cursor,
        })
    }

    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.items
    }

    #[must_use]
    pub const fn returned_items(&self) -> u16 {
        self.returned_items
    }

    #[must_use]
    pub const fn total_items(&self) -> u64 {
        self.total_items
    }

    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    #[must_use]
    pub const fn next_cursor(&self) -> Option<&Cursor> {
        self.next_cursor.as_ref()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "T: Deserialize<'de>"))]
struct PageWire<T> {
    items: Vec<T>,
    returned_items: u16,
    total_items: u64,
    complete: bool,
    #[serde(default)]
    next_cursor: Option<Cursor>,
}

impl<'de, T> Deserialize<'de> for Page<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PageWire::<T>::deserialize(deserializer)?;
        let page = Self::new(
            wire.items,
            wire.total_items,
            wire.complete,
            wire.next_cursor,
        )
        .map_err(D::Error::custom)?;
        if page.returned_items != wire.returned_items {
            return Err(D::Error::custom(ContractBuildError::ReturnedItemCount));
        }
        Ok(page)
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessEnvelope<T> {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot_id: Option<SnapshotId>,
    result: T,
}

impl<T> SuccessEnvelope<T> {
    #[must_use]
    pub const fn new(
        repository_id: LogicalRepositoryId,
        snapshot_id: Option<SnapshotId>,
        result: T,
    ) -> Self {
        Self {
            contract_version: ContractVersion::V1,
            repository_id,
            snapshot_id,
            result,
        }
    }

    #[must_use]
    pub const fn repository_id(&self) -> &LogicalRepositoryId {
        &self.repository_id
    }

    #[must_use]
    pub const fn snapshot_id(&self) -> Option<&SnapshotId> {
        self.snapshot_id.as_ref()
    }

    #[must_use]
    pub const fn result(&self) -> &T {
        &self.result
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentErrorCode {
    InvalidArgument,
    InvalidRepositoryPath,
    SnapshotNotFound,
    SnapshotMismatch,
    SnapshotWorktreeMismatch,
    QueryRejected,
    CursorInvalid,
    CursorMismatch,
    CapabilityDenied,
    NotFound,
    Conflict,
    ResourceExhausted,
    OperationNotReady,
    IdempotencyConflict,
    Cancelled,
    IntegrityFailure,
    Internal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentErrorCategory {
    Input,
    Authorization,
    NotFound,
    Conflict,
    Resource,
    State,
    Cancelled,
    Integrity,
    Internal,
}

impl AgentErrorCode {
    #[must_use]
    pub const fn category(self) -> AgentErrorCategory {
        match self {
            Self::InvalidArgument
            | Self::InvalidRepositoryPath
            | Self::SnapshotMismatch
            | Self::SnapshotWorktreeMismatch
            | Self::CursorInvalid
            | Self::CursorMismatch => AgentErrorCategory::Input,
            Self::QueryRejected => AgentErrorCategory::Resource,
            Self::CapabilityDenied => AgentErrorCategory::Authorization,
            Self::SnapshotNotFound | Self::NotFound => AgentErrorCategory::NotFound,
            Self::Conflict | Self::IdempotencyConflict => AgentErrorCategory::Conflict,
            Self::ResourceExhausted => AgentErrorCategory::Resource,
            Self::OperationNotReady => AgentErrorCategory::State,
            Self::Cancelled => AgentErrorCategory::Cancelled,
            Self::IntegrityFailure => AgentErrorCategory::Integrity,
            Self::Internal => AgentErrorCategory::Internal,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRemediation {
    CorrectInput,
    SelectCompletedSnapshot,
    RestartFromFirstPage,
    NarrowQuery,
    ExportFile,
    IncreaseLimit,
    EnableRequiredCapability,
    Retry,
    PollOperation,
    UseOperationResult,
    ContactOperator,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AgentCapability {
    Read,
    StoreWrite,
    RepositoryWrite,
    DaemonControl,
    ProjectExec,
}

impl From<depgraph_core::DepgraphCapability> for AgentCapability {
    fn from(capability: depgraph_core::DepgraphCapability) -> Self {
        match capability {
            depgraph_core::DepgraphCapability::Read => Self::Read,
            depgraph_core::DepgraphCapability::StoreWrite => Self::StoreWrite,
            depgraph_core::DepgraphCapability::RepositoryWrite => Self::RepositoryWrite,
            depgraph_core::DepgraphCapability::DaemonControl => Self::DaemonControl,
            depgraph_core::DepgraphCapability::ProjectExec => Self::ProjectExec,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentResourceLimit {
    InputBytes,
    OutputBytes,
    PageItems,
    /// Edge visits of one traversal; widened by `max_traversal`.
    TraversalItems,
    DeadlineMilliseconds,
    /// Snapshot edges a dependency traversal inspects to build its adjacency.
    SnapshotEdges,
    /// Snapshot-wide preprocessing work items: selector resolution, path
    /// search adjacency, traversal postprocessing, and each health analysis
    /// phase or range.
    PreprocessingWorkItems,
    /// Unique nodes an impact traversal keeps; widened by `max_nodes`.
    ImpactNodes,
    /// Unique edges an impact traversal keeps; widened by `max_edges`.
    ImpactEdges,
    /// Dependency-path steps materialized for one impact response.
    ImpactPathSteps,
    /// Changed paths read from Git for a changed-set impact or audit.
    ChangedPaths,
    /// Findings in one health response or one analyzed range.
    HealthFindings,
    /// Evidence, remediation, suppression, or blocker entries of one finding.
    HealthFindingItems,
    /// Dependency manifests read by one health analysis.
    HealthManifests,
    /// Items in one snapshot diff or policy evaluation result.
    ArtifactItems,
    /// Work items of one snapshot diff, policy evaluation, or export selection.
    ArtifactWorkItems,
    /// Nodes of one graph export; widened by `max_nodes`.
    ExportNodes,
    /// Edges of one graph export; widened by `max_edges`.
    ExportEdges,
}

/// Closed reason a tool argument was rejected (Issue #565).
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentArgumentReason {
    /// A required argument is absent.
    Missing,
    /// An argument is not part of the tool's input schema. Its name is not
    /// echoed; compare the call with the tool's input schema.
    UnknownArgument,
    /// The value has the wrong type, format, or enumeration member.
    InvalidValue,
    /// A numeric value is outside its documented range.
    OutOfRange,
    /// An array has more items than the tool accepts.
    TooManyItems,
    /// The selector matched several nodes; retry with `id:<stable-id>`.
    AmbiguousSelector,
    /// The selector matched no node in the selected snapshot.
    NoMatchingNode,
}

/// Failure class of a rejected bounded graph query.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentQueryFailureClass {
    Input,
    Security,
    Syntax,
    Limit,
    Binding,
    Type,
}

/// `graph_query` argument a query diagnostic refers to.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentQueryArgument {
    Query,
    QueryFile,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentErrorDetails {
    RequiredCapability {
        capability: AgentCapability,
    },
    ResourceLimit {
        limit: AgentResourceLimit,
        maximum: u64,
        /// Work counted when the request stopped, when known (Issue #565).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        observed: Option<u64>,
        /// Tool argument that widens or narrows this bound, when one does.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        argument: Option<AgentToken>,
    },
    Operation {
        operation_id: OperationId,
    },
    /// The requested `repository_id` is not served here; retry with one of these IDs
    /// or omit `repository_id` to use the server's bound repository.
    Repository {
        available_repository_ids: AgentRepositoryIds,
    },
    /// Which tool argument was rejected and why (Issue #565). `argument` is
    /// omitted when the server cannot name a schema-defined argument.
    Argument {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        argument: Option<AgentToken>,
        reason: AgentArgumentReason,
    },
    /// Where a bounded graph query failed to parse or type-check. The query
    /// text is never echoed; `line`, `column`, and `byte_offset` locate the
    /// offending token, `clause` names the grammar clause being parsed, and
    /// `token_class` names the token found there.
    QueryDiagnostic {
        argument: AgentQueryArgument,
        code: AgentToken,
        class: AgentQueryFailureClass,
        clause: AgentToken,
        token_class: AgentToken,
        line: u64,
        column: u64,
        byte_offset: u64,
    },
}

impl AgentErrorDetails {
    /// A resource bound without observed work or a narrowing argument.
    #[must_use]
    pub const fn resource_limit(limit: AgentResourceLimit, maximum: u64) -> Self {
        Self::ResourceLimit {
            limit,
            maximum,
            observed: None,
            argument: None,
        }
    }

    /// Names a schema-defined tool argument. Argument names are compile-time
    /// constants, so a name outside the token contract is a programming error
    /// and degrades to an unnamed argument rather than failing the response.
    #[must_use]
    pub fn argument(argument: Option<&str>, reason: AgentArgumentReason) -> Self {
        Self::Argument {
            argument: argument.and_then(|name| AgentToken::parse(name).ok()),
            reason,
        }
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentError {
    code: AgentErrorCode,
    category: AgentErrorCategory,
    retryable: bool,
    remediation: AgentRemediation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    details: Option<AgentErrorDetails>,
}

impl AgentError {
    #[must_use]
    pub const fn new(
        code: AgentErrorCode,
        retryable: bool,
        remediation: AgentRemediation,
        details: Option<AgentErrorDetails>,
    ) -> Self {
        Self {
            code,
            category: code.category(),
            retryable,
            remediation,
            details,
        }
    }

    #[must_use]
    pub const fn code(&self) -> AgentErrorCode {
        self.code
    }

    #[must_use]
    pub const fn category(&self) -> AgentErrorCategory {
        self.category
    }

    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    #[must_use]
    pub const fn remediation(&self) -> AgentRemediation {
        self.remediation
    }

    #[must_use]
    pub const fn details(&self) -> Option<&AgentErrorDetails> {
        self.details.as_ref()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentErrorWire {
    code: AgentErrorCode,
    category: AgentErrorCategory,
    retryable: bool,
    remediation: AgentRemediation,
    #[serde(default)]
    details: Option<AgentErrorDetails>,
}

impl<'de> Deserialize<'de> for AgentError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentErrorWire::deserialize(deserializer)?;
        if wire.category != wire.code.category() {
            return Err(D::Error::custom(ContractBuildError::ErrorCategory));
        }
        Ok(Self::new(
            wire.code,
            wire.retryable,
            wire.remediation,
            wire.details,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorEnvelope {
    contract_version: ContractVersion,
    repository_id: LogicalRepositoryId,
    error: AgentError,
}

impl ErrorEnvelope {
    #[must_use]
    pub const fn new(repository_id: LogicalRepositoryId, error: AgentError) -> Self {
        Self {
            contract_version: ContractVersion::V1,
            repository_id,
            error,
        }
    }

    #[must_use]
    pub const fn repository_id(&self) -> &LogicalRepositoryId {
        &self.repository_id
    }

    #[must_use]
    pub const fn error(&self) -> &AgentError {
        &self.error
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContractBuildError {
    #[error("page size is outside the contract bounds")]
    PageSize,
    #[error("page byte limit is outside the contract bounds")]
    PageByteLimit,
    #[error("page contains too many items")]
    TooManyPageItems,
    #[error("Agent DTO contains too many evidence summaries")]
    TooManyEvidenceItems,
    #[error("Agent DTO contains too many target identifiers")]
    TooManyTargetItems,
    #[error("page total is smaller than its returned item count")]
    PageTotal,
    #[error("a complete page cannot carry a continuation cursor")]
    CompletePageCursor,
    #[error("an incomplete page must carry a continuation cursor")]
    IncompletePageCursor,
    #[error("returned_items does not match the item array")]
    ReturnedItemCount,
    #[error("error category does not match the typed error code")]
    ErrorCategory,
    #[error("source span bounds are invalid")]
    SourceSpan,
    #[error("task timing is outside the closed contract")]
    TaskTiming,
    #[error("snapshot availability does not match its fields")]
    SnapshotAvailability,
    #[error("Agent context capabilities must be unique and stably ordered")]
    CapabilitySet,
    #[error("Agent DTO contains a value outside the closed scalar contract")]
    AgentDtoValue,
    #[error("Agent snapshot contains too many metadata items")]
    TooManySnapshotMetadataItems,
    #[error("Agent path contains too many steps")]
    TooManyPathSteps,
    #[error("Agent path topology is inconsistent")]
    PathTopology,
    #[error("Agent graph response traversal counts are inconsistent")]
    TraversalCount,
    #[error("Agent impact state is inconsistent with its result page")]
    ImpactState,
    #[error("Agent cycle topology is inconsistent")]
    CycleTopology,
    #[error("Agent cycle contains too many nodes")]
    TooManyCycleNodes,
    #[error("Agent unresolved site/profile/correlation state is inconsistent")]
    UnresolvedState,
    #[error("Agent unresolved correlation contains too many reasons")]
    TooManyCorrelationReasons,
    #[error("Agent unresolved site contains too many phases")]
    TooManyPhases,
    #[error("Agent query row contains too many projected values")]
    TooManyQueryValues,
    #[error("Agent query value is outside the closed projection contract")]
    QueryValue,
    #[error("Agent artifact response contains too many items")]
    TooManyArtifactItems,
    #[error("Agent artifact change contains too many changed fields")]
    TooManyChangedFields,
    #[error("Agent snapshot diff state is inconsistent")]
    SnapshotDiffState,
    #[error("Agent policy evaluation state is inconsistent")]
    PolicyEvaluationState,
    #[error("Agent graph export state is inconsistent")]
    GraphExportState,
    #[error("Agent repository identifiers must be non-empty, bounded, unique, and stably ordered")]
    RepositorySet,
    #[error("Agent dependency detail projection is inconsistent with its detail level")]
    DependencyDetailState,
    #[error("Agent import evidence contains a value outside the public disclosure contract")]
    ImportEvidence,
}
