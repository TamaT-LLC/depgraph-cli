use std::{
    fmt::{self, Write as _},
    io::{self, Write},
};

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, OsRng, Payload},
};
use depgraph_core::{
    CancellationToken, DepgraphCapability, DepgraphServiceError, RepositoryFileError,
    service::{CyclesResult, DependenciesResult, ImpactServiceResult, UnresolvedServiceResult},
};
use rmcp::model::CallToolResult;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::dto::{AgentImpactProjection, ImpactProjectionFailure};
use crate::{
    AgentCapability, AgentCompletedSnapshot, AgentContext, AgentCycle, AgentDaemonStatus,
    AgentDependenciesResponse, AgentDoctor, AgentEdge, AgentError, AgentErrorCode,
    AgentErrorDetails, AgentEvidence, AgentGraphExportResponse, AgentHealthAudit,
    AgentHealthFinding, AgentHealthFindingDetail, AgentHealthFindingsPage, AgentHealthHotspots,
    AgentHealthSummary, AgentImpact, AgentImpactResponse, AgentNamedSnapshot, AgentNode,
    AgentNodeSummary, AgentOperation, AgentPathResponse, AgentPathStep,
    AgentPolicyEvaluationResponse, AgentProfilePlan, AgentQueryRow, AgentRemediation,
    AgentRepositoryInitOutcome, AgentResourceLimit, AgentRuntimeOutcome, AgentRuntimeTraceEvent,
    AgentRuntimeValidationResponse, AgentSite, AgentSnapshot, AgentSnapshotDiffResponse,
    AgentUnresolved, CanonicalJsonError, ContractBuildError, Cursor, DurableSubmitResult,
    ErrorEnvelope, LogicalRepositoryId, MAX_AGENT_CONDITION_BYTES, MAX_PAGE_BYTES, MAX_PAGE_ITEMS,
    MCP_TOOLS_CONTRACT_VERSION, OperationAccepted, Page, PageRequest, PortableTerminalOutput,
    SnapshotId, SuccessEnvelope, TaskAccepted, canonical_json_bytes,
};

const CURSOR_VERSION: &str = "v1";
const REDACTED: &str = "[REDACTED]";
const CURSOR_NONCE_BYTES: usize = 12;
const CURSOR_STATE_BYTES: usize = 48;
const CURSOR_TAG_BYTES: usize = 16;

mod private {
    pub trait Sealed {}
    pub trait PageItemSealed {}
}

/// Closed marker for DTOs permitted in public MCP success envelopes.
pub trait PublicToolResult: Serialize + private::Sealed {}

/// Closed marker for DTOs permitted as public paginated items.
pub trait PublicPageItem: Clone + Serialize + private::PageItemSealed {}

macro_rules! public_result {
    ($($type:ty),+ $(,)?) => {$ (
        impl private::Sealed for $type {}
        impl PublicToolResult for $type {}
    )+ };
}

macro_rules! public_page_item {
    ($($type:ty),+ $(,)?) => {$ (
        impl private::PageItemSealed for $type {}
        impl PublicPageItem for $type {}
    )+ };
}

public_result!(
    AgentCompletedSnapshot,
    AgentContext,
    AgentImpactResponse,
    AgentDependenciesResponse,
    AgentEdge,
    AgentEvidence,
    AgentDaemonStatus,
    AgentDoctor,
    AgentNamedSnapshot,
    AgentNode,
    AgentNodeSummary,
    AgentPathResponse,
    AgentPathStep,
    AgentProfilePlan,
    AgentRuntimeOutcome,
    AgentRuntimeValidationResponse,
    AgentSite,
    AgentSnapshot,
    AgentSnapshotDiffResponse,
    AgentPolicyEvaluationResponse,
    AgentGraphExportResponse,
    AgentHealthAudit,
    AgentHealthFindingDetail,
    AgentHealthFindingsPage,
    AgentHealthHotspots,
    AgentHealthSummary,
    AgentRepositoryInitOutcome,
    AgentOperation,
    DurableSubmitResult,
    OperationAccepted,
    TaskAccepted,
);
public_page_item!(
    AgentCycle,
    AgentEdge,
    AgentEvidence,
    AgentNamedSnapshot,
    AgentNode,
    AgentNodeSummary,
    AgentPathStep,
    AgentSite,
    AgentSnapshot,
    AgentImpact,
    AgentUnresolved,
    AgentQueryRow,
    AgentRuntimeTraceEvent,
    AgentHealthFinding,
);

impl<T: PublicPageItem> private::Sealed for Page<T> {}
impl<T: PublicPageItem> PublicToolResult for Page<T> {}

/// Canonical MCP result plus the exact byte count of its public JSON payload.
#[derive(Clone, Debug)]
pub struct MappedToolResult {
    result: CallToolResult,
    output_bytes: usize,
}

impl MappedToolResult {
    #[must_use]
    pub const fn result(&self) -> &CallToolResult {
        &self.result
    }

    #[must_use]
    pub const fn output_bytes(&self) -> usize {
        self.output_bytes
    }

    #[must_use]
    pub fn into_result(self) -> CallToolResult {
        self.result
    }
}

/// The sole mapper from closed depgraph envelopes to MCP tool results.
pub struct CanonicalResponseMapper;

impl CanonicalResponseMapper {
    /// Maps the closed durable-submit union without wrapping it in a repository
    /// success envelope. The baseline wire contract is the accepted handle
    /// itself; native MCP Tasks uses the transport-level result union instead.
    pub fn durable_submit(
        result: &DurableSubmitResult,
    ) -> Result<MappedToolResult, ResponseMappingError> {
        map_envelope(result, false, MAX_PAGE_BYTES as usize)
    }

    pub fn success<T>(
        envelope: &SuccessEnvelope<T>,
    ) -> Result<MappedToolResult, ResponseMappingError>
    where
        T: PublicToolResult,
    {
        match map_envelope(envelope, false, MAX_PAGE_BYTES as usize) {
            Err(ResponseMappingError::OutputTooLarge) => Self::error(&ErrorEnvelope::new(
                envelope.repository_id().clone(),
                resource_error(AgentResourceLimit::OutputBytes, u64::from(MAX_PAGE_BYTES)),
            )),
            mapped => mapped,
        }
    }

    /// Maps an inline graph export while preserving file-export remediation if
    /// the final public envelope exceeds the MCP byte limit.
    pub fn export_success<T>(
        envelope: &SuccessEnvelope<T>,
    ) -> Result<MappedToolResult, ResponseMappingError>
    where
        T: PublicToolResult,
    {
        match map_envelope(envelope, false, MAX_PAGE_BYTES as usize) {
            Err(ResponseMappingError::OutputTooLarge) => Self::error(&ErrorEnvelope::new(
                envelope.repository_id().clone(),
                AgentError::new(
                    AgentErrorCode::ResourceExhausted,
                    false,
                    AgentRemediation::ExportFile,
                    Some(AgentErrorDetails::ResourceLimit {
                        limit: AgentResourceLimit::OutputBytes,
                        maximum: u64::from(MAX_PAGE_BYTES),
                    }),
                ),
            )),
            mapped => mapped,
        }
    }

    pub fn error(envelope: &ErrorEnvelope) -> Result<MappedToolResult, ResponseMappingError> {
        map_envelope(envelope, true, MAX_PAGE_BYTES as usize)
    }

    /// Map a terminal success only after it crossed the originating tool's
    /// closed portable-output contract.
    pub fn terminal_output(
        output: &PortableTerminalOutput,
    ) -> Result<MappedToolResult, ResponseMappingError> {
        match map_envelope(output, false, MAX_PAGE_BYTES as usize) {
            Err(ResponseMappingError::OutputTooLarge) => Self::error(&ErrorEnvelope::new(
                output.repository_id().clone(),
                resource_error(AgentResourceLimit::OutputBytes, u64::from(MAX_PAGE_BYTES)),
            )),
            mapped => mapped,
        }
    }

    pub fn service_error(
        repository_id: LogicalRepositoryId,
        source: &DepgraphServiceError,
    ) -> Result<MappedToolResult, ResponseMappingError> {
        Self::error(&ErrorEnvelope::new(
            repository_id,
            map_service_error(source),
        ))
    }
}

fn map_envelope<T>(
    envelope: &T,
    is_error: bool,
    byte_limit: usize,
) -> Result<MappedToolResult, ResponseMappingError>
where
    T: Serialize + ?Sized,
{
    let mut value = bounded_json_value(envelope, byte_limit)?;
    redact_public_value(&mut value);
    let canonical = canonical_json_bytes(&value)?;
    if canonical.len() > byte_limit {
        return Err(ResponseMappingError::OutputTooLarge);
    }
    let text = String::from_utf8(canonical.clone())
        .expect("canonical JSON generated from a serde_json::Value is UTF-8");
    let mut result = CallToolResult::structured(value);
    result.content = vec![rmcp::model::ContentBlock::text(text)];
    result.is_error = Some(is_error);
    Ok(MappedToolResult {
        result,
        output_bytes: canonical.len(),
    })
}

struct LimitedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl LimitedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            exceeded: false,
        }
    }
}

impl Write for LimitedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("public JSON byte limit exceeded"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_json_value<T>(value: &T, limit: usize) -> Result<Value, ResponseMappingError>
where
    T: Serialize + ?Sized,
{
    let mut writer = LimitedWriter::new(limit);
    if let Err(error) = serde_json::to_writer(&mut writer, value) {
        return if writer.exceeded {
            Err(ResponseMappingError::OutputTooLarge)
        } else {
            Err(ResponseMappingError::Json(error))
        };
    }
    serde_json::from_slice(&writer.bytes).map_err(ResponseMappingError::Json)
}

fn map_service_error(source: &DepgraphServiceError) -> AgentError {
    match source {
        DepgraphServiceError::InvalidConfiguration { .. } => internal_error(false),
        DepgraphServiceError::CapabilityDenied { required } => AgentError::new(
            AgentErrorCode::CapabilityDenied,
            false,
            AgentRemediation::EnableRequiredCapability,
            Some(AgentErrorDetails::RequiredCapability {
                capability: map_capability(*required),
            }),
        ),
        DepgraphServiceError::InvalidRepositoryPath { .. } => AgentError::new(
            AgentErrorCode::InvalidRepositoryPath,
            false,
            AgentRemediation::CorrectInput,
            None,
        ),
        DepgraphServiceError::RepositoryFile { reason } => match reason {
            RepositoryFileError::NotFound => AgentError::new(
                AgentErrorCode::NotFound,
                false,
                AgentRemediation::CorrectInput,
                None,
            ),
            RepositoryFileError::AlreadyExists => AgentError::new(
                AgentErrorCode::Conflict,
                false,
                AgentRemediation::CorrectInput,
                None,
            ),
            RepositoryFileError::BoundaryViolation | RepositoryFileError::NotRegular => {
                integrity_error()
            }
            RepositoryFileError::Unavailable { .. } => internal_error(true),
        },
        DepgraphServiceError::InvalidInput
        | DepgraphServiceError::ProfilePlan { .. }
        | DepgraphServiceError::GraphQuery { .. }
        | DepgraphServiceError::BoundedQueryInput { .. }
        | DepgraphServiceError::RuntimeTraceInput { .. }
        | DepgraphServiceError::PolicyInput => AgentError::new(
            AgentErrorCode::InvalidArgument,
            false,
            AgentRemediation::CorrectInput,
            None,
        ),
        DepgraphServiceError::NotFound => AgentError::new(
            AgentErrorCode::NotFound,
            false,
            AgentRemediation::CorrectInput,
            None,
        ),
        DepgraphServiceError::Conflict | DepgraphServiceError::StoreWriterConflict => {
            AgentError::new(
                AgentErrorCode::Conflict,
                false,
                AgentRemediation::CorrectInput,
                None,
            )
        }
        DepgraphServiceError::SnapshotWorktreeMismatch => AgentError::new(
            AgentErrorCode::SnapshotWorktreeMismatch,
            false,
            AgentRemediation::SelectCompletedSnapshot,
            None,
        ),
        DepgraphServiceError::QueryRejected => AgentError::new(
            AgentErrorCode::QueryRejected,
            false,
            AgentRemediation::NarrowQuery,
            None,
        ),
        DepgraphServiceError::ResourceExhausted => AgentError::new(
            AgentErrorCode::ResourceExhausted,
            false,
            AgentRemediation::NarrowQuery,
            None,
        ),
        DepgraphServiceError::InlineExportTooLarge { maximum } => AgentError::new(
            AgentErrorCode::ResourceExhausted,
            false,
            AgentRemediation::ExportFile,
            Some(AgentErrorDetails::ResourceLimit {
                limit: AgentResourceLimit::OutputBytes,
                maximum: *maximum as u64,
            }),
        ),
        DepgraphServiceError::Cancelled => AgentError::new(
            AgentErrorCode::Cancelled,
            true,
            AgentRemediation::Retry,
            None,
        ),
        DepgraphServiceError::ReadStoreUnavailable { .. }
        | DepgraphServiceError::MutatingStoreUnavailable { .. }
        | DepgraphServiceError::StoreOperation { .. } => internal_error(true),
        DepgraphServiceError::ProfilePlanSecurity { .. }
        | DepgraphServiceError::ProjectExecution { .. }
        | DepgraphServiceError::Integrity => integrity_error(),
        DepgraphServiceError::Internal => internal_error(true),
    }
}

const fn map_capability(capability: DepgraphCapability) -> AgentCapability {
    match capability {
        DepgraphCapability::Read => AgentCapability::Read,
        DepgraphCapability::StoreWrite => AgentCapability::StoreWrite,
        DepgraphCapability::RepositoryWrite => AgentCapability::RepositoryWrite,
        DepgraphCapability::DaemonControl => AgentCapability::DaemonControl,
        DepgraphCapability::ProjectExec => AgentCapability::ProjectExec,
    }
}

const fn internal_error(retryable: bool) -> AgentError {
    AgentError::new(
        AgentErrorCode::Internal,
        retryable,
        if retryable {
            AgentRemediation::Retry
        } else {
            AgentRemediation::ContactOperator
        },
        None,
    )
}

const fn integrity_error() -> AgentError {
    AgentError::new(
        AgentErrorCode::IntegrityFailure,
        false,
        AgentRemediation::ContactOperator,
        None,
    )
}

const fn resource_error(limit: AgentResourceLimit, maximum: u64) -> AgentError {
    AgentError::new(
        AgentErrorCode::ResourceExhausted,
        false,
        AgentRemediation::NarrowQuery,
        Some(AgentErrorDetails::ResourceLimit { limit, maximum }),
    )
}

/// Secret key used to authenticate and encrypt continuation cursor state.
#[derive(Clone)]
pub struct CursorKey([u8; 32]);

impl CursorKey {
    /// Generates an ephemeral process-local cursor key.
    #[must_use]
    pub fn generate() -> Self {
        Self(ChaCha20Poly1305::generate_key(&mut OsRng).into())
    }

    /// Constructs a cursor key from secret bytes supplied by the server runtime.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for CursorKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CursorKey([REDACTED])")
    }
}

impl Drop for CursorKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Immutable cursor scope for one tool, repository, snapshot, and normalized filter.
#[derive(Clone, Debug)]
pub struct PaginationContext {
    repository_id: LogicalRepositoryId,
    snapshot_id: SnapshotId,
    binding_digest: String,
    cursor_key: CursorKey,
}

trait PageByteProjection {
    fn projected_page_bytes(
        &mut self,
        count: usize,
        item_bytes: usize,
        total_items: u64,
        complete: bool,
        next_cursor: Option<&Cursor>,
    ) -> Result<usize, AgentError>;
}

struct BarePageByteProjection<'a> {
    pagination: &'a PaginationContext,
}

impl PageByteProjection for BarePageByteProjection<'_> {
    fn projected_page_bytes(
        &mut self,
        count: usize,
        item_bytes: usize,
        total_items: u64,
        complete: bool,
        next_cursor: Option<&Cursor>,
    ) -> Result<usize, AgentError> {
        self.pagination
            .projected_page_bytes(count, item_bytes, total_items, complete, next_cursor)
    }
}

impl PaginationContext {
    pub fn new<T>(
        cursor_key: &CursorKey,
        tool: impl Into<String>,
        repository_id: LogicalRepositoryId,
        snapshot_id: SnapshotId,
        normalized_input: &T,
    ) -> Result<Self, ResponseMappingError>
    where
        T: Serialize + ?Sized,
    {
        let tool = tool.into();
        if tool.is_empty() {
            return Err(ResponseMappingError::InvalidToolName);
        }
        let normalized_input = bounded_json_value(normalized_input, MAX_PAGE_BYTES as usize)?;
        let binding = json!({
            "contract_version": MCP_TOOLS_CONTRACT_VERSION,
            "normalized_input": normalized_input,
            "repository_id": &repository_id,
            "snapshot_id": &snapshot_id,
            "tool": tool,
        });
        let binding_bytes = canonical_json_bytes(&binding)?;
        if binding_bytes.len() > MAX_PAGE_BYTES as usize {
            return Err(ResponseMappingError::OutputTooLarge);
        }
        let binding_digest = lowercase_sha256(&binding_bytes);
        Ok(Self {
            repository_id,
            snapshot_id,
            binding_digest,
            cursor_key: cursor_key.clone(),
        })
    }

    pub fn paginate<T>(&self, items: &[T], request: &PageRequest) -> Result<Page<T>, AgentError>
    where
        T: PublicPageItem,
    {
        let result_digest = public_result_digest(items)?;
        self.paginate_with_digest_cancellable(items, request, result_digest, &mut || false)
    }

    /// Computes the complete bounded collection digest and selects one page while observing
    /// cooperative cancellation throughout both phases.
    pub fn paginate_cancellable<T>(
        &self,
        items: &[T],
        request: &PageRequest,
        cancellation: &CancellationToken,
    ) -> Result<Page<T>, AgentError>
    where
        T: PublicPageItem,
    {
        let mut is_cancelled = || cancellation.is_cancelled();
        let result_digest = public_result_digest_bounded_cancellable(
            items,
            depgraph_core::MAX_INTERACTIVE_QUERY_TRAVERSAL,
            depgraph_core::DEFAULT_SERVICE_MAX_OUTPUT_BYTES,
            &mut is_cancelled,
        )?;
        self.paginate_with_digest_cancellable(items, request, result_digest, &mut is_cancelled)
    }

    fn paginate_cancellable_with_projection<T, P>(
        &self,
        items: &[T],
        request: &PageRequest,
        cancellation: &CancellationToken,
        project_candidate_bytes: &mut P,
    ) -> Result<Page<T>, AgentError>
    where
        T: PublicPageItem,
        P: PageByteProjection,
    {
        let mut is_cancelled = || cancellation.is_cancelled();
        let result_digest = public_result_digest_bounded_cancellable(
            items,
            depgraph_core::MAX_INTERACTIVE_QUERY_TRAVERSAL,
            depgraph_core::DEFAULT_SERVICE_MAX_OUTPUT_BYTES,
            &mut is_cancelled,
        )?;
        self.paginate_with_digest_and_projection_cancellable(
            items,
            request,
            result_digest,
            &mut is_cancelled,
            project_candidate_bytes,
        )
    }

    fn paginate_with_digest_cancellable<T>(
        &self,
        items: &[T],
        request: &PageRequest,
        result_digest: [u8; 32],
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<Page<T>, AgentError>
    where
        T: PublicPageItem,
    {
        let mut project_candidate_bytes = BarePageByteProjection { pagination: self };
        self.paginate_with_digest_and_projection_cancellable(
            items,
            request,
            result_digest,
            is_cancelled,
            &mut project_candidate_bytes,
        )
    }

    fn paginate_with_digest_and_projection_cancellable<T, P>(
        &self,
        items: &[T],
        request: &PageRequest,
        result_digest: [u8; 32],
        is_cancelled: &mut impl FnMut() -> bool,
        project_candidate_bytes: &mut P,
    ) -> Result<Page<T>, AgentError>
    where
        T: PublicPageItem,
        P: PageByteProjection,
    {
        if is_cancelled() {
            return Err(cancelled_error());
        }
        let total_items = u64::try_from(items.len()).map_err(|_| internal_error(false))?;
        let offset = match request.cursor() {
            Some(cursor) => {
                let (offset, cursor_total, cursor_digest) = self.decode_cursor(cursor)?;
                if cursor_total != total_items || cursor_digest != result_digest {
                    return Err(cursor_mismatch());
                }
                offset
            }
            None => 0,
        };
        if offset > items.len() {
            return Err(cursor_mismatch());
        }
        let remaining = &items[offset..];
        if remaining.is_empty() {
            if is_cancelled() {
                return Err(cancelled_error());
            }
            let maximum_bytes = request.max_bytes().get() as usize;
            let projected =
                project_candidate_bytes.projected_page_bytes(0, 0, total_items, true, None)?;
            if is_cancelled() {
                return Err(cancelled_error());
            }
            if projected > maximum_bytes {
                return Err(resource_error(
                    AgentResourceLimit::OutputBytes,
                    maximum_bytes as u64,
                ));
            }
            return Page::new(Vec::new(), total_items, true, None)
                .map_err(|_| internal_error(false));
        }

        let maximum_items = usize::from(request.max_items().get()).min(remaining.len());
        let maximum_bytes = request.max_bytes().get() as usize;
        let mut item_bytes = 0usize;
        let mut selected = None;

        for (index, item) in remaining.iter().take(maximum_items).enumerate() {
            if is_cancelled() {
                return Err(cancelled_error());
            }
            let mut item_value = match bounded_json_value(item, maximum_bytes) {
                Ok(value) => value,
                Err(ResponseMappingError::OutputTooLarge) if selected.is_some() => break,
                Err(ResponseMappingError::OutputTooLarge) => {
                    return Err(resource_error(
                        AgentResourceLimit::OutputBytes,
                        maximum_bytes as u64,
                    ));
                }
                Err(_) => return Err(internal_error(false)),
            };
            redact_public_value(&mut item_value);
            let canonical_item =
                canonical_json_bytes(&item_value).map_err(|_| internal_error(false))?;
            if canonical_item.len() > maximum_bytes {
                if selected.is_some() {
                    break;
                }
                return Err(resource_error(
                    AgentResourceLimit::OutputBytes,
                    maximum_bytes as u64,
                ));
            }
            item_bytes = item_bytes
                .checked_add(canonical_item.len())
                .ok_or_else(|| {
                    resource_error(AgentResourceLimit::OutputBytes, maximum_bytes as u64)
                })?;
            let count = index + 1;
            let next_offset = offset + count;
            let complete = next_offset == items.len();
            let next_cursor = if complete {
                None
            } else {
                Some(
                    self.encode_cursor(next_offset, total_items, &result_digest)
                        .map_err(|_| internal_error(false))?,
                )
            };
            if is_cancelled() {
                return Err(cancelled_error());
            }
            let projected = project_candidate_bytes.projected_page_bytes(
                count,
                item_bytes,
                total_items,
                complete,
                next_cursor.as_ref(),
            )?;
            if is_cancelled() {
                return Err(cancelled_error());
            }
            if projected <= maximum_bytes {
                selected = Some((count, next_cursor));
            } else {
                break;
            }
        }

        let Some((count, next_cursor)) = selected else {
            return Err(resource_error(
                AgentResourceLimit::OutputBytes,
                maximum_bytes as u64,
            ));
        };
        let complete = offset + count == items.len();
        if is_cancelled() {
            return Err(cancelled_error());
        }
        Page::new(
            remaining[..count].to_vec(),
            total_items,
            complete,
            next_cursor,
        )
        .map_err(|_| internal_error(false))
    }

    /// Decode the starting offset without materializing the bound collection.
    /// Collection totals and identity are validated by `paginate_window` after
    /// the bounded store query returns.
    pub fn cursor_offset(&self, request: &PageRequest) -> Result<usize, AgentError> {
        request
            .cursor()
            .map(|cursor| self.decode_cursor(cursor).map(|state| state.0))
            .transpose()
            .map(Option::unwrap_or_default)
    }

    pub fn paginate_window<T>(
        &self,
        items: &[T],
        offset: usize,
        total_items: u64,
        request: &PageRequest,
    ) -> Result<Page<T>, AgentError>
    where
        T: PublicPageItem,
    {
        let result_digest = self.bounded_collection_digest();
        if let Some(cursor) = request.cursor() {
            let (cursor_offset, cursor_total, cursor_digest) = self.decode_cursor(cursor)?;
            if cursor_offset != offset
                || cursor_total != total_items
                || cursor_digest != result_digest
            {
                return Err(cursor_mismatch());
            }
        } else if offset != 0 {
            return Err(cursor_mismatch());
        }
        let offset_u64 = u64::try_from(offset).map_err(|_| cursor_mismatch())?;
        if offset_u64 > total_items
            || u64::try_from(items.len())
                .ok()
                .is_none_or(|count| offset_u64.saturating_add(count) > total_items)
            || items.len() > usize::from(request.max_items().get())
        {
            return Err(cursor_mismatch());
        }
        if items.is_empty() {
            if offset_u64 != total_items {
                return Err(internal_error(false));
            }
            let maximum_bytes = request.max_bytes().get() as usize;
            let projected = self.projected_page_bytes(0, 0, total_items, true, None)?;
            if projected > maximum_bytes {
                return Err(resource_error(
                    AgentResourceLimit::OutputBytes,
                    maximum_bytes as u64,
                ));
            }
            return Page::new(Vec::new(), total_items, true, None)
                .map_err(|_| internal_error(false));
        }

        let maximum_bytes = request.max_bytes().get() as usize;
        let mut item_bytes = 0usize;
        let mut selected = None;
        for (index, item) in items.iter().enumerate() {
            let mut item_value = match bounded_json_value(item, maximum_bytes) {
                Ok(value) => value,
                Err(ResponseMappingError::OutputTooLarge) if selected.is_some() => break,
                Err(ResponseMappingError::OutputTooLarge) => {
                    return Err(resource_error(
                        AgentResourceLimit::OutputBytes,
                        maximum_bytes as u64,
                    ));
                }
                Err(_) => return Err(internal_error(false)),
            };
            redact_public_value(&mut item_value);
            let canonical_item =
                canonical_json_bytes(&item_value).map_err(|_| internal_error(false))?;
            item_bytes = item_bytes
                .checked_add(canonical_item.len())
                .ok_or_else(|| {
                    resource_error(AgentResourceLimit::OutputBytes, maximum_bytes as u64)
                })?;
            let count = index + 1;
            let next_offset = offset
                .checked_add(count)
                .ok_or_else(|| internal_error(false))?;
            let complete = u64::try_from(next_offset).ok() == Some(total_items);
            let next_cursor = if complete {
                None
            } else {
                Some(
                    self.encode_cursor(next_offset, total_items, &result_digest)
                        .map_err(|_| internal_error(false))?,
                )
            };
            let projected = self.projected_page_bytes(
                count,
                item_bytes,
                total_items,
                complete,
                next_cursor.as_ref(),
            )?;
            if projected <= maximum_bytes {
                selected = Some((count, next_cursor));
            } else {
                break;
            }
        }
        let Some((count, next_cursor)) = selected else {
            return Err(resource_error(
                AgentResourceLimit::OutputBytes,
                maximum_bytes as u64,
            ));
        };
        let complete = u64::try_from(offset.saturating_add(count)).ok() == Some(total_items);
        Page::new(items[..count].to_vec(), total_items, complete, next_cursor)
            .map_err(|_| internal_error(false))
    }

    fn bounded_collection_digest(&self) -> [u8; 32] {
        Sha256::digest(self.binding_digest.as_bytes()).into()
    }

    fn encode_cursor(
        &self,
        offset: usize,
        total_items: u64,
        result_digest: &[u8; 32],
    ) -> Result<Cursor, ResponseMappingError> {
        let offset = u64::try_from(offset).map_err(|_| ResponseMappingError::CursorEncoding)?;
        let mut state = [0_u8; CURSOR_STATE_BYTES];
        state[..8].copy_from_slice(&offset.to_be_bytes());
        state[8..16].copy_from_slice(&total_items.to_be_bytes());
        state[16..].copy_from_slice(result_digest);
        // The cursor state and binding are immutable for a pinned query, so derive a
        // unique nonce from them. This keeps authenticated cursors reproducible while
        // avoiding nonce reuse for distinct cursor states under the process-local key.
        let mut nonce_hasher = Sha256::new();
        nonce_hasher.update(&self.cursor_key.0);
        nonce_hasher.update(self.binding_digest.as_bytes());
        nonce_hasher.update(state);
        let nonce_digest = nonce_hasher.finalize();
        let nonce = Nonce::from_slice(&nonce_digest[..CURSOR_NONCE_BYTES]);
        let cipher = ChaCha20Poly1305::new((&self.cursor_key.0).into());
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &state,
                    aad: self.binding_digest.as_bytes(),
                },
            )
            .map_err(|_| ResponseMappingError::CursorEncoding)?;
        state.zeroize();
        let mut sealed = Vec::with_capacity(CURSOR_NONCE_BYTES + ciphertext.len());
        sealed.extend_from_slice(nonce);
        sealed.extend_from_slice(&ciphertext);
        format!("{CURSOR_VERSION}.{}", hex::encode(sealed))
            .parse()
            .map_err(|_| ResponseMappingError::CursorEncoding)
    }

    fn decode_cursor(&self, cursor: &Cursor) -> Result<(usize, u64, [u8; 32]), AgentError> {
        let Some((version, encoded)) = cursor.as_str().split_once('.') else {
            return Err(cursor_invalid());
        };
        if encoded.contains('.') {
            return Err(cursor_invalid());
        }
        if version != CURSOR_VERSION {
            return Err(cursor_mismatch());
        }
        let sealed = hex::decode(encoded).map_err(|_| cursor_invalid())?;
        let expected_bytes = CURSOR_NONCE_BYTES + CURSOR_STATE_BYTES + CURSOR_TAG_BYTES;
        if sealed.len() != expected_bytes {
            return Err(cursor_invalid());
        }
        let (nonce_bytes, ciphertext) = sealed.split_at(CURSOR_NONCE_BYTES);
        let cipher = ChaCha20Poly1305::new((&self.cursor_key.0).into());
        let mut plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: self.binding_digest.as_bytes(),
                },
            )
            .map_err(|_| cursor_mismatch())?;
        let state: [u8; CURSOR_STATE_BYTES] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| cursor_invalid())?;
        plaintext.zeroize();
        let offset = usize::try_from(u64::from_be_bytes(
            state[..8].try_into().map_err(|_| cursor_invalid())?,
        ))
        .map_err(|_| cursor_invalid())?;
        let total_items =
            u64::from_be_bytes(state[8..16].try_into().map_err(|_| cursor_invalid())?);
        let result_digest = state[16..].try_into().map_err(|_| cursor_invalid())?;
        Ok((offset, total_items, result_digest))
    }

    fn projected_page_bytes(
        &self,
        count: usize,
        item_bytes: usize,
        total_items: u64,
        complete: bool,
        next_cursor: Option<&Cursor>,
    ) -> Result<usize, AgentError> {
        let mut page = json!({
            "complete": complete,
            "items": [],
            "next_cursor": next_cursor,
            "returned_items": count,
            "total_items": total_items,
        });
        if next_cursor.is_none() {
            page.as_object_mut()
                .expect("page projection is an object")
                .remove("next_cursor");
        }
        let mut envelope = serde_json::to_value(SuccessEnvelope::new(
            self.repository_id.clone(),
            Some(self.snapshot_id.clone()),
            page,
        ))
        .map_err(|_| internal_error(false))?;
        redact_public_value(&mut envelope);
        let empty_page_bytes = canonical_json_bytes(&envelope)
            .map_err(|_| internal_error(false))?
            .len();
        empty_page_bytes
            .checked_add(item_bytes)
            .and_then(|bytes| bytes.checked_add(count.saturating_sub(1)))
            .ok_or_else(|| resource_error(AgentResourceLimit::OutputBytes, u64::MAX))
    }
}

/// Exact byte projection for a page nested inside another public result DTO.
///
/// The fixed result is serialized and redacted once with an empty page. Candidate projection
/// mutates only the page metadata, canonicalizes that bounded fixed shape, and adds the already
/// canonicalized item byte total plus JSON array commas.
struct WrappedPageByteProjection {
    envelope: Value,
    page_field: &'static str,
}

impl WrappedPageByteProjection {
    fn new<T>(
        pagination: &PaginationContext,
        result_with_empty_page: T,
        page_field: &'static str,
    ) -> Result<Self, AgentError>
    where
        T: Serialize,
    {
        let envelope = SuccessEnvelope::new(
            pagination.repository_id.clone(),
            Some(pagination.snapshot_id.clone()),
            result_with_empty_page,
        );
        let mut envelope = match bounded_json_value(&envelope, MAX_PAGE_BYTES as usize) {
            Ok(value) => value,
            Err(ResponseMappingError::OutputTooLarge) => {
                return Err(resource_error(
                    AgentResourceLimit::OutputBytes,
                    u64::from(MAX_PAGE_BYTES),
                ));
            }
            Err(_) => return Err(internal_error(false)),
        };
        redact_public_value(&mut envelope);
        let page = envelope
            .get("result")
            .and_then(|result| result.get(page_field))
            .and_then(Value::as_object)
            .ok_or_else(|| internal_error(false))?;
        if !page
            .get("items")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            return Err(internal_error(false));
        }
        Ok(Self {
            envelope,
            page_field,
        })
    }
}

impl PageByteProjection for WrappedPageByteProjection {
    fn projected_page_bytes(
        &mut self,
        count: usize,
        item_bytes: usize,
        total_items: u64,
        complete: bool,
        next_cursor: Option<&Cursor>,
    ) -> Result<usize, AgentError> {
        let count = u64::try_from(count).map_err(|_| internal_error(false))?;
        let page = self
            .envelope
            .get_mut("result")
            .and_then(|result| result.get_mut(self.page_field))
            .and_then(Value::as_object_mut)
            .ok_or_else(|| internal_error(false))?;
        page.insert("returned_items".to_owned(), Value::from(count));
        page.insert("total_items".to_owned(), Value::from(total_items));
        page.insert("complete".to_owned(), Value::from(complete));
        if let Some(next_cursor) = next_cursor {
            page.insert(
                "next_cursor".to_owned(),
                serde_json::to_value(next_cursor).map_err(|_| internal_error(false))?,
            );
        } else {
            page.remove("next_cursor");
        }
        let empty_items_bytes = canonical_json_bytes(&self.envelope)
            .map_err(|_| internal_error(false))?
            .len();
        empty_items_bytes
            .checked_add(item_bytes)
            .and_then(|bytes| bytes.checked_add(usize::try_from(count).ok()?.saturating_sub(1)))
            .ok_or_else(|| resource_error(AgentResourceLimit::OutputBytes, u64::MAX))
    }
}

fn empty_projection_page<T>(
    pagination: &PaginationContext,
    total_items: u64,
) -> Result<Page<T>, AgentError> {
    let (complete, next_cursor) = if total_items == 0 {
        (true, None)
    } else {
        (
            false,
            Some(
                pagination
                    .encode_cursor(0, total_items, &[0_u8; 32])
                    .map_err(|_| internal_error(false))?,
            ),
        )
    };
    Page::new(Vec::new(), total_items, complete, next_cursor).map_err(|_| internal_error(false))
}

/// Projects and paginates one complete impact result under the closed Agent bounds.
///
/// The node projection lookup is constructed exactly once, the cursor digest covers the full
/// converted collection, and every linear phase cooperatively observes request cancellation.
pub fn project_impact_response_cancellable(
    source: &ImpactServiceResult,
    pagination: &PaginationContext,
    request: &PageRequest,
    cancellation: &CancellationToken,
) -> Result<AgentImpactResponse, AgentError> {
    let impact = source.impact();
    let mut is_cancelled = || cancellation.is_cancelled();
    if is_cancelled() {
        return Err(cancelled_error());
    }
    let (root, root_impacted, changed_since) =
        AgentImpactResponse::core_fields(impact).map_err(impact_contract_error)?;
    if is_cancelled() {
        return Err(cancelled_error());
    }
    let total_items = u64::try_from(impact.impacts.len()).map_err(|_| internal_error(false))?;
    let empty_page = empty_projection_page(pagination, total_items)?;
    let projection_response = AgentImpactResponse::new(
        root.clone(),
        root_impacted,
        changed_since.clone(),
        empty_page,
    )
    .map_err(impact_contract_error)?;
    let mut byte_projection =
        WrappedPageByteProjection::new(pagination, projection_response, "impacts")?;
    if is_cancelled() {
        return Err(cancelled_error());
    }
    validate_aggregate_condition_bytes(
        impact
            .impacts
            .iter()
            .flat_map(|impact| impact.dependency_path.iter())
            .map(|step| step.condition_text.as_str()),
    )?;
    let projection = AgentImpactProjection::try_new(impact, &mut is_cancelled)
        .map_err(impact_projection_error)?;
    let items = projection
        .convert_all(&mut is_cancelled)
        .map_err(impact_projection_error)?;
    let page = pagination.paginate_cancellable_with_projection(
        &items,
        request,
        cancellation,
        &mut byte_projection,
    )?;
    if is_cancelled() {
        return Err(cancelled_error());
    }
    AgentImpactResponse::new(root, root_impacted, changed_since, page)
        .map_err(impact_contract_error)
}

/// Converts and paginates one complete dependency traversal with cooperative cancellation.
pub fn project_dependencies_page_cancellable(
    source: &DependenciesResult,
    direction: crate::AgentDependencyDirection,
    transitive: bool,
    pagination: &PaginationContext,
    request: &PageRequest,
    cancellation: &CancellationToken,
) -> Result<AgentDependenciesResponse, AgentError> {
    if !source.complete() {
        return Err(resource_error(
            AgentResourceLimit::TraversalItems,
            depgraph_core::MAX_INTERACTIVE_QUERY_TRAVERSAL as u64,
        ));
    }
    let mut is_cancelled = || cancellation.is_cancelled();
    if is_cancelled() {
        return Err(cancelled_error());
    }
    let root = AgentNode::try_from(source).map_err(impact_contract_error)?;
    let total_items = u64::try_from(source.items().len()).map_err(|_| internal_error(false))?;
    let empty_page = empty_projection_page(pagination, total_items)?;
    let projection_response = AgentDependenciesResponse::new(
        root.clone(),
        direction,
        transitive,
        source.complete(),
        source.traversed_edges(),
        empty_page,
    )
    .map_err(impact_contract_error)?;
    let mut byte_projection =
        WrappedPageByteProjection::new(pagination, projection_response, "edges")?;
    if is_cancelled() {
        return Err(cancelled_error());
    }
    validate_aggregate_condition_bytes(
        source
            .items()
            .iter()
            .map(|item| item.step.condition_text.as_str()),
    )?;
    let items = convert_dependency_items_cancellable(
        source.items(),
        depgraph_core::MAX_INTERACTIVE_QUERY_TRAVERSAL,
        &mut is_cancelled,
    )?;
    if is_cancelled() {
        return Err(cancelled_error());
    }
    let page = pagination.paginate_cancellable_with_projection(
        &items,
        request,
        cancellation,
        &mut byte_projection,
    )?;
    if is_cancelled() {
        return Err(cancelled_error());
    }
    AgentDependenciesResponse::new(
        root,
        direction,
        transitive,
        source.complete(),
        source.traversed_edges(),
        page,
    )
    .map_err(impact_contract_error)
}

fn convert_dependency_items_cancellable(
    source: &[depgraph_core::query::TraversalPageItem],
    maximum_items: usize,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<AgentEdge>, AgentError> {
    validate_dependency_item_count(source.len(), maximum_items)?;
    if is_cancelled() {
        return Err(cancelled_error());
    }
    let mut items = Vec::with_capacity(source.len());
    for item in source {
        if is_cancelled() {
            return Err(cancelled_error());
        }
        items.push(
            AgentEdge::try_from_core_cancellable(&item.step, is_cancelled)
                .map_err(impact_projection_error)?,
        );
    }
    if is_cancelled() {
        return Err(cancelled_error());
    }
    Ok(items)
}

fn validate_dependency_item_count(
    item_count: usize,
    maximum_items: usize,
) -> Result<(), AgentError> {
    if item_count > maximum_items {
        return Err(resource_error(
            AgentResourceLimit::TraversalItems,
            maximum_items.try_into().unwrap_or(u64::MAX),
        ));
    }
    Ok(())
}

fn validate_aggregate_condition_bytes<'a>(
    conditions: impl IntoIterator<Item = &'a str>,
) -> Result<(), AgentError> {
    let mut total = 0_usize;
    for condition in conditions {
        total = total.checked_add(condition.len()).ok_or_else(|| {
            resource_error(AgentResourceLimit::OutputBytes, u64::from(MAX_PAGE_BYTES))
        })?;
        if total > MAX_PAGE_BYTES as usize {
            return Err(resource_error(
                AgentResourceLimit::OutputBytes,
                u64::from(MAX_PAGE_BYTES),
            ));
        }
    }
    Ok(())
}

/// Converts and paginates a complete service cycle result with cooperative cancellation.
pub fn project_cycles_page_cancellable(
    source: &CyclesResult,
    pagination: &PaginationContext,
    request: &PageRequest,
    cancellation: &CancellationToken,
) -> Result<Page<AgentCycle>, AgentError> {
    if source.cycles().len() > depgraph_core::MAX_INTERACTIVE_QUERY_TRAVERSAL {
        return Err(resource_error(
            AgentResourceLimit::TraversalItems,
            depgraph_core::MAX_INTERACTIVE_QUERY_TRAVERSAL as u64,
        ));
    }
    let mut is_cancelled = || cancellation.is_cancelled();
    let mut items = Vec::with_capacity(source.cycles().len());
    for cycle in source.cycles() {
        if is_cancelled() {
            return Err(cancelled_error());
        }
        items.push(
            AgentCycle::try_from_core_cancellable(cycle, &mut is_cancelled)
                .map_err(impact_projection_error)?,
        );
    }
    if is_cancelled() {
        return Err(cancelled_error());
    }
    pagination.paginate_cancellable(&items, request, cancellation)
}

/// Converts and paginates a complete unresolved-site result with cooperative cancellation.
pub fn project_unresolved_page_cancellable(
    source: &UnresolvedServiceResult,
    pagination: &PaginationContext,
    request: &PageRequest,
    cancellation: &CancellationToken,
) -> Result<Page<AgentUnresolved>, AgentError> {
    if source.items().len() > depgraph_core::MAX_INTERACTIVE_QUERY_TRAVERSAL {
        return Err(resource_error(
            AgentResourceLimit::TraversalItems,
            depgraph_core::MAX_INTERACTIVE_QUERY_TRAVERSAL as u64,
        ));
    }
    let mut is_cancelled = || cancellation.is_cancelled();
    let mut items = Vec::with_capacity(source.items().len());
    for unresolved in source.items() {
        if is_cancelled() {
            return Err(cancelled_error());
        }
        items.push(
            AgentUnresolved::try_from_core_cancellable(unresolved, &mut is_cancelled)
                .map_err(impact_projection_error)?,
        );
    }
    if is_cancelled() {
        return Err(cancelled_error());
    }
    pagination.paginate_cancellable(&items, request, cancellation)
}

fn impact_projection_error(error: ImpactProjectionFailure) -> AgentError {
    match error {
        ImpactProjectionFailure::Cancelled => cancelled_error(),
        ImpactProjectionFailure::ConditionTooLarge => resource_error(
            AgentResourceLimit::OutputBytes,
            MAX_AGENT_CONDITION_BYTES as u64,
        ),
        ImpactProjectionFailure::TooManyItems => resource_error(
            AgentResourceLimit::TraversalItems,
            depgraph_core::MAX_INTERACTIVE_QUERY_TRAVERSAL as u64,
        ),
        ImpactProjectionFailure::TooManyMaterializedPathSteps => resource_error(
            AgentResourceLimit::TraversalItems,
            depgraph_core::service::MAX_IMPACT_MATERIALIZED_PATH_STEPS as u64,
        ),
        ImpactProjectionFailure::Contract(error) => impact_contract_error(error),
    }
}

fn impact_contract_error(error: ContractBuildError) -> AgentError {
    match error {
        ContractBuildError::PageByteLimit => {
            resource_error(AgentResourceLimit::OutputBytes, u64::from(MAX_PAGE_BYTES))
        }
        ContractBuildError::TooManyPathSteps
        | ContractBuildError::TooManyPageItems
        | ContractBuildError::TooManyCorrelationReasons
        | ContractBuildError::TooManyPhases
        | ContractBuildError::TooManyEvidenceItems
        | ContractBuildError::TooManyTargetItems => resource_error(
            AgentResourceLimit::TraversalItems,
            u64::from(MAX_PAGE_ITEMS),
        ),
        _ => integrity_error(),
    }
}

fn public_result_digest<T>(items: &[T]) -> Result<[u8; 32], AgentError>
where
    T: PublicPageItem,
{
    let mut hasher = Sha256::new();
    let total_items = u64::try_from(items.len()).map_err(|_| internal_error(false))?;
    hasher.update(total_items.to_be_bytes());
    for item in items {
        let mut value = match bounded_json_value(item, MAX_PAGE_BYTES as usize) {
            Ok(value) => value,
            Err(ResponseMappingError::OutputTooLarge) => {
                return Err(resource_error(
                    AgentResourceLimit::OutputBytes,
                    u64::from(MAX_PAGE_BYTES),
                ));
            }
            Err(_) => return Err(internal_error(false)),
        };
        redact_public_value(&mut value);
        let canonical = canonical_json_bytes(&value).map_err(|_| internal_error(false))?;
        let item_bytes = u64::try_from(canonical.len()).map_err(|_| internal_error(false))?;
        hasher.update(item_bytes.to_be_bytes());
        hasher.update(canonical);
    }
    Ok(hasher.finalize().into())
}

fn public_result_digest_bounded_cancellable<T>(
    items: &[T],
    maximum_items: usize,
    maximum_item_bytes: usize,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<[u8; 32], AgentError>
where
    T: PublicPageItem,
{
    if items.len() > maximum_items {
        return Err(resource_error(
            AgentResourceLimit::TraversalItems,
            maximum_items.try_into().unwrap_or(u64::MAX),
        ));
    }
    let mut hasher = Sha256::new();
    let total_items = u64::try_from(items.len()).map_err(|_| internal_error(false))?;
    hasher.update(total_items.to_be_bytes());
    for item in items {
        if is_cancelled() {
            return Err(cancelled_error());
        }
        let mut value = match bounded_json_value(item, maximum_item_bytes) {
            Ok(value) => value,
            Err(ResponseMappingError::OutputTooLarge) => {
                return Err(resource_error(
                    AgentResourceLimit::OutputBytes,
                    maximum_item_bytes.try_into().unwrap_or(u64::MAX),
                ));
            }
            Err(_) => return Err(internal_error(false)),
        };
        redact_public_value(&mut value);
        let canonical = canonical_json_bytes(&value).map_err(|_| internal_error(false))?;
        if canonical.len() > maximum_item_bytes {
            return Err(resource_error(
                AgentResourceLimit::OutputBytes,
                maximum_item_bytes.try_into().unwrap_or(u64::MAX),
            ));
        }
        let item_bytes = u64::try_from(canonical.len()).map_err(|_| internal_error(false))?;
        hasher.update(item_bytes.to_be_bytes());
        hasher.update(canonical);
    }
    if is_cancelled() {
        return Err(cancelled_error());
    }
    Ok(hasher.finalize().into())
}

const fn cancelled_error() -> AgentError {
    AgentError::new(
        AgentErrorCode::Cancelled,
        true,
        AgentRemediation::Retry,
        None,
    )
}

fn cursor_invalid() -> AgentError {
    AgentError::new(
        AgentErrorCode::CursorInvalid,
        false,
        AgentRemediation::RestartFromFirstPage,
        None,
    )
}

fn cursor_mismatch() -> AgentError {
    AgentError::new(
        AgentErrorCode::CursorMismatch,
        false,
        AgentRemediation::RestartFromFirstPage,
        None,
    )
}

#[derive(Debug, thiserror::Error)]
pub enum ResponseMappingError {
    #[error("response could not be serialized")]
    Json(#[from] serde_json::Error),
    #[error("response could not be canonicalized")]
    Canonical(#[from] CanonicalJsonError),
    #[error("response exceeds the public output byte limit")]
    OutputTooLarge,
    #[error("tool name must not be empty")]
    InvalidToolName,
    #[error("continuation cursor could not be encoded")]
    CursorEncoding,
}

fn redact_public_value(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (name, child) in object {
                if sensitive_field(name) {
                    *child = Value::String(REDACTED.to_owned());
                } else {
                    redact_public_value(child);
                }
            }
        }
        Value::Array(values) => {
            for child in values {
                redact_public_value(child);
            }
        }
        Value::String(text) if sensitive_string(text) => {
            *text = REDACTED.to_owned();
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn sensitive_field(name: &str) -> bool {
    let normalized: String = name
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect();
    matches!(
        normalized.as_str(),
        "query"
            | "rawquery"
            | "stderr"
            | "workerstderr"
            | "authorization"
            | "proxyauthorization"
            | "credential"
            | "credentials"
            | "password"
            | "passwd"
            | "secret"
            | "clientsecret"
            | "secretkey"
            | "apikey"
            | "xapikey"
            | "accesskey"
            | "awsaccesskeyid"
            | "awssecretaccesskey"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "sessiontoken"
            | "absolutepath"
    ) || normalized.ends_with("password")
        || normalized.ends_with("secret")
        || normalized.ends_with("token")
}

fn sensitive_string(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let trimmed = lower.trim_start();
    contains_absolute_path(text)
        || lower.contains(concat!("file", "://"))
        || [
            "authorization:",
            "proxy-authorization:",
            concat!("x-api-", "key:"),
            concat!("api-", "key:"),
            "bearer ",
            "basic ",
            "private key",
            "-----begin ",
            "password=",
            "password:",
            "passwd=",
            "token=",
            "token:",
            "api_key=",
            "api-key=",
            "secret_key=",
            "secret-key=",
            "aws_access_key_id=",
            "aws_secret_access_key=",
        ]
        .iter()
        .any(|marker| lower.contains(marker))
        || contains_credential_prefix(trimmed)
        || looks_like_raw_query(trimmed)
}

fn contains_credential_prefix(text: &str) -> bool {
    [
        "akia",
        "asia",
        concat!("gh", "p_"),
        "github_pat_",
        "xoxb-",
        "xoxp-",
    ]
    .iter()
    .any(|prefix| {
        text.match_indices(prefix).any(|(offset, _)| {
            offset == 0
                || text[..offset]
                    .chars()
                    .next_back()
                    .is_some_and(|character| !character.is_ascii_alphanumeric())
        })
    })
}

fn looks_like_raw_query(mut trimmed: &str) -> bool {
    loop {
        trimmed = trimmed.trim_start();
        if let Some(comment) = trimmed.strip_prefix("--") {
            let Some(line_end) = comment.find('\n') else {
                return true;
            };
            trimmed = &comment[line_end + 1..];
            continue;
        }
        if let Some(comment) = trimmed.strip_prefix("/*") {
            let Some(comment_end) = comment.find("*/") else {
                return true;
            };
            trimmed = &comment[comment_end + 2..];
            continue;
        }
        break;
    }

    [
        "explain ",
        "analyze ",
        "match ",
        "optional match ",
        "return ",
        "unwind ",
        "foreach ",
        "select ",
        "insert ",
        "update ",
        "delete ",
        "with ",
        "create ",
        "merge ",
        "call ",
        "set ",
        "remove ",
        "drop ",
        "alter ",
        "query ",
        "mutation ",
        "subscription ",
        "prefix ",
        "base ",
        "ask ",
        "construct ",
        "describe ",
        "g.",
        "g(",
    ]
    .iter()
    .any(|prefix| trimmed.starts_with(prefix))
}

fn contains_absolute_path(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.iter().enumerate().any(|(index, byte)| {
        let boundary = index == 0
            || bytes[index - 1].is_ascii_whitespace()
            || matches!(
                bytes[index - 1],
                b'(' | b'[' | b'{' | b'\"' | b'\'' | b'=' | b':' | b','
            );
        if byte.is_ascii_alphabetic()
            && bytes.get(index + 1) == Some(&b':')
            && matches!(bytes.get(index + 2), Some(b'/' | b'\\'))
        {
            return boundary;
        }
        if *byte == b'\\' {
            return boundary
                && matches!(bytes.get(index + 1), Some(next) if *next == b'\\' || next.is_ascii_alphabetic());
        }
        if *byte != b'/' {
            return false;
        }
        if bytes.get(index + 1) == Some(&b'/') {
            return boundary && (index == 0 || bytes[index - 1] != b':');
        }
        boundary
    })
}

fn lowercase_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use serde::{Serialize, Serializer, ser::SerializeSeq};
    use serde_json::json;

    use super::{
        AgentErrorCode, AgentNode, CanonicalResponseMapper, CursorKey, LogicalRepositoryId,
        PageRequest, PaginationContext, ResponseMappingError, SnapshotId,
        WrappedPageByteProjection, bounded_json_value, canonical_json_bytes,
        contains_credential_prefix, convert_dependency_items_cancellable, empty_projection_page,
        impact_contract_error, looks_like_raw_query, public_result_digest,
        public_result_digest_bounded_cancellable, redact_public_value, sensitive_field,
        validate_aggregate_condition_bytes, validate_dependency_item_count,
    };
    use crate::{
        AgentDependenciesResponse, AgentDependencyDirection, AgentImpact, AgentImpactResponse,
        ContractBuildError, MAX_PAGE_BYTES, Page, PageByteLimit, PageSize, SuccessEnvelope,
    };
    use depgraph_core::CancellationToken;

    struct StreamingSequence;

    impl Serialize for StreamingSequence {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut sequence = serializer.serialize_seq(None)?;
            for value in 0_u64..1_000_000 {
                sequence.serialize_element(&value)?;
            }
            sequence.end()
        }
    }

    #[test]
    fn bounded_serializer_stops_streaming_values_at_the_hard_limit() {
        let result = bounded_json_value(&StreamingSequence, 128);
        assert!(matches!(result, Err(ResponseMappingError::OutputTooLarge)));
    }

    #[test]
    fn query_modifiers_and_comments_cannot_bypass_redaction() {
        for query in [
            "EXPLAIN SELECT * FROM credentials",
            "ANALYZE MATCH (n) RETURN n",
            "-- audit\nSELECT * FROM credentials",
            "/* audit */ SELECT * FROM credentials",
            "/* first */ /* second */ CALL db.labels()",
        ] {
            assert!(
                looks_like_raw_query(&query.to_ascii_lowercase()),
                "query was not recognized: {query}"
            );
        }
    }

    #[test]
    fn credential_prefixes_are_detected_at_token_boundaries_inside_rendered_conditions() {
        assert!(contains_credential_prefix(
            r#"feature == \"ghp_examplecredential\""#
        ));
        assert!(contains_credential_prefix(
            r#"feature == \"github_pat_examplecredential\""#
        ));
        assert!(!contains_credential_prefix("paragraphp_example"));
        assert!(!contains_credential_prefix("euthanasia"));
    }

    #[test]
    fn aggregate_condition_bytes_are_bounded_before_projection_materialization() {
        let exact = "x".repeat(MAX_PAGE_BYTES as usize);
        validate_aggregate_condition_bytes([exact.as_str()])
            .expect("the exact aggregate byte ceiling is accepted");

        let overflow = "y".repeat(MAX_PAGE_BYTES as usize + 1);
        let error = validate_aggregate_condition_bytes([overflow.as_str()])
            .expect_err("one byte beyond the aggregate ceiling fails closed");
        assert_eq!(error.code(), AgentErrorCode::ResourceExhausted);
    }

    #[test]
    fn credential_field_variants_are_always_sensitive() {
        for field in [
            "x-api-key",
            "secret_key",
            "token",
            "accessToken",
            "AWS_SECRET_ACCESS_KEY",
            "proxy-authorization",
        ] {
            assert!(sensitive_field(field), "field was not redacted: {field}");
        }
    }

    fn page_item(index: u32) -> AgentNode {
        AgentNode::new(
            format!("node-{index}").parse().expect("valid node ID"),
            "module".parse().expect("valid node kind"),
            format!("src/module-{index}.rs")
                .parse()
                .expect("valid locator"),
            None,
            None,
        )
    }

    fn dependency_item(index: usize) -> depgraph_core::query::TraversalPageItem {
        serde_json::from_value(json!({
            "source": {
                "id": format!("node:source-{index}"),
                "kind": "module",
                "locator": format!("module:source-{index}"),
                "display_name": format!("source-{index}"),
                "properties": {}
            },
            "target": {
                "id": format!("node:target-{index}"),
                "kind": "module",
                "locator": format!("module:target-{index}"),
                "display_name": format!("target-{index}"),
                "properties": {}
            },
            "step": {
                "edge": {
                    "id": format!("edge:{index}"),
                    "source": format!("node:source-{index}"),
                    "target": format!("node:target-{index}"),
                    "kind": "imports",
                    "phase": "source",
                    "environment": "host",
                    "profile_id": "profile:test",
                    "resolution_status": "resolved",
                    "precision": "exact",
                    "condition": {"op":"all","conditions":[]},
                    "generated": false
                },
                "condition_text": "all",
                "evidence": [],
                "effective_profile_id": null,
                "correlation_status": null,
                "observed_difference_reasons": [],
                "phase_coverage": {}
            }
        }))
        .expect("valid dependency traversal item")
    }

    fn pagination_context() -> PaginationContext {
        PaginationContext::new(
            &CursorKey::from_bytes([0x52; 32]),
            "graph_impact_get",
            "repository-1"
                .parse::<LogicalRepositoryId>()
                .expect("valid repository ID"),
            "snapshot:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse::<SnapshotId>()
                .expect("valid snapshot ID"),
            &json!({"selector":"id:node:root"}),
        )
        .expect("valid pagination context")
    }

    #[test]
    fn cancellable_digest_is_complete_collection_digest_with_per_item_byte_bounds() {
        let items = vec![page_item(1), page_item(2), page_item(3)];
        let serialized_item_bytes = items
            .iter()
            .map(|item| serde_json::to_vec(item).expect("serialize item").len())
            .collect::<Vec<_>>();
        let per_item_limit = *serialized_item_bytes.iter().max().expect("non-empty items");
        let total_item_bytes: usize = serialized_item_bytes.iter().sum();
        assert!(total_item_bytes > per_item_limit);

        let digest = public_result_digest_bounded_cancellable(
            &items,
            depgraph_core::MAX_INTERACTIVE_QUERY_TRAVERSAL,
            per_item_limit,
            &mut || false,
        )
        .expect("cumulative bytes above one page are valid when each item is bounded");
        assert_eq!(digest, public_result_digest(&items).expect("public digest"));

        let mut checks = 0_usize;
        let cancelled = public_result_digest_bounded_cancellable(
            &items,
            depgraph_core::MAX_INTERACTIVE_QUERY_TRAVERSAL,
            per_item_limit,
            &mut || {
                checks += 1;
                checks >= 2
            },
        )
        .expect_err("digest cancellation must fail closed");
        assert_eq!(cancelled.code(), AgentErrorCode::Cancelled);
    }

    #[test]
    fn dependency_projection_is_count_bounded_and_cancellable_before_partial_output() {
        let canonical_maximum = depgraph_core::MAX_INTERACTIVE_QUERY_TRAVERSAL;
        validate_dependency_item_count(canonical_maximum, canonical_maximum)
            .expect("the exact canonical dependency count is accepted");
        let over = validate_dependency_item_count(canonical_maximum + 1, canonical_maximum)
            .expect_err("the canonical maximum plus one is rejected");
        assert_eq!(over.code(), AgentErrorCode::ResourceExhausted);

        let source = (0..4).map(dependency_item).collect::<Vec<_>>();
        let exact = convert_dependency_items_cancellable(&source[..3], 3, &mut || false)
            .expect("exact dependency count projects");
        assert_eq!(exact.len(), 3);

        let mut over_checks = 0_usize;
        let over = convert_dependency_items_cancellable(&source, 3, &mut || {
            over_checks += 1;
            false
        })
        .expect_err("one dependency above the collection cap fails closed");
        assert_eq!(over.code(), AgentErrorCode::ResourceExhausted);
        assert_eq!(
            over_checks, 0,
            "count guard runs before allocation/conversion"
        );

        let mut conversion_checks = 0_usize;
        let cancelled = convert_dependency_items_cancellable(&source[..3], 3, &mut || {
            conversion_checks += 1;
            conversion_checks >= 3
        })
        .expect_err("cancellation inside AgentEdge conversion returns no vector");
        assert_eq!(cancelled.code(), AgentErrorCode::Cancelled);
        assert_eq!(conversion_checks, 3);
    }

    #[test]
    fn dependency_projection_digest_and_page_selection_are_cancellable() {
        let source = (0..3).map(dependency_item).collect::<Vec<_>>();
        let items = convert_dependency_items_cancellable(&source, 3, &mut || false)
            .expect("dependency conversion");
        let mut digest_checks = 0_usize;
        let cancelled = public_result_digest_bounded_cancellable(
            &items,
            3,
            depgraph_core::DEFAULT_SERVICE_MAX_OUTPUT_BYTES,
            &mut || {
                digest_checks += 1;
                digest_checks >= 2
            },
        )
        .expect_err("dependency digest cancellation fails closed");
        assert_eq!(cancelled.code(), AgentErrorCode::Cancelled);

        let digest = public_result_digest(&items).expect("dependency digest");
        let request = PageRequest::new(
            PageSize::new(3).expect("page size"),
            PageByteLimit::new(16 * 1024).expect("page bytes"),
            None,
        );
        let mut page_checks = 0_usize;
        let cancelled = pagination_context()
            .paginate_with_digest_cancellable(&items, &request, digest, &mut || {
                page_checks += 1;
                page_checks >= 3
            })
            .expect_err("dependency page selection cancellation fails closed");
        assert_eq!(cancelled.code(), AgentErrorCode::Cancelled);
    }

    fn wrapped_dependencies_response(
        context: &PaginationContext,
        items: &[crate::AgentEdge],
        maximum_bytes: u32,
    ) -> Result<AgentDependenciesResponse, crate::AgentError> {
        let total_items = u64::try_from(items.len()).expect("test item count fits u64");
        let root = page_item(10_000);
        let empty_page = empty_projection_page(context, total_items)?;
        let projection_response = AgentDependenciesResponse::new(
            root.clone(),
            AgentDependencyDirection::Outgoing,
            true,
            true,
            total_items,
            empty_page,
        )
        .expect("valid dependency projection shape");
        let mut projection = WrappedPageByteProjection::new(context, projection_response, "edges")?;
        let request = PageRequest::new(
            PageSize::new(10).expect("ten item page"),
            PageByteLimit::new(maximum_bytes).expect("valid test byte limit"),
            None,
        );
        let page = context.paginate_cancellable_with_projection(
            items,
            &request,
            &CancellationToken::new(),
            &mut projection,
        )?;
        AgentDependenciesResponse::new(
            root,
            AgentDependencyDirection::Outgoing,
            true,
            true,
            total_items,
            page,
        )
        .map_err(impact_contract_error)
    }

    fn impact_page_item(index: u32) -> AgentImpact {
        let node = AgentNode::new(
            format!("node-{index}").parse().expect("valid node ID"),
            "module".parse().expect("valid node kind"),
            format!("src/module-{index}.rs")
                .parse()
                .expect("valid locator"),
            Some(
                format!("impact-{index}-{}", "x".repeat(96))
                    .parse()
                    .expect("valid display name"),
            ),
            None,
        );
        AgentImpact::new(node.clone(), 0, node.id().clone(), Vec::new())
            .expect("valid zero-step impact")
    }

    fn wrapped_impact_response(
        context: &PaginationContext,
        items: &[AgentImpact],
        maximum_bytes: u32,
    ) -> Result<AgentImpactResponse, crate::AgentError> {
        let total_items = u64::try_from(items.len()).expect("test item count fits u64");
        let root = page_item(20_000);
        let empty_page = empty_projection_page(context, total_items)?;
        let projection_response =
            AgentImpactResponse::new(root.clone(), total_items > 0, None, empty_page)
                .expect("valid impact projection shape");
        let mut projection =
            WrappedPageByteProjection::new(context, projection_response, "impacts")?;
        let request = PageRequest::new(
            PageSize::new(10).expect("ten item page"),
            PageByteLimit::new(maximum_bytes).expect("valid test byte limit"),
            None,
        );
        let page = context.paginate_cancellable_with_projection(
            items,
            &request,
            &CancellationToken::new(),
            &mut projection,
        )?;
        AgentImpactResponse::new(root, total_items > 0, None, page).map_err(impact_contract_error)
    }

    #[test]
    fn dependency_wrapper_projection_matches_exact_mapper_boundary() {
        let core_items = (0..10).map(dependency_item).collect::<Vec<_>>();
        let items = convert_dependency_items_cancellable(&core_items, 10, &mut || false)
            .expect("dependency conversion");
        let context = pagination_context();
        let complete = AgentDependenciesResponse::new(
            page_item(10_000),
            AgentDependencyDirection::Outgoing,
            true,
            true,
            10,
            Page::new(items.clone(), 10, true, None).expect("complete dependency page"),
        )
        .expect("complete dependency response");
        let mapped = CanonicalResponseMapper::success(&SuccessEnvelope::new(
            context.repository_id.clone(),
            Some(context.snapshot_id.clone()),
            complete,
        ))
        .expect("map complete dependency response");
        let exact_bytes = u32::try_from(mapped.output_bytes()).expect("response fits u32");

        let exact = wrapped_dependencies_response(&context, &items, exact_bytes)
            .expect("exact dependency wrapper boundary fits");
        assert_eq!(exact.edges().returned_items(), 10);
        let exact_mapped = CanonicalResponseMapper::success(&SuccessEnvelope::new(
            context.repository_id.clone(),
            Some(context.snapshot_id.clone()),
            exact,
        ))
        .expect("accepted dependency response maps");
        assert_eq!(exact_mapped.output_bytes(), exact_bytes as usize);

        match wrapped_dependencies_response(&context, &items, exact_bytes - 1) {
            Ok(response) => {
                assert!(response.edges().returned_items() < 10);
                let mapped = CanonicalResponseMapper::success(&SuccessEnvelope::new(
                    context.repository_id.clone(),
                    Some(context.snapshot_id.clone()),
                    response,
                ))
                .expect("smaller dependency response maps");
                assert!(mapped.output_bytes() < exact_bytes as usize);
            }
            Err(error) => assert_eq!(error.code(), AgentErrorCode::ResourceExhausted),
        }
    }

    #[test]
    fn impact_wrapper_projection_matches_exact_mapper_boundary() {
        let items = (0..10).map(impact_page_item).collect::<Vec<_>>();
        let context = pagination_context();
        let complete = AgentImpactResponse::new(
            page_item(20_000),
            true,
            None,
            Page::new(items.clone(), 10, true, None).expect("complete impact page"),
        )
        .expect("complete impact response");
        let mapped = CanonicalResponseMapper::success(&SuccessEnvelope::new(
            context.repository_id.clone(),
            Some(context.snapshot_id.clone()),
            complete,
        ))
        .expect("map complete impact response");
        let exact_bytes = u32::try_from(mapped.output_bytes()).expect("response fits u32");

        let exact = wrapped_impact_response(&context, &items, exact_bytes)
            .expect("exact impact wrapper boundary fits");
        let exact_mapped = CanonicalResponseMapper::success(&SuccessEnvelope::new(
            context.repository_id.clone(),
            Some(context.snapshot_id.clone()),
            exact,
        ))
        .expect("accepted impact response maps");
        assert_eq!(exact_mapped.output_bytes(), exact_bytes as usize);
        assert_eq!(exact_mapped.result().is_error, Some(false));

        match wrapped_impact_response(&context, &items, exact_bytes - 1) {
            Ok(response) => {
                let returned_items = serde_json::to_value(&response)
                    .expect("serialize impact response")
                    .pointer("/impacts/returned_items")
                    .and_then(serde_json::Value::as_u64)
                    .expect("returned impact count");
                assert!(returned_items < 10);
                let mapped = CanonicalResponseMapper::success(&SuccessEnvelope::new(
                    context.repository_id.clone(),
                    Some(context.snapshot_id.clone()),
                    response,
                ))
                .expect("smaller impact response maps");
                assert!(mapped.output_bytes() < exact_bytes as usize);
                assert_eq!(mapped.result().is_error, Some(false));
            }
            Err(error) => assert_eq!(error.code(), AgentErrorCode::ResourceExhausted),
        }
    }

    #[test]
    fn projected_page_bytes_equal_actual_ten_item_envelope_bytes() {
        let items = (0..10).map(page_item).collect::<Vec<_>>();
        let mut item_bytes = 0_usize;
        for item in &items {
            let mut value = bounded_json_value(item, 16 * 1024).expect("bounded item");
            redact_public_value(&mut value);
            item_bytes += canonical_json_bytes(&value).expect("canonical item").len();
        }
        let projected = pagination_context()
            .projected_page_bytes(10, item_bytes, 10, true, None)
            .expect("projected page bytes");
        let page = Page::new(items, 10, true, None).expect("complete ten-item page");
        let mapped = CanonicalResponseMapper::success(&SuccessEnvelope::new(
            pagination_context().repository_id.clone(),
            Some(pagination_context().snapshot_id.clone()),
            page,
        ))
        .expect("map ten-item page");
        assert_eq!(projected, mapped.output_bytes());
    }

    #[test]
    fn pagination_cancellation_during_selection_returns_no_partial_page() {
        let items = vec![page_item(1), page_item(2), page_item(3)];
        let digest = public_result_digest(&items).expect("public digest");
        let request = PageRequest::new(
            PageSize::new(3).expect("valid page size"),
            PageByteLimit::new(16 * 1024).expect("valid byte limit"),
            None,
        );
        let mut checks = 0_usize;
        let page = pagination_context().paginate_with_digest_cancellable(
            &items,
            &request,
            digest,
            &mut || {
                checks += 1;
                checks >= 3
            },
        );
        let error = page.expect_err("page selection cancellation must fail closed");
        assert_eq!(error.code(), AgentErrorCode::Cancelled);
    }

    #[test]
    fn public_projection_caps_map_to_typed_resource_exhausted() {
        for contract_error in [
            ContractBuildError::TooManyEvidenceItems,
            ContractBuildError::TooManyCorrelationReasons,
            ContractBuildError::TooManyPhases,
        ] {
            assert_eq!(
                impact_contract_error(contract_error).code(),
                AgentErrorCode::ResourceExhausted
            );
        }
    }
}
