use std::{
    fmt::{self, Write as _},
    io::{self, Write},
};

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, OsRng, Payload},
};
use depgraph_core::{DepgraphCapability, DepgraphServiceError, RepositoryFileError};
use rmcp::model::CallToolResult;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{
    AgentCapability, AgentCompletedSnapshot, AgentContext, AgentDaemonStatus,
    AgentDependenciesResponse, AgentDoctor, AgentEdge, AgentError, AgentErrorCode,
    AgentErrorDetails, AgentEvidence, AgentNamedSnapshot, AgentNode, AgentNodeSummary,
    AgentPathResponse, AgentPathStep, AgentProfilePlan, AgentRemediation, AgentResourceLimit,
    AgentSite, AgentSnapshot, CanonicalJsonError, Cursor, DurableSubmitResult, ErrorEnvelope,
    LogicalRepositoryId, MAX_PAGE_BYTES, MCP_TOOLS_CONTRACT_VERSION, OperationAccepted, Page,
    PageRequest, SnapshotId, SuccessEnvelope, TaskAccepted, canonical_json_bytes,
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
    AgentSite,
    AgentSnapshot,
    DurableSubmitResult,
    OperationAccepted,
    TaskAccepted,
);
public_page_item!(
    AgentEdge,
    AgentEvidence,
    AgentNamedSnapshot,
    AgentNode,
    AgentNodeSummary,
    AgentPathStep,
    AgentSite,
    AgentSnapshot
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

    pub fn error(envelope: &ErrorEnvelope) -> Result<MappedToolResult, ResponseMappingError> {
        map_envelope(envelope, true, MAX_PAGE_BYTES as usize)
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
        | DepgraphServiceError::GraphQuery { .. } => AgentError::new(
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
        DepgraphServiceError::Conflict => AgentError::new(
            AgentErrorCode::Conflict,
            false,
            AgentRemediation::CorrectInput,
            None,
        ),
        DepgraphServiceError::ResourceExhausted => AgentError::new(
            AgentErrorCode::ResourceExhausted,
            false,
            AgentRemediation::NarrowQuery,
            None,
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
        DepgraphServiceError::ProfilePlanSecurity { .. } | DepgraphServiceError::Integrity => {
            integrity_error()
        }
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
        let total_items = u64::try_from(items.len()).map_err(|_| internal_error(false))?;
        let result_digest = public_result_digest(items)?;
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

        let maximum_items = usize::from(request.max_items().get()).min(remaining.len());
        let maximum_bytes = request.max_bytes().get() as usize;
        let mut item_bytes = 0usize;
        let mut selected = None;

        for (index, item) in remaining.iter().take(maximum_items).enumerate() {
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
        let complete = offset + count == items.len();
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
        || [
            "akia",
            "asia",
            concat!("gh", "p_"),
            "github_pat_",
            "xoxb-",
            "xoxp-",
        ]
        .iter()
        .any(|prefix| trimmed.starts_with(prefix))
        || looks_like_raw_query(trimmed)
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

    use super::{ResponseMappingError, bounded_json_value, looks_like_raw_query, sensitive_field};

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
}
