//! Durable, process-independent operation journal for depgraph Agent work.
//!
//! The journal is deliberately independent from an MCP connection or runner
//! lifetime. It stores only digests for idempotency keys and lease tokens, retains
//! bounded canonical operation input for durable runner recovery, and validates
//! repository identity plus every canonical payload digest whenever an operation
//! crosses the journal boundary.

mod launcher;
mod runner;

pub use depgraph_core::service::{OPERATION_JOURNAL_SUFFIX, RUNNER_PURGE_LOCK_SUFFIX};
pub use launcher::{
    DaemonExecutableLauncher, LaunchedDaemonProcess, LaunchedOperationRunner,
    OPERATION_RUNNER_STARTUP_CONTRACT, OperationRunnerLauncher, RunnerLaunchError,
    RunnerResolutionPolicy,
};
pub use runner::{
    CompletionRecovery, DeferredOperationCompletion, DispatchOutcome, ExecutionCheckpoint,
    ExecutionControl, OperationDispatcher, OperationRunner, RunnerError, RunnerReport,
    RunnerStartupConfig, RunnerWork, ScanOperationDispatcher, UNSUPPORTED_OPERATION_ERROR_JSON,
    UnsupportedOperationDispatcher,
};

use std::{
    fmt,
    fs::{File, OpenOptions},
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use depgraph_core::{
    DepgraphServiceConfig, RUNTIME_TRACE_MAX_EVENTS,
    service::{DEFAULT_SERVICE_MAX_INLINE_INPUT_BYTES, RepositoryRootSeal},
};
use depgraph_mcp_tools::{
    AgentCapability, CapabilityProfile, LogicalRepositoryId, MAX_TASK_TTL_MS, OperationId,
    canonical_json_bytes,
};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, limits::Limit,
    params,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// SQLite schema version owned by this crate.
pub const JOURNAL_SCHEMA_VERSION: i64 = 5;
/// Portable durable-operation record and recovery contract shipped to Agent hosts.
pub const OPERATION_CONTRACT_VERSION: &str = "depgraph-operation-v1";
const LEGACY_JOURNAL_SCHEMA_VERSION: i64 = 1;
const ROOT_BOUND_JOURNAL_SCHEMA_VERSION: i64 = 2;
const COMPLETION_INTENT_JOURNAL_SCHEMA_VERSION: i64 = 3;
const RETENTION_ANCHOR_JOURNAL_SCHEMA_VERSION: i64 = 4;
/// Minimum duration for which a terminal record remains retrievable.
pub const TERMINAL_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1_000;
/// Duration for which a purged operation's identity and idempotency scope remain reserved.
pub const TOMBSTONE_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1_000;
/// Maximum number of units exposed by operation progress.
pub const MAX_PROGRESS_UNITS: u64 = 1_000_000_000;
/// Maximum canonical terminal result or error payload size.
pub const MAX_TERMINAL_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
/// Maximum canonical normalized input retained inline for a durable operation.
///
/// The established 16 MiB closed-payload ceiling safely contains every inline
/// runtime trace admitted by MCP's 1 MiB raw-input boundary after normalization
/// and addition of its durable binding envelope. See the closed derivation below.
pub const MAX_OPERATION_INPUT_BYTES: usize = MAX_TERMINAL_PAYLOAD_BYTES;
/// Maximum canonical capability-set JSON size accepted from durable storage.
pub const MAX_CAPABILITY_JSON_BYTES: usize = 256;
/// Maximum accepted idempotency-key size before hashing.
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 4 * 1024;
/// Maximum accepted lease-token size before hashing.
pub const MAX_LEASE_TOKEN_BYTES: usize = 4 * 1024;
/// Maximum number of rows processed in each purge category by one transaction.
pub const MAX_PURGE_BATCH_SIZE: usize = 256;
/// Canonical non-secret error recorded when purge reaps deadline-expired work.
pub const DEADLINE_EXCEEDED_ERROR_JSON: &str =
    r#"{"code":"operation_execution_deadline_exceeded"}"#;
/// Canonical non-secret terminal error for a project-exec operation whose
/// external execution state cannot be proven after lease loss.
pub const EXECUTION_STATE_UNKNOWN_ERROR_JSON: &str = r#"{"code":"EXECUTION_STATE_UNKNOWN"}"#;

const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TASK_TTL_MS_I64: i64 = MAX_TASK_TTL_MS as i64;
// Runtime trace normalization can only add omitted serde defaults and normalize
// timestamps. Per event, the complete redaction object plus count and separators
// consume 107 bytes; RFC 3339 UTC normalization adds at most 10 bytes, so 128 is
// a closed ceiling. The fixed 512 bytes cover the same session-level defaults
// and timestamps. Stable binding IDs, field names, and punctuation fit within
// the separate 1 KiB envelope. Applying the independent 100,000-event cap is
// deliberately conservative because a 1 MiB raw document cannot contain that
// many valid events.
const MAX_RUNTIME_TRACE_NORMALIZATION_BYTES_PER_EVENT: usize = 128;
const MAX_RUNTIME_TRACE_FIXED_NORMALIZATION_BYTES: usize = 512;
const MAX_RUNTIME_DURABLE_BINDING_ENVELOPE_BYTES: usize = 1024;
const MAX_RUNTIME_IMPORT_NORMALIZED_INPUT_BYTES: usize = DEFAULT_SERVICE_MAX_INLINE_INPUT_BYTES
    + RUNTIME_TRACE_MAX_EVENTS * MAX_RUNTIME_TRACE_NORMALIZATION_BYTES_PER_EVENT
    + MAX_RUNTIME_TRACE_FIXED_NORMALIZATION_BYTES
    + MAX_RUNTIME_DURABLE_BINDING_ENVELOPE_BYTES;
const _: () = assert!(MAX_RUNTIME_IMPORT_NORMALIZED_INPUT_BYTES <= MAX_OPERATION_INPUT_BYTES);
const SQLITE_ALLOCATION_LIMIT_BYTES: usize =
    MAX_TERMINAL_PAYLOAD_BYTES + MAX_OPERATION_INPUT_BYTES + MAX_CAPABILITY_JSON_BYTES + 64 * 1024;
const _: () = assert!(SQLITE_ALLOCATION_LIMIT_BYTES <= i32::MAX as usize);

/// Journal path derived from a service configuration's validated immutable store path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationJournalPath(PathBuf);

impl OperationJournalPath {
    /// Derive a journal path only after `DepgraphServiceConfig` has rejected relative,
    /// parent-traversing, symlinked, or otherwise unsafe graph-store paths.
    #[must_use]
    pub fn from_service_config(config: &DepgraphServiceConfig) -> Self {
        let mut path = config.store_path().as_os_str().to_os_string();
        path.push(OPERATION_JOURNAL_SUFFIX);
        Self(PathBuf::from(path))
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for OperationJournalPath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

/// Derive the deterministic operation-journal path without changing the graph store.
#[must_use]
pub fn operation_journal_path(config: &DepgraphServiceConfig) -> OperationJournalPath {
    OperationJournalPath::from_service_config(config)
}

/// Closed failures produced by the journal. Messages intentionally do not echo
/// supplied keys, lease tokens, payloads, or filesystem paths.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("operation journal input is invalid")]
    InvalidArgument,
    #[error("operation journal schema version is unsupported")]
    UnsupportedSchemaVersion,
    #[error("operation journal integrity validation failed")]
    IntegrityFailure,
    #[error("operation was not found")]
    NotFound,
    #[error("operation is no longer retained")]
    Expired,
    #[error("repository identity does not match the operation")]
    RepositoryMismatch,
    #[error("the current capability set does not authorize the operation")]
    CapabilityDenied,
    #[error("the idempotency key is already bound to different work")]
    IdempotencyConflict,
    #[error("operation has not reached a terminal state")]
    OperationNotReady,
    #[error("operation state transition is invalid")]
    InvalidTransition,
    #[error("operation lease is already held")]
    LeaseHeld,
    #[error("operation lease token does not match")]
    LeaseMismatch,
    #[error("operation lease has expired")]
    LeaseExpired,
    #[error("operation execution deadline has elapsed")]
    DeadlineExceeded,
    #[error("operation request was cancelled")]
    RequestCancelled,
    #[error("operation journal storage failed")]
    Storage(#[source] rusqlite::Error),
    #[error("operation journal filesystem access failed")]
    Io(#[source] std::io::Error),
    #[error("secure operation identifier generation failed")]
    EntropyUnavailable,
}

impl From<rusqlite::Error> for JournalError {
    fn from(source: rusqlite::Error) -> Self {
        Self::Storage(source)
    }
}

impl From<std::io::Error> for JournalError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

/// A SHA-256 digest stored by the journal.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct JournalDigest([u8; 32]);

impl JournalDigest {
    #[must_use]
    pub fn sha256(bytes: impl AsRef<[u8]>) -> Self {
        Self(Sha256::digest(bytes.as_ref()).into())
    }

    pub fn canonical_json(value: &Value) -> Result<Self, JournalError> {
        let bytes = canonical_json_bytes(value).map_err(|_| JournalError::InvalidArgument)?;
        Ok(Self::sha256(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        let mut result = String::with_capacity(64);
        for byte in self.0 {
            use fmt::Write as _;
            write!(&mut result, "{byte:02x}").expect("writing to a String cannot fail");
        }
        result
    }

    fn from_database(bytes: Vec<u8>) -> Result<Self, JournalError> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| JournalError::IntegrityFailure)?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for JournalDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("JournalDigest")
            .field(&self.to_hex())
            .finish()
    }
}

/// Closed durable-submit tools supported by the operation catalog.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OperationKind {
    ScanSubmit,
    RuntimeTraceImportSubmit,
    ExportFile,
    DaemonStartSubmit,
    DaemonStop,
    ResolveBuildSubmit,
}

impl OperationKind {
    pub const ALL: [Self; 6] = [
        Self::ScanSubmit,
        Self::RuntimeTraceImportSubmit,
        Self::ExportFile,
        Self::DaemonStartSubmit,
        Self::DaemonStop,
        Self::ResolveBuildSubmit,
    ];

    pub fn parse(value: impl AsRef<str>) -> Result<Self, JournalError> {
        match value.as_ref() {
            "scan_submit" => Ok(Self::ScanSubmit),
            "runtime_trace_import_submit" => Ok(Self::RuntimeTraceImportSubmit),
            "export_file" => Ok(Self::ExportFile),
            "daemon_start_submit" => Ok(Self::DaemonStartSubmit),
            "daemon_stop" => Ok(Self::DaemonStop),
            "resolve_build_submit" => Ok(Self::ResolveBuildSubmit),
            _ => Err(JournalError::InvalidArgument),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ScanSubmit => "scan_submit",
            Self::RuntimeTraceImportSubmit => "runtime_trace_import_submit",
            Self::ExportFile => "export_file",
            Self::DaemonStartSubmit => "daemon_start_submit",
            Self::DaemonStop => "daemon_stop",
            Self::ResolveBuildSubmit => "resolve_build_submit",
        }
    }

    #[must_use]
    pub const fn capability_profile(self) -> CapabilityProfile {
        match self {
            Self::ScanSubmit | Self::RuntimeTraceImportSubmit => CapabilityProfile::StoreWrite,
            Self::ExportFile => CapabilityProfile::RepositoryWrite,
            Self::DaemonStartSubmit | Self::DaemonStop => CapabilityProfile::DaemonControl,
            Self::ResolveBuildSubmit => CapabilityProfile::ProjectExec,
        }
    }

    pub(crate) const fn requires_runner_cleanup(self) -> bool {
        matches!(
            self,
            Self::ScanSubmit | Self::RuntimeTraceImportSubmit | Self::ExportFile
        )
    }

    fn required_capabilities(self) -> Result<CapabilitySet, JournalError> {
        CapabilitySet::new(
            self.capability_profile()
                .required_capabilities()
                .iter()
                .copied()
                .map(AgentCapability::from),
        )
    }
}

/// Closed, validated runner/worker owner identifier. Lease secrets are separate
/// and are never stored in plaintext.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LeaseOwner(String);

impl LeaseOwner {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, JournalError> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'@' | b'-')
            })
        {
            return Err(JournalError::InvalidArgument);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical set of Agent capabilities, sorted by the closed enum order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilitySet {
    capabilities: Vec<AgentCapability>,
    digest: JournalDigest,
}

impl CapabilitySet {
    pub fn new(
        capabilities: impl IntoIterator<Item = AgentCapability>,
    ) -> Result<Self, JournalError> {
        let mut capabilities: Vec<_> = capabilities.into_iter().collect();
        capabilities.sort_unstable();
        capabilities.dedup();
        let digest = capability_digest(&capabilities)?;
        Ok(Self {
            capabilities,
            digest,
        })
    }

    #[must_use]
    pub fn capabilities(&self) -> &[AgentCapability] {
        &self.capabilities
    }

    #[must_use]
    pub const fn digest(&self) -> JournalDigest {
        self.digest
    }

    #[must_use]
    pub fn contains(&self, capability: AgentCapability) -> bool {
        self.capabilities.binary_search(&capability).is_ok()
    }

    #[must_use]
    pub fn contains_all(&self, required: &Self) -> bool {
        required
            .capabilities
            .iter()
            .all(|capability| self.contains(*capability))
    }

    fn canonical_json(&self) -> Result<String, JournalError> {
        let encoded = canonical_json_string(&self.capabilities)?;
        if encoded.len() > MAX_CAPABILITY_JSON_BYTES {
            return Err(JournalError::InvalidArgument);
        }
        Ok(encoded)
    }

    fn from_database(json: String, stored_digest: Vec<u8>) -> Result<Self, JournalError> {
        if json.len() > MAX_CAPABILITY_JSON_BYTES {
            return Err(JournalError::IntegrityFailure);
        }
        let decoded: Vec<AgentCapability> =
            serde_json::from_str(&json).map_err(|_| JournalError::IntegrityFailure)?;
        let set = Self::new(decoded).map_err(|_| JournalError::IntegrityFailure)?;
        if set.capabilities.is_empty()
            || set
                .canonical_json()
                .map_err(|_| JournalError::IntegrityFailure)?
                != json
            || set.digest != JournalDigest::from_database(stored_digest)?
        {
            return Err(JournalError::IntegrityFailure);
        }
        Ok(set)
    }
}

#[derive(Clone, Copy)]
struct EnabledOperationKinds {
    store_write: bool,
    repository_write: bool,
    daemon_control: bool,
    project_exec: bool,
}

impl EnabledOperationKinds {
    fn new(enabled_capabilities: &CapabilitySet) -> Result<Self, JournalError> {
        Ok(Self {
            store_write: enabled_capabilities
                .contains_all(&OperationKind::ScanSubmit.required_capabilities()?),
            repository_write: enabled_capabilities
                .contains_all(&OperationKind::ExportFile.required_capabilities()?),
            daemon_control: enabled_capabilities
                .contains_all(&OperationKind::DaemonStartSubmit.required_capabilities()?),
            project_exec: enabled_capabilities
                .contains_all(&OperationKind::ResolveBuildSubmit.required_capabilities()?),
        })
    }
}

fn capability_digest(capabilities: &[AgentCapability]) -> Result<JournalDigest, JournalError> {
    let bytes = canonical_json_bytes(capabilities).map_err(|_| JournalError::InvalidArgument)?;
    Ok(JournalDigest::sha256(bytes))
}

/// Canonical, size-bounded normalized input retained for durable execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalInput {
    encoded: String,
    value: Value,
    digest: JournalDigest,
}

impl CanonicalInput {
    pub fn new(value: &Value) -> Result<Self, JournalError> {
        let encoded = canonical_json_string(value)?;
        if encoded.len() > MAX_OPERATION_INPUT_BYTES {
            return Err(JournalError::InvalidArgument);
        }
        let value = serde_json::from_str(&encoded).map_err(|_| JournalError::InvalidArgument)?;
        let digest = JournalDigest::sha256(encoded.as_bytes());
        Ok(Self {
            encoded,
            value,
            digest,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.value
    }

    #[must_use]
    pub const fn digest(&self) -> JournalDigest {
        self.digest
    }

    fn from_database(encoded: String, stored_digest: Vec<u8>) -> Result<Self, JournalError> {
        if encoded.len() > MAX_OPERATION_INPUT_BYTES {
            return Err(JournalError::IntegrityFailure);
        }
        let value = serde_json::from_str(&encoded).map_err(|_| JournalError::IntegrityFailure)?;
        let canonical =
            canonical_json_string(&value).map_err(|_| JournalError::IntegrityFailure)?;
        let digest = JournalDigest::sha256(encoded.as_bytes());
        if canonical != encoded || digest != JournalDigest::from_database(stored_digest)? {
            return Err(JournalError::IntegrityFailure);
        }
        Ok(Self {
            encoded,
            value,
            digest,
        })
    }
}

/// Canonical, size-bounded terminal payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalJson {
    encoded: String,
    value: Value,
}

impl CanonicalJson {
    pub fn new(value: Value) -> Result<Self, JournalError> {
        let encoded = canonical_json_string(&value)?;
        if encoded.len() > MAX_TERMINAL_PAYLOAD_BYTES {
            return Err(JournalError::InvalidArgument);
        }
        Ok(Self { encoded, value })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.value
    }

    fn from_database(encoded: String) -> Result<Self, JournalError> {
        if encoded.len() > MAX_TERMINAL_PAYLOAD_BYTES {
            return Err(JournalError::IntegrityFailure);
        }
        let value = serde_json::from_str(&encoded).map_err(|_| JournalError::IntegrityFailure)?;
        let canonical =
            canonical_json_string(&value).map_err(|_| JournalError::IntegrityFailure)?;
        if canonical != encoded {
            return Err(JournalError::IntegrityFailure);
        }
        Ok(Self { encoded, value })
    }
}

fn canonical_json_string<T: serde::Serialize + ?Sized>(value: &T) -> Result<String, JournalError> {
    let bytes = canonical_json_bytes(value).map_err(|_| JournalError::InvalidArgument)?;
    String::from_utf8(bytes).map_err(|_| JournalError::InvalidArgument)
}

/// Bounded operation progress. The journal rejects regressions and total changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationProgress {
    completed_units: u64,
    total_units: u64,
}

impl OperationProgress {
    pub fn new(completed_units: u64, total_units: u64) -> Result<Self, JournalError> {
        if total_units == 0 || total_units > MAX_PROGRESS_UNITS || completed_units > total_units {
            return Err(JournalError::InvalidArgument);
        }
        Ok(Self {
            completed_units,
            total_units,
        })
    }

    #[must_use]
    pub const fn completed_units(self) -> u64 {
        self.completed_units
    }

    #[must_use]
    pub const fn total_units(self) -> u64 {
        self.total_units
    }
}

/// Canonical journal state. Stdio and process lifetimes are intentionally absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationStatus {
    Queued,
    Running,
    Cancelling,
    Completed,
    Failed,
    Cancelled,
}

impl OperationStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Cancelling => "cancelling",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    #[must_use]
    pub const fn allows_transition_to(self, target: Self) -> bool {
        matches!(
            (self, target),
            (
                Self::Queued,
                Self::Running | Self::Cancelling | Self::Failed
            ) | (
                Self::Running,
                Self::Cancelling | Self::Completed | Self::Failed
            ) | (
                Self::Cancelling,
                Self::Completed | Self::Failed | Self::Cancelled
            )
        )
    }

    fn parse(value: &str) -> Result<Self, JournalError> {
        match value {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "cancelling" => Ok(Self::Cancelling),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(JournalError::IntegrityFailure),
        }
    }
}

/// Durable lease metadata. Only the token digest is represented.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationLease {
    owner: LeaseOwner,
    token_digest: JournalDigest,
    expires_at_ms: i64,
}

impl OperationLease {
    #[must_use]
    pub const fn owner(&self) -> &LeaseOwner {
        &self.owner
    }

    #[must_use]
    pub const fn token_digest(&self) -> JournalDigest {
        self.token_digest
    }

    #[must_use]
    pub const fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }
}

/// Complete validated operation view returned from the journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationRecord {
    operation_id: OperationId,
    repository_id: LogicalRepositoryId,
    kind: OperationKind,
    required_capabilities: CapabilitySet,
    normalized_input: CanonicalInput,
    input_digest: JournalDigest,
    idempotency_key_digest: JournalDigest,
    status: OperationStatus,
    progress: OperationProgress,
    lease: Option<OperationLease>,
    execution_deadline_ms: i64,
    result: Option<CanonicalJson>,
    error: Option<CanonicalJson>,
    created_at_ms: i64,
    updated_at_ms: i64,
    terminal_at_ms: Option<i64>,
    retention_anchor_ms: i64,
    retain_until_ms: i64,
}

impl OperationRecord {
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    #[must_use]
    pub const fn repository_id(&self) -> &LogicalRepositoryId {
        &self.repository_id
    }

    #[must_use]
    pub const fn kind(&self) -> &OperationKind {
        &self.kind
    }

    #[must_use]
    pub const fn required_capabilities(&self) -> &CapabilitySet {
        &self.required_capabilities
    }

    #[must_use]
    pub const fn normalized_input(&self) -> &CanonicalInput {
        &self.normalized_input
    }

    #[must_use]
    pub const fn input_digest(&self) -> JournalDigest {
        self.input_digest
    }

    #[must_use]
    pub const fn idempotency_key_digest(&self) -> JournalDigest {
        self.idempotency_key_digest
    }

    #[must_use]
    pub const fn status(&self) -> OperationStatus {
        self.status
    }

    #[must_use]
    pub const fn progress(&self) -> OperationProgress {
        self.progress
    }

    #[must_use]
    pub const fn lease(&self) -> Option<&OperationLease> {
        self.lease.as_ref()
    }

    #[must_use]
    pub const fn execution_deadline_ms(&self) -> i64 {
        self.execution_deadline_ms
    }

    #[must_use]
    pub const fn result(&self) -> Option<&CanonicalJson> {
        self.result.as_ref()
    }

    #[must_use]
    pub const fn error(&self) -> Option<&CanonicalJson> {
        self.error.as_ref()
    }

    #[must_use]
    pub const fn created_at_ms(&self) -> i64 {
        self.created_at_ms
    }

    #[must_use]
    pub const fn updated_at_ms(&self) -> i64 {
        self.updated_at_ms
    }

    #[must_use]
    pub const fn terminal_at_ms(&self) -> Option<i64> {
        self.terminal_at_ms
    }

    #[must_use]
    pub const fn retain_until_ms(&self) -> i64 {
        self.retain_until_ms
    }
}

/// Canonical submission ready for a transactional operation and handoff insert.
#[derive(Clone, Eq, PartialEq)]
pub struct SubmitRequest {
    repository_id: LogicalRepositoryId,
    repository_binding_digest: JournalDigest,
    kind: OperationKind,
    required_capabilities: CapabilitySet,
    normalized_input: CanonicalInput,
    input_digest: JournalDigest,
    idempotency_key_digest: JournalDigest,
    execution_deadline_ms: i64,
    initial_progress: OperationProgress,
}

impl fmt::Debug for SubmitRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubmitRequest")
            .field("repository_id", &self.repository_id)
            .field("kind", &self.kind)
            .field("required_capabilities", &self.required_capabilities)
            .field("normalized_input", &self.normalized_input)
            .field("input_digest", &self.input_digest)
            .field("idempotency_key_digest", &self.idempotency_key_digest)
            .field("execution_deadline_ms", &self.execution_deadline_ms)
            .field("initial_progress", &self.initial_progress)
            .finish_non_exhaustive()
    }
}

impl SubmitRequest {
    pub fn new(
        config: &DepgraphServiceConfig,
        kind: OperationKind,
        normalized_input: &Value,
        idempotency_key: impl AsRef<[u8]>,
        execution_deadline_ms: i64,
    ) -> Result<Self, JournalError> {
        let root_seal = config.repository_root_seal();
        validate_live_root(&root_seal)?;
        let required = kind.capability_profile().required_capabilities();
        if !config.capabilities().contains_all(required) {
            return Err(JournalError::CapabilityDenied);
        }
        let repository_id = LogicalRepositoryId::parse(config.logical_repository_id())
            .map_err(|_| JournalError::IntegrityFailure)?;
        let required_capabilities = kind.required_capabilities()?;
        let idempotency_key = idempotency_key.as_ref();
        validate_secret_input(idempotency_key, MAX_IDEMPOTENCY_KEY_BYTES)?;
        let normalized_input = CanonicalInput::new(normalized_input)?;
        Ok(Self {
            repository_id,
            repository_binding_digest: JournalDigest(root_seal.binding_digest()),
            kind,
            required_capabilities,
            input_digest: normalized_input.digest(),
            normalized_input,
            idempotency_key_digest: JournalDigest::sha256(idempotency_key),
            execution_deadline_ms,
            initial_progress: OperationProgress::new(0, 1)?,
        })
    }

    pub fn with_progress_total(mut self, total_units: u64) -> Result<Self, JournalError> {
        self.initial_progress = OperationProgress::new(0, total_units)?;
        Ok(self)
    }

    #[must_use]
    pub const fn repository_id(&self) -> &LogicalRepositoryId {
        &self.repository_id
    }

    #[must_use]
    pub const fn kind(&self) -> &OperationKind {
        &self.kind
    }

    #[must_use]
    pub const fn required_capabilities(&self) -> &CapabilitySet {
        &self.required_capabilities
    }

    #[must_use]
    pub const fn normalized_input(&self) -> &CanonicalInput {
        &self.normalized_input
    }

    #[must_use]
    pub const fn input_digest(&self) -> JournalDigest {
        self.input_digest
    }

    #[must_use]
    pub const fn idempotency_key_digest(&self) -> JournalDigest {
        self.idempotency_key_digest
    }
}

/// Validated durable work handoff. It contains no transport, session, or
/// process owner; claim and completion times describe only journal lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerHandoff {
    operation_id: OperationId,
    operation_kind: OperationKind,
    payload: CanonicalInput,
    payload_digest: JournalDigest,
    enqueued_at_ms: i64,
    claimed_at_ms: Option<i64>,
    completed_at_ms: Option<i64>,
}

/// One atomically claimed operation and its validated durable runner handoff.
///
/// This is an internal Rust service boundary: it is deliberately a single
/// closed pair, not an Agent-facing operation enumeration surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedRunnerHandoff {
    record: OperationRecord,
    handoff: RunnerHandoff,
}

impl ClaimedRunnerHandoff {
    #[must_use]
    pub const fn record(&self) -> &OperationRecord {
        &self.record
    }

    #[must_use]
    pub const fn handoff(&self) -> &RunnerHandoff {
        &self.handoff
    }

    #[must_use]
    pub fn into_parts(self) -> (OperationRecord, RunnerHandoff) {
        (self.record, self.handoff)
    }
}

impl RunnerHandoff {
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    #[must_use]
    pub const fn operation_kind(&self) -> OperationKind {
        self.operation_kind
    }

    #[must_use]
    pub const fn payload(&self) -> &CanonicalInput {
        &self.payload
    }

    #[must_use]
    pub const fn payload_digest(&self) -> JournalDigest {
        self.payload_digest
    }

    #[must_use]
    pub const fn enqueued_at_ms(&self) -> i64 {
        self.enqueued_at_ms
    }

    #[must_use]
    pub const fn claimed_at_ms(&self) -> Option<i64> {
        self.claimed_at_ms
    }

    #[must_use]
    pub const fn completed_at_ms(&self) -> Option<i64> {
        self.completed_at_ms
    }
}

/// Result of submit, including whether this caller created the durable work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmitOutcome {
    record: OperationRecord,
    created: bool,
}

impl SubmitOutcome {
    #[must_use]
    pub const fn record(&self) -> &OperationRecord {
        &self.record
    }

    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        self.record.operation_id()
    }

    #[must_use]
    pub const fn created(&self) -> bool {
        self.created
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelOutcome {
    Requested,
    AlreadyRequested,
    TerminalNoOp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionDecision {
    Committed,
    CancellationWon,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionIntent {
    operation_id: OperationId,
    kind: OperationKind,
    normalized_input: CanonicalInput,
    result: CanonicalJson,
    decided_at_ms: i64,
}

impl CompletionIntent {
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    #[must_use]
    pub const fn kind(&self) -> OperationKind {
        self.kind
    }

    #[must_use]
    pub const fn normalized_input(&self) -> &CanonicalInput {
        &self.normalized_input
    }

    #[must_use]
    pub const fn result(&self) -> &CanonicalJson {
        &self.result
    }

    #[must_use]
    pub const fn decided_at_ms(&self) -> i64 {
        self.decided_at_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationOutcome {
    Completed(CanonicalJson),
    Failed(CanonicalJson),
    Cancelled,
}

/// Closed timestamps exposed by the operation manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationTimestamps {
    created_at_ms: i64,
    updated_at_ms: i64,
    terminal_at_ms: Option<i64>,
}

impl OperationTimestamps {
    #[must_use]
    pub const fn created_at_ms(self) -> i64 {
        self.created_at_ms
    }

    #[must_use]
    pub const fn updated_at_ms(self) -> i64 {
        self.updated_at_ms
    }

    #[must_use]
    pub const fn terminal_at_ms(self) -> Option<i64> {
        self.terminal_at_ms
    }
}

/// Closed execution and retention bounds exposed by the operation manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationRetention {
    execution_deadline_ms: i64,
    retain_until_ms: i64,
}

impl OperationRetention {
    #[must_use]
    pub const fn execution_deadline_ms(self) -> i64 {
        self.execution_deadline_ms
    }

    #[must_use]
    pub const fn retain_until_ms(self) -> i64 {
        self.retain_until_ms
    }
}

/// Agent-safe operation state. Raw input, digests, leases, and handoff data are
/// intentionally absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationView {
    operation_id: OperationId,
    status: OperationStatus,
    progress: OperationProgress,
    timestamps: OperationTimestamps,
    retention: OperationRetention,
}

impl OperationView {
    fn from_record(record: &OperationRecord) -> Self {
        Self {
            operation_id: record.operation_id.clone(),
            status: record.status,
            progress: record.progress,
            timestamps: OperationTimestamps {
                created_at_ms: record.created_at_ms,
                updated_at_ms: record.updated_at_ms,
                terminal_at_ms: record.terminal_at_ms,
            },
            retention: OperationRetention {
                execution_deadline_ms: record.execution_deadline_ms,
                retain_until_ms: record.retain_until_ms,
            },
        }
    }

    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    #[must_use]
    pub const fn status(&self) -> OperationStatus {
        self.status
    }

    #[must_use]
    pub const fn progress(&self) -> OperationProgress {
        self.progress
    }

    #[must_use]
    pub const fn timestamps(&self) -> OperationTimestamps {
        self.timestamps
    }

    #[must_use]
    pub const fn retention(&self) -> OperationRetention {
        self.retention
    }
}

/// Closed submission handle returned only after the journal transaction commits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationHandle {
    operation: OperationView,
    created: bool,
}

impl OperationHandle {
    fn from_submit_outcome(outcome: SubmitOutcome) -> Self {
        Self {
            operation: OperationView::from_record(&outcome.record),
            created: outcome.created,
        }
    }

    #[must_use]
    pub const fn operation(&self) -> &OperationView {
        &self.operation
    }

    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        self.operation.operation_id()
    }

    #[must_use]
    pub const fn status(&self) -> OperationStatus {
        self.operation.status()
    }

    #[must_use]
    pub const fn progress(&self) -> OperationProgress {
        self.operation.progress()
    }

    #[must_use]
    pub const fn timestamps(&self) -> OperationTimestamps {
        self.operation.timestamps()
    }

    #[must_use]
    pub const fn retention(&self) -> OperationRetention {
        self.operation.retention()
    }

    #[must_use]
    pub const fn created(&self) -> bool {
        self.created
    }
}

/// Existing immutable input binding for an idempotent submission scope.
/// Callers use this before resolving dynamic selectors, then revalidate the
/// request against the originally pinned input before submitting it unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExistingSubmissionBinding {
    normalized_input: CanonicalInput,
}

impl ExistingSubmissionBinding {
    #[must_use]
    pub const fn normalized_input(&self) -> &CanonicalInput {
        &self.normalized_input
    }
}

/// Closed terminal result paired with the validated operation state used to
/// resolve it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationResultView {
    operation: OperationView,
    operation_kind: OperationKind,
    outcome: OperationOutcome,
}

impl OperationResultView {
    #[must_use]
    pub const fn operation(&self) -> &OperationView {
        &self.operation
    }

    /// Originating durable submit kind used to validate the stored terminal
    /// payload against the corresponding closed tool contract.
    #[must_use]
    pub const fn operation_kind(&self) -> OperationKind {
        self.operation_kind
    }

    #[must_use]
    pub const fn outcome(&self) -> &OperationOutcome {
        &self.outcome
    }
}

fn terminal_outcome(record: OperationRecord) -> Result<OperationOutcome, JournalError> {
    match record.status {
        OperationStatus::Completed => Ok(OperationOutcome::Completed(
            record.result.ok_or(JournalError::IntegrityFailure)?,
        )),
        OperationStatus::Failed => Ok(OperationOutcome::Failed(
            record.error.ok_or(JournalError::IntegrityFailure)?,
        )),
        OperationStatus::Cancelled => Ok(OperationOutcome::Cancelled),
        OperationStatus::Queued | OperationStatus::Running | OperationStatus::Cancelling => {
            Err(JournalError::OperationNotReady)
        }
    }
}

enum FinishPayload {
    Completed(CanonicalJson),
    Failed(CanonicalJson),
    Cancelled,
}

impl FinishPayload {
    const fn status(&self) -> OperationStatus {
        match self {
            Self::Completed(_) => OperationStatus::Completed,
            Self::Failed(_) => OperationStatus::Failed,
            Self::Cancelled => OperationStatus::Cancelled,
        }
    }

    fn into_columns(self) -> (Option<CanonicalJson>, Option<CanonicalJson>) {
        match self {
            Self::Completed(result) => (Some(result), None),
            Self::Failed(error) => (None, Some(error)),
            Self::Cancelled => (None, None),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PurgeReport {
    reaped_operations: u64,
    purged_operations: u64,
    created_tombstones: u64,
    purged_tombstones: u64,
    more_work: bool,
}

impl PurgeReport {
    #[must_use]
    pub const fn reaped_operations(self) -> u64 {
        self.reaped_operations
    }

    #[must_use]
    pub const fn purged_operations(self) -> u64 {
        self.purged_operations
    }

    #[must_use]
    pub const fn created_tombstones(self) -> u64 {
        self.created_tombstones
    }

    #[must_use]
    pub const fn purged_tombstones(self) -> u64 {
        self.purged_tombstones
    }

    #[must_use]
    pub const fn more_work(self) -> bool {
        self.more_work
    }
}

/// SQLite-backed durable journal. It contains no transport or process ownership.
pub struct OperationJournal {
    path: PathBuf,
    connection: Connection,
    repository_id: LogicalRepositoryId,
    enabled_capabilities: CapabilitySet,
    repository_root_seal: RepositoryRootSeal,
    has_retention_anchor: bool,
}

pub(crate) struct RunnerPurgeGuard {
    _file: File,
}

fn runner_purge_lock_path(journal_path: &Path) -> PathBuf {
    let mut path = journal_path.as_os_str().to_os_string();
    path.push(RUNNER_PURGE_LOCK_SUFFIX);
    PathBuf::from(path)
}

fn try_acquire_runner_purge_guard(
    journal_path: &Path,
) -> Result<Option<RunnerPurgeGuard>, JournalError> {
    try_acquire_runner_purge_guard_after_validation(journal_path, |_| Ok(()))
}

fn try_acquire_runner_purge_guard_after_validation(
    journal_path: &Path,
    after_validation: impl FnOnce(&Path) -> Result<(), JournalError>,
) -> Result<Option<RunnerPurgeGuard>, JournalError> {
    let lock_path = runner_purge_lock_path(journal_path);
    if let Ok(metadata) = std::fs::symlink_metadata(&lock_path)
        && !metadata.file_type().is_file()
    {
        return Err(JournalError::IntegrityFailure);
    }
    after_validation(&lock_path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        options
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(&lock_path)?;
    let opened_metadata = file.metadata()?;
    let path_metadata = std::fs::symlink_metadata(&lock_path)?;
    if !opened_metadata.file_type().is_file() || !path_metadata.file_type().is_file() {
        return Err(JournalError::IntegrityFailure);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if opened_metadata.dev() != path_metadata.dev()
            || opened_metadata.ino() != path_metadata.ino()
        {
            return Err(JournalError::IntegrityFailure);
        }
    }
    match file.try_lock() {
        Ok(()) => Ok(Some(RunnerPurgeGuard { _file: file })),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(error)) => Err(error.into()),
    }
}

#[cfg(all(test, unix))]
mod runner_purge_lock_tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn runner_purge_lock_open_does_not_follow_a_post_validation_symlink() {
        let repository = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let journal_path = repository.path().join("graph.operations.sqlite");
        let lock_path = runner_purge_lock_path(&journal_path);
        let outside_target = outside.path().join("must-not-be-created");
        std::fs::write(&lock_path, b"validated-lock").unwrap();

        let result =
            try_acquire_runner_purge_guard_after_validation(&journal_path, |validated_lock_path| {
                std::fs::remove_file(validated_lock_path)?;
                symlink(&outside_target, validated_lock_path)?;
                Ok(())
            });

        assert!(result.is_err());
        assert!(!outside_target.exists());
    }
}

impl OperationJournal {
    /// Open the journal associated with the configuration's validated graph-store path.
    pub fn open(config: &DepgraphServiceConfig) -> Result<Self, JournalError> {
        let root_seal = config.repository_root_seal();
        Self::open_with_root_seal(config, &root_seal)
    }

    fn open_with_root_seal(
        config: &DepgraphServiceConfig,
        root_seal: &RepositoryRootSeal,
    ) -> Result<Self, JournalError> {
        if !root_seal.matches_live_root() {
            return Err(JournalError::RepositoryMismatch);
        }
        let repository_id = LogicalRepositoryId::parse(config.logical_repository_id())
            .map_err(|_| JournalError::IntegrityFailure)?;
        let enabled_capabilities =
            CapabilitySet::new(config.capabilities().iter().map(Into::into))?;
        let journal = Self::open_at(
            operation_journal_path(config),
            repository_id,
            enabled_capabilities,
            root_seal.clone(),
        )?;
        if !root_seal.matches_live_root() {
            return Err(JournalError::RepositoryMismatch);
        }
        Ok(journal)
    }

    fn open_existing_read_only_with_root_seal(
        config: &DepgraphServiceConfig,
        root_seal: &RepositoryRootSeal,
    ) -> Result<Option<Self>, JournalError> {
        if !root_seal.matches_live_root() {
            return Err(JournalError::RepositoryMismatch);
        }
        let repository_id = LogicalRepositoryId::parse(config.logical_repository_id())
            .map_err(|_| JournalError::IntegrityFailure)?;
        let enabled_capabilities =
            CapabilitySet::new(config.capabilities().iter().map(Into::into))?;
        let path = operation_journal_path(config).as_path().to_path_buf();
        match std::fs::symlink_metadata(&path) {
            Ok(metadata)
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() =>
            {
                return Err(JournalError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "operation journal entry must be a regular file",
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(JournalError::Io(error)),
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(&path, flags)?;
        validate_journal_entry(&path)?;
        let allocation_limit = i32::try_from(SQLITE_ALLOCATION_LIMIT_BYTES)
            .map_err(|_| JournalError::IntegrityFailure)?;
        connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, allocation_limit)?;
        if connection.limit(Limit::SQLITE_LIMIT_LENGTH)? != allocation_limit {
            return Err(JournalError::IntegrityFailure);
        }
        connection.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA query_only = ON;",
        )?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let journal = Self {
            path,
            connection,
            repository_id,
            enabled_capabilities,
            repository_root_seal: root_seal.clone(),
            has_retention_anchor: version >= RETENTION_ANCHOR_JOURNAL_SCHEMA_VERSION,
        };
        journal.validate_supported_read_only()?;
        if !root_seal.matches_live_root() {
            return Err(JournalError::RepositoryMismatch);
        }
        Ok(Some(journal))
    }

    fn open_at(
        path: impl AsRef<Path>,
        repository_id: LogicalRepositoryId,
        enabled_capabilities: CapabilitySet,
        repository_root_seal: RepositoryRootSeal,
    ) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        validate_journal_entry(&path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(&path, flags)?;
        validate_journal_entry(&path)?;
        let allocation_limit = i32::try_from(SQLITE_ALLOCATION_LIMIT_BYTES)
            .map_err(|_| JournalError::IntegrityFailure)?;
        connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, allocation_limit)?;
        if connection.limit(Limit::SQLITE_LIMIT_LENGTH)? != allocation_limit {
            return Err(JournalError::IntegrityFailure);
        }
        connection.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;",
        )?;
        validate_connection_integrity(&connection)?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;",
        )?;
        let mut journal = Self {
            path,
            connection,
            repository_id,
            enabled_capabilities,
            repository_root_seal,
            has_retention_anchor: true,
        };
        journal.initialize_schema()?;
        journal.validate()?;
        Ok(journal)
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn try_acquire_runner_purge_guard(
        &self,
    ) -> Result<Option<RunnerPurgeGuard>, JournalError> {
        try_acquire_runner_purge_guard(&self.path)
    }

    pub fn schema_version(&self) -> Result<i64, JournalError> {
        let transaction = self.connection.unchecked_transaction()?;
        self.validate_transaction_root(&transaction)?;
        let version = transaction.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        commit_authorized(transaction, &self.repository_root_seal)?;
        Ok(version)
    }

    /// Validate SQLite integrity, the exact current schema, root binding, and all durable rows.
    pub fn validate(&self) -> Result<(), JournalError> {
        let transaction = self.connection.unchecked_transaction()?;
        self.validate_transaction_root(&transaction)?;
        validate_connection_integrity(&transaction)?;
        validate_schema(&transaction)?;
        validate_foreign_keys(&transaction)?;
        validate_no_operation_tombstone_overlap(&transaction)?;
        validate_operation_handoff_cardinality(&transaction)?;
        validate_journal_rows(&transaction, &self.repository_id, true, true)?;
        commit_authorized(transaction, &self.repository_root_seal)?;
        Ok(())
    }

    /// Validate a supported root-bound schema without changing it. Runtime
    /// submit prevalidation uses this view before ordinary writable open is
    /// authorized to migrate a genuine v2 or v3 journal to v4.
    fn validate_supported_read_only(&self) -> Result<(), JournalError> {
        let transaction = self.connection.unchecked_transaction()?;
        self.validate_transaction_root(&transaction)?;
        validate_connection_integrity(&transaction)?;
        let version: i64 = transaction.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let include_completion_intents = match version {
            ROOT_BOUND_JOURNAL_SCHEMA_VERSION => {
                validate_v2_schema(&transaction)?;
                false
            }
            COMPLETION_INTENT_JOURNAL_SCHEMA_VERSION => {
                validate_v3_schema(&transaction)?;
                true
            }
            RETENTION_ANCHOR_JOURNAL_SCHEMA_VERSION => {
                validate_v4_schema(&transaction)?;
                true
            }
            JOURNAL_SCHEMA_VERSION => {
                validate_schema(&transaction)?;
                true
            }
            _ => return Err(JournalError::UnsupportedSchemaVersion),
        };
        validate_foreign_keys(&transaction)?;
        validate_no_operation_tombstone_overlap(&transaction)?;
        validate_operation_handoff_cardinality(&transaction)?;
        validate_journal_rows(
            &transaction,
            &self.repository_id,
            include_completion_intents,
            self.has_retention_anchor,
        )?;
        commit_authorized(transaction, &self.repository_root_seal)?;
        Ok(())
    }

    /// Atomically create or resolve an idempotent operation.
    pub fn submit(
        &mut self,
        request: &SubmitRequest,
        now_ms: i64,
    ) -> Result<SubmitOutcome, JournalError> {
        validate_timestamp(now_ms)?;
        self.submit_with_clock(request, || now_ms)
    }

    /// Atomically create or resolve an idempotent operation, sampling the
    /// supplied clock only after the IMMEDIATE transaction owns its snapshot.
    pub fn submit_with_clock<F>(
        &mut self,
        request: &SubmitRequest,
        now_ms: F,
    ) -> Result<SubmitOutcome, JournalError>
    where
        F: FnOnce() -> i64,
    {
        self.validate_submit_request(request)?;
        let required_capabilities_json = request.required_capabilities.canonical_json()?;
        let repository_id = self.repository_id.clone();
        let enabled_capabilities = self.enabled_capabilities.clone();
        let root_seal = self.repository_root_seal.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_transaction_root(&transaction, &root_seal)?;
        let now_ms = now_ms();
        validate_timestamp(now_ms)?;
        validate_submit_request_authority(
            request,
            &repository_id,
            &enabled_capabilities,
            &root_seal,
        )?;

        if let Some(raw) = select_operation_by_scope(
            &transaction,
            request.repository_id.as_str(),
            request.kind.as_str(),
            request.idempotency_key_digest,
        )? {
            let record = validated_record(&transaction, raw)?;
            validate_record_not_from_future(&record, now_ms)?;
            validate_repository(&record, &request.repository_id)?;
            validate_submission_binding(&record, request)?;
            if now_ms >= record.retain_until_ms {
                return Err(JournalError::Expired);
            }
            commit_authorized(transaction, &root_seal)?;
            return Ok(SubmitOutcome {
                record,
                created: false,
            });
        }

        if let Some(tombstone) = select_tombstone_by_scope(
            &transaction,
            request.repository_id.as_str(),
            request.kind.as_str(),
            request.idempotency_key_digest,
        )? {
            validate_tombstone(&tombstone)?;
            if tombstone.idempotency_key_digest != request.idempotency_key_digest {
                return Err(JournalError::IntegrityFailure);
            }
            if now_ms < tombstone.tombstone_until_ms {
                if tombstone.input_digest != request.input_digest
                    || tombstone.required_capabilities_digest
                        != request.required_capabilities.digest
                {
                    return Err(JournalError::IdempotencyConflict);
                }
                return Err(JournalError::Expired);
            }
            transaction.execute(
                "DELETE FROM operation_tombstones WHERE operation_id = ?1",
                params![tombstone.operation_id],
            )?;
        }

        if request.execution_deadline_ms <= now_ms {
            return Err(JournalError::InvalidArgument);
        }
        let retain_until_ms = checked_add(request.execution_deadline_ms, TERMINAL_RETENTION_MS)?;
        let maximum_retain_until_ms = checked_add(now_ms, MAX_TASK_TTL_MS_I64)?;
        if retain_until_ms > maximum_retain_until_ms {
            return Err(JournalError::InvalidArgument);
        }

        let operation_id = new_operation_id()?;
        transaction.execute(
            "INSERT INTO operations (
                operation_id, repository_id, kind,
                required_capabilities_json, required_capabilities_digest,
                input_json, input_digest, idempotency_key_digest, status,
                progress_completed, progress_total,
                lease_owner, lease_token_digest, lease_expires_at_ms,
                execution_deadline_ms, result_json, error_json,
                created_at_ms, updated_at_ms, terminal_at_ms,
                retention_anchor_ms, retain_until_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9, ?10,
                NULL, NULL, NULL, ?11, NULL, NULL, ?12, ?12, NULL, ?11, ?13
             )",
            params![
                operation_id.as_str(),
                request.repository_id.as_str(),
                request.kind.as_str(),
                required_capabilities_json,
                request.required_capabilities.digest.as_bytes().as_slice(),
                request.normalized_input.as_str(),
                request.input_digest.as_bytes().as_slice(),
                request.idempotency_key_digest.as_bytes().as_slice(),
                u64_to_i64(request.initial_progress.completed_units)?,
                u64_to_i64(request.initial_progress.total_units)?,
                request.execution_deadline_ms,
                now_ms,
                retain_until_ms,
            ],
        )?;
        transaction.execute(
            "INSERT INTO runner_handoffs (
                operation_id, operation_kind, payload_json, payload_digest,
                enqueued_at_ms, claimed_at_ms, completed_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL)",
            params![
                operation_id.as_str(),
                request.kind.as_str(),
                request.normalized_input.as_str(),
                request.input_digest.as_bytes().as_slice(),
                now_ms,
            ],
        )?;
        let raw = select_operation_by_id(&transaction, operation_id.as_str())?
            .ok_or(JournalError::IntegrityFailure)?;
        let record = validated_record(&transaction, raw)?;
        commit_authorized(transaction, &root_seal)?;
        Ok(SubmitOutcome {
            record,
            created: true,
        })
    }

    pub fn get(
        &self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        now_ms: i64,
    ) -> Result<OperationRecord, JournalError> {
        validate_timestamp(now_ms)?;
        self.get_with_clock(repository_id, operation_id, || now_ms)
    }

    /// Read one operation using a timestamp sampled after the transaction has
    /// fixed its SQLite snapshot.
    pub fn get_with_clock<F>(
        &self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        now_ms: F,
    ) -> Result<OperationRecord, JournalError>
    where
        F: FnOnce() -> i64,
    {
        self.validate_requested_repository(repository_id)?;
        let transaction = self.connection.unchecked_transaction()?;
        self.validate_transaction_root(&transaction)?;
        let now_ms = now_ms();
        validate_timestamp(now_ms)?;
        let record = load_record_or_tombstone(&transaction, repository_id, operation_id, now_ms)?;
        self.validate_record_repository(&record)?;
        commit_authorized(transaction, &self.repository_root_seal)?;
        Ok(record)
    }

    /// Recover a validated durable runner handoff by repository identity and
    /// operation ID. This read-only API carries no session or process ownership.
    pub fn runner_handoff(
        &self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        now_ms: i64,
    ) -> Result<RunnerHandoff, JournalError> {
        validate_timestamp(now_ms)?;
        self.validate_requested_repository(repository_id)?;
        let transaction = self.connection.unchecked_transaction()?;
        self.validate_transaction_root(&transaction)?;
        let record = load_record_or_tombstone(&transaction, repository_id, operation_id, now_ms)?;
        self.validate_record_repository(&record)?;
        validate_enabled_capabilities(&self.enabled_capabilities, &record)?;
        let raw = select_handoff_by_id(&transaction, operation_id.as_str())?
            .ok_or(JournalError::IntegrityFailure)?;
        let handoff = decode_handoff(raw)?;
        validate_operation_handoff(&record, &handoff)?;
        commit_authorized(transaction, &self.repository_root_seal)?;
        Ok(handoff)
    }

    /// Atomically claim the next recoverable runner handoff without requiring
    /// the caller to know an operation ID.
    ///
    /// Selection and lease mutation share one IMMEDIATE transaction. At most
    /// one queued operation or running/cancelling operation with an expired
    /// lease is selected, in `(created_at_ms, operation_id)` order.
    pub fn claim_next_runner_handoff(
        &mut self,
        repository_id: &LogicalRepositoryId,
        owner: &LeaseOwner,
        lease_token: impl AsRef<[u8]>,
        now_ms: i64,
        lease_expires_at_ms: i64,
    ) -> Result<Option<ClaimedRunnerHandoff>, JournalError> {
        validate_timestamp(now_ms)?;
        validate_timestamp(lease_expires_at_ms)?;
        self.validate_requested_repository(repository_id)?;
        if lease_expires_at_ms <= now_ms {
            return Err(JournalError::InvalidArgument);
        }
        let token_digest = digest_lease_token(lease_token.as_ref())?;
        let enabled_capabilities = self.enabled_capabilities.clone();
        let enabled_kinds = EnabledOperationKinds::new(&enabled_capabilities)?;
        let root_seal = self.repository_root_seal.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_transaction_root(&transaction, &root_seal)?;
        if enabled_kinds.project_exec {
            fail_lost_project_exec_leases(&transaction, repository_id, now_ms)?;
        }
        let Some(raw) = select_next_claim_candidate(
            &transaction,
            repository_id.as_str(),
            now_ms,
            enabled_kinds,
        )?
        else {
            commit_authorized(transaction, &root_seal)?;
            return Ok(None);
        };
        let record = validated_record(&transaction, raw)?;
        validate_repository(&record, repository_id)?;
        validate_enabled_capabilities(&enabled_capabilities, &record)?;
        validate_update_time(&record, now_ms)?;
        let lease_expires_at_ms = lease_expires_at_ms.min(record.execution_deadline_ms);
        validate_lease_window(&record, now_ms, lease_expires_at_ms)?;
        if record.status.is_terminal()
            || (record.status == OperationStatus::Queued && record.lease.is_some())
            || (record.status != OperationStatus::Queued
                && record
                    .lease
                    .as_ref()
                    .is_some_and(|lease| lease.expires_at_ms > now_ms))
        {
            return Err(JournalError::IntegrityFailure);
        }
        let status = if record.status == OperationStatus::Queued {
            OperationStatus::Running
        } else {
            record.status
        };
        if status != record.status && !record.status.allows_transition_to(status) {
            return Err(JournalError::InvalidTransition);
        }
        let updated = transaction.execute(
            "UPDATE operations
             SET status = ?1, lease_owner = ?2, lease_token_digest = ?3,
                 lease_expires_at_ms = ?4, updated_at_ms = ?5
             WHERE operation_id = ?6 AND status = ?7",
            params![
                status.as_str(),
                owner.as_str(),
                token_digest.as_bytes().as_slice(),
                lease_expires_at_ms,
                now_ms,
                record.operation_id.as_str(),
                record.status.as_str(),
            ],
        )?;
        if updated != 1 {
            return Err(JournalError::IntegrityFailure);
        }
        let claimed_handoff = transaction.execute(
            "UPDATE runner_handoffs
             SET claimed_at_ms = COALESCE(claimed_at_ms, ?1)
             WHERE operation_id = ?2",
            params![now_ms, record.operation_id.as_str()],
        )?;
        if claimed_handoff != 1 {
            return Err(JournalError::IntegrityFailure);
        }
        let record = select_validated_by_id(&transaction, &record.operation_id)?;
        let raw_handoff = select_handoff_by_id(&transaction, record.operation_id.as_str())?
            .ok_or(JournalError::IntegrityFailure)?;
        let handoff = decode_handoff(raw_handoff)?;
        validate_operation_handoff(&record, &handoff)?;
        commit_authorized(transaction, &root_seal)?;
        Ok(Some(ClaimedRunnerHandoff { record, handoff }))
    }

    pub fn result(
        &self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        now_ms: i64,
    ) -> Result<OperationOutcome, JournalError> {
        let outcome = terminal_outcome(self.get(repository_id, operation_id, now_ms)?)?;
        self.validate_live_root()?;
        Ok(outcome)
    }

    /// Record cooperative cancellation. Terminal and already-cancelling states
    /// are successful no-ops and do not change timestamps, leases, or payloads.
    pub fn cancel(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        current_capabilities: &CapabilitySet,
        now_ms: i64,
    ) -> Result<CancelOutcome, JournalError> {
        validate_timestamp(now_ms)?;
        self.cancel_with_clock(repository_id, operation_id, current_capabilities, || now_ms)
    }

    /// Cancel using a timestamp sampled after the IMMEDIATE transaction owns
    /// its validated snapshot.
    pub fn cancel_with_clock<C>(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        current_capabilities: &CapabilitySet,
        now_ms: C,
    ) -> Result<CancelOutcome, JournalError>
    where
        C: FnOnce() -> i64,
    {
        self.cancel_if_with_clock(
            repository_id,
            operation_id,
            current_capabilities,
            now_ms,
            || true,
        )
    }

    /// Record cooperative cancellation only if the caller still wants the
    /// mutation after authorization and transaction acquisition complete.
    pub fn cancel_if<F>(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        current_capabilities: &CapabilitySet,
        now_ms: i64,
        should_commit: F,
    ) -> Result<CancelOutcome, JournalError>
    where
        F: FnOnce() -> bool,
    {
        validate_timestamp(now_ms)?;
        self.cancel_if_with_clock(
            repository_id,
            operation_id,
            current_capabilities,
            || now_ms,
            should_commit,
        )
    }

    /// Conditionally cancel with both the clock and final mutation predicate
    /// evaluated at the journal transaction boundary.
    pub fn cancel_if_with_clock<C, F>(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        current_capabilities: &CapabilitySet,
        now_ms: C,
        should_commit: F,
    ) -> Result<CancelOutcome, JournalError>
    where
        C: FnOnce() -> i64,
        F: FnOnce() -> bool,
    {
        self.validate_requested_repository(repository_id)?;
        let enabled_capabilities = self.enabled_capabilities.clone();
        let root_seal = self.repository_root_seal.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_transaction_root(&transaction, &root_seal)?;
        let now_ms = now_ms();
        validate_timestamp(now_ms)?;
        let record = load_active_record(&transaction, repository_id, operation_id, now_ms)?;
        if !enabled_capabilities.contains_all(&record.required_capabilities)
            || !current_capabilities.contains_all(&record.required_capabilities)
        {
            return Err(JournalError::CapabilityDenied);
        }
        if completion_intent_exists(&transaction, operation_id)? {
            commit_authorized(transaction, &root_seal)?;
            return Ok(CancelOutcome::TerminalNoOp);
        }
        if record.status.is_terminal() {
            commit_authorized(transaction, &root_seal)?;
            return Ok(CancelOutcome::TerminalNoOp);
        }
        if record.status == OperationStatus::Cancelling {
            commit_authorized(transaction, &root_seal)?;
            return Ok(CancelOutcome::AlreadyRequested);
        }
        validate_update_time(&record, now_ms)?;
        validate_before_deadline(&record, now_ms)?;
        if !record
            .status
            .allows_transition_to(OperationStatus::Cancelling)
        {
            return Err(JournalError::InvalidTransition);
        }
        if !should_commit() {
            return Err(JournalError::RequestCancelled);
        }
        transaction.execute(
            "UPDATE operations SET status = 'cancelling', updated_at_ms = ?1
             WHERE operation_id = ?2",
            params![now_ms, operation_id.as_str()],
        )?;
        commit_authorized(transaction, &root_seal)?;
        Ok(CancelOutcome::Requested)
    }

    /// Cancel a durable submission when request cancellation wins before this
    /// caller launches its runner handoff. A still-unclaimed queued record is
    /// made terminal in this transaction; work already claimed elsewhere is
    /// moved to cooperative cancellation.
    pub fn cancel_before_launch(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        current_capabilities: &CapabilitySet,
        now_ms: i64,
    ) -> Result<CancelOutcome, JournalError> {
        validate_timestamp(now_ms)?;
        self.cancel_before_launch_with_clock(
            repository_id,
            operation_id,
            current_capabilities,
            || now_ms,
        )
    }

    /// Arbitrate pre-launch cancellation using a timestamp sampled after the
    /// IMMEDIATE transaction owns its validated snapshot.
    pub fn cancel_before_launch_with_clock<C>(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        current_capabilities: &CapabilitySet,
        now_ms: C,
    ) -> Result<CancelOutcome, JournalError>
    where
        C: FnOnce() -> i64,
    {
        self.validate_requested_repository(repository_id)?;
        let enabled_capabilities = self.enabled_capabilities.clone();
        let root_seal = self.repository_root_seal.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_transaction_root(&transaction, &root_seal)?;
        let now_ms = now_ms();
        validate_timestamp(now_ms)?;
        let record = load_active_record(&transaction, repository_id, operation_id, now_ms)?;
        if !enabled_capabilities.contains_all(&record.required_capabilities)
            || !current_capabilities.contains_all(&record.required_capabilities)
        {
            return Err(JournalError::CapabilityDenied);
        }
        if completion_intent_exists(&transaction, operation_id)? || record.status.is_terminal() {
            commit_authorized(transaction, &root_seal)?;
            return Ok(CancelOutcome::TerminalNoOp);
        }
        if record.status != OperationStatus::Queued {
            if record.status == OperationStatus::Cancelling {
                commit_authorized(transaction, &root_seal)?;
                return Ok(CancelOutcome::AlreadyRequested);
            }
            validate_update_time(&record, now_ms)?;
            validate_before_deadline(&record, now_ms)?;
            transaction.execute(
                "UPDATE operations SET status='cancelling', updated_at_ms=?1
                 WHERE operation_id=?2",
                params![now_ms, operation_id.as_str()],
            )?;
            commit_authorized(transaction, &root_seal)?;
            return Ok(CancelOutcome::Requested);
        }
        validate_update_time(&record, now_ms)?;
        validate_before_deadline(&record, now_ms)?;
        let handoff = select_handoff_by_id(&transaction, operation_id.as_str())?
            .ok_or(JournalError::IntegrityFailure)?;
        if handoff.claimed_at_ms.is_some() || record.lease.is_some() {
            return Err(JournalError::IntegrityFailure);
        }
        // The schema transition trigger intentionally retains the ordinary
        // queued -> cancelling -> cancelled path. Both writes are private to
        // this transaction, so observers see only the terminal cancellation.
        let cancelling = transaction.execute(
            "UPDATE operations SET status='cancelling', updated_at_ms=?1
             WHERE operation_id=?2 AND status='queued'",
            params![now_ms, operation_id.as_str()],
        )?;
        if cancelling != 1 {
            return Err(JournalError::IntegrityFailure);
        }
        let retain_until_ms = record
            .retain_until_ms
            .max(checked_add(now_ms, TERMINAL_RETENTION_MS)?);
        let updated = transaction.execute(
            "UPDATE operations
             SET status='cancelled', updated_at_ms=?1, terminal_at_ms=?1,
                 retain_until_ms=?2
             WHERE operation_id=?3 AND status='cancelling'",
            params![now_ms, retain_until_ms, operation_id.as_str()],
        )?;
        if updated != 1 {
            return Err(JournalError::IntegrityFailure);
        }
        let completed_handoff = transaction.execute(
            "UPDATE runner_handoffs
             SET claimed_at_ms=COALESCE(claimed_at_ms, ?1), completed_at_ms=?1
             WHERE operation_id=?2 AND completed_at_ms IS NULL",
            params![now_ms, operation_id.as_str()],
        )?;
        if completed_handoff != 1 {
            return Err(JournalError::IntegrityFailure);
        }
        let cancelled = select_validated_by_id(&transaction, operation_id)?;
        commit_authorized(transaction, &root_seal)?;
        debug_assert_eq!(cancelled.status(), OperationStatus::Cancelled);
        Ok(CancelOutcome::Requested)
    }

    /// Claim or reclaim non-terminal work. Claiming a queued operation starts it;
    /// reclaiming an expired running/cancelling lease preserves its current state.
    pub fn acquire_lease(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        owner: &LeaseOwner,
        lease_token: impl AsRef<[u8]>,
        now_ms: i64,
        lease_expires_at_ms: i64,
    ) -> Result<OperationRecord, JournalError> {
        validate_timestamp(now_ms)?;
        self.validate_requested_repository(repository_id)?;
        let token_digest = digest_lease_token(lease_token.as_ref())?;
        let enabled_capabilities = self.enabled_capabilities.clone();
        let root_seal = self.repository_root_seal.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_transaction_root(&transaction, &root_seal)?;
        let record = load_active_record(&transaction, repository_id, operation_id, now_ms)?;
        validate_enabled_capabilities(&enabled_capabilities, &record)?;
        validate_update_time(&record, now_ms)?;
        validate_lease_window(&record, now_ms, lease_expires_at_ms)?;
        if record.status.is_terminal() {
            return Err(JournalError::InvalidTransition);
        }
        if record
            .lease
            .as_ref()
            .is_some_and(|lease| lease.expires_at_ms > now_ms)
        {
            return Err(JournalError::LeaseHeld);
        }
        let status = if record.status == OperationStatus::Queued {
            OperationStatus::Running
        } else {
            record.status
        };
        if status != record.status && !record.status.allows_transition_to(status) {
            return Err(JournalError::InvalidTransition);
        }
        transaction.execute(
            "UPDATE operations
             SET status = ?1, lease_owner = ?2, lease_token_digest = ?3,
                 lease_expires_at_ms = ?4, updated_at_ms = ?5
             WHERE operation_id = ?6",
            params![
                status.as_str(),
                owner.as_str(),
                token_digest.as_bytes().as_slice(),
                lease_expires_at_ms,
                now_ms,
                operation_id.as_str(),
            ],
        )?;
        transaction.execute(
            "UPDATE runner_handoffs
             SET claimed_at_ms = COALESCE(claimed_at_ms, ?1)
             WHERE operation_id = ?2",
            params![now_ms, operation_id.as_str()],
        )?;
        let record = select_validated_by_id(&transaction, operation_id)?;
        commit_authorized(transaction, &root_seal)?;
        Ok(record)
    }

    pub fn renew_lease(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        lease_token: impl AsRef<[u8]>,
        now_ms: i64,
        lease_expires_at_ms: i64,
    ) -> Result<OperationRecord, JournalError> {
        validate_timestamp(now_ms)?;
        self.validate_requested_repository(repository_id)?;
        let lease_token = lease_token.as_ref();
        let token_digest = digest_lease_token(lease_token)?;
        let enabled_capabilities = self.enabled_capabilities.clone();
        let root_seal = self.repository_root_seal.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_transaction_root(&transaction, &root_seal)?;
        let record = load_active_record(&transaction, repository_id, operation_id, now_ms)?;
        validate_enabled_capabilities(&enabled_capabilities, &record)?;
        validate_update_time(&record, now_ms)?;
        validate_lease_window(&record, now_ms, lease_expires_at_ms)?;
        validate_active_lease(&record, token_digest, now_ms)?;
        transaction.execute(
            "UPDATE operations SET lease_expires_at_ms = ?1, updated_at_ms = ?2
             WHERE operation_id = ?3",
            params![lease_expires_at_ms, now_ms, operation_id.as_str()],
        )?;
        let record = select_validated_by_id(&transaction, operation_id)?;
        commit_authorized(transaction, &root_seal)?;
        Ok(record)
    }

    pub fn release_lease(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        lease_token: impl AsRef<[u8]>,
        now_ms: i64,
    ) -> Result<OperationRecord, JournalError> {
        validate_timestamp(now_ms)?;
        self.validate_requested_repository(repository_id)?;
        let token_digest = digest_lease_token(lease_token.as_ref())?;
        let enabled_capabilities = self.enabled_capabilities.clone();
        let root_seal = self.repository_root_seal.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_transaction_root(&transaction, &root_seal)?;
        let record = load_active_record(&transaction, repository_id, operation_id, now_ms)?;
        validate_enabled_capabilities(&enabled_capabilities, &record)?;
        validate_update_time(&record, now_ms)?;
        validate_before_deadline(&record, now_ms)?;
        if record.status.is_terminal() {
            return Err(JournalError::InvalidTransition);
        }
        validate_lease_token(&record, token_digest)?;
        transaction.execute(
            "UPDATE operations
             SET lease_owner = NULL, lease_token_digest = NULL,
                 lease_expires_at_ms = NULL, updated_at_ms = ?1
             WHERE operation_id = ?2",
            params![now_ms, operation_id.as_str()],
        )?;
        let record = select_validated_by_id(&transaction, operation_id)?;
        commit_authorized(transaction, &root_seal)?;
        Ok(record)
    }

    pub fn update_progress(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        lease_token: impl AsRef<[u8]>,
        progress: OperationProgress,
        now_ms: i64,
    ) -> Result<OperationRecord, JournalError> {
        validate_timestamp(now_ms)?;
        self.validate_requested_repository(repository_id)?;
        let token_digest = digest_lease_token(lease_token.as_ref())?;
        let enabled_capabilities = self.enabled_capabilities.clone();
        let root_seal = self.repository_root_seal.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_transaction_root(&transaction, &root_seal)?;
        let record = load_active_record(&transaction, repository_id, operation_id, now_ms)?;
        validate_enabled_capabilities(&enabled_capabilities, &record)?;
        validate_update_time(&record, now_ms)?;
        validate_before_deadline(&record, now_ms)?;
        if !matches!(
            record.status,
            OperationStatus::Running | OperationStatus::Cancelling
        ) {
            return Err(JournalError::InvalidTransition);
        }
        validate_active_lease(&record, token_digest, now_ms)?;
        if progress.total_units != record.progress.total_units
            || progress.completed_units < record.progress.completed_units
        {
            return Err(JournalError::InvalidArgument);
        }
        transaction.execute(
            "UPDATE operations
             SET progress_completed = ?1, updated_at_ms = ?2
             WHERE operation_id = ?3",
            params![
                u64_to_i64(progress.completed_units)?,
                now_ms,
                operation_id.as_str()
            ],
        )?;
        let record = select_validated_by_id(&transaction, operation_id)?;
        commit_authorized(transaction, &root_seal)?;
        Ok(record)
    }

    pub fn complete(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        lease_token: impl AsRef<[u8]>,
        result: CanonicalJson,
        now_ms: i64,
    ) -> Result<OperationRecord, JournalError> {
        self.finish(
            repository_id,
            operation_id,
            lease_token.as_ref(),
            FinishPayload::Completed(result),
            now_ms,
        )
    }

    /// Atomically decide that a running operation will complete successfully.
    /// The result becomes durable in an internal intent before any external
    /// store finalizer runs. Cancellation that commits first wins; cancellation
    /// after this decision is a no-op even though the public status stays
    /// `running` until finalization finishes.
    pub fn commit_completion_intent(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        lease_token: impl AsRef<[u8]>,
        result: CanonicalJson,
        now_ms: i64,
    ) -> Result<CompletionDecision, JournalError> {
        validate_timestamp(now_ms)?;
        self.validate_requested_repository(repository_id)?;
        let token_digest = digest_lease_token(lease_token.as_ref())?;
        let enabled_capabilities = self.enabled_capabilities.clone();
        let root_seal = self.repository_root_seal.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_transaction_root(&transaction, &root_seal)?;
        let record = load_active_record(&transaction, repository_id, operation_id, now_ms)?;
        validate_enabled_capabilities(&enabled_capabilities, &record)?;
        validate_update_time(&record, now_ms)?;
        validate_before_deadline(&record, now_ms)?;
        validate_active_lease(&record, token_digest, now_ms)?;
        if record.status == OperationStatus::Cancelling {
            commit_authorized(transaction, &root_seal)?;
            return Ok(CompletionDecision::CancellationWon);
        }
        if record.status != OperationStatus::Running
            || completion_intent_exists(&transaction, operation_id)?
        {
            return Err(JournalError::InvalidTransition);
        }
        let result_digest = JournalDigest::sha256(result.as_str().as_bytes());
        transaction.execute(
            "INSERT INTO operation_completion_intents(
                 operation_id, result_json, result_digest, decided_at_ms
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                operation_id.as_str(),
                result.as_str(),
                result_digest.as_bytes().as_slice(),
                now_ms,
            ],
        )?;
        transaction.execute(
            "UPDATE operations SET updated_at_ms=?1 WHERE operation_id=?2",
            params![now_ms, operation_id.as_str()],
        )?;
        commit_authorized(transaction, &root_seal)?;
        Ok(CompletionDecision::Committed)
    }

    /// Return the oldest durable completion intent. Runners recover this before
    /// purging deadlines or claiming new work, closing both crash gaps around
    /// graph-store promotion.
    pub fn next_completion_intent(
        &self,
        repository_id: &LogicalRepositoryId,
        now_ms: i64,
    ) -> Result<Option<CompletionIntent>, JournalError> {
        validate_timestamp(now_ms)?;
        self.validate_requested_repository(repository_id)?;
        let transaction = self.connection.unchecked_transaction()?;
        self.validate_transaction_root(&transaction)?;
        let intent = select_next_completion_intent(&transaction)?;
        if let Some(intent) = intent.as_ref() {
            let record = load_completion_intent_record(
                &transaction,
                repository_id,
                intent.operation_id(),
                now_ms,
            )?;
            validate_completion_intent(&record, intent, now_ms)?;
        }
        commit_authorized(transaction, &self.repository_root_seal)?;
        Ok(intent)
    }

    /// Internal cross-store acknowledgement used to retire a cancelled scan's
    /// durable ownership proof. Retention expiry does not hide the terminal
    /// state from this reconciliation path; purge runs only after reconciliation.
    pub(crate) fn scan_cleanup_acknowledged(
        &self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
    ) -> Result<bool, JournalError> {
        self.validate_requested_repository(repository_id)?;
        let transaction = self.connection.unchecked_transaction()?;
        self.validate_transaction_root(&transaction)?;
        let raw = select_operation_by_id(&transaction, operation_id.as_str())?
            .ok_or(JournalError::IntegrityFailure)?;
        let record = validated_record(&transaction, raw)?;
        validate_repository(&record, repository_id)?;
        validate_enabled_capabilities(&self.enabled_capabilities, &record)?;
        if record.kind != OperationKind::ScanSubmit {
            return Err(JournalError::IntegrityFailure);
        }
        let acknowledged = match record.status {
            OperationStatus::Failed | OperationStatus::Cancelled => true,
            OperationStatus::Queued | OperationStatus::Running | OperationStatus::Cancelling => {
                false
            }
            OperationStatus::Completed => return Err(JournalError::IntegrityFailure),
        };
        commit_authorized(transaction, &self.repository_root_seal)?;
        Ok(acknowledged)
    }

    /// Return the oldest expired external-store operation that has no committed
    /// completion intent. This internal recovery read intentionally bypasses
    /// public observability retention only for a validated nonterminal record;
    /// the operation and its one durable handoff are authenticated together.
    pub(crate) fn next_expired_external_store_operation(
        &self,
        repository_id: &LogicalRepositoryId,
        now_ms: i64,
    ) -> Result<Option<ClaimedRunnerHandoff>, JournalError> {
        validate_timestamp(now_ms)?;
        self.validate_requested_repository(repository_id)?;
        let transaction = self.connection.unchecked_transaction()?;
        self.validate_transaction_root(&transaction)?;
        let operation_id = transaction
            .query_row(
                "SELECT operation_id FROM operations
                  WHERE repository_id=?1
                    AND kind IN ('scan_submit', 'runtime_trace_import_submit', 'export_file')
                    AND status IN ('queued', 'running', 'cancelling')
                    AND execution_deadline_ms<=?2
                    AND NOT EXISTS (
                        SELECT 1 FROM operation_completion_intents AS intent
                         WHERE intent.operation_id=operations.operation_id
                    )
                  ORDER BY execution_deadline_ms, operation_id
                  LIMIT 1",
                params![repository_id.as_str(), now_ms],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let claimed = operation_id
            .map(|operation_id| {
                let operation_id =
                    OperationId::parse(operation_id).map_err(|_| JournalError::IntegrityFailure)?;
                let record = select_validated_by_id(&transaction, &operation_id)?;
                if &record.repository_id != repository_id
                    || !matches!(
                        record.kind,
                        OperationKind::ScanSubmit
                            | OperationKind::RuntimeTraceImportSubmit
                            | OperationKind::ExportFile
                    )
                    || record.status.is_terminal()
                    || record.execution_deadline_ms > now_ms
                    || completion_intent_exists(&transaction, &operation_id)?
                {
                    return Err(JournalError::IntegrityFailure);
                }
                validate_enabled_capabilities(&self.enabled_capabilities, &record)?;
                let raw_handoff = select_handoff_by_id(&transaction, operation_id.as_str())?
                    .ok_or(JournalError::IntegrityFailure)?;
                let handoff = decode_handoff(raw_handoff)?;
                validate_operation_handoff(&record, &handoff)?;
                Ok(ClaimedRunnerHandoff { record, handoff })
            })
            .transpose()?;
        commit_authorized(transaction, &self.repository_root_seal)?;
        Ok(claimed)
    }

    /// Publish a previously committed completion intent after its idempotent
    /// external finalizer has succeeded. The decision may finish after the
    /// original execution deadline because it linearized at `decided_at_ms`.
    pub fn finish_completion_intent(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        now_ms: i64,
    ) -> Result<OperationRecord, JournalError> {
        validate_timestamp(now_ms)?;
        self.validate_requested_repository(repository_id)?;
        let root_seal = self.repository_root_seal.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_transaction_root(&transaction, &root_seal)?;
        let intent = select_completion_intent(&transaction, operation_id)?
            .ok_or(JournalError::InvalidTransition)?;
        let record =
            load_completion_intent_record(&transaction, repository_id, operation_id, now_ms)?;
        validate_completion_intent(&record, &intent, now_ms)?;
        let retention_anchor_ms = record.retention_anchor_ms.max(now_ms);
        let retain_until_ms = checked_add(retention_anchor_ms, TERMINAL_RETENTION_MS)?;
        let updated = transaction.execute(
            "UPDATE operations
             SET status='completed', progress_completed=progress_total,
                 result_json=?1, error_json=NULL, lease_owner=NULL,
                 lease_token_digest=NULL, lease_expires_at_ms=NULL,
                 updated_at_ms=?2, terminal_at_ms=?2,
                 retention_anchor_ms=?3, retain_until_ms=?4
             WHERE operation_id=?5 AND status='running' AND updated_at_ms=?2",
            params![
                intent.result.as_str(),
                intent.decided_at_ms,
                retention_anchor_ms,
                retain_until_ms,
                operation_id.as_str(),
            ],
        )?;
        if updated != 1 {
            return Err(JournalError::IntegrityFailure);
        }
        let completed = transaction.execute(
            "UPDATE runner_handoffs SET completed_at_ms=?1
             WHERE operation_id=?2 AND claimed_at_ms IS NOT NULL AND completed_at_ms IS NULL",
            params![intent.decided_at_ms, operation_id.as_str()],
        )?;
        if completed != 1 {
            return Err(JournalError::IntegrityFailure);
        }
        let deleted = transaction.execute(
            "DELETE FROM operation_completion_intents WHERE operation_id=?1",
            params![operation_id.as_str()],
        )?;
        if deleted != 1 {
            return Err(JournalError::IntegrityFailure);
        }
        let completed = select_validated_by_id(&transaction, operation_id)?;
        commit_authorized(transaction, &root_seal)?;
        Ok(completed)
    }

    pub fn fail(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        lease_token: impl AsRef<[u8]>,
        error: CanonicalJson,
        now_ms: i64,
    ) -> Result<OperationRecord, JournalError> {
        self.finish(
            repository_id,
            operation_id,
            lease_token.as_ref(),
            FinishPayload::Failed(error),
            now_ms,
        )
    }

    pub fn mark_cancelled(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        lease_token: impl AsRef<[u8]>,
        now_ms: i64,
    ) -> Result<OperationRecord, JournalError> {
        self.finish(
            repository_id,
            operation_id,
            lease_token.as_ref(),
            FinishPayload::Cancelled,
            now_ms,
        )
    }

    /// Fail work after its hard deadline even when no live lease remains.
    ///
    /// This deadline reaper is intentionally the only path that permits a
    /// queued operation to transition directly to failed: work can expire
    /// before any runner claims its handoff.
    pub fn fail_deadline(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        now_ms: i64,
    ) -> Result<OperationRecord, JournalError> {
        self.fail_deadline_inner(repository_id, operation_id, now_ms, false)
    }

    pub(crate) fn fail_deadline_after_runner_cleanup(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        now_ms: i64,
    ) -> Result<OperationRecord, JournalError> {
        self.fail_deadline_inner(repository_id, operation_id, now_ms, true)
    }

    fn fail_deadline_inner(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        now_ms: i64,
        runner_cleanup_completed: bool,
    ) -> Result<OperationRecord, JournalError> {
        validate_timestamp(now_ms)?;
        self.validate_requested_repository(repository_id)?;
        let enabled_capabilities = self.enabled_capabilities.clone();
        let root_seal = self.repository_root_seal.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_transaction_root(&transaction, &root_seal)?;
        let record =
            load_record_for_deadline_failure(&transaction, repository_id, operation_id, now_ms)?;
        validate_enabled_capabilities(&enabled_capabilities, &record)?;
        if record.kind.requires_runner_cleanup() && !runner_cleanup_completed {
            return Err(JournalError::InvalidTransition);
        }
        if completion_intent_exists(&transaction, operation_id)? {
            return Err(JournalError::InvalidTransition);
        }
        if now_ms < record.execution_deadline_ms {
            return Err(JournalError::InvalidArgument);
        }
        if !record.status.allows_transition_to(OperationStatus::Failed) {
            return Err(JournalError::InvalidTransition);
        }
        let error = CanonicalJson::from_database(DEADLINE_EXCEEDED_ERROR_JSON.to_owned())?;
        let record = transition_to_deadline_failure(&transaction, &record, &error)?;
        commit_authorized(transaction, &root_seal)?;
        Ok(record)
    }

    /// Transactionally reap one bounded batch of deadline-expired work, replace
    /// one bounded batch of expired terminal records with tombstones, and remove
    /// one bounded batch of elapsed tombstones. Purge defers while a runner owns
    /// the cross-process cleanup/terminal/acknowledgement window.
    pub fn purge(&mut self, now_ms: i64) -> Result<PurgeReport, JournalError> {
        validate_timestamp(now_ms)?;
        let Some(guard) = self.try_acquire_runner_purge_guard()? else {
            return Ok(PurgeReport {
                more_work: true,
                ..PurgeReport::default()
            });
        };
        self.purge_with_runner_guard(now_ms, &guard)
    }

    pub(crate) fn purge_with_runner_guard(
        &mut self,
        now_ms: i64,
        _guard: &RunnerPurgeGuard,
    ) -> Result<PurgeReport, JournalError> {
        validate_timestamp(now_ms)?;
        let repository_id = self.repository_id.clone();
        let deadline_error = CanonicalJson::from_database(DEADLINE_EXCEEDED_ERROR_JSON.to_owned())?;
        let root_seal = self.repository_root_seal.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_transaction_root(&transaction, &root_seal)?;

        let deadline_expired_operation_ids = {
            let mut statement = transaction.prepare(
                "SELECT substr(operation_id, 1, 36) FROM operations
                 WHERE status IN ('queued', 'running', 'cancelling')
                   AND kind NOT IN ('scan_submit', 'runtime_trace_import_submit', 'export_file')
                   AND execution_deadline_ms <= ?1
                   AND NOT EXISTS (
                       SELECT 1 FROM operation_completion_intents AS intent
                       WHERE intent.operation_id=operations.operation_id
                   )
                 ORDER BY execution_deadline_ms, operation_id
                 LIMIT ?2",
            )?;
            let rows = statement
                .query_map(params![now_ms, MAX_PURGE_BATCH_SIZE as i64], |row| {
                    row.get::<_, String>(0)
                })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(map_database_decode_error)?
        };
        let mut reaped_operations = 0_u64;
        for operation_id in deadline_expired_operation_ids {
            let operation_id =
                OperationId::parse(operation_id).map_err(|_| JournalError::IntegrityFailure)?;
            // Load and validate only one potentially large active record at a time;
            // the bounded candidate list itself contains operation IDs only.
            let record = select_validated_by_id(&transaction, &operation_id)?;
            if record.repository_id != repository_id
                || record.status.is_terminal()
                || record.execution_deadline_ms > now_ms
            {
                return Err(JournalError::IntegrityFailure);
            }
            transition_to_deadline_failure(&transaction, &record, &deadline_error)?;
            reaped_operations += 1;
        }

        let expired_terminal_operation_ids = {
            let mut statement = transaction.prepare(
                "SELECT substr(operation_id, 1, 36) FROM operations
                 WHERE status IN ('completed', 'failed', 'cancelled')
                   AND retain_until_ms <= ?1
                 ORDER BY retain_until_ms, operation_id
                 LIMIT ?2",
            )?;
            let rows = statement
                .query_map(params![now_ms, MAX_PURGE_BATCH_SIZE as i64], |row| {
                    row.get::<_, String>(0)
                })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(map_database_decode_error)?
        };
        let mut created_tombstones = 0_u64;
        let mut purged_operations = 0_u64;
        for operation_id in expired_terminal_operation_ids {
            let operation_id =
                OperationId::parse(operation_id).map_err(|_| JournalError::IntegrityFailure)?;
            // Validate one potentially large terminal record at a time so malformed
            // payloads fail closed without retaining a whole batch in memory.
            let record = select_validated_by_id(&transaction, &operation_id)?;
            if record.repository_id != repository_id
                || !record.status.is_terminal()
                || record.retain_until_ms > now_ms
            {
                return Err(JournalError::IntegrityFailure);
            }
            let tombstone_until_ms = checked_add(record.retain_until_ms, TOMBSTONE_RETENTION_MS)
                .map_err(|_| JournalError::IntegrityFailure)?;
            let deleted = transaction.execute(
                "DELETE FROM operations
                 WHERE operation_id = ?1
                   AND status IN ('completed', 'failed', 'cancelled')",
                params![record.operation_id.as_str()],
            )?;
            if deleted != 1 {
                return Err(JournalError::IntegrityFailure);
            }
            if tombstone_until_ms > now_ms {
                transaction.execute(
                    "INSERT INTO operation_tombstones (
                        operation_id, repository_id, kind,
                        required_capabilities_json, required_capabilities_digest, input_digest,
                        idempotency_key_digest, expired_at_ms,
                        tombstone_until_ms
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        record.operation_id.as_str(),
                        record.repository_id.as_str(),
                        record.kind.as_str(),
                        record.required_capabilities.canonical_json()?,
                        record.required_capabilities.digest.as_bytes().as_slice(),
                        record.input_digest.as_bytes().as_slice(),
                        record.idempotency_key_digest.as_bytes().as_slice(),
                        record.retain_until_ms,
                        tombstone_until_ms,
                    ],
                )?;
                created_tombstones += 1;
            }
            purged_operations += 1;
        }

        let expired_tombstone_ids = {
            let mut statement = transaction.prepare(
                "SELECT substr(operation_id, 1, 36) FROM operation_tombstones
                 WHERE tombstone_until_ms <= ?1
                 ORDER BY tombstone_until_ms, operation_id
                 LIMIT ?2",
            )?;
            let rows = statement
                .query_map(params![now_ms, MAX_PURGE_BATCH_SIZE as i64], |row| {
                    row.get::<_, String>(0)
                })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(map_database_decode_error)?
        };
        let mut purged_tombstones = 0_u64;
        for operation_id in expired_tombstone_ids {
            let operation_id =
                OperationId::parse(operation_id).map_err(|_| JournalError::IntegrityFailure)?;
            let tombstone = select_tombstone_by_id(&transaction, operation_id.as_str())?
                .ok_or(JournalError::IntegrityFailure)?;
            validate_tombstone(&tombstone)?;
            if tombstone.repository_id != repository_id.as_str()
                || tombstone.tombstone_until_ms > now_ms
            {
                return Err(JournalError::IntegrityFailure);
            }
            let deleted = transaction.execute(
                "DELETE FROM operation_tombstones WHERE operation_id = ?1",
                params![operation_id.as_str()],
            )?;
            if deleted != 1 {
                return Err(JournalError::IntegrityFailure);
            }
            purged_tombstones += 1;
        }

        let more_work: bool = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM operations
                 WHERE status IN ('queued', 'running', 'cancelling')
                   AND kind NOT IN ('scan_submit', 'runtime_trace_import_submit', 'export_file')
                   AND execution_deadline_ms <= ?1
                   AND NOT EXISTS (
                       SELECT 1 FROM operation_completion_intents AS intent
                       WHERE intent.operation_id=operations.operation_id
                   )
             ) OR EXISTS(
                 SELECT 1 FROM operations
                 WHERE status IN ('completed', 'failed', 'cancelled')
                   AND retain_until_ms <= ?1
             ) OR EXISTS(
                 SELECT 1 FROM operation_tombstones WHERE tombstone_until_ms <= ?1
             )",
            params![now_ms],
            |row| row.get(0),
        )?;
        commit_authorized(transaction, &root_seal)?;
        Ok(PurgeReport {
            reaped_operations,
            purged_operations,
            created_tombstones,
            purged_tombstones,
            more_work,
        })
    }

    fn finish(
        &mut self,
        repository_id: &LogicalRepositoryId,
        operation_id: &OperationId,
        lease_token: &[u8],
        payload: FinishPayload,
        now_ms: i64,
    ) -> Result<OperationRecord, JournalError> {
        validate_timestamp(now_ms)?;
        self.validate_requested_repository(repository_id)?;
        let token_digest = digest_lease_token(lease_token)?;
        let status = payload.status();
        let (result, error) = payload.into_columns();
        let enabled_capabilities = self.enabled_capabilities.clone();
        let root_seal = self.repository_root_seal.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_transaction_root(&transaction, &root_seal)?;
        let record = load_active_record(&transaction, repository_id, operation_id, now_ms)?;
        validate_enabled_capabilities(&enabled_capabilities, &record)?;
        validate_update_time(&record, now_ms)?;
        validate_before_deadline(&record, now_ms)?;
        if record.status == OperationStatus::Queued || !record.status.allows_transition_to(status) {
            return Err(JournalError::InvalidTransition);
        }
        validate_active_lease(&record, token_digest, now_ms)?;
        let retain_until_ms = record
            .retain_until_ms
            .max(checked_add(now_ms, TERMINAL_RETENTION_MS)?);
        let progress_completed = if status == OperationStatus::Completed {
            record.progress.total_units
        } else {
            record.progress.completed_units
        };
        let updated = transaction.execute(
            "UPDATE operations
             SET status = ?1, progress_completed = ?2,
                 result_json = ?3, error_json = ?4,
                 lease_owner = NULL, lease_token_digest = NULL,
                 lease_expires_at_ms = NULL, updated_at_ms = ?5,
                 terminal_at_ms = ?5, retain_until_ms = ?6
             WHERE operation_id = ?7 AND status = ?8",
            params![
                status.as_str(),
                u64_to_i64(progress_completed)?,
                result.as_ref().map(CanonicalJson::as_str),
                error.as_ref().map(CanonicalJson::as_str),
                now_ms,
                retain_until_ms,
                operation_id.as_str(),
                record.status.as_str(),
            ],
        )?;
        if updated != 1 {
            return Err(JournalError::IntegrityFailure);
        }
        let completed = transaction.execute(
            "UPDATE runner_handoffs SET completed_at_ms = ?1
              WHERE operation_id = ?2
                AND claimed_at_ms IS NOT NULL AND completed_at_ms IS NULL",
            params![now_ms, operation_id.as_str()],
        )?;
        if completed != 1 {
            return Err(JournalError::IntegrityFailure);
        }
        let record = select_validated_by_id(&transaction, operation_id)?;
        commit_authorized(transaction, &root_seal)?;
        Ok(record)
    }

    fn validate_requested_repository(
        &self,
        repository_id: &LogicalRepositoryId,
    ) -> Result<(), JournalError> {
        if repository_id != &self.repository_id {
            return Err(JournalError::RepositoryMismatch);
        }
        Ok(())
    }

    fn validate_record_repository(&self, record: &OperationRecord) -> Result<(), JournalError> {
        if record.repository_id != self.repository_id {
            return Err(JournalError::IntegrityFailure);
        }
        Ok(())
    }

    fn validate_submit_request(&self, request: &SubmitRequest) -> Result<(), JournalError> {
        validate_submit_request_authority(
            request,
            &self.repository_id,
            &self.enabled_capabilities,
            &self.repository_root_seal,
        )
    }

    fn validate_live_root(&self) -> Result<(), JournalError> {
        validate_live_root(&self.repository_root_seal)
    }

    fn validate_transaction_root(&self, connection: &Connection) -> Result<(), JournalError> {
        validate_transaction_root(connection, &self.repository_root_seal)
    }

    fn initialize_schema(&mut self) -> Result<(), JournalError> {
        let root_seal = self.repository_root_seal.clone();
        let repository_id = self.repository_id.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_live_root(&root_seal)?;
        let version: i64 = transaction.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version == 0 {
            transaction.execute_batch(&schema_current_base()?)?;
            transaction.execute_batch(SCHEMA_V2_METADATA)?;
            transaction.execute_batch(SCHEMA_V3_COMPLETION_INTENTS)?;
            insert_repository_binding(&transaction, JournalDigest(root_seal.binding_digest()))?;
            transaction.pragma_update(None, "user_version", JOURNAL_SCHEMA_VERSION)?;
        } else if version == LEGACY_JOURNAL_SCHEMA_VERSION {
            // Schema v1 stored only the basename-derived logical repository ID.
            // Distinct exact roots can have that same ID, so retained v1 rows carry
            // insufficient information to determine their originating root. Any
            // automatic binding would therefore guess at provenance and is
            // information-theoretically unsafe. Only a journal with no retained
            // operations, handoffs, or tombstones can be bound without attribution.
            validate_legacy_schema(&transaction)?;
            if !legacy_journal_is_empty(&transaction)? {
                return Err(JournalError::IntegrityFailure);
            }
            validate_foreign_keys(&transaction)?;
            validate_no_operation_tombstone_overlap(&transaction)?;
            validate_operation_handoff_cardinality(&transaction)?;
            transaction.execute_batch(SCHEMA_V2_METADATA)?;
            transaction.execute_batch(SCHEMA_V3_COMPLETION_INTENTS)?;
            insert_repository_binding(&transaction, JournalDigest(root_seal.binding_digest()))?;
            transaction.pragma_update(
                None,
                "user_version",
                COMPLETION_INTENT_JOURNAL_SCHEMA_VERSION,
            )?;
            migrate_v3_to_v4(&transaction, &root_seal, &repository_id)?;
            migrate_v4_to_v5(&transaction, &root_seal, &repository_id)?;
        } else if version == ROOT_BOUND_JOURNAL_SCHEMA_VERSION {
            validate_v2_schema(&transaction)?;
            transaction.execute_batch(SCHEMA_V3_COMPLETION_INTENTS)?;
            transaction.pragma_update(
                None,
                "user_version",
                COMPLETION_INTENT_JOURNAL_SCHEMA_VERSION,
            )?;
            migrate_v3_to_v4(&transaction, &root_seal, &repository_id)?;
            migrate_v4_to_v5(&transaction, &root_seal, &repository_id)?;
        } else if version == COMPLETION_INTENT_JOURNAL_SCHEMA_VERSION {
            migrate_v3_to_v4(&transaction, &root_seal, &repository_id)?;
            migrate_v4_to_v5(&transaction, &root_seal, &repository_id)?;
        } else if version == RETENTION_ANCHOR_JOURNAL_SCHEMA_VERSION {
            migrate_v4_to_v5(&transaction, &root_seal, &repository_id)?;
        } else if version != JOURNAL_SCHEMA_VERSION {
            return Err(JournalError::UnsupportedSchemaVersion);
        } else {
            validate_repository_binding(&transaction, JournalDigest(root_seal.binding_digest()))?;
        }
        commit_authorized(transaction, &root_seal)?;
        Ok(())
    }
}

/// Authorized, closed operation lifecycle API over the durable journal.
///
/// This type deliberately has no operation enumeration or raw journal accessor.
/// Runner recovery continues to use [`OperationJournal`] as an internal Rust
/// boundary, while Agent-facing callers receive only bounded projections.
///
/// ```compile_fail
/// use depgraph_operation::OperationManager;
///
/// fn enumerate_operations(manager: &OperationManager) {
///     let _ = manager.list();
/// }
/// ```
///
/// Lifecycle callers cannot inject repository or capability authority:
///
/// ```compile_fail
/// use depgraph_mcp_tools::{LogicalRepositoryId, OperationId};
/// use depgraph_operation::{CapabilitySet, OperationManager};
///
/// fn inject_authority(
///     manager: &OperationManager,
///     repository: &LogicalRepositoryId,
///     capabilities: &CapabilitySet,
///     operation: &OperationId,
/// ) {
///     let _ = manager.get(repository, capabilities, operation, 0);
/// }
/// ```
pub struct OperationManager {
    journal: OperationJournal,
    authority: OperationManagerAuthority,
}

struct OperationManagerAuthority {
    repository_id: LogicalRepositoryId,
    capabilities: CapabilitySet,
    root_seal: RepositoryRootSeal,
}

impl OperationManager {
    /// Open the durable journal using the current service repository and
    /// capability configuration.
    pub fn open(config: &DepgraphServiceConfig) -> Result<Self, JournalError> {
        let root_seal = config.repository_root_seal();
        let repository_id = LogicalRepositoryId::parse(config.logical_repository_id())
            .map_err(|_| JournalError::IntegrityFailure)?;
        let capabilities = CapabilitySet::new(config.capabilities().iter().map(Into::into))?;
        let manager = Self {
            journal: OperationJournal::open_with_root_seal(config, &root_seal)?,
            authority: OperationManagerAuthority {
                repository_id,
                capabilities,
                root_seal,
            },
        };
        manager.revalidate_root()?;
        Ok(manager)
    }

    /// Look up an existing submission using an existing, current journal only.
    /// This path never creates a journal and never migrates an older schema.
    pub fn existing_submission_binding_read_only(
        config: &DepgraphServiceConfig,
        kind: OperationKind,
        idempotency_key: impl AsRef<[u8]>,
        now_ms: i64,
    ) -> Result<Option<ExistingSubmissionBinding>, JournalError> {
        validate_timestamp(now_ms)?;
        Self::existing_submission_binding_read_only_with_clock(
            config,
            kind,
            idempotency_key,
            || now_ms,
        )
    }

    /// Look up an existing binding using a timestamp sampled only after the
    /// read-only journal has fixed its validated SQLite snapshot.
    pub fn existing_submission_binding_read_only_with_clock<F>(
        config: &DepgraphServiceConfig,
        kind: OperationKind,
        idempotency_key: impl AsRef<[u8]>,
        now_ms: F,
    ) -> Result<Option<ExistingSubmissionBinding>, JournalError>
    where
        F: FnOnce() -> i64,
    {
        let idempotency_key = idempotency_key.as_ref();
        validate_secret_input(idempotency_key, MAX_IDEMPOTENCY_KEY_BYTES)?;
        let root_seal = config.repository_root_seal();
        let repository_id = LogicalRepositoryId::parse(config.logical_repository_id())
            .map_err(|_| JournalError::IntegrityFailure)?;
        let capabilities = CapabilitySet::new(config.capabilities().iter().map(Into::into))?;
        let required_capabilities = kind.required_capabilities()?;
        if !capabilities.contains_all(&required_capabilities) {
            return Err(JournalError::CapabilityDenied);
        }
        let Some(journal) =
            OperationJournal::open_existing_read_only_with_root_seal(config, &root_seal)?
        else {
            if !root_seal.matches_live_root() {
                return Err(JournalError::RepositoryMismatch);
            }
            return Ok(None);
        };
        let manager = Self {
            journal,
            authority: OperationManagerAuthority {
                repository_id,
                capabilities,
                root_seal,
            },
        };
        manager.existing_submission_binding_with_clock(kind, idempotency_key, now_ms)
    }

    /// Submit validated normalized work and return only after the operation and
    /// its runner handoff are committed atomically.
    pub fn submit(
        &mut self,
        request: &SubmitRequest,
        now_ms: i64,
    ) -> Result<OperationHandle, JournalError> {
        validate_timestamp(now_ms)?;
        self.submit_with_clock(request, || now_ms)
    }

    /// Submit work using a timestamp sampled after the journal's IMMEDIATE
    /// transaction has acquired its snapshot.
    pub fn submit_with_clock<F>(
        &mut self,
        request: &SubmitRequest,
        now_ms: F,
    ) -> Result<OperationHandle, JournalError>
    where
        F: FnOnce() -> i64,
    {
        self.revalidate_root()?;
        self.validate_submit_request_root(request)?;
        let handle = self
            .journal
            .submit_with_clock(request, now_ms)
            .map(OperationHandle::from_submit_outcome)?;
        self.revalidate_root()?;
        Ok(handle)
    }

    /// Look up an existing repository/kind/idempotency binding without first
    /// constructing new normalized input. This preserves dynamic-selector
    /// replay while keeping the normal submit binding validation authoritative.
    pub fn existing_submission_binding(
        &self,
        kind: OperationKind,
        idempotency_key: impl AsRef<[u8]>,
        now_ms: i64,
    ) -> Result<Option<ExistingSubmissionBinding>, JournalError> {
        validate_timestamp(now_ms)?;
        self.existing_submission_binding_with_clock(kind, idempotency_key, || now_ms)
    }

    /// Resolve an idempotency binding using a timestamp sampled after the
    /// transaction has fixed its SQLite snapshot.
    pub fn existing_submission_binding_with_clock<F>(
        &self,
        kind: OperationKind,
        idempotency_key: impl AsRef<[u8]>,
        now_ms: F,
    ) -> Result<Option<ExistingSubmissionBinding>, JournalError>
    where
        F: FnOnce() -> i64,
    {
        self.revalidate_root()?;
        let required_capabilities = kind.required_capabilities()?;
        if !self
            .authority
            .capabilities
            .contains_all(&required_capabilities)
        {
            return Err(JournalError::CapabilityDenied);
        }
        let idempotency_key = idempotency_key.as_ref();
        validate_secret_input(idempotency_key, MAX_IDEMPOTENCY_KEY_BYTES)?;
        let idempotency_key_digest = JournalDigest::sha256(idempotency_key);
        let transaction = self.journal.connection.unchecked_transaction()?;
        validate_transaction_root(&transaction, &self.authority.root_seal)?;
        let now_ms = now_ms();
        validate_timestamp(now_ms)?;
        let binding = if let Some(raw) = select_operation_by_scope_for_schema(
            &transaction,
            self.authority.repository_id.as_str(),
            kind.as_str(),
            idempotency_key_digest,
            self.journal.has_retention_anchor,
        )? {
            let record = validated_record(&transaction, raw)?;
            validate_record_not_from_future(&record, now_ms)?;
            validate_repository(&record, &self.authority.repository_id)?;
            validate_enabled_capabilities(&self.authority.capabilities, &record)?;
            if record.kind != kind || record.idempotency_key_digest != idempotency_key_digest {
                return Err(JournalError::IntegrityFailure);
            }
            if now_ms >= record.retain_until_ms {
                return Err(JournalError::Expired);
            }
            Some(ExistingSubmissionBinding {
                normalized_input: record.normalized_input,
            })
        } else if let Some(tombstone) = select_tombstone_by_scope(
            &transaction,
            self.authority.repository_id.as_str(),
            kind.as_str(),
            idempotency_key_digest,
        )? {
            validate_tombstone(&tombstone)?;
            if now_ms < tombstone.tombstone_until_ms {
                return Err(JournalError::Expired);
            }
            None
        } else {
            None
        };
        commit_authorized(transaction, &self.authority.root_seal)?;
        self.revalidate_root()?;
        Ok(binding)
    }

    /// Resolve an Agent-safe operation status under the sealed open authority.
    pub fn get(
        &self,
        operation_id: &OperationId,
        now_ms: i64,
    ) -> Result<OperationView, JournalError> {
        validate_timestamp(now_ms)?;
        self.get_with_clock(operation_id, || now_ms)
    }

    /// Resolve status using a timestamp sampled after the read snapshot is fixed.
    pub fn get_with_clock<F>(
        &self,
        operation_id: &OperationId,
        now_ms: F,
    ) -> Result<OperationView, JournalError>
    where
        F: FnOnce() -> i64,
    {
        let record = self.authorized_read_with_clock(operation_id, now_ms)?;
        let view = OperationView::from_record(&record);
        self.revalidate_root()?;
        Ok(view)
    }

    /// Resolve a closed terminal result. Non-terminal operations return
    /// [`JournalError::OperationNotReady`].
    pub fn result(
        &self,
        operation_id: &OperationId,
        now_ms: i64,
    ) -> Result<OperationResultView, JournalError> {
        validate_timestamp(now_ms)?;
        self.result_with_clock(operation_id, || now_ms)
    }

    /// Resolve a terminal result using a timestamp sampled after the read
    /// snapshot is fixed.
    pub fn result_with_clock<F>(
        &self,
        operation_id: &OperationId,
        now_ms: F,
    ) -> Result<OperationResultView, JournalError>
    where
        F: FnOnce() -> i64,
    {
        let record = self.authorized_read_with_clock(operation_id, now_ms)?;
        let operation = OperationView::from_record(&record);
        let operation_kind = record.kind;
        let outcome = terminal_outcome(record)?;
        self.revalidate_root()?;
        Ok(OperationResultView {
            operation,
            operation_kind,
            outcome,
        })
    }

    /// Record cooperative cancellation only when the sealed current authority
    /// contains every immutable capability recorded at submit.
    pub fn cancel(
        &mut self,
        operation_id: &OperationId,
        now_ms: i64,
    ) -> Result<CancelOutcome, JournalError> {
        validate_timestamp(now_ms)?;
        self.cancel_with_clock(operation_id, || now_ms)
    }

    /// Cancel while sampling the clock separately for the authorization read
    /// and the mutation transaction snapshots.
    pub fn cancel_with_clock<C>(
        &mut self,
        operation_id: &OperationId,
        now_ms: C,
    ) -> Result<CancelOutcome, JournalError>
    where
        C: FnMut() -> i64,
    {
        self.cancel_if_with_clock(operation_id, now_ms, || true)
    }

    /// Record cooperative cancellation only when authorization remains valid
    /// and `should_commit` still permits the mutation at the journal boundary.
    pub fn cancel_if<F>(
        &mut self,
        operation_id: &OperationId,
        now_ms: i64,
        should_commit: F,
    ) -> Result<CancelOutcome, JournalError>
    where
        F: FnOnce() -> bool,
    {
        validate_timestamp(now_ms)?;
        self.cancel_if_with_clock(operation_id, || now_ms, should_commit)
    }

    /// Conditionally cancel while sampling the clock at each journal boundary.
    pub fn cancel_if_with_clock<C, F>(
        &mut self,
        operation_id: &OperationId,
        mut now_ms: C,
        should_commit: F,
    ) -> Result<CancelOutcome, JournalError>
    where
        C: FnMut() -> i64,
        F: FnOnce() -> bool,
    {
        self.revalidate_root()?;
        let record = self.journal.get_with_clock(
            &self.authority.repository_id,
            operation_id,
            &mut now_ms,
        )?;
        if !self
            .authority
            .capabilities
            .contains_all(record.required_capabilities())
        {
            return Err(JournalError::CapabilityDenied);
        }
        let outcome = self.journal.cancel_if_with_clock(
            &self.authority.repository_id,
            operation_id,
            &self.authority.capabilities,
            now_ms,
            should_commit,
        )?;
        self.revalidate_root()?;
        Ok(outcome)
    }

    /// Terminally cancel a queued durable operation when request cancellation
    /// wins before this caller's runner launch handoff.
    pub fn cancel_before_launch(
        &mut self,
        operation_id: &OperationId,
        now_ms: i64,
    ) -> Result<CancelOutcome, JournalError> {
        validate_timestamp(now_ms)?;
        self.cancel_before_launch_with_clock(operation_id, || now_ms)
    }

    /// Arbitrate pre-launch cancellation with transaction-scoped clock
    /// sampling.
    pub fn cancel_before_launch_with_clock<C>(
        &mut self,
        operation_id: &OperationId,
        now_ms: C,
    ) -> Result<CancelOutcome, JournalError>
    where
        C: FnOnce() -> i64,
    {
        self.revalidate_root()?;
        let outcome = self.journal.cancel_before_launch_with_clock(
            &self.authority.repository_id,
            operation_id,
            &self.authority.capabilities,
            now_ms,
        )?;
        self.revalidate_root()?;
        Ok(outcome)
    }

    fn authorized_read_with_clock<F>(
        &self,
        operation_id: &OperationId,
        now_ms: F,
    ) -> Result<OperationRecord, JournalError>
    where
        F: FnOnce() -> i64,
    {
        self.revalidate_root()?;
        if !self.authority.capabilities.contains(AgentCapability::Read) {
            return Err(JournalError::CapabilityDenied);
        }
        let record =
            self.journal
                .get_with_clock(&self.authority.repository_id, operation_id, now_ms)?;
        self.revalidate_root()?;
        Ok(record)
    }

    fn validate_submit_request_root(&self, request: &SubmitRequest) -> Result<(), JournalError> {
        if request.repository_binding_digest
            != JournalDigest(self.authority.root_seal.binding_digest())
        {
            return Err(JournalError::RepositoryMismatch);
        }
        Ok(())
    }

    fn revalidate_root(&self) -> Result<(), JournalError> {
        if !self.authority.root_seal.matches_live_root() {
            return Err(JournalError::RepositoryMismatch);
        }
        Ok(())
    }
}

fn validate_live_root(root_seal: &RepositoryRootSeal) -> Result<(), JournalError> {
    if !root_seal.matches_live_root() {
        return Err(JournalError::RepositoryMismatch);
    }
    Ok(())
}

fn validate_transaction_root(
    connection: &Connection,
    root_seal: &RepositoryRootSeal,
) -> Result<(), JournalError> {
    validate_live_root(root_seal)?;
    validate_repository_binding(connection, JournalDigest(root_seal.binding_digest()))
}

fn commit_authorized(
    transaction: Transaction<'_>,
    root_seal: &RepositoryRootSeal,
) -> Result<(), JournalError> {
    // This check is deliberately adjacent to commit. Returning an error drops
    // the still-open transaction, rolling back every mutation in it.
    validate_live_root(root_seal)?;
    transaction.commit()?;
    Ok(())
}

fn validate_submit_request_authority(
    request: &SubmitRequest,
    repository_id: &LogicalRepositoryId,
    enabled_capabilities: &CapabilitySet,
    root_seal: &RepositoryRootSeal,
) -> Result<(), JournalError> {
    if request.repository_id != *repository_id
        || request.repository_binding_digest != JournalDigest(root_seal.binding_digest())
    {
        return Err(JournalError::RepositoryMismatch);
    }
    let required_capabilities = request.kind.required_capabilities()?;
    if request.required_capabilities != required_capabilities {
        return Err(JournalError::IntegrityFailure);
    }
    if !enabled_capabilities.contains_all(&required_capabilities) {
        return Err(JournalError::CapabilityDenied);
    }
    Ok(())
}

fn validate_schema(connection: &Connection) -> Result<(), JournalError> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != JOURNAL_SCHEMA_VERSION {
        return Err(JournalError::UnsupportedSchemaVersion);
    }
    validate_schema_surface(connection, true, true, true, &schema_current_base()?)
}

fn validate_v4_schema(connection: &Connection) -> Result<(), JournalError> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != RETENTION_ANCHOR_JOURNAL_SCHEMA_VERSION {
        return Err(JournalError::UnsupportedSchemaVersion);
    }
    validate_schema_surface(connection, true, true, true, &schema_v4_base()?)
}

fn validate_v3_schema(connection: &Connection) -> Result<(), JournalError> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != COMPLETION_INTENT_JOURNAL_SCHEMA_VERSION {
        return Err(JournalError::UnsupportedSchemaVersion);
    }
    validate_schema_surface(connection, true, true, false, SCHEMA_V1)
}

fn validate_v2_schema(connection: &Connection) -> Result<(), JournalError> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != ROOT_BOUND_JOURNAL_SCHEMA_VERSION {
        return Err(JournalError::UnsupportedSchemaVersion);
    }
    validate_schema_surface(connection, true, false, false, SCHEMA_V1)
}

fn validate_legacy_schema(connection: &Connection) -> Result<(), JournalError> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != LEGACY_JOURNAL_SCHEMA_VERSION {
        return Err(JournalError::UnsupportedSchemaVersion);
    }
    validate_schema_surface(connection, false, false, false, SCHEMA_V1)
}

fn validate_schema_surface(
    connection: &Connection,
    include_repository_binding: bool,
    include_completion_intents: bool,
    include_retention_anchor: bool,
    base_schema: &str,
) -> Result<(), JournalError> {
    let mut operation_columns = vec![
        "operation_id",
        "repository_id",
        "kind",
        "required_capabilities_json",
        "required_capabilities_digest",
        "input_json",
        "input_digest",
        "idempotency_key_digest",
        "status",
        "progress_completed",
        "progress_total",
        "lease_owner",
        "lease_token_digest",
        "lease_expires_at_ms",
        "execution_deadline_ms",
        "result_json",
        "error_json",
        "created_at_ms",
        "updated_at_ms",
        "terminal_at_ms",
    ];
    if include_retention_anchor {
        operation_columns.push("retention_anchor_ms");
    }
    operation_columns.push("retain_until_ms");
    validate_columns(connection, "operations", &operation_columns)?;
    validate_columns(
        connection,
        "runner_handoffs",
        &[
            "operation_id",
            "operation_kind",
            "payload_json",
            "payload_digest",
            "enqueued_at_ms",
            "claimed_at_ms",
            "completed_at_ms",
        ],
    )?;
    validate_columns(
        connection,
        "operation_tombstones",
        &[
            "operation_id",
            "repository_id",
            "kind",
            "required_capabilities_json",
            "required_capabilities_digest",
            "input_digest",
            "idempotency_key_digest",
            "expired_at_ms",
            "tombstone_until_ms",
        ],
    )?;
    if include_repository_binding {
        validate_columns(
            connection,
            "operation_journal_metadata",
            &["singleton", "metadata_version", "repository_binding_digest"],
        )?;
    }
    if include_completion_intents {
        validate_columns(
            connection,
            "operation_completion_intents",
            &[
                "operation_id",
                "result_json",
                "result_digest",
                "decided_at_ms",
            ],
        )?;
    }
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(base_schema)?;
    if include_repository_binding {
        reference.execute_batch(SCHEMA_V2_METADATA)?;
    }
    if include_completion_intents {
        reference.execute_batch(SCHEMA_V3_COMPLETION_INTENTS)?;
    }
    validate_schema_objects(connection, &reference)?;
    Ok(())
}

fn migrate_v3_to_v4(
    connection: &Connection,
    root_seal: &RepositoryRootSeal,
    repository_id: &LogicalRepositoryId,
) -> Result<(), JournalError> {
    // Authenticate the complete v3 surface and every retained row before
    // creating a copy. A malformed journal must remain logically unchanged on
    // its existing version path when this transaction rolls back.
    validate_v3_schema(connection)?;
    validate_repository_binding(connection, JournalDigest(root_seal.binding_digest()))?;
    validate_connection_integrity(connection)?;
    validate_foreign_keys(connection)?;
    validate_no_operation_tombstone_overlap(connection)?;
    validate_operation_handoff_cardinality(connection)?;
    validate_journal_rows(connection, repository_id, true, false)?;

    // SQLite cannot alter CHECK constraints in place. Retain all five tables in
    // transactional temporary copies, drop children before parents, recreate
    // the exact v4 surface, then restore parents before their dependent rows.
    connection.execute_batch(
        "CREATE TEMP TABLE operation_journal_v4_operations AS
             SELECT * FROM operations;
         CREATE TEMP TABLE operation_journal_v4_runner_handoffs AS
             SELECT * FROM runner_handoffs;
         CREATE TEMP TABLE operation_journal_v4_tombstones AS
             SELECT * FROM operation_tombstones;
         CREATE TEMP TABLE operation_journal_v4_metadata AS
             SELECT * FROM operation_journal_metadata;
         CREATE TEMP TABLE operation_journal_v4_completion_intents AS
             SELECT * FROM operation_completion_intents;

         DROP TRIGGER operations_reject_tombstone_overlap_insert;
         DROP TRIGGER operations_reject_tombstone_overlap_update;
         DROP TRIGGER tombstones_reject_operation_overlap_insert;
         DROP TRIGGER tombstones_reject_operation_overlap_update;
         DROP TABLE operation_completion_intents;
         DROP TABLE runner_handoffs;
         DROP TABLE operations;
         DROP TABLE operation_tombstones;
         DROP TABLE operation_journal_metadata;",
    )?;
    connection.execute_batch(&schema_v4_base()?)?;
    connection.execute_batch(SCHEMA_V2_METADATA)?;
    connection.execute_batch(SCHEMA_V3_COMPLETION_INTENTS)?;
    connection.execute_batch(
        "INSERT INTO operations(
             operation_id, repository_id, kind,
             required_capabilities_json, required_capabilities_digest,
             input_json, input_digest, idempotency_key_digest, status,
             progress_completed, progress_total,
             lease_owner, lease_token_digest, lease_expires_at_ms,
             execution_deadline_ms, result_json, error_json,
             created_at_ms, updated_at_ms, terminal_at_ms,
             retention_anchor_ms, retain_until_ms
         )
         SELECT operation_id, repository_id, kind,
                required_capabilities_json, required_capabilities_digest,
                input_json, input_digest, idempotency_key_digest, status,
                progress_completed, progress_total,
                lease_owner, lease_token_digest, lease_expires_at_ms,
                execution_deadline_ms, result_json, error_json,
                created_at_ms, updated_at_ms, terminal_at_ms,
                execution_deadline_ms, retain_until_ms
           FROM operation_journal_v4_operations;
         INSERT INTO operation_tombstones SELECT * FROM operation_journal_v4_tombstones;
         INSERT INTO operation_journal_metadata SELECT * FROM operation_journal_v4_metadata;
         INSERT INTO runner_handoffs SELECT * FROM operation_journal_v4_runner_handoffs;
         INSERT INTO operation_completion_intents
             SELECT * FROM operation_journal_v4_completion_intents;

         DROP TABLE operation_journal_v4_completion_intents;
         DROP TABLE operation_journal_v4_runner_handoffs;
         DROP TABLE operation_journal_v4_operations;
         DROP TABLE operation_journal_v4_tombstones;
         DROP TABLE operation_journal_v4_metadata;",
    )?;
    connection.pragma_update(
        None,
        "user_version",
        RETENTION_ANCHOR_JOURNAL_SCHEMA_VERSION,
    )?;

    validate_v4_schema(connection)?;
    validate_repository_binding(connection, JournalDigest(root_seal.binding_digest()))?;
    validate_connection_integrity(connection)?;
    validate_foreign_keys(connection)?;
    validate_no_operation_tombstone_overlap(connection)?;
    validate_operation_handoff_cardinality(connection)?;
    validate_journal_rows(connection, repository_id, true, true)?;
    Ok(())
}

fn migrate_v4_to_v5(
    connection: &Connection,
    root_seal: &RepositoryRootSeal,
    repository_id: &LogicalRepositoryId,
) -> Result<(), JournalError> {
    validate_v4_schema(connection)?;
    validate_repository_binding(connection, JournalDigest(root_seal.binding_digest()))?;
    validate_connection_integrity(connection)?;
    validate_foreign_keys(connection)?;
    validate_no_operation_tombstone_overlap(connection)?;
    validate_operation_handoff_cardinality(connection)?;
    validate_journal_rows(connection, repository_id, true, true)?;

    connection.execute_batch(
        "CREATE TEMP TABLE operation_journal_v5_operations AS SELECT * FROM operations;
         CREATE TEMP TABLE operation_journal_v5_runner_handoffs AS SELECT * FROM runner_handoffs;
         CREATE TEMP TABLE operation_journal_v5_tombstones AS SELECT * FROM operation_tombstones;
         CREATE TEMP TABLE operation_journal_v5_metadata AS SELECT * FROM operation_journal_metadata;
         CREATE TEMP TABLE operation_journal_v5_completion_intents AS SELECT * FROM operation_completion_intents;

         DROP TRIGGER operations_reject_tombstone_overlap_insert;
         DROP TRIGGER operations_reject_tombstone_overlap_update;
         DROP TRIGGER tombstones_reject_operation_overlap_insert;
         DROP TRIGGER tombstones_reject_operation_overlap_update;
         DROP TABLE operation_completion_intents;
         DROP TABLE runner_handoffs;
         DROP TABLE operations;
         DROP TABLE operation_tombstones;
         DROP TABLE operation_journal_metadata;",
    )?;
    connection.execute_batch(&schema_current_base()?)?;
    connection.execute_batch(SCHEMA_V2_METADATA)?;
    connection.execute_batch(SCHEMA_V3_COMPLETION_INTENTS)?;
    connection.execute_batch(
        "INSERT INTO operations SELECT * FROM operation_journal_v5_operations;
         INSERT INTO operation_tombstones SELECT * FROM operation_journal_v5_tombstones;
         INSERT INTO operation_journal_metadata SELECT * FROM operation_journal_v5_metadata;
         INSERT INTO runner_handoffs SELECT * FROM operation_journal_v5_runner_handoffs;
         INSERT INTO operation_completion_intents SELECT * FROM operation_journal_v5_completion_intents;

         DROP TABLE operation_journal_v5_completion_intents;
         DROP TABLE operation_journal_v5_runner_handoffs;
         DROP TABLE operation_journal_v5_operations;
         DROP TABLE operation_journal_v5_tombstones;
         DROP TABLE operation_journal_v5_metadata;",
    )?;
    connection.pragma_update(None, "user_version", JOURNAL_SCHEMA_VERSION)?;

    validate_schema(connection)?;
    validate_repository_binding(connection, JournalDigest(root_seal.binding_digest()))?;
    validate_connection_integrity(connection)?;
    validate_foreign_keys(connection)?;
    validate_no_operation_tombstone_overlap(connection)?;
    validate_operation_handoff_cardinality(connection)?;
    validate_journal_rows(connection, repository_id, true, true)?;
    Ok(())
}

fn insert_repository_binding(
    connection: &Connection,
    binding_digest: JournalDigest,
) -> Result<(), JournalError> {
    let inserted = connection.execute(
        "INSERT INTO operation_journal_metadata (
             singleton, metadata_version, repository_binding_digest
         ) VALUES (1, 1, ?1)",
        params![binding_digest.as_bytes().as_slice()],
    )?;
    if inserted != 1 {
        return Err(JournalError::IntegrityFailure);
    }
    Ok(())
}

fn validate_repository_binding(
    connection: &Connection,
    expected: JournalDigest,
) -> Result<(), JournalError> {
    let stored: Option<(i64, Vec<u8>)> = connection
        .query_row(
            "SELECT metadata_version, repository_binding_digest
             FROM operation_journal_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((metadata_version, digest)) = stored else {
        return Err(JournalError::IntegrityFailure);
    };
    if metadata_version != 1 {
        return Err(JournalError::IntegrityFailure);
    }
    let actual = JournalDigest::from_database(digest)?;
    if actual != expected {
        return Err(JournalError::RepositoryMismatch);
    }
    Ok(())
}

fn validate_connection_integrity(connection: &Connection) -> Result<(), JournalError> {
    let mut statement = connection
        .prepare("PRAGMA integrity_check")
        .map_err(|_| JournalError::IntegrityFailure)?;
    let mut rows = statement
        .query([])
        .map_err(|_| JournalError::IntegrityFailure)?;
    let Some(first) = rows.next().map_err(|_| JournalError::IntegrityFailure)? else {
        return Err(JournalError::IntegrityFailure);
    };
    let result: String = first.get(0).map_err(|_| JournalError::IntegrityFailure)?;
    if result != "ok"
        || rows
            .next()
            .map_err(|_| JournalError::IntegrityFailure)?
            .is_some()
    {
        return Err(JournalError::IntegrityFailure);
    }
    Ok(())
}

fn validate_journal_entry(path: &Path) -> Result<(), JournalError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            Err(JournalError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "operation journal entry must be a regular file",
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(JournalError::Io(error)),
    }
}

fn validate_no_operation_tombstone_overlap(connection: &Connection) -> Result<(), JournalError> {
    let overlap: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM operations AS operation
             JOIN operation_tombstones AS tombstone
               ON operation.operation_id = tombstone.operation_id
               OR (
                   operation.repository_id = tombstone.repository_id
                   AND operation.kind = tombstone.kind
                   AND operation.idempotency_key_digest = tombstone.idempotency_key_digest
               )
         )",
        [],
        |row| row.get(0),
    )?;
    if overlap {
        return Err(JournalError::IntegrityFailure);
    }
    Ok(())
}

fn validate_operation_handoff_cardinality(connection: &Connection) -> Result<(), JournalError> {
    let (operation_count, handoff_count): (i64, i64) = connection.query_row(
        "SELECT (SELECT COUNT(*) FROM operations),
                (SELECT COUNT(*) FROM runner_handoffs)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if operation_count != handoff_count {
        return Err(JournalError::IntegrityFailure);
    }
    let missing_or_orphan: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM operations AS operation
             LEFT JOIN runner_handoffs AS handoff USING(operation_id)
             WHERE handoff.operation_id IS NULL
         ) OR EXISTS(
             SELECT 1 FROM runner_handoffs AS handoff
             LEFT JOIN operations AS operation USING(operation_id)
             WHERE operation.operation_id IS NULL
         )",
        [],
        |row| row.get(0),
    )?;
    if missing_or_orphan {
        return Err(JournalError::IntegrityFailure);
    }
    Ok(())
}

fn legacy_journal_is_empty(connection: &Connection) -> Result<bool, JournalError> {
    connection
        .query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM operations LIMIT 1)
                    AND NOT EXISTS(SELECT 1 FROM runner_handoffs LIMIT 1)
                    AND NOT EXISTS(SELECT 1 FROM operation_tombstones LIMIT 1)",
            [],
            |row| row.get(0),
        )
        .map_err(JournalError::from)
}

fn validate_journal_rows(
    connection: &Connection,
    repository_id: &LogicalRepositoryId,
    include_completion_intents: bool,
    include_retention_anchor: bool,
) -> Result<(), JournalError> {
    {
        let operation_columns = qualified_columns(
            if include_retention_anchor {
                OPERATION_COLUMNS
            } else {
                LEGACY_OPERATION_COLUMNS
            },
            "operation",
        );
        let handoff_columns = qualified_columns(HANDOFF_COLUMNS, "handoff");
        let mut statement = connection.prepare(&format!(
            "SELECT {operation_columns}, {handoff_columns}
             FROM operations AS operation
             LEFT JOIN runner_handoffs AS handoff USING(operation_id)
             ORDER BY operation.operation_id"
        ))?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next().map_err(map_database_decode_error)? {
            let operation = if include_retention_anchor {
                raw_operation_from_row(row)
            } else {
                raw_legacy_operation_from_row(row)
            }
            .map_err(map_database_decode_error)?;
            let raw_handoff =
                raw_handoff_from_row_at(row, if include_retention_anchor { 22 } else { 21 })
                    .map_err(map_database_decode_error)?;
            let record = decode_operation(operation)?;
            if record.repository_id != *repository_id {
                return Err(JournalError::IntegrityFailure);
            }
            let handoff = decode_handoff(raw_handoff)?;
            validate_operation_handoff(&record, &handoff)?;
        }
    }

    {
        let mut statement = connection.prepare(&format!(
            "SELECT {TOMBSTONE_COLUMNS} FROM operation_tombstones ORDER BY operation_id"
        ))?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next().map_err(map_database_decode_error)? {
            let tombstone = raw_tombstone_from_row(row).map_err(map_database_decode_error)?;
            validate_tombstone(&tombstone)?;
            if tombstone.repository_id != repository_id.as_str() {
                return Err(JournalError::IntegrityFailure);
            }
        }
    }

    if include_completion_intents {
        let mut statement = connection.prepare(
            "SELECT intent.operation_id, operation.kind,
                    operation.input_json, operation.input_digest,
                    handoff.operation_kind, handoff.payload_json, handoff.payload_digest,
                    intent.result_json, intent.result_digest, intent.decided_at_ms,
                    operation.status, operation.updated_at_ms,
                    operation.created_at_ms, operation.execution_deadline_ms,
                    operation.lease_expires_at_ms, handoff.claimed_at_ms
             FROM operation_completion_intents AS intent
             JOIN operations AS operation USING(operation_id)
             LEFT JOIN runner_handoffs AS handoff USING(operation_id)
             ORDER BY intent.operation_id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next().map_err(map_database_decode_error)? {
            let intent = completion_intent_from_row(row).map_err(map_database_decode_error)?;
            let status = OperationStatus::parse(&row.get::<_, String>(10)?)?;
            let updated_at_ms: i64 = row.get(11)?;
            let created_at_ms: i64 = row.get(12)?;
            let execution_deadline_ms: i64 = row.get(13)?;
            let lease_expires_at_ms: Option<i64> = row.get(14)?;
            let claimed_at_ms: Option<i64> = row.get(15)?;
            if validate_timestamp(intent.decided_at_ms).is_err()
                || status != OperationStatus::Running
                || intent.decided_at_ms != updated_at_ms
                || intent.decided_at_ms < created_at_ms
                || intent.decided_at_ms >= execution_deadline_ms
                || lease_expires_at_ms
                    .is_none_or(|expires_at_ms| intent.decided_at_ms >= expires_at_ms)
                || claimed_at_ms.is_none_or(|claimed_at_ms| intent.decided_at_ms < claimed_at_ms)
            {
                return Err(JournalError::IntegrityFailure);
            }
        }
    }
    Ok(())
}

fn validate_columns(
    connection: &Connection,
    table: &'static str,
    expected: &[&str],
) -> Result<(), JournalError> {
    let sql = match table {
        "operations" => "PRAGMA table_info(operations)",
        "runner_handoffs" => "PRAGMA table_info(runner_handoffs)",
        "operation_tombstones" => "PRAGMA table_info(operation_tombstones)",
        "operation_journal_metadata" => "PRAGMA table_info(operation_journal_metadata)",
        "operation_completion_intents" => "PRAGMA table_info(operation_completion_intents)",
        _ => return Err(JournalError::IntegrityFailure),
    };
    let mut statement = connection.prepare(sql)?;
    let mut rows = statement.query([])?;
    for expected_column in expected {
        let Some(row) = rows.next()? else {
            return Err(JournalError::IntegrityFailure);
        };
        let actual_column: String = row.get(1)?;
        if actual_column != *expected_column {
            return Err(JournalError::IntegrityFailure);
        }
    }
    if rows.next()?.is_some() {
        return Err(JournalError::IntegrityFailure);
    }
    Ok(())
}

fn validate_schema_objects(
    connection: &Connection,
    reference: &Connection,
) -> Result<(), JournalError> {
    let expected = schema_objects(reference)?;
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema
         WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'
         ORDER BY type, name",
    )?;
    let mut rows = statement.query([])?;
    for expected_object in expected {
        let Some(row) = rows.next()? else {
            return Err(JournalError::IntegrityFailure);
        };
        if schema_object_from_row(row)? != expected_object {
            return Err(JournalError::IntegrityFailure);
        }
    }
    if rows.next()?.is_some() {
        return Err(JournalError::IntegrityFailure);
    }
    Ok(())
}

fn schema_objects(
    connection: &Connection,
) -> Result<Vec<(String, String, String, String)>, JournalError> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema
         WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'
         ORDER BY type, name",
    )?;
    statement
        .query_map([], schema_object_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(JournalError::from)
}

fn schema_object_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(String, String, String, String)> {
    let sql: String = row.get(3)?;
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        normalize_schema_sql(&sql),
    ))
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.trim().trim_end_matches(';').trim_end().to_owned()
}

fn validate_foreign_keys(connection: &Connection) -> Result<(), JournalError> {
    let enabled: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    if enabled != 1 {
        return Err(JournalError::IntegrityFailure);
    }
    let mut statement = connection.prepare("PRAGMA foreign_key_check")?;
    if statement.query([])?.next()?.is_some() {
        return Err(JournalError::IntegrityFailure);
    }
    Ok(())
}

fn map_database_decode_error(error: rusqlite::Error) -> JournalError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(_) => JournalError::IntegrityFailure,
        rusqlite::Error::SqliteFailure(sqlite_error, _)
            if sqlite_error.code == rusqlite::ffi::ErrorCode::TooBig =>
        {
            JournalError::IntegrityFailure
        }
        other => JournalError::Storage(other),
    }
}

fn validate_secret_input(bytes: &[u8], maximum: usize) -> Result<(), JournalError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(JournalError::InvalidArgument);
    }
    Ok(())
}

fn digest_lease_token(token: &[u8]) -> Result<JournalDigest, JournalError> {
    validate_secret_input(token, MAX_LEASE_TOKEN_BYTES)?;
    Ok(JournalDigest::sha256(token))
}

fn checked_add(value: i64, delta: i64) -> Result<i64, JournalError> {
    value
        .checked_add(delta)
        .ok_or(JournalError::InvalidArgument)
}

fn validate_timestamp(timestamp_ms: i64) -> Result<(), JournalError> {
    if timestamp_ms < 0 {
        return Err(JournalError::InvalidArgument);
    }
    Ok(())
}

fn u64_to_i64(value: u64) -> Result<i64, JournalError> {
    i64::try_from(value).map_err(|_| JournalError::InvalidArgument)
}

fn i64_to_u64(value: i64) -> Result<u64, JournalError> {
    u64::try_from(value).map_err(|_| JournalError::IntegrityFailure)
}

fn new_operation_id() -> Result<OperationId, JournalError> {
    let mut random_bytes = [0_u8; 16];
    getrandom::fill(&mut random_bytes).map_err(|_| JournalError::EntropyUnavailable)?;
    operation_id_from_random_bytes(random_bytes)
}

fn operation_id_from_random_bytes(random_bytes: [u8; 16]) -> Result<OperationId, JournalError> {
    let mut encoded = String::with_capacity(35);
    encoded.push_str("op_");
    for byte in random_bytes {
        use fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    OperationId::parse(encoded).map_err(|_| JournalError::IntegrityFailure)
}

fn validate_operation_id(operation_id: &OperationId) -> Result<(), JournalError> {
    let suffix = operation_id
        .as_str()
        .strip_prefix("op_")
        .ok_or(JournalError::IntegrityFailure)?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(JournalError::IntegrityFailure);
    }
    Ok(())
}

fn validate_submission_binding(
    record: &OperationRecord,
    request: &SubmitRequest,
) -> Result<(), JournalError> {
    if record.input_digest != request.input_digest
        || record.normalized_input != request.normalized_input
        || record.required_capabilities != request.required_capabilities
    {
        return Err(JournalError::IdempotencyConflict);
    }
    Ok(())
}

fn validate_repository(
    record: &OperationRecord,
    repository_id: &LogicalRepositoryId,
) -> Result<(), JournalError> {
    if &record.repository_id != repository_id {
        return Err(JournalError::RepositoryMismatch);
    }
    Ok(())
}

fn validate_enabled_capabilities(
    enabled_capabilities: &CapabilitySet,
    record: &OperationRecord,
) -> Result<(), JournalError> {
    if !enabled_capabilities.contains_all(&record.required_capabilities) {
        return Err(JournalError::CapabilityDenied);
    }
    Ok(())
}

fn validate_update_time(record: &OperationRecord, now_ms: i64) -> Result<(), JournalError> {
    if now_ms < record.updated_at_ms {
        return Err(JournalError::InvalidArgument);
    }
    Ok(())
}

fn validate_before_deadline(record: &OperationRecord, now_ms: i64) -> Result<(), JournalError> {
    if now_ms >= record.execution_deadline_ms {
        return Err(JournalError::DeadlineExceeded);
    }
    Ok(())
}

fn validate_lease_window(
    record: &OperationRecord,
    now_ms: i64,
    expires_at_ms: i64,
) -> Result<(), JournalError> {
    validate_before_deadline(record, now_ms)?;
    if expires_at_ms <= now_ms || expires_at_ms > record.execution_deadline_ms {
        return Err(JournalError::InvalidArgument);
    }
    Ok(())
}

fn validate_lease_token(
    record: &OperationRecord,
    supplied_digest: JournalDigest,
) -> Result<(), JournalError> {
    let lease = record.lease.as_ref().ok_or(JournalError::LeaseMismatch)?;
    if !digest_equal(lease.token_digest, supplied_digest) {
        return Err(JournalError::LeaseMismatch);
    }
    Ok(())
}

fn validate_active_lease(
    record: &OperationRecord,
    supplied_digest: JournalDigest,
    now_ms: i64,
) -> Result<(), JournalError> {
    validate_lease_token(record, supplied_digest)?;
    if record
        .lease
        .as_ref()
        .is_none_or(|lease| lease.expires_at_ms <= now_ms)
    {
        return Err(JournalError::LeaseExpired);
    }
    Ok(())
}

fn digest_equal(left: JournalDigest, right: JournalDigest) -> bool {
    left.0
        .iter()
        .zip(right.0)
        .fold(0_u8, |difference, (left, right)| {
            difference | (*left ^ right)
        })
        == 0
}

fn transition_to_deadline_failure(
    connection: &Connection,
    record: &OperationRecord,
    error: &CanonicalJson,
) -> Result<OperationRecord, JournalError> {
    if !record.status.allows_transition_to(OperationStatus::Failed)
        || record.updated_at_ms > record.execution_deadline_ms
    {
        return Err(JournalError::IntegrityFailure);
    }
    let terminal_at_ms = record.execution_deadline_ms;
    let terminal_retain_until_ms = checked_add(terminal_at_ms, TERMINAL_RETENTION_MS)
        .map_err(|_| JournalError::IntegrityFailure)?;
    let maximum_retain_until_ms = checked_add(record.created_at_ms, MAX_TASK_TTL_MS_I64)
        .map_err(|_| JournalError::IntegrityFailure)?;
    let retain_until_ms = record.retain_until_ms.max(terminal_retain_until_ms);
    if retain_until_ms > maximum_retain_until_ms {
        return Err(JournalError::IntegrityFailure);
    }
    let updated = connection.execute(
        "UPDATE operations
         SET status = 'failed', error_json = ?1,
             lease_owner = NULL, lease_token_digest = NULL,
             lease_expires_at_ms = NULL, updated_at_ms = ?2,
             terminal_at_ms = ?2, retain_until_ms = ?3
         WHERE operation_id = ?4 AND status = ?5",
        params![
            error.as_str(),
            terminal_at_ms,
            retain_until_ms,
            record.operation_id.as_str(),
            record.status.as_str(),
        ],
    )?;
    if updated != 1 {
        return Err(JournalError::IntegrityFailure);
    }
    let completed = connection.execute(
        "UPDATE runner_handoffs
         SET completed_at_ms = ?1
         WHERE operation_id = ?2 AND completed_at_ms IS NULL",
        params![terminal_at_ms, record.operation_id.as_str()],
    )?;
    if completed != 1 {
        return Err(JournalError::IntegrityFailure);
    }
    select_validated_by_id(connection, &record.operation_id)
}

fn transition_to_execution_state_unknown(
    connection: &Connection,
    record: &OperationRecord,
    now_ms: i64,
) -> Result<OperationRecord, JournalError> {
    if record.kind != OperationKind::ResolveBuildSubmit
        || !matches!(
            record.status,
            OperationStatus::Running | OperationStatus::Cancelling
        )
        || record.updated_at_ms > now_ms
        || record.execution_deadline_ms <= now_ms
        || record
            .lease
            .as_ref()
            .is_some_and(|lease| lease.expires_at_ms > now_ms)
    {
        return Err(JournalError::IntegrityFailure);
    }
    let error = CanonicalJson::from_database(EXECUTION_STATE_UNKNOWN_ERROR_JSON.to_owned())?;
    let retain_until_ms = record
        .retain_until_ms
        .max(checked_add(now_ms, TERMINAL_RETENTION_MS)?);
    let maximum_retain_until_ms = checked_add(record.created_at_ms, MAX_TASK_TTL_MS_I64)
        .map_err(|_| JournalError::IntegrityFailure)?;
    if retain_until_ms > maximum_retain_until_ms {
        return Err(JournalError::IntegrityFailure);
    }
    let updated = connection.execute(
        "UPDATE operations
         SET status = 'failed', error_json = ?1,
             lease_owner = NULL, lease_token_digest = NULL,
             lease_expires_at_ms = NULL, updated_at_ms = ?2,
             terminal_at_ms = ?2, retain_until_ms = ?3
         WHERE operation_id = ?4 AND status = ?5",
        params![
            error.as_str(),
            now_ms,
            retain_until_ms,
            record.operation_id.as_str(),
            record.status.as_str(),
        ],
    )?;
    if updated != 1 {
        return Err(JournalError::IntegrityFailure);
    }
    let completed = connection.execute(
        "UPDATE runner_handoffs
         SET completed_at_ms = ?1
         WHERE operation_id = ?2 AND completed_at_ms IS NULL",
        params![now_ms, record.operation_id.as_str()],
    )?;
    if completed != 1 {
        return Err(JournalError::IntegrityFailure);
    }
    select_validated_by_id(connection, &record.operation_id)
}

fn load_active_record(
    connection: &Connection,
    repository_id: &LogicalRepositoryId,
    operation_id: &OperationId,
    now_ms: i64,
) -> Result<OperationRecord, JournalError> {
    let raw =
        select_operation_by_id(connection, operation_id.as_str())?.ok_or(JournalError::NotFound)?;
    let record = validated_record(connection, raw)?;
    validate_record_not_from_future(&record, now_ms)?;
    if &record.repository_id != repository_id {
        return Err(JournalError::IntegrityFailure);
    }
    if now_ms >= record.retain_until_ms {
        return Err(JournalError::Expired);
    }
    Ok(record)
}

fn load_completion_intent_record(
    connection: &Connection,
    repository_id: &LogicalRepositoryId,
    operation_id: &OperationId,
    now_ms: i64,
) -> Result<OperationRecord, JournalError> {
    let raw =
        select_operation_by_id(connection, operation_id.as_str())?.ok_or(JournalError::NotFound)?;
    let record = validated_record(connection, raw)?;
    validate_record_not_from_future(&record, now_ms)?;
    if &record.repository_id != repository_id {
        return Err(JournalError::IntegrityFailure);
    }
    Ok(record)
}

fn validate_completion_intent(
    record: &OperationRecord,
    intent: &CompletionIntent,
    now_ms: i64,
) -> Result<(), JournalError> {
    validate_timestamp(intent.decided_at_ms).map_err(|_| JournalError::IntegrityFailure)?;
    if intent.operation_id != record.operation_id
        || intent.kind != record.kind
        || intent.normalized_input != record.normalized_input
        || record.status != OperationStatus::Running
        || intent.decided_at_ms != record.updated_at_ms
        || intent.decided_at_ms >= record.execution_deadline_ms
        || intent.decided_at_ms > now_ms
        || record
            .lease
            .as_ref()
            .is_none_or(|lease| intent.decided_at_ms >= lease.expires_at_ms)
    {
        return Err(JournalError::IntegrityFailure);
    }
    Ok(())
}

fn load_record_for_deadline_failure(
    connection: &Connection,
    repository_id: &LogicalRepositoryId,
    operation_id: &OperationId,
    now_ms: i64,
) -> Result<OperationRecord, JournalError> {
    if let Some(raw) = select_operation_by_id(connection, operation_id.as_str())? {
        let record = validated_record(connection, raw)?;
        validate_record_not_from_future(&record, now_ms)?;
        if &record.repository_id != repository_id {
            return Err(JournalError::IntegrityFailure);
        }
        return Ok(record);
    }
    if let Some(tombstone) = select_tombstone_by_id(connection, operation_id.as_str())? {
        validate_tombstone(&tombstone)?;
        if tombstone.repository_id != repository_id.as_str() {
            return Err(JournalError::IntegrityFailure);
        }
        if now_ms < tombstone.tombstone_until_ms {
            return Err(JournalError::Expired);
        }
    }
    Err(JournalError::NotFound)
}

fn load_record_or_tombstone(
    connection: &Connection,
    repository_id: &LogicalRepositoryId,
    operation_id: &OperationId,
    now_ms: i64,
) -> Result<OperationRecord, JournalError> {
    if let Some(raw) = select_operation_by_id(connection, operation_id.as_str())? {
        let record = validated_record(connection, raw)?;
        validate_record_not_from_future(&record, now_ms)?;
        if &record.repository_id != repository_id {
            return Err(JournalError::IntegrityFailure);
        }
        if now_ms >= record.retain_until_ms {
            return Err(JournalError::Expired);
        }
        return Ok(record);
    }
    if let Some(tombstone) = select_tombstone_by_id(connection, operation_id.as_str())? {
        validate_tombstone(&tombstone)?;
        if tombstone.repository_id != repository_id.as_str() {
            return Err(JournalError::IntegrityFailure);
        }
        if now_ms < tombstone.tombstone_until_ms {
            return Err(JournalError::Expired);
        }
    }
    Err(JournalError::NotFound)
}

fn validate_record_not_from_future(
    record: &OperationRecord,
    now_ms: i64,
) -> Result<(), JournalError> {
    if record.updated_at_ms > now_ms
        || record
            .terminal_at_ms
            .is_some_and(|terminal_at_ms| terminal_at_ms > now_ms)
    {
        return Err(JournalError::IntegrityFailure);
    }
    Ok(())
}

fn select_validated_by_id(
    connection: &Connection,
    operation_id: &OperationId,
) -> Result<OperationRecord, JournalError> {
    let raw = select_operation_by_id(connection, operation_id.as_str())?
        .ok_or(JournalError::IntegrityFailure)?;
    validated_record(connection, raw)
}

const LEGACY_OPERATION_COLUMNS: &str = "operation_id, repository_id, kind,
    required_capabilities_json, required_capabilities_digest,
    input_json, input_digest, idempotency_key_digest, status,
    progress_completed, progress_total,
    lease_owner, lease_token_digest, lease_expires_at_ms,
    execution_deadline_ms, result_json, error_json,
    created_at_ms, updated_at_ms, terminal_at_ms, retain_until_ms";
const OPERATION_COLUMNS: &str = "operation_id, repository_id, kind,
    required_capabilities_json, required_capabilities_digest,
    input_json, input_digest, idempotency_key_digest, status,
    progress_completed, progress_total,
    lease_owner, lease_token_digest, lease_expires_at_ms,
    execution_deadline_ms, result_json, error_json,
    created_at_ms, updated_at_ms, terminal_at_ms,
    retention_anchor_ms, retain_until_ms";

fn qualified_columns(columns: &str, table: &str) -> String {
    columns
        .split(',')
        .map(str::trim)
        .map(|column| format!("{table}.{column}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Clone)]
struct RawOperation {
    operation_id: String,
    repository_id: String,
    kind: String,
    required_capabilities_json: String,
    required_capabilities_digest: Vec<u8>,
    input_json: String,
    input_digest: Vec<u8>,
    idempotency_key_digest: Vec<u8>,
    status: String,
    progress_completed: i64,
    progress_total: i64,
    lease_owner: Option<String>,
    lease_token_digest: Option<Vec<u8>>,
    lease_expires_at_ms: Option<i64>,
    execution_deadline_ms: i64,
    result_json: Option<String>,
    error_json: Option<String>,
    created_at_ms: i64,
    updated_at_ms: i64,
    terminal_at_ms: Option<i64>,
    retention_anchor_ms: i64,
    retain_until_ms: i64,
}

fn raw_operation_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawOperation> {
    Ok(RawOperation {
        operation_id: row.get(0)?,
        repository_id: row.get(1)?,
        kind: row.get(2)?,
        required_capabilities_json: row.get(3)?,
        required_capabilities_digest: row.get(4)?,
        input_json: row.get(5)?,
        input_digest: row.get(6)?,
        idempotency_key_digest: row.get(7)?,
        status: row.get(8)?,
        progress_completed: row.get(9)?,
        progress_total: row.get(10)?,
        lease_owner: row.get(11)?,
        lease_token_digest: row.get(12)?,
        lease_expires_at_ms: row.get(13)?,
        execution_deadline_ms: row.get(14)?,
        result_json: row.get(15)?,
        error_json: row.get(16)?,
        created_at_ms: row.get(17)?,
        updated_at_ms: row.get(18)?,
        terminal_at_ms: row.get(19)?,
        retention_anchor_ms: row.get(20)?,
        retain_until_ms: row.get(21)?,
    })
}

fn raw_legacy_operation_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawOperation> {
    let execution_deadline_ms = row.get(14)?;
    Ok(RawOperation {
        operation_id: row.get(0)?,
        repository_id: row.get(1)?,
        kind: row.get(2)?,
        required_capabilities_json: row.get(3)?,
        required_capabilities_digest: row.get(4)?,
        input_json: row.get(5)?,
        input_digest: row.get(6)?,
        idempotency_key_digest: row.get(7)?,
        status: row.get(8)?,
        progress_completed: row.get(9)?,
        progress_total: row.get(10)?,
        lease_owner: row.get(11)?,
        lease_token_digest: row.get(12)?,
        lease_expires_at_ms: row.get(13)?,
        execution_deadline_ms,
        result_json: row.get(15)?,
        error_json: row.get(16)?,
        created_at_ms: row.get(17)?,
        updated_at_ms: row.get(18)?,
        terminal_at_ms: row.get(19)?,
        retention_anchor_ms: execution_deadline_ms,
        retain_until_ms: row.get(20)?,
    })
}

fn select_operation_by_id(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<RawOperation>, JournalError> {
    connection
        .query_row(
            &format!("SELECT {OPERATION_COLUMNS} FROM operations WHERE operation_id = ?1"),
            params![operation_id],
            raw_operation_from_row,
        )
        .optional()
        .map_err(map_database_decode_error)
}

fn select_operation_by_scope(
    connection: &Connection,
    repository_id: &str,
    kind: &str,
    idempotency_key_digest: JournalDigest,
) -> Result<Option<RawOperation>, JournalError> {
    connection
        .query_row(
            &format!(
                "SELECT {OPERATION_COLUMNS} FROM operations
                 WHERE repository_id = ?1 AND kind = ?2 AND idempotency_key_digest = ?3"
            ),
            params![
                repository_id,
                kind,
                idempotency_key_digest.as_bytes().as_slice()
            ],
            raw_operation_from_row,
        )
        .optional()
        .map_err(map_database_decode_error)
}

fn select_operation_by_scope_for_schema(
    connection: &Connection,
    repository_id: &str,
    kind: &str,
    idempotency_key_digest: JournalDigest,
    include_retention_anchor: bool,
) -> Result<Option<RawOperation>, JournalError> {
    let columns = if include_retention_anchor {
        OPERATION_COLUMNS
    } else {
        LEGACY_OPERATION_COLUMNS
    };
    connection
        .query_row(
            &format!(
                "SELECT {columns} FROM operations
                 WHERE repository_id = ?1 AND kind = ?2 AND idempotency_key_digest = ?3"
            ),
            params![
                repository_id,
                kind,
                idempotency_key_digest.as_bytes().as_slice()
            ],
            |row| {
                if include_retention_anchor {
                    raw_operation_from_row(row)
                } else {
                    raw_legacy_operation_from_row(row)
                }
            },
        )
        .optional()
        .map_err(map_database_decode_error)
}

fn completion_intent_exists(
    connection: &Connection,
    operation_id: &OperationId,
) -> Result<bool, JournalError> {
    connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM operation_completion_intents WHERE operation_id=?1
             )",
            params![operation_id.as_str()],
            |row| row.get(0),
        )
        .map_err(JournalError::from)
}

fn select_completion_intent(
    connection: &Connection,
    operation_id: &OperationId,
) -> Result<Option<CompletionIntent>, JournalError> {
    connection
        .query_row(
            "SELECT intent.operation_id, operation.kind,
                    operation.input_json, operation.input_digest,
                    handoff.operation_kind, handoff.payload_json, handoff.payload_digest,
                    intent.result_json, intent.result_digest, intent.decided_at_ms
             FROM operation_completion_intents AS intent
             JOIN operations AS operation USING(operation_id)
             LEFT JOIN runner_handoffs AS handoff USING(operation_id)
             WHERE intent.operation_id=?1",
            params![operation_id.as_str()],
            completion_intent_from_row,
        )
        .optional()
        .map_err(map_database_decode_error)
}

fn select_next_completion_intent(
    connection: &Connection,
) -> Result<Option<CompletionIntent>, JournalError> {
    connection
        .query_row(
            "SELECT intent.operation_id, operation.kind,
                    operation.input_json, operation.input_digest,
                    handoff.operation_kind, handoff.payload_json, handoff.payload_digest,
                    intent.result_json, intent.result_digest, intent.decided_at_ms
             FROM operation_completion_intents AS intent
             JOIN operations AS operation USING(operation_id)
             LEFT JOIN runner_handoffs AS handoff USING(operation_id)
             ORDER BY intent.decided_at_ms, intent.operation_id
             LIMIT 1",
            [],
            completion_intent_from_row,
        )
        .optional()
        .map_err(map_database_decode_error)
}

fn completion_intent_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CompletionIntent> {
    let operation_id = OperationId::parse(row.get::<_, String>(0)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let kind = OperationKind::parse(&row.get::<_, String>(1)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let input_encoded: String = row.get(2)?;
    let input_stored_digest: Vec<u8> = row.get(3)?;
    let normalized_input = CanonicalInput::from_database(input_encoded, input_stored_digest)
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Blob,
                Box::new(error),
            )
        })?;
    let handoff_kind = OperationKind::parse(&row.get::<_, String>(4)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let handoff_encoded: String = row.get(5)?;
    let handoff_stored_digest: Vec<u8> = row.get(6)?;
    let handoff_input = CanonicalInput::from_database(handoff_encoded, handoff_stored_digest)
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                6,
                rusqlite::types::Type::Blob,
                Box::new(error),
            )
        })?;
    if handoff_kind != kind || handoff_input != normalized_input {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            6,
            rusqlite::types::Type::Blob,
            Box::new(JournalError::IntegrityFailure),
        ));
    }
    let encoded: String = row.get(7)?;
    let stored_digest: Vec<u8> = row.get(8)?;
    let observed_digest = JournalDigest::sha256(encoded.as_bytes());
    let expected_digest = JournalDigest::from_database(stored_digest).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Blob, Box::new(error))
    })?;
    if observed_digest != expected_digest {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            8,
            rusqlite::types::Type::Blob,
            Box::new(JournalError::IntegrityFailure),
        ));
    }
    let result = CanonicalJson::from_database(encoded).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(CompletionIntent {
        operation_id,
        kind,
        normalized_input,
        result,
        decided_at_ms: row.get(9)?,
    })
}

fn select_next_claim_candidate(
    connection: &Connection,
    repository_id: &str,
    now_ms: i64,
    enabled_kinds: EnabledOperationKinds,
) -> Result<Option<RawOperation>, JournalError> {
    connection
        .query_row(
            &format!(
                "SELECT {OPERATION_COLUMNS} FROM operations AS candidate
                 WHERE candidate.repository_id = ?5
                   AND NOT EXISTS (SELECT 1 FROM operation_completion_intents)
                   AND candidate.status IN ('queued', 'running', 'cancelling')
                   AND candidate.execution_deadline_ms > ?6
                   AND (
                       (?1 AND candidate.kind IN ('scan_submit', 'runtime_trace_import_submit')
                           AND NOT EXISTS (
                               SELECT 1 FROM operations AS active_writer
                               WHERE active_writer.repository_id = candidate.repository_id
                                 AND active_writer.kind IN (
                                     'scan_submit', 'runtime_trace_import_submit'
                                 )
                                 AND active_writer.status IN ('running', 'cancelling')
                                 AND active_writer.lease_expires_at_ms > ?6
                           ))
                       OR (?2 AND candidate.kind = 'export_file')
                       OR (?3 AND candidate.kind IN ('daemon_start_submit', 'daemon_stop'))
                       OR (?4 AND candidate.kind = 'resolve_build_submit'
                           AND NOT EXISTS (
                               SELECT 1 FROM operations AS active_project_exec
                               WHERE active_project_exec.repository_id = candidate.repository_id
                                 AND active_project_exec.kind = 'resolve_build_submit'
                                 AND active_project_exec.status IN ('running', 'cancelling')
                                 AND active_project_exec.lease_expires_at_ms > ?6
                           ))
                   )
                   AND (
                       candidate.status = 'queued'
                       OR (
                           candidate.status IN ('running', 'cancelling')
                           AND (
                               candidate.lease_expires_at_ms IS NULL
                               OR candidate.lease_expires_at_ms <= ?6
                           )
                       )
                   )
                 ORDER BY candidate.created_at_ms, candidate.operation_id
                 LIMIT 1"
            ),
            params![
                enabled_kinds.store_write,
                enabled_kinds.repository_write,
                enabled_kinds.daemon_control,
                enabled_kinds.project_exec,
                repository_id,
                now_ms,
            ],
            raw_operation_from_row,
        )
        .optional()
        .map_err(map_database_decode_error)
}

fn fail_lost_project_exec_leases(
    connection: &Connection,
    repository_id: &LogicalRepositoryId,
    now_ms: i64,
) -> Result<(), JournalError> {
    let operation_ids = {
        let mut statement = connection.prepare(
            "SELECT substr(operation_id, 1, 36) FROM operations
             WHERE repository_id = ?1
               AND kind = 'resolve_build_submit'
               AND status IN ('running', 'cancelling')
               AND execution_deadline_ms > ?2
               AND (lease_expires_at_ms IS NULL OR lease_expires_at_ms <= ?2)
             ORDER BY created_at_ms, operation_id
             LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![repository_id.as_str(), now_ms, MAX_PURGE_BATCH_SIZE as i64],
            |row| row.get::<_, String>(0),
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(map_database_decode_error)?
    };
    for operation_id in operation_ids {
        let operation_id =
            OperationId::parse(operation_id).map_err(|_| JournalError::IntegrityFailure)?;
        let record = select_validated_by_id(connection, &operation_id)?;
        if &record.repository_id != repository_id {
            return Err(JournalError::IntegrityFailure);
        }
        transition_to_execution_state_unknown(connection, &record, now_ms)?;
    }
    Ok(())
}

fn validated_record(
    connection: &Connection,
    raw: RawOperation,
) -> Result<OperationRecord, JournalError> {
    let raw_handoff = select_handoff_by_id(connection, &raw.operation_id)?
        .ok_or(JournalError::IntegrityFailure)?;
    let record = decode_operation(raw)?;
    let handoff = decode_handoff(raw_handoff)?;
    validate_operation_handoff(&record, &handoff)?;
    Ok(record)
}

fn decode_operation(raw: RawOperation) -> Result<OperationRecord, JournalError> {
    let operation_id =
        OperationId::parse(&raw.operation_id).map_err(|_| JournalError::IntegrityFailure)?;
    validate_operation_id(&operation_id)?;
    let repository_id = LogicalRepositoryId::parse(&raw.repository_id)
        .map_err(|_| JournalError::IntegrityFailure)?;
    let kind = OperationKind::parse(&raw.kind).map_err(|_| JournalError::IntegrityFailure)?;
    let required_capabilities = CapabilitySet::from_database(
        raw.required_capabilities_json,
        raw.required_capabilities_digest,
    )?;
    if required_capabilities
        != kind
            .required_capabilities()
            .map_err(|_| JournalError::IntegrityFailure)?
    {
        return Err(JournalError::IntegrityFailure);
    }
    let normalized_input = CanonicalInput::from_database(raw.input_json, raw.input_digest)?;
    let input_digest = normalized_input.digest();
    let idempotency_key_digest = JournalDigest::from_database(raw.idempotency_key_digest)?;
    let status = OperationStatus::parse(&raw.status)?;
    let progress = OperationProgress::new(
        i64_to_u64(raw.progress_completed)?,
        i64_to_u64(raw.progress_total)?,
    )
    .map_err(|_| JournalError::IntegrityFailure)?;
    validate_timestamp(raw.created_at_ms).map_err(|_| JournalError::IntegrityFailure)?;
    let maximum_submitted_retain_until_ms = checked_add(raw.created_at_ms, MAX_TASK_TTL_MS_I64)
        .map_err(|_| JournalError::IntegrityFailure)?;
    let submitted_retain_until_ms = checked_add(raw.execution_deadline_ms, TERMINAL_RETENTION_MS)
        .map_err(|_| JournalError::IntegrityFailure)?;
    let anchored_retain_until_ms = checked_add(raw.retention_anchor_ms, TERMINAL_RETENTION_MS)
        .map_err(|_| JournalError::IntegrityFailure)?;
    if raw.updated_at_ms < raw.created_at_ms
        || raw.updated_at_ms > raw.execution_deadline_ms
        || raw.execution_deadline_ms <= raw.created_at_ms
        || submitted_retain_until_ms > maximum_submitted_retain_until_ms
        || raw.retention_anchor_ms < raw.execution_deadline_ms
        || raw.retain_until_ms != anchored_retain_until_ms
    {
        return Err(JournalError::IntegrityFailure);
    }

    let lease = match (
        raw.lease_owner,
        raw.lease_token_digest,
        raw.lease_expires_at_ms,
    ) {
        (None, None, None) => None,
        (Some(owner), Some(token_digest), Some(expires_at_ms)) => {
            if status.is_terminal()
                || expires_at_ms <= raw.created_at_ms
                || expires_at_ms > raw.execution_deadline_ms
            {
                return Err(JournalError::IntegrityFailure);
            }
            Some(OperationLease {
                owner: LeaseOwner::parse(owner).map_err(|_| JournalError::IntegrityFailure)?,
                token_digest: JournalDigest::from_database(token_digest)?,
                expires_at_ms,
            })
        }
        _ => return Err(JournalError::IntegrityFailure),
    };
    if status == OperationStatus::Queued && lease.is_some() {
        return Err(JournalError::IntegrityFailure);
    }

    let result = raw
        .result_json
        .map(CanonicalJson::from_database)
        .transpose()?;
    let error = raw
        .error_json
        .map(CanonicalJson::from_database)
        .transpose()?;
    match status {
        OperationStatus::Queued | OperationStatus::Running | OperationStatus::Cancelling => {
            if raw.terminal_at_ms.is_some() || result.is_some() || error.is_some() {
                return Err(JournalError::IntegrityFailure);
            }
        }
        OperationStatus::Completed => {
            if result.is_none() || error.is_some() || raw.terminal_at_ms.is_none() {
                return Err(JournalError::IntegrityFailure);
            }
        }
        OperationStatus::Failed => {
            if result.is_some() || error.is_none() || raw.terminal_at_ms.is_none() {
                return Err(JournalError::IntegrityFailure);
            }
        }
        OperationStatus::Cancelled => {
            if result.is_some() || error.is_some() || raw.terminal_at_ms.is_none() {
                return Err(JournalError::IntegrityFailure);
            }
        }
    }
    if let Some(terminal_at_ms) = raw.terminal_at_ms
        && (terminal_at_ms < raw.created_at_ms
            || terminal_at_ms > raw.execution_deadline_ms
            || terminal_at_ms != raw.updated_at_ms
            || raw.retention_anchor_ms < terminal_at_ms)
    {
        return Err(JournalError::IntegrityFailure);
    }
    if raw.retention_anchor_ms != raw.execution_deadline_ms
        && (status != OperationStatus::Completed || raw.terminal_at_ms.is_none())
    {
        // Only completion decisions can be recovered after their submitted
        // retention window. The separately durable anchor keeps that late
        // observability finite without weakening accepted task TTL bounds.
        return Err(JournalError::IntegrityFailure);
    }

    Ok(OperationRecord {
        operation_id,
        repository_id,
        kind,
        required_capabilities,
        normalized_input,
        input_digest,
        idempotency_key_digest,
        status,
        progress,
        lease,
        execution_deadline_ms: raw.execution_deadline_ms,
        result,
        error,
        created_at_ms: raw.created_at_ms,
        updated_at_ms: raw.updated_at_ms,
        terminal_at_ms: raw.terminal_at_ms,
        retention_anchor_ms: raw.retention_anchor_ms,
        retain_until_ms: raw.retain_until_ms,
    })
}

const HANDOFF_COLUMNS: &str = "operation_id, operation_kind, payload_json, payload_digest,
    enqueued_at_ms, claimed_at_ms, completed_at_ms";

struct RawHandoff {
    operation_id: String,
    operation_kind: String,
    payload_json: String,
    payload_digest: Vec<u8>,
    enqueued_at_ms: i64,
    claimed_at_ms: Option<i64>,
    completed_at_ms: Option<i64>,
}

fn raw_handoff_from_row_at(row: &rusqlite::Row<'_>, offset: usize) -> rusqlite::Result<RawHandoff> {
    Ok(RawHandoff {
        operation_id: row.get(offset)?,
        operation_kind: row.get(offset + 1)?,
        payload_json: row.get(offset + 2)?,
        payload_digest: row.get(offset + 3)?,
        enqueued_at_ms: row.get(offset + 4)?,
        claimed_at_ms: row.get(offset + 5)?,
        completed_at_ms: row.get(offset + 6)?,
    })
}

fn raw_handoff_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawHandoff> {
    raw_handoff_from_row_at(row, 0)
}

fn select_handoff_by_id(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<RawHandoff>, JournalError> {
    connection
        .query_row(
            &format!("SELECT {HANDOFF_COLUMNS} FROM runner_handoffs WHERE operation_id = ?1"),
            params![operation_id],
            raw_handoff_from_row,
        )
        .optional()
        .map_err(map_database_decode_error)
}

fn decode_handoff(raw: RawHandoff) -> Result<RunnerHandoff, JournalError> {
    let operation_id =
        OperationId::parse(&raw.operation_id).map_err(|_| JournalError::IntegrityFailure)?;
    validate_operation_id(&operation_id)?;
    let operation_kind =
        OperationKind::parse(&raw.operation_kind).map_err(|_| JournalError::IntegrityFailure)?;
    let payload = CanonicalInput::from_database(raw.payload_json, raw.payload_digest)?;
    validate_timestamp(raw.enqueued_at_ms).map_err(|_| JournalError::IntegrityFailure)?;
    if raw
        .claimed_at_ms
        .is_some_and(|claimed_at_ms| claimed_at_ms < raw.enqueued_at_ms)
        || raw.completed_at_ms.is_some_and(|completed_at_ms| {
            completed_at_ms < raw.enqueued_at_ms
                || raw
                    .claimed_at_ms
                    .is_some_and(|claimed_at_ms| completed_at_ms < claimed_at_ms)
        })
    {
        return Err(JournalError::IntegrityFailure);
    }
    Ok(RunnerHandoff {
        operation_id,
        operation_kind,
        payload_digest: payload.digest(),
        payload,
        enqueued_at_ms: raw.enqueued_at_ms,
        claimed_at_ms: raw.claimed_at_ms,
        completed_at_ms: raw.completed_at_ms,
    })
}

fn validate_operation_handoff(
    operation: &OperationRecord,
    handoff: &RunnerHandoff,
) -> Result<(), JournalError> {
    if handoff.operation_id != operation.operation_id
        || handoff.operation_kind != operation.kind
        || handoff.payload != operation.normalized_input
        || handoff.payload_digest != operation.input_digest
        || handoff.enqueued_at_ms != operation.created_at_ms
        || handoff
            .claimed_at_ms
            .is_some_and(|claimed_at_ms| claimed_at_ms > operation.updated_at_ms)
        || handoff.completed_at_ms != operation.terminal_at_ms
        || (operation.status == OperationStatus::Queued && handoff.claimed_at_ms.is_some())
        || (operation.status == OperationStatus::Running && handoff.claimed_at_ms.is_none())
        || (operation.lease.is_some() && handoff.claimed_at_ms.is_none())
        || (matches!(
            operation.status,
            OperationStatus::Completed | OperationStatus::Cancelled
        ) && handoff.claimed_at_ms.is_none())
        || (operation.status == OperationStatus::Failed
            && handoff.claimed_at_ms.is_none()
            && (operation.terminal_at_ms != Some(operation.execution_deadline_ms)
                || operation.error.as_ref().map(CanonicalJson::as_str)
                    != Some(DEADLINE_EXCEEDED_ERROR_JSON)))
    {
        return Err(JournalError::IntegrityFailure);
    }
    Ok(())
}

const TOMBSTONE_COLUMNS: &str = "operation_id, repository_id, kind,
    required_capabilities_json, required_capabilities_digest, input_digest, idempotency_key_digest,
    expired_at_ms, tombstone_until_ms";

struct RawTombstone {
    operation_id: String,
    repository_id: String,
    kind: String,
    required_capabilities_json: String,
    required_capabilities_digest: JournalDigest,
    input_digest: JournalDigest,
    idempotency_key_digest: JournalDigest,
    expired_at_ms: i64,
    tombstone_until_ms: i64,
}

fn raw_tombstone_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawTombstone> {
    let digest = |index| -> rusqlite::Result<JournalDigest> {
        let bytes: Vec<u8> = row.get(index)?;
        JournalDigest::from_database(bytes).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Blob,
                Box::new(error),
            )
        })
    };
    Ok(RawTombstone {
        operation_id: row.get(0)?,
        repository_id: row.get(1)?,
        kind: row.get(2)?,
        required_capabilities_json: row.get(3)?,
        required_capabilities_digest: digest(4)?,
        input_digest: digest(5)?,
        idempotency_key_digest: digest(6)?,
        expired_at_ms: row.get(7)?,
        tombstone_until_ms: row.get(8)?,
    })
}

fn select_tombstone_by_id(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<RawTombstone>, JournalError> {
    connection
        .query_row(
            &format!(
                "SELECT {TOMBSTONE_COLUMNS} FROM operation_tombstones WHERE operation_id = ?1"
            ),
            params![operation_id],
            raw_tombstone_from_row,
        )
        .optional()
        .map_err(map_database_decode_error)
}

fn select_tombstone_by_scope(
    connection: &Connection,
    repository_id: &str,
    kind: &str,
    idempotency_key_digest: JournalDigest,
) -> Result<Option<RawTombstone>, JournalError> {
    connection
        .query_row(
            &format!(
                "SELECT {TOMBSTONE_COLUMNS} FROM operation_tombstones
                 WHERE repository_id = ?1 AND kind = ?2 AND idempotency_key_digest = ?3"
            ),
            params![
                repository_id,
                kind,
                idempotency_key_digest.as_bytes().as_slice()
            ],
            raw_tombstone_from_row,
        )
        .optional()
        .map_err(map_database_decode_error)
}

fn validate_tombstone(tombstone: &RawTombstone) -> Result<(), JournalError> {
    let operation_id =
        OperationId::parse(&tombstone.operation_id).map_err(|_| JournalError::IntegrityFailure)?;
    validate_operation_id(&operation_id)?;
    LogicalRepositoryId::parse(&tombstone.repository_id)
        .map_err(|_| JournalError::IntegrityFailure)?;
    let kind = OperationKind::parse(&tombstone.kind).map_err(|_| JournalError::IntegrityFailure)?;
    let required_capabilities = CapabilitySet::from_database(
        tombstone.required_capabilities_json.clone(),
        tombstone.required_capabilities_digest.as_bytes().to_vec(),
    )?;
    if required_capabilities
        != kind
            .required_capabilities()
            .map_err(|_| JournalError::IntegrityFailure)?
    {
        return Err(JournalError::IntegrityFailure);
    }
    validate_timestamp(tombstone.expired_at_ms).map_err(|_| JournalError::IntegrityFailure)?;
    if tombstone.tombstone_until_ms
        != checked_add(tombstone.expired_at_ms, TOMBSTONE_RETENTION_MS)
            .map_err(|_| JournalError::IntegrityFailure)?
    {
        return Err(JournalError::IntegrityFailure);
    }
    Ok(())
}

// Immutable base schema shared by journal versions 1 through 3. Migration
// validation deliberately compares old journals against this exact surface.
const SCHEMA_V1: &str = r#"
CREATE TABLE operations (
    operation_id TEXT PRIMARY KEY CHECK(
        length(operation_id) = 35
        AND substr(operation_id, 1, 3) = 'op_'
        AND substr(operation_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    repository_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('scan_submit', 'runtime_trace_import_submit', 'daemon_start_submit', 'daemon_stop', 'resolve_build_submit')),
    required_capabilities_json TEXT NOT NULL CHECK(
        typeof(required_capabilities_json) = 'text'
        AND octet_length(required_capabilities_json) BETWEEN 1 AND 256
    ),
    required_capabilities_digest BLOB NOT NULL CHECK(length(required_capabilities_digest) = 32),
    input_json TEXT NOT NULL CHECK(
        typeof(input_json) = 'text' AND octet_length(input_json) <= 1048576
    ),
    input_digest BLOB NOT NULL CHECK(length(input_digest) = 32),
    idempotency_key_digest BLOB NOT NULL CHECK(length(idempotency_key_digest) = 32),
    status TEXT NOT NULL CHECK(status IN ('queued', 'running', 'cancelling', 'completed', 'failed', 'cancelled')),
    progress_completed INTEGER NOT NULL CHECK(progress_completed >= 0),
    progress_total INTEGER NOT NULL CHECK(progress_total >= 1 AND progress_total <= 1000000000 AND progress_completed <= progress_total),
    lease_owner TEXT,
    lease_token_digest BLOB CHECK(lease_token_digest IS NULL OR length(lease_token_digest) = 32),
    lease_expires_at_ms INTEGER,
    execution_deadline_ms INTEGER NOT NULL,
    result_json TEXT CHECK(
        result_json IS NULL
        OR (typeof(result_json) = 'text' AND octet_length(result_json) <= 16777216)
    ),
    error_json TEXT CHECK(
        error_json IS NULL
        OR (typeof(error_json) = 'text' AND octet_length(error_json) <= 16777216)
    ),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    terminal_at_ms INTEGER,
    retain_until_ms INTEGER NOT NULL,
    CHECK(
        (lease_owner IS NULL AND lease_token_digest IS NULL AND lease_expires_at_ms IS NULL)
        OR
        (lease_owner IS NOT NULL AND lease_token_digest IS NOT NULL AND lease_expires_at_ms IS NOT NULL)
    ),
    CHECK(
        (status IN ('queued', 'running', 'cancelling') AND terminal_at_ms IS NULL AND result_json IS NULL AND error_json IS NULL)
        OR (status = 'completed' AND terminal_at_ms IS NOT NULL AND result_json IS NOT NULL AND error_json IS NULL)
        OR (status = 'failed' AND terminal_at_ms IS NOT NULL AND result_json IS NULL AND error_json IS NOT NULL)
        OR (status = 'cancelled' AND terminal_at_ms IS NOT NULL AND result_json IS NULL AND error_json IS NULL)
    ),
    CHECK(status NOT IN ('completed', 'failed', 'cancelled') OR lease_owner IS NULL)
);
CREATE UNIQUE INDEX operations_idempotency_scope
    ON operations(repository_id, kind, idempotency_key_digest);
CREATE INDEX operations_retention
    ON operations(retain_until_ms, operation_id)
    WHERE status IN ('completed', 'failed', 'cancelled');
CREATE INDEX operations_deadline_purge
    ON operations(execution_deadline_ms, operation_id)
    WHERE status IN ('queued', 'running', 'cancelling');
CREATE INDEX operations_runner_claim_next
    ON operations(repository_id, created_at_ms, operation_id)
    WHERE status IN ('queued', 'running', 'cancelling');

CREATE TABLE runner_handoffs (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id) ON DELETE CASCADE,
    operation_kind TEXT NOT NULL CHECK(operation_kind IN ('scan_submit', 'runtime_trace_import_submit', 'daemon_start_submit', 'daemon_stop', 'resolve_build_submit')),
    payload_json TEXT NOT NULL CHECK(
        typeof(payload_json) = 'text' AND octet_length(payload_json) <= 1048576
    ),
    payload_digest BLOB NOT NULL CHECK(length(payload_digest) = 32),
    enqueued_at_ms INTEGER NOT NULL,
    claimed_at_ms INTEGER,
    completed_at_ms INTEGER,
    CHECK(claimed_at_ms IS NULL OR claimed_at_ms >= enqueued_at_ms),
    CHECK(completed_at_ms IS NULL OR completed_at_ms >= enqueued_at_ms),
    CHECK(claimed_at_ms IS NULL OR completed_at_ms IS NULL OR completed_at_ms >= claimed_at_ms)
);

CREATE TABLE operation_tombstones (
    operation_id TEXT PRIMARY KEY CHECK(
        length(operation_id) = 35
        AND substr(operation_id, 1, 3) = 'op_'
        AND substr(operation_id, 4) NOT GLOB '*[^0-9a-f]*'
    ),
    repository_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('scan_submit', 'runtime_trace_import_submit', 'daemon_start_submit', 'daemon_stop', 'resolve_build_submit')),
    required_capabilities_json TEXT NOT NULL CHECK(
        typeof(required_capabilities_json) = 'text'
        AND octet_length(required_capabilities_json) BETWEEN 1 AND 256
    ),
    required_capabilities_digest BLOB NOT NULL CHECK(length(required_capabilities_digest) = 32),
    input_digest BLOB NOT NULL CHECK(length(input_digest) = 32),
    idempotency_key_digest BLOB NOT NULL CHECK(length(idempotency_key_digest) = 32),
    expired_at_ms INTEGER NOT NULL,
    tombstone_until_ms INTEGER NOT NULL CHECK(tombstone_until_ms > expired_at_ms)
);
CREATE UNIQUE INDEX operation_tombstones_idempotency_scope
    ON operation_tombstones(repository_id, kind, idempotency_key_digest);
CREATE INDEX operation_tombstones_retention
    ON operation_tombstones(tombstone_until_ms, operation_id);

CREATE TRIGGER operations_reject_tombstone_overlap_insert
BEFORE INSERT ON operations
WHEN EXISTS (
    SELECT 1 FROM operation_tombstones AS tombstone
    WHERE tombstone.operation_id = NEW.operation_id
       OR (
           tombstone.repository_id = NEW.repository_id
           AND tombstone.kind = NEW.kind
           AND tombstone.idempotency_key_digest = NEW.idempotency_key_digest
       )
)
BEGIN
    SELECT RAISE(ABORT, 'operation overlaps retained tombstone');
END;

CREATE TRIGGER operations_reject_tombstone_overlap_update
BEFORE UPDATE OF operation_id, repository_id, kind, idempotency_key_digest ON operations
WHEN EXISTS (
    SELECT 1 FROM operation_tombstones AS tombstone
    WHERE tombstone.operation_id = NEW.operation_id
       OR (
           tombstone.repository_id = NEW.repository_id
           AND tombstone.kind = NEW.kind
           AND tombstone.idempotency_key_digest = NEW.idempotency_key_digest
       )
)
BEGIN
    SELECT RAISE(ABORT, 'operation overlaps retained tombstone');
END;

CREATE TRIGGER tombstones_reject_operation_overlap_insert
BEFORE INSERT ON operation_tombstones
WHEN EXISTS (
    SELECT 1 FROM operations AS operation
    WHERE operation.operation_id = NEW.operation_id
       OR (
           operation.repository_id = NEW.repository_id
           AND operation.kind = NEW.kind
           AND operation.idempotency_key_digest = NEW.idempotency_key_digest
       )
)
BEGIN
    SELECT RAISE(ABORT, 'tombstone overlaps live operation');
END;

CREATE TRIGGER tombstones_reject_operation_overlap_update
BEFORE UPDATE OF operation_id, repository_id, kind, idempotency_key_digest ON operation_tombstones
WHEN EXISTS (
    SELECT 1 FROM operations AS operation
    WHERE operation.operation_id = NEW.operation_id
       OR (
           operation.repository_id = NEW.repository_id
           AND operation.kind = NEW.kind
           AND operation.idempotency_key_digest = NEW.idempotency_key_digest
       )
)
BEGIN
    SELECT RAISE(ABORT, 'tombstone overlaps live operation');
END;

CREATE TRIGGER operations_state_transition
BEFORE UPDATE OF status ON operations
WHEN NEW.status <> OLD.status AND NOT (
    (OLD.status = 'queued' AND NEW.status IN ('running', 'cancelling', 'failed'))
    OR (OLD.status = 'running' AND NEW.status IN ('cancelling', 'completed', 'failed'))
    OR (OLD.status = 'cancelling' AND NEW.status IN ('completed', 'failed', 'cancelled'))
)
BEGIN
    SELECT RAISE(ABORT, 'invalid operation state transition');
END;

CREATE TRIGGER operations_terminal_immutable
BEFORE UPDATE ON operations
WHEN OLD.status IN ('completed', 'failed', 'cancelled')
BEGIN
    SELECT RAISE(ABORT, 'terminal operation is immutable');
END;
"#;

fn schema_v4_base() -> Result<String, JournalError> {
    const V3_INPUT_CHECK: &str =
        "typeof(input_json) = 'text' AND octet_length(input_json) <= 1048576";
    const V4_INPUT_CHECK: &str =
        "typeof(input_json) = 'text' AND octet_length(input_json) <= 16777216";
    const V3_HANDOFF_CHECK: &str =
        "typeof(payload_json) = 'text' AND octet_length(payload_json) <= 1048576";
    const V4_HANDOFF_CHECK: &str =
        "typeof(payload_json) = 'text' AND octet_length(payload_json) <= 16777216";
    const V3_RETENTION_COLUMNS: &str =
        "    terminal_at_ms INTEGER,\n    retain_until_ms INTEGER NOT NULL,";
    const V4_RETENTION_COLUMNS: &str = "    terminal_at_ms INTEGER,\n    retention_anchor_ms INTEGER NOT NULL,\n    retain_until_ms INTEGER NOT NULL,";
    if SCHEMA_V1.matches(V3_INPUT_CHECK).count() != 1
        || SCHEMA_V1.matches(V3_HANDOFF_CHECK).count() != 1
        || SCHEMA_V1.matches(V3_RETENTION_COLUMNS).count() != 1
    {
        return Err(JournalError::IntegrityFailure);
    }
    Ok(SCHEMA_V1
        .replacen(V3_INPUT_CHECK, V4_INPUT_CHECK, 1)
        .replacen(V3_HANDOFF_CHECK, V4_HANDOFF_CHECK, 1)
        .replacen(V3_RETENTION_COLUMNS, V4_RETENTION_COLUMNS, 1))
}

fn schema_current_base() -> Result<String, JournalError> {
    const V4_KINDS: &str = "'scan_submit', 'runtime_trace_import_submit', 'daemon_start_submit', 'daemon_stop', 'resolve_build_submit'";
    const V5_KINDS: &str = "'scan_submit', 'runtime_trace_import_submit', 'export_file', 'daemon_start_submit', 'daemon_stop', 'resolve_build_submit'";
    let schema = schema_v4_base()?;
    if schema.matches(V4_KINDS).count() != 3 {
        return Err(JournalError::IntegrityFailure);
    }
    Ok(schema.replace(V4_KINDS, V5_KINDS))
}

const SCHEMA_V2_METADATA: &str = r#"
CREATE TABLE operation_journal_metadata (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    metadata_version INTEGER NOT NULL CHECK(metadata_version = 1),
    repository_binding_digest BLOB NOT NULL CHECK(
        typeof(repository_binding_digest) = 'blob'
        AND length(repository_binding_digest) = 32
    )
);
"#;

const SCHEMA_V3_COMPLETION_INTENTS: &str = r#"
CREATE TABLE operation_completion_intents (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id) ON DELETE CASCADE,
    result_json TEXT NOT NULL CHECK(
        typeof(result_json) = 'text'
        AND octet_length(result_json) BETWEEN 1 AND 16777216
    ),
    result_digest BLOB NOT NULL CHECK(length(result_digest) = 32),
    decided_at_ms INTEGER NOT NULL
);
CREATE INDEX operation_completion_intents_order
    ON operation_completion_intents(decided_at_ms, operation_id);
"#;

#[cfg(test)]
mod unit_tests {
    use super::*;

    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    static ROOT_TOCTOU_TEST_LOCK: Mutex<()> = Mutex::new(());
    static SQLITE_BUSY_REACHED: AtomicBool = AtomicBool::new(false);

    fn signal_sqlite_busy(_attempts: i32) -> bool {
        SQLITE_BUSY_REACHED.store(true, Ordering::SeqCst);
        true
    }

    fn wait_until_sqlite_busy() {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !SQLITE_BUSY_REACHED.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < deadline,
                "journal mutation never reached the external SQLite lock"
            );
            std::thread::yield_now();
        }
    }

    fn toctou_config(root: &Path) -> DepgraphServiceConfig {
        use depgraph_core::{DepgraphCapability, DepgraphCapabilitySet, DepgraphServiceLimits};

        let repository_root = root.join("repository");
        std::fs::create_dir(&repository_root).unwrap();
        DepgraphServiceConfig::new(
            repository_root,
            root.join("graph.sqlite"),
            DepgraphCapabilitySet::try_new([
                DepgraphCapability::Read,
                DepgraphCapability::StoreWrite,
            ])
            .unwrap(),
            DepgraphServiceLimits::default(),
        )
        .unwrap()
    }

    fn toctou_request(config: &DepgraphServiceConfig, key: &[u8]) -> SubmitRequest {
        SubmitRequest::new(
            config,
            OperationKind::ScanSubmit,
            &serde_json::json!({"value": 1}),
            key,
            1_800_000_060_000,
        )
        .unwrap()
    }

    fn journal_rows_digest(path: &Path) -> [u8; 32] {
        use rusqlite::types::ValueRef;

        let connection = Connection::open(path).unwrap();
        let mut digest = Sha256::new();
        for query in [
            "SELECT * FROM operations ORDER BY operation_id",
            "SELECT * FROM runner_handoffs ORDER BY operation_id",
            "SELECT * FROM operation_tombstones ORDER BY operation_id",
        ] {
            let mut statement = connection.prepare(query).unwrap();
            let column_count = statement.column_count();
            let mut rows = statement.query([]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                digest.update([0xff]);
                for index in 0..column_count {
                    match row.get_ref(index).unwrap() {
                        ValueRef::Null => digest.update([0]),
                        ValueRef::Integer(value) => {
                            digest.update([1]);
                            digest.update(value.to_le_bytes());
                        }
                        ValueRef::Real(value) => {
                            digest.update([2]);
                            digest.update(value.to_bits().to_le_bytes());
                        }
                        ValueRef::Text(value) => {
                            digest.update([3]);
                            digest.update((value.len() as u64).to_le_bytes());
                            digest.update(value);
                        }
                        ValueRef::Blob(value) => {
                            digest.update([4]);
                            digest.update((value.len() as u64).to_le_bytes());
                            digest.update(value);
                        }
                    }
                }
            }
        }
        digest.finalize().into()
    }

    fn replace_repository_root(config: &DepgraphServiceConfig, parent: &Path) {
        let original_root = config.canonical_root();
        std::fs::rename(original_root, parent.join("original-repository")).unwrap();
        std::fs::create_dir(original_root).unwrap();
    }

    #[test]
    fn transition_matrix_is_closed() {
        let statuses = [
            OperationStatus::Queued,
            OperationStatus::Running,
            OperationStatus::Cancelling,
            OperationStatus::Completed,
            OperationStatus::Failed,
            OperationStatus::Cancelled,
        ];
        for from in statuses {
            for to in statuses {
                let expected = matches!(
                    (from, to),
                    (
                        OperationStatus::Queued,
                        OperationStatus::Running
                            | OperationStatus::Cancelling
                            | OperationStatus::Failed
                    ) | (
                        OperationStatus::Running,
                        OperationStatus::Cancelling
                            | OperationStatus::Completed
                            | OperationStatus::Failed
                    ) | (
                        OperationStatus::Cancelling,
                        OperationStatus::Completed
                            | OperationStatus::Failed
                            | OperationStatus::Cancelled
                    )
                );
                assert_eq!(
                    from.allows_transition_to(to),
                    expected,
                    "{from:?} -> {to:?}"
                );
            }
        }
    }

    #[test]
    fn operation_id_encodes_all_128_random_bits_without_reserved_uuid_bits() {
        assert_eq!(
            operation_id_from_random_bytes([0_u8; 16]).unwrap().as_str(),
            "op_00000000000000000000000000000000"
        );
        assert_eq!(
            operation_id_from_random_bytes([0xff_u8; 16])
                .unwrap()
                .as_str(),
            "op_ffffffffffffffffffffffffffffffff"
        );

        let generated: std::collections::BTreeSet<_> = (0..128)
            .map(|_| new_operation_id().unwrap().as_str().to_owned())
            .collect();
        assert_eq!(generated.len(), 128);
        assert!(generated.iter().all(|operation_id| {
            operation_id.len() == 35
                && operation_id.starts_with("op_")
                && operation_id[3..]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }));
    }

    #[test]
    fn journal_connection_applies_the_production_allocation_limit() {
        use depgraph_core::{DepgraphCapability, DepgraphCapabilitySet, DepgraphServiceLimits};

        let root = tempfile::tempdir().unwrap();
        let repository_root = root.path().join("repository");
        std::fs::create_dir(&repository_root).unwrap();
        let config = DepgraphServiceConfig::new(
            &repository_root,
            root.path().join("graph.sqlite"),
            DepgraphCapabilitySet::try_new([
                DepgraphCapability::Read,
                DepgraphCapability::StoreWrite,
            ])
            .unwrap(),
            DepgraphServiceLimits::default(),
        )
        .unwrap();
        let journal = OperationJournal::open(&config).unwrap();

        assert_eq!(
            journal
                .connection
                .limit(Limit::SQLITE_LIMIT_LENGTH)
                .unwrap(),
            i32::try_from(SQLITE_ALLOCATION_LIMIT_BYTES).unwrap()
        );
    }

    #[test]
    fn submit_waiting_for_immediate_lock_revalidates_root_before_mutation() {
        let _serial = ROOT_TOCTOU_TEST_LOCK.lock().unwrap();
        SQLITE_BUSY_REACHED.store(false, Ordering::SeqCst);
        let root = tempfile::tempdir().unwrap();
        let config = toctou_config(root.path());
        let request = toctou_request(&config, b"submit-root-toctou");
        let mut manager = OperationManager::open(&config).unwrap();
        manager
            .journal
            .connection
            .busy_handler(Some(signal_sqlite_busy))
            .unwrap();
        let journal_path = operation_journal_path(&config);
        let before_digest = journal_rows_digest(journal_path.as_path());
        let blocker = Connection::open(journal_path.as_path()).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();

        let pending = std::thread::spawn(move || manager.submit(&request, 1_800_000_000_000));
        wait_until_sqlite_busy();
        replace_repository_root(&config, root.path());
        blocker.execute_batch("COMMIT").unwrap();

        assert!(matches!(
            pending.join().unwrap(),
            Err(JournalError::RepositoryMismatch)
        ));
        assert_eq!(journal_rows_digest(journal_path.as_path()), before_digest);
    }

    #[test]
    fn cancel_waiting_for_immediate_lock_revalidates_root_before_mutation() {
        let _serial = ROOT_TOCTOU_TEST_LOCK.lock().unwrap();
        SQLITE_BUSY_REACHED.store(false, Ordering::SeqCst);
        let root = tempfile::tempdir().unwrap();
        let config = toctou_config(root.path());
        let request = toctou_request(&config, b"cancel-root-toctou");
        let mut manager = OperationManager::open(&config).unwrap();
        let operation_id = manager
            .submit(&request, 1_800_000_000_000)
            .unwrap()
            .operation_id()
            .clone();
        manager
            .journal
            .connection
            .busy_handler(Some(signal_sqlite_busy))
            .unwrap();
        let journal_path = operation_journal_path(&config);
        let before_digest = journal_rows_digest(journal_path.as_path());
        let blocker = Connection::open(journal_path.as_path()).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();

        let pending = std::thread::spawn(move || manager.cancel(&operation_id, 1_800_000_000_001));
        wait_until_sqlite_busy();
        replace_repository_root(&config, root.path());
        blocker.execute_batch("COMMIT").unwrap();

        assert!(matches!(
            pending.join().unwrap(),
            Err(JournalError::RepositoryMismatch)
        ));
        assert_eq!(journal_rows_digest(journal_path.as_path()), before_digest);
    }

    #[test]
    fn cancel_waiting_for_immediate_lock_rechecks_request_before_mutation() {
        let _serial = ROOT_TOCTOU_TEST_LOCK.lock().unwrap();
        SQLITE_BUSY_REACHED.store(false, Ordering::SeqCst);
        let root = tempfile::tempdir().unwrap();
        let config = toctou_config(root.path());
        let request = toctou_request(&config, b"cancel-request-toctou");
        let mut manager = OperationManager::open(&config).unwrap();
        let operation_id = manager
            .submit(&request, 1_800_000_000_000)
            .unwrap()
            .operation_id()
            .clone();
        manager
            .journal
            .connection
            .busy_handler(Some(signal_sqlite_busy))
            .unwrap();
        let journal_path = operation_journal_path(&config);
        let before_digest = journal_rows_digest(journal_path.as_path());
        let blocker = Connection::open(journal_path.as_path()).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);

        let pending = std::thread::spawn(move || {
            manager.cancel_if(&operation_id, 1_800_000_000_001, || {
                !worker_cancelled.load(Ordering::SeqCst)
            })
        });
        wait_until_sqlite_busy();
        cancelled.store(true, Ordering::SeqCst);
        blocker.execute_batch("COMMIT").unwrap();

        assert!(matches!(
            pending.join().unwrap(),
            Err(JournalError::RequestCancelled)
        ));
        assert_eq!(journal_rows_digest(journal_path.as_path()), before_digest);
    }
}
