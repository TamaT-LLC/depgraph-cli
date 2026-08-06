use std::{
    fs::Metadata,
    io::{Cursor, Read},
    time::SystemTime,
};

use depgraph_protocol::stable_id_from_value;

use crate::{
    BoundedQueryExecutionOptions, BoundedQueryLimits, BoundedQueryPlan, BoundedQueryResult,
    CancellationToken, MAX_QUERY_BYTES, QueryDiagnostic, TypedProjection, TypedQuery,
    ValidatedRuntimeTrace, execute_bounded_query_with_options, match_runtime_trace,
    parse_and_type_check_bounded_query, plan_bounded_query_with_limits, read_bounded_query_file,
    read_runtime_trace,
};

use crate::service::{
    DepgraphService, DepgraphServiceError, DepgraphServiceResult, RepositoryRelativePath,
    ResolvedSnapshotId, SnapshotLocator, SnapshotReadRequest,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceSnapshotSelector {
    Locator(SnapshotLocator),
    ScanId(String),
}

impl ServiceSnapshotSelector {
    #[must_use]
    pub const fn current() -> Self {
        Self::Locator(SnapshotLocator::Current)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundedQueryMode {
    Explain,
    Execute,
}

#[derive(Clone, Debug)]
pub struct BoundedQueryRequest {
    pub query: Option<String>,
    pub query_file: Option<RepositoryRelativePath>,
    pub snapshot: ServiceSnapshotSelector,
    pub mode: BoundedQueryMode,
}

#[derive(Clone, Debug)]
pub struct BoundedQueryServiceResult {
    resolved_snapshot_id: ResolvedSnapshotId,
    scan_id: String,
    typed_query: TypedQuery,
    plan: BoundedQueryPlan,
    result: Option<BoundedQueryResult>,
}

impl BoundedQueryServiceResult {
    #[must_use]
    pub const fn resolved_snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.resolved_snapshot_id
    }

    #[must_use]
    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    #[must_use]
    pub fn input_digest(&self) -> &str {
        &self.typed_query.digest
    }

    #[must_use]
    pub fn projections(&self) -> &[TypedProjection] {
        &self.typed_query.ast.return_clause.projections
    }

    #[must_use]
    pub const fn plan(&self) -> &BoundedQueryPlan {
        &self.plan
    }

    #[must_use]
    pub const fn result(&self) -> Option<&BoundedQueryResult> {
        self.result.as_ref()
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeValidateRequest {
    pub trace: Option<String>,
    pub trace_file: Option<RepositoryRelativePath>,
    pub snapshot: ServiceSnapshotSelector,
}

#[derive(Clone, Debug)]
pub struct RuntimeValidateServiceResult {
    resolved_snapshot_id: ResolvedSnapshotId,
    scan_id: String,
    input_digest: String,
    trace: ValidatedRuntimeTrace,
}

impl RuntimeValidateServiceResult {
    #[must_use]
    pub const fn resolved_snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.resolved_snapshot_id
    }

    #[must_use]
    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    #[must_use]
    pub fn input_digest(&self) -> &str {
        &self.input_digest
    }

    #[must_use]
    pub const fn trace(&self) -> &ValidatedRuntimeTrace {
        &self.trace
    }

    #[must_use]
    pub fn into_trace(self) -> ValidatedRuntimeTrace {
        self.trace
    }
}

impl DepgraphService {
    pub fn bounded_query(
        &self,
        request: &BoundedQueryRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<BoundedQueryServiceResult> {
        check_cancellation(cancellation)?;
        let query = self.read_query_input(request, cancellation)?;
        let typed_query = parse_and_type_check_bounded_query(&query)
            .map_err(|diagnostic| query_input_error(diagnostic, cancellation))?;
        drop(query);
        check_cancellation(cancellation)?;

        // The executor's hard serialized-row ceiling is itself a valid pre-store
        // worst-case bound. A service configuration below it cannot admit any
        // query without inspecting repository data, so fail closed before the
        // snapshot store is opened.
        let mut limits = BoundedQueryLimits::default();
        let service_output_limit = u64::try_from(self.config().limits().max_output_bytes())
            .map_err(|_| {
                cancellation_priority(DepgraphServiceError::QueryRejected, cancellation)
            })?;
        if limits.serialized_output_bytes > service_output_limit {
            check_cancellation(cancellation)?;
            return Err(DepgraphServiceError::QueryRejected);
        }
        limits.serialized_output_bytes = service_output_limit;

        let mut snapshot_request =
            self.start_service_snapshot_request(&request.snapshot, cancellation)?;
        let resolved_snapshot_id = snapshot_request.snapshot_id().clone();
        let snapshot =
            crate::service_graph::load_pinned_snapshot(&mut snapshot_request, cancellation)?;
        let scan_id = snapshot.scan.id.clone();
        check_cancellation(cancellation)?;
        let plan = plan_bounded_query_with_limits(
            &typed_query,
            resolved_snapshot_id.as_str(),
            &snapshot,
            limits,
        )
        .map_err(|_| cancellation_priority(DepgraphServiceError::Integrity, cancellation))?;
        check_cancellation(cancellation)?;

        if matches!(request.mode, BoundedQueryMode::Execute) && !plan.admitted {
            return Err(DepgraphServiceError::QueryRejected);
        }
        let result = if matches!(request.mode, BoundedQueryMode::Execute) {
            Some(
                execute_bounded_query_with_options(
                    &typed_query,
                    &plan,
                    &snapshot,
                    cancellation,
                    BoundedQueryExecutionOptions {
                        limits: plan.limits,
                    },
                )
                .map_err(|error| bounded_execution_error(error, cancellation))?,
            )
        } else {
            None
        };
        check_cancellation(cancellation)?;
        Ok(BoundedQueryServiceResult {
            resolved_snapshot_id,
            scan_id,
            typed_query,
            plan,
            result,
        })
    }

    pub fn runtime_validate(
        &self,
        request: &RuntimeValidateRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<RuntimeValidateServiceResult> {
        check_cancellation(cancellation)?;
        let bytes = self.read_runtime_input(request, cancellation)?;
        let trace = read_runtime_trace(Cursor::new(bytes))
            .map_err(|source| runtime_input_error(source, cancellation))?;
        check_cancellation(cancellation)?;
        let input_value =
            serde_json::to_value(&trace).map_err(|_| DepgraphServiceError::Internal)?;
        let input_digest = stable_id_from_value("runtime-validation-input", &input_value);

        let mut snapshot_request =
            self.start_service_snapshot_request(&request.snapshot, cancellation)?;
        let resolved_snapshot_id = snapshot_request.snapshot_id().clone();
        let snapshot =
            crate::service_graph::load_pinned_snapshot(&mut snapshot_request, cancellation)?;
        let scan_id = snapshot.scan.id.clone();
        check_cancellation(cancellation)?;
        let trace = match_runtime_trace(trace, &snapshot)
            .map_err(|source| runtime_input_error(source, cancellation))?;
        check_cancellation(cancellation)?;
        ensure_serialized_output_bound(&trace, self.config().limits().max_output_bytes())
            .map_err(|error| cancellation_priority(error, cancellation))?;
        check_cancellation(cancellation)?;
        Ok(RuntimeValidateServiceResult {
            resolved_snapshot_id,
            scan_id,
            input_digest,
            trace,
        })
    }

    fn read_query_input(
        &self,
        request: &BoundedQueryRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<String> {
        match (&request.query, &request.query_file) {
            (Some(query), None) => {
                if query.len() > MAX_QUERY_BYTES
                    || query.len() > self.config().limits().max_inline_input_bytes()
                {
                    return Err(DepgraphServiceError::BoundedQueryInput {
                        diagnostic: QueryDiagnostic::service_input_limit(),
                    });
                }
                Ok(query.clone())
            }
            (None, Some(path)) => read_bounded_query_file(
                self.config().canonical_root(),
                std::path::Path::new(path.as_str()),
            )
            .map_err(|diagnostic| query_input_error(diagnostic, cancellation)),
            _ => Err(DepgraphServiceError::InvalidInput),
        }
    }

    fn read_runtime_input(
        &self,
        request: &RuntimeValidateRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<Vec<u8>> {
        match (&request.trace, &request.trace_file) {
            (Some(trace), None) => {
                if trace.len() > self.config().limits().max_inline_input_bytes()
                    || trace.len() > crate::RUNTIME_TRACE_MAX_BYTES
                {
                    return Err(DepgraphServiceError::ResourceExhausted);
                }
                Ok(trace.as_bytes().to_vec())
            }
            (None, Some(path)) => read_stable_repository_file(
                self,
                path,
                crate::RUNTIME_TRACE_MAX_BYTES,
                cancellation,
            ),
            _ => Err(DepgraphServiceError::InvalidInput),
        }
    }

    fn start_service_snapshot_request(
        &self,
        selector: &ServiceSnapshotSelector,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<SnapshotReadRequest> {
        match selector {
            ServiceSnapshotSelector::Locator(locator) => {
                self.start_snapshot_request_at_cancellable(locator, cancellation)
            }
            ServiceSnapshotSelector::ScanId(scan_id) => {
                self.start_snapshot_request_for_scan(scan_id, cancellation)
            }
        }
    }
}

fn check_cancellation(cancellation: &CancellationToken) -> DepgraphServiceResult<()> {
    if cancellation.is_cancelled() {
        Err(DepgraphServiceError::Cancelled)
    } else {
        Ok(())
    }
}

fn cancellation_priority(
    error: DepgraphServiceError,
    cancellation: &CancellationToken,
) -> DepgraphServiceError {
    if cancellation.is_cancelled() {
        DepgraphServiceError::Cancelled
    } else {
        error
    }
}

fn query_input_error(
    diagnostic: QueryDiagnostic,
    cancellation: &CancellationToken,
) -> DepgraphServiceError {
    if cancellation.is_cancelled() {
        DepgraphServiceError::Cancelled
    } else {
        DepgraphServiceError::BoundedQueryInput { diagnostic }
    }
}

fn runtime_input_error(
    source: anyhow::Error,
    cancellation: &CancellationToken,
) -> DepgraphServiceError {
    if cancellation.is_cancelled() {
        DepgraphServiceError::Cancelled
    } else {
        DepgraphServiceError::RuntimeTraceInput { source }
    }
}

fn bounded_execution_error(
    error: crate::BoundedQueryExecutionError,
    cancellation: &CancellationToken,
) -> DepgraphServiceError {
    if cancellation.is_cancelled() || error.code == "query_execution_cancelled" {
        DepgraphServiceError::Cancelled
    } else if matches!(
        error.code,
        "query_execution_resource_exhausted" | "query_execution_deadline_exceeded"
    ) {
        DepgraphServiceError::ResourceExhausted
    } else {
        DepgraphServiceError::Integrity
    }
}

fn read_stable_repository_file(
    service: &DepgraphService,
    path: &RepositoryRelativePath,
    maximum: usize,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<Vec<u8>> {
    check_cancellation(cancellation)?;
    let mut opened = service
        .open_normalized_repository_input(path)
        .map_err(|error| cancellation_priority(error, cancellation))?;
    let before = opened.file().metadata().map_err(|source| {
        runtime_input_error(
            anyhow::Error::new(source).context("runtime trace file metadata is unavailable"),
            cancellation,
        )
    })?;
    let maximum_u64 = u64::try_from(maximum).map_err(|_| {
        cancellation_priority(DepgraphServiceError::ResourceExhausted, cancellation)
    })?;
    if before.len() > maximum_u64 {
        check_cancellation(cancellation)?;
        return Err(DepgraphServiceError::ResourceExhausted);
    }
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        check_cancellation(cancellation)?;
        let read = opened.read(&mut buffer).map_err(|source| {
            runtime_input_error(
                anyhow::Error::new(source).context("runtime trace file could not be read"),
                cancellation,
            )
        })?;
        if read == 0 {
            break;
        }
        if bytes.len().saturating_add(read) > maximum {
            check_cancellation(cancellation)?;
            return Err(DepgraphServiceError::ResourceExhausted);
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    let after = opened.file().metadata().map_err(|source| {
        runtime_input_error(
            anyhow::Error::new(source).context("runtime trace file metadata is unavailable"),
            cancellation,
        )
    })?;
    let reopened = service
        .open_normalized_repository_input(path)
        .map_err(|error| cancellation_priority(error, cancellation))?;
    let path_after = reopened.file().metadata().map_err(|source| {
        runtime_input_error(
            anyhow::Error::new(source).context("runtime trace file metadata is unavailable"),
            cancellation,
        )
    })?;
    if !stable_file_snapshot(&before, &after, &path_after, bytes.len()) {
        return Err(runtime_input_error(
            anyhow::anyhow!("runtime trace file changed while it was read"),
            cancellation,
        ));
    }
    check_cancellation(cancellation)?;
    Ok(bytes)
}

fn stable_file_snapshot(
    before: &Metadata,
    after: &Metadata,
    path_after: &Metadata,
    bytes_read: usize,
) -> bool {
    before.is_file()
        && after.is_file()
        && path_after.is_file()
        && u64::try_from(bytes_read).is_ok_and(|bytes| bytes == after.len())
        && before.len() == after.len()
        && metadata_modified(before) == metadata_modified(after)
        && same_file_identity(before, after)
        && same_file_identity(after, path_after)
}

fn metadata_modified(metadata: &Metadata) -> Option<SystemTime> {
    metadata.modified().ok()
}

#[cfg(unix)]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    left.file_attributes() == right.file_attributes()
        && left.creation_time() == right.creation_time()
        && left.last_write_time() == right.last_write_time()
        && left.file_size() == right.file_size()
}

#[cfg(not(any(unix, windows)))]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len() && metadata_modified(left) == metadata_modified(right)
}

fn ensure_serialized_output_bound<T: serde::Serialize>(
    value: &T,
    maximum: usize,
) -> DepgraphServiceResult<()> {
    struct BoundedWriter {
        written: usize,
        maximum: usize,
    }

    impl std::io::Write for BoundedWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.written = self.written.checked_add(buffer.len()).ok_or_else(|| {
                std::io::Error::other("serialized service output exceeds its byte limit")
            })?;
            if self.written > self.maximum {
                return Err(std::io::Error::other(
                    "serialized service output exceeds its byte limit",
                ));
            }
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    serde_json::to_writer(
        BoundedWriter {
            written: 0,
            maximum,
        },
        value,
    )
    .map_err(|_| DepgraphServiceError::ResourceExhausted)
}
