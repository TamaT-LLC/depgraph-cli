use crate::{
    CancellationToken, Config, ScanCacheMode, ScanOutcome, StoreLockGuard,
    acquire_store_writer_lock, run_scan_with_cache_mode_and_cancellation, runtime_session_delta,
    runtime_trace::runtime_trace_identity,
    scan::{
        DeferredScanOperation, DeferredScanOperationIdentity, PendingScanPromotion,
        prepare_deferred_scan_with_cache_mode_and_cancellation,
    },
};
use depgraph_store::{
    PendingCancelledScanOperations, RuntimeImportRecoveryIdentity, RuntimeImportResult,
    RuntimeSessionDelta, ScanCompletionRecoveryIdentity, Store,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::service::{
    CompletedSnapshotView, DepgraphCapability, DepgraphService, DepgraphServiceError,
    DepgraphServiceResult, NamedCompletedSnapshot, ResolvedSnapshotId,
    RuntimeTraceSourcePrevalidation, RuntimeValidateRequest, ServiceSnapshotSelector,
    SnapshotLocator,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanRequest {
    strict: bool,
    cache_mode: ScanCacheMode,
}

impl ScanRequest {
    #[must_use]
    pub const fn new(strict: bool, cache_mode: ScanCacheMode) -> Self {
        Self { strict, cache_mode }
    }

    #[must_use]
    pub const fn strict(self) -> bool {
        self.strict
    }

    #[must_use]
    pub const fn cache_mode(self) -> ScanCacheMode {
        self.cache_mode
    }
}

#[derive(Clone, Debug)]
pub struct ScanServiceOutcome {
    outcome: ScanOutcome,
    completed_snapshot_id: Option<ResolvedSnapshotId>,
}

pub enum DeferredScanServiceOutcome {
    Finished(Box<ScanServiceOutcome>),
    Pending(Box<DeferredScanCompletion>),
}

pub struct DeferredScanCompletion {
    // Fields drop in declaration order: close the SQLite connection before
    // the writer guard releases store exclusion.
    store: Store,
    _writer: StoreLockGuard,
    outcome: ScanServiceOutcome,
    promotion: PendingScanPromotion,
    operation_id: Option<String>,
}

impl DeferredScanCompletion {
    #[must_use]
    pub const fn outcome(&self) -> &ScanServiceOutcome {
        &self.outcome
    }

    /// Durably bind the complete canonical result digest before the operation
    /// journal is allowed to commit its completion intent.
    pub fn bind_recovery_result_digest(
        &mut self,
        result_digest: &[u8; 32],
    ) -> DepgraphServiceResult<()> {
        let Some(operation_id) = self.operation_id.as_deref() else {
            return Ok(());
        };
        self.store
            .bind_scan_operation_result(operation_id, result_digest)
            .map_err(DepgraphServiceError::store_operation)
    }

    pub fn promote(mut self) -> DepgraphServiceResult<ScanServiceOutcome> {
        let expected_snapshot_id = self
            .outcome
            .completed_snapshot_id()
            .ok_or(DepgraphServiceError::Integrity)?
            .as_str()
            .to_owned();
        self.promotion
            .promote(&mut self.store, &mut self.outcome.outcome)
            .map_err(DepgraphServiceError::store_operation)?;
        let observed_snapshot_id = self
            .store
            .snapshot_id_for_scan_selection(&self.outcome.outcome.scan_id)
            .map_err(DepgraphServiceError::store_operation)?
            .ok_or(DepgraphServiceError::Integrity)?;
        if observed_snapshot_id != expected_snapshot_id
            || self
                .store
                .current_snapshot_id()
                .map_err(DepgraphServiceError::store_operation)?
                .as_deref()
                != Some(expected_snapshot_id.as_str())
        {
            return Err(DepgraphServiceError::Integrity);
        }
        Ok(self.outcome)
    }

    pub fn cancel(mut self) -> DepgraphServiceResult<()> {
        self.cancel_store()?;
        if let Some(operation_id) = self.operation_id.as_deref() {
            self.store
                .finalize_cancelled_scan_for_operation(operation_id)
                .map_err(DepgraphServiceError::store_operation)?;
        }
        Ok(())
    }

    /// Cancel the staged scan while retaining the writer exclusion guard for
    /// a caller that must durably terminalize related state before unlock.
    pub fn cancel_with_writer_guard(mut self) -> DepgraphServiceResult<StoreLockGuard> {
        self.cancel_store()?;
        Ok(self._writer)
    }

    fn cancel_store(&mut self) -> DepgraphServiceResult<()> {
        self.store
            .finish_scan(
                &self.outcome.outcome.scan_id,
                "cancelled",
                Some("operation cancelled before scan promotion"),
                false,
            )
            .map_err(DepgraphServiceError::store_operation)?;
        Ok(())
    }
}

impl ScanServiceOutcome {
    #[must_use]
    pub const fn outcome(&self) -> &ScanOutcome {
        &self.outcome
    }

    #[must_use]
    pub const fn completed_snapshot_id(&self) -> Option<&ResolvedSnapshotId> {
        self.completed_snapshot_id.as_ref()
    }

    #[must_use]
    pub fn into_outcome(self) -> ScanOutcome {
        self.outcome
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeImportPreparation {
    base_snapshot_id: ResolvedSnapshotId,
    scan_id: String,
    input_digest: String,
    normalized_trace: Value,
    trace_file: Option<crate::service::RepositoryRelativePath>,
    delta: RuntimeSessionDelta,
}

impl RuntimeImportPreparation {
    #[must_use]
    pub const fn base_snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.base_snapshot_id
    }

    #[must_use]
    pub fn input_digest(&self) -> &str {
        &self.input_digest
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.delta.session.id
    }

    #[must_use]
    pub fn runtime_trace_digest(&self) -> &str {
        &self.delta.session.trace_digest
    }

    /// Canonical bounded input retained by the durable operation journal. An
    /// inline trace is stored as its parsed JSON value; a file input stores the
    /// confined locator plus the validated content digest and is revalidated by
    /// the runner before any writer mutation.
    #[must_use]
    pub fn durable_input(&self) -> Value {
        runtime_import_durable_input(
            &self.base_snapshot_id,
            &self.input_digest,
            &self.normalized_trace,
            self.trace_file.as_ref(),
            &self.delta.session.id,
            &self.delta.session.trace_digest,
        )
    }
}

/// Complete runtime operation binding computed against a migration-compatible
/// read-only store. It is suitable for exact replay admission but carries no
/// authority to mutate or publish the store.
#[derive(Clone, Debug)]
pub struct RuntimeImportDurableBinding {
    base_snapshot_id: ResolvedSnapshotId,
    input_digest: String,
    normalized_trace: Value,
    trace_file: Option<crate::service::RepositoryRelativePath>,
    session_id: String,
    runtime_trace_digest: String,
}

impl RuntimeImportDurableBinding {
    #[must_use]
    pub fn durable_input(&self) -> Value {
        runtime_import_durable_input(
            &self.base_snapshot_id,
            &self.input_digest,
            &self.normalized_trace,
            self.trace_file.as_ref(),
            &self.session_id,
            &self.runtime_trace_digest,
        )
    }
}

fn runtime_import_durable_input(
    base_snapshot_id: &ResolvedSnapshotId,
    input_digest: &str,
    normalized_trace: &Value,
    trace_file: Option<&crate::service::RepositoryRelativePath>,
    session_id: &str,
    runtime_trace_digest: &str,
) -> Value {
    let mut input = json!({
        "runtime_trace_digest": runtime_trace_digest,
        "session_id": session_id,
        "snapshot_id": base_snapshot_id.as_str(),
        "trace_digest": input_digest,
    });
    if let Some(trace_file) = trace_file {
        input["trace_file"] = json!(trace_file.as_str());
    } else {
        input["trace"] = normalized_trace.clone();
    }
    input
}

#[derive(Clone, Debug)]
pub struct RuntimeImportServiceOutcome {
    scan_id: String,
    completed_snapshot_id: ResolvedSnapshotId,
    result: RuntimeImportResult,
}

impl RuntimeImportServiceOutcome {
    #[must_use]
    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    #[must_use]
    pub const fn completed_snapshot_id(&self) -> &ResolvedSnapshotId {
        &self.completed_snapshot_id
    }

    #[must_use]
    pub const fn result(&self) -> &RuntimeImportResult {
        &self.result
    }

    #[must_use]
    pub fn into_result(self) -> RuntimeImportResult {
        self.result
    }
}

pub enum DeferredRuntimeImportServiceOutcome {
    Finished(Box<RuntimeImportServiceOutcome>),
    Pending(Box<DeferredRuntimeImportCompletion>),
}

/// Complete identity proof required to recover a deferred runtime import from
/// a durable operation completion intent. `runtime_trace_digest` is absent only
/// for legacy normalized input; in that case `import_id` and `session_id` came
/// from the validated immutable result envelope and the store reconstructs the
/// trace binding transactionally from that exact session.
pub struct DeferredRuntimeImportRecovery<'a> {
    pub operation_id: &'a str,
    pub base_snapshot_id: &'a str,
    pub runtime_trace_digest: Option<&'a str>,
    pub import_id: &'a str,
    pub session_id: &'a str,
    pub snapshot_id: &'a str,
    pub status: &'a str,
    pub deduplicated: bool,
}

/// Closed scan completion identity already deserialized and validated by the
/// operation runner. The complete result is bound by its canonical digest.
pub struct DeferredScanRecovery<'a> {
    pub operation_id: &'a str,
    pub scan_id: &'a str,
    pub snapshot_id: &'a str,
    pub strict: bool,
    pub cache_enabled: bool,
    pub result_digest: &'a [u8; 32],
}

pub struct DeferredRuntimeImportCompletion {
    // Fields drop in declaration order: close the SQLite connection before
    // the writer guard releases store exclusion.
    store: Store,
    _writer: StoreLockGuard,
    operation_id: String,
    outcome: RuntimeImportServiceOutcome,
}

impl DeferredRuntimeImportCompletion {
    #[must_use]
    pub const fn outcome(&self) -> &RuntimeImportServiceOutcome {
        &self.outcome
    }

    pub fn promote(mut self) -> DepgraphServiceResult<RuntimeImportServiceOutcome> {
        let result = self
            .store
            .promote_runtime_session_import(
                &self.outcome.result.import_id,
                &self.outcome.result.session_id,
                self.outcome.completed_snapshot_id.as_str(),
            )
            .map_err(DepgraphServiceError::store_operation)?;
        if result != self.outcome.result {
            return Err(DepgraphServiceError::Integrity);
        }
        self.outcome.result = result;
        Ok(self.outcome)
    }

    pub fn cancel(self) -> DepgraphServiceResult<()> {
        self.cancel_with_writer_guard().map(drop)
    }

    /// Cancel this operation's staged runtime import while retaining the
    /// writer exclusion guard until the caller durably terminalizes it.
    pub fn cancel_with_writer_guard(mut self) -> DepgraphServiceResult<StoreLockGuard> {
        let released = self
            .store
            .cancel_runtime_session_import_for_operation(
                &self.outcome.result.import_id,
                &self.operation_id,
            )
            .map_err(DepgraphServiceError::store_operation)?;
        if !released {
            return Err(DepgraphServiceError::Integrity);
        }
        Ok(self._writer)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotNameCreateSelector {
    Completed(SnapshotLocator),
    CompletedForScan(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotNameCreateRequest {
    name: String,
    selector: SnapshotNameCreateSelector,
}

impl SnapshotNameCreateRequest {
    #[must_use]
    pub fn new(name: impl Into<String>, snapshot: SnapshotLocator) -> Self {
        Self {
            name: name.into(),
            selector: SnapshotNameCreateSelector::Completed(snapshot),
        }
    }

    #[must_use]
    pub fn for_scan(name: impl Into<String>, scan_id: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            selector: SnapshotNameCreateSelector::CompletedForScan(scan_id.into()),
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn selector(&self) -> &SnapshotNameCreateSelector {
        &self.selector
    }
}

impl DepgraphService {
    /// Fully validate, match, and materialize the runtime-session delta. Raw
    /// trace validation and snapshot matching complete against a compatible
    /// read-only schema before migration; CLI and the runner pass the resulting
    /// opaque preparation to the writer boundary.
    pub fn prepare_runtime_import(
        &self,
        request: &RuntimeValidateRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<RuntimeImportPreparation> {
        let prevalidated =
            self.prevalidate_runtime_trace_source(&request.source(), cancellation)?;
        self.prepare_runtime_import_prevalidated(
            prevalidated,
            &request.snapshot,
            request.trace_file.clone(),
            cancellation,
        )
    }

    /// Complete snapshot matching and runtime-delta materialization from an
    /// already validated trace source.
    pub fn prepare_runtime_import_prevalidated(
        &self,
        prevalidated: RuntimeTraceSourcePrevalidation,
        snapshot: &ServiceSnapshotSelector,
        trace_file: Option<crate::service::RepositoryRelativePath>,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<RuntimeImportPreparation> {
        self.prepare_runtime_import_prevalidated_with_retained_identity(
            prevalidated,
            snapshot,
            trace_file,
            None,
            cancellation,
        )
    }

    /// Construct the complete durable runtime binding without opening a
    /// writable store or running a schema migration. Callers use this only to
    /// authenticate an existing idempotency binding before writable admission.
    pub fn prepare_runtime_import_durable_binding_prevalidated(
        &self,
        prevalidated: RuntimeTraceSourcePrevalidation,
        snapshot: &ServiceSnapshotSelector,
        trace_file: Option<crate::service::RepositoryRelativePath>,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<RuntimeImportDurableBinding> {
        self.require_store_write()?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let validated = self.runtime_validate_prevalidated_before_migration(
            prevalidated,
            snapshot,
            cancellation,
        )?;
        let (session_id, runtime_trace_digest) = runtime_trace_identity(validated.trace())
            .map_err(|_| DepgraphServiceError::Internal)?;
        Ok(RuntimeImportDurableBinding {
            base_snapshot_id: validated.resolved_snapshot_id().clone(),
            input_digest: validated.input_digest().to_owned(),
            normalized_trace: validated.normalized_trace().clone(),
            trace_file,
            session_id,
            runtime_trace_digest,
        })
    }

    /// Complete runtime import preparation while matching an optional durable
    /// session/trace identity before any writable store migration is opened.
    pub fn prepare_runtime_import_prevalidated_with_retained_identity(
        &self,
        prevalidated: RuntimeTraceSourcePrevalidation,
        snapshot: &ServiceSnapshotSelector,
        trace_file: Option<crate::service::RepositoryRelativePath>,
        retained_identity: Option<(&str, &str)>,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<RuntimeImportPreparation> {
        self.require_store_write()?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let writer = acquire_store_writer_lock(self.config().store_path())
            .map_err(|_| DepgraphServiceError::StoreWriterConflict)?;
        let before_migration = self.runtime_validate_prevalidated_before_migration(
            prevalidated.clone(),
            snapshot,
            cancellation,
        )?;
        if let Some((expected_session_id, expected_trace_digest)) = retained_identity {
            let (session_id, trace_digest) = runtime_trace_identity(before_migration.trace())
                .map_err(|_| DepgraphServiceError::Internal)?;
            if session_id != expected_session_id || trace_digest != expected_trace_digest {
                return Err(DepgraphServiceError::Conflict);
            }
        }
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let migrated = Store::open(self.config().store_path())
            .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?;
        drop(migrated);
        let validated = self.runtime_validate_prevalidated(prevalidated, snapshot, cancellation)?;
        if !before_migration.semantically_matches(&validated) {
            return Err(DepgraphServiceError::Integrity);
        }
        drop(writer);
        let base_snapshot_id = validated.resolved_snapshot_id().clone();
        let scan_id = validated.scan_id().to_owned();
        let input_digest = validated.input_digest().to_owned();
        let normalized_trace = validated.normalized_trace().clone();
        let locator = SnapshotLocator::StableId(base_snapshot_id.as_str().to_owned());
        let mut snapshot_request =
            self.start_snapshot_request_at_cancellable(&locator, cancellation)?;
        let snapshot =
            crate::service_graph::load_pinned_snapshot(&mut snapshot_request, cancellation)?;
        if snapshot.scan.id != scan_id {
            return Err(DepgraphServiceError::Integrity);
        }
        let delta =
            runtime_session_delta(validated.into_trace(), base_snapshot_id.as_str(), &snapshot)
                .map_err(|source| DepgraphServiceError::RuntimeTraceInput { source })?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        Ok(RuntimeImportPreparation {
            base_snapshot_id,
            scan_id,
            input_digest,
            normalized_trace,
            trace_file,
            delta,
        })
    }

    pub fn runtime_import(
        &self,
        request: &RuntimeValidateRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<RuntimeImportServiceOutcome> {
        let prepared = self.prepare_runtime_import(request, cancellation)?;
        self.runtime_import_prepared(prepared, cancellation)
    }

    pub fn runtime_import_prepared(
        &self,
        prepared: RuntimeImportPreparation,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<RuntimeImportServiceOutcome> {
        self.require_store_write()?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let _writer = acquire_store_writer_lock(self.config().store_path())
            .map_err(|_| DepgraphServiceError::StoreWriterConflict)?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let mut store = Store::open(self.config().store_path())
            .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?;
        let result = store
            .import_runtime_session(prepared.base_snapshot_id.as_str(), prepared.delta)
            .map_err(DepgraphServiceError::store_operation)?;
        runtime_import_outcome(prepared.scan_id, result)
    }

    pub fn runtime_import_deferred_prepared(
        &self,
        prepared: RuntimeImportPreparation,
        operation_id: &str,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<DeferredRuntimeImportServiceOutcome> {
        self.require_store_write()?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let writer = acquire_store_writer_lock(self.config().store_path())
            .map_err(|_| DepgraphServiceError::StoreWriterConflict)?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let mut store = Store::open(self.config().store_path())
            .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?;
        let staged = store
            .prepare_runtime_session_import(
                prepared.base_snapshot_id.as_str(),
                prepared.delta,
                operation_id,
            )
            .map_err(DepgraphServiceError::store_operation)?;
        let pending = staged.is_pending();
        let outcome = runtime_import_outcome(prepared.scan_id, staged.into_result())?;
        if !pending {
            return Ok(DeferredRuntimeImportServiceOutcome::Finished(Box::new(
                outcome,
            )));
        }
        if cancellation.is_cancelled() {
            let released = store
                .cancel_runtime_session_import_for_operation(
                    &outcome.result.import_id,
                    operation_id,
                )
                .map_err(DepgraphServiceError::store_operation)?;
            if !released {
                return Err(DepgraphServiceError::Integrity);
            }
            return Err(DepgraphServiceError::Cancelled);
        }
        Ok(DeferredRuntimeImportServiceOutcome::Pending(Box::new(
            DeferredRuntimeImportCompletion {
                _writer: writer,
                store,
                operation_id: operation_id.to_owned(),
                outcome,
            },
        )))
    }

    /// Recover promotion after a completion intent was committed. A staging
    /// import is promoted atomically; an already-completed import is accepted
    /// idempotently without changing a newer current pointer.
    pub fn recover_deferred_runtime_import_completion(
        &self,
        recovery: &DeferredRuntimeImportRecovery<'_>,
    ) -> DepgraphServiceResult<()> {
        self.require_store_write()?;
        let _writer = acquire_store_writer_lock(self.config().store_path())
            .map_err(|_| DepgraphServiceError::StoreWriterConflict)?;
        let mut store = Store::open(self.config().store_path())
            .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?;
        let identity = match recovery.runtime_trace_digest {
            Some(trace_digest) => RuntimeImportRecoveryIdentity::new(
                recovery.import_id,
                recovery.session_id,
                recovery.snapshot_id,
                recovery.base_snapshot_id,
                trace_digest,
                recovery.status,
                recovery.operation_id,
            ),
            None => RuntimeImportRecoveryIdentity::from_validated_outcome(
                recovery.import_id,
                recovery.session_id,
                recovery.snapshot_id,
                recovery.base_snapshot_id,
                recovery.status,
                recovery.operation_id,
            ),
        };
        let result = store
            .recover_runtime_session_import_for_operation(&identity)
            .map_err(DepgraphServiceError::store_operation)?;
        if result.import_id != recovery.import_id
            || result.session_id != recovery.session_id
            || result.snapshot_id != recovery.snapshot_id
            || result.status != recovery.status
            || result.deduplicated != recovery.deduplicated
        {
            return Err(DepgraphServiceError::Integrity);
        }
        Ok(())
    }

    /// Reclaim evidence left by a runner that crashed after staging but before
    /// committing a completion intent. The durable operation supplies all
    /// identities, so cleanup never needs to trust mutable file contents. The
    /// returned writer guard remains locked until the caller drops it.
    pub fn cancel_matching_staged_runtime_import(
        &self,
        base_snapshot_id: &str,
        session_id: &str,
        trace_digest: &str,
        operation_id: &str,
    ) -> DepgraphServiceResult<StoreLockGuard> {
        self.require_store_write()?;
        let writer = acquire_store_writer_lock(self.config().store_path())
            .map_err(|_| DepgraphServiceError::StoreWriterConflict)?;
        let mut store = Store::open(self.config().store_path())
            .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?;
        store
            .cancel_matching_staged_runtime_session_import(
                base_snapshot_id,
                session_id,
                trace_digest,
                operation_id,
            )
            .map_err(DepgraphServiceError::store_operation)?;
        Ok(writer)
    }

    /// Reclaim a staged runtime import through its unique durable operation
    /// owner when legacy normalized input has no session/trace binding.
    pub fn cancel_staged_runtime_import_for_operation(
        &self,
        operation_id: &str,
    ) -> DepgraphServiceResult<StoreLockGuard> {
        self.require_store_write()?;
        let writer = acquire_store_writer_lock(self.config().store_path())
            .map_err(|_| DepgraphServiceError::StoreWriterConflict)?;
        if !self.config().store_path().exists() {
            return Ok(writer);
        }
        let legacy_store = Store::open_read_only_for_migration(self.config().store_path())
            .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?;
        if !legacy_store
            .runtime_operation_cleanup_requires_writable_store()
            .map_err(DepgraphServiceError::store_operation)?
        {
            return Ok(writer);
        }
        drop(legacy_store);
        let mut store = Store::open(self.config().store_path())
            .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?;
        store
            .cancel_staged_runtime_session_import_for_operation(operation_id)
            .map_err(DepgraphServiceError::store_operation)?;
        Ok(writer)
    }

    pub async fn scan(&self, request: &ScanRequest) -> DepgraphServiceResult<ScanServiceOutcome> {
        let cancellation = CancellationToken::new();
        let scan = self.scan_cancellable(request, cancellation.clone());
        tokio::pin!(scan);
        tokio::select! {
            outcome = &mut scan => outcome,
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|_| DepgraphServiceError::Internal)?;
                cancellation.cancel();
                scan.await
            }
        }
    }

    pub async fn scan_cancellable(
        &self,
        request: &ScanRequest,
        cancellation: CancellationToken,
    ) -> DepgraphServiceResult<ScanServiceOutcome> {
        self.require_store_write()?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let writer = acquire_store_writer_lock(self.config().store_path())
            .map_err(|_| DepgraphServiceError::StoreWriterConflict)?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let config = Config::load(self.config().canonical_root())
            .map_err(DepgraphServiceError::store_operation)?;
        let mut store = Store::open(self.config().store_path())
            .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?;
        let outcome = run_scan_with_cache_mode_and_cancellation(
            &mut store,
            self.config().canonical_root().to_path_buf(),
            &config,
            request.strict,
            request.cache_mode,
            cancellation,
        )
        .await
        .map_err(DepgraphServiceError::store_operation)?;
        let completed_snapshot_id = if outcome.status == "completed" {
            let snapshot_id = store
                .snapshot_id_for_scan_selection(&outcome.scan_id)
                .map_err(DepgraphServiceError::store_operation)?
                .ok_or(DepgraphServiceError::Integrity)?;
            Some(ResolvedSnapshotId::from_completed(snapshot_id)?)
        } else {
            None
        };
        let outcome = ScanServiceOutcome {
            outcome,
            completed_snapshot_id,
        };
        drop(store);
        // A caller may immediately start another scan against the same store.
        // Release exclusion synchronously because close-on-drop can otherwise
        // leave a transient self-conflict on some hosts.
        writer
            .unlock()
            .map_err(|source| DepgraphServiceError::store_operation(source.into()))?;
        Ok(outcome)
    }

    /// Run and validate a scan while retaining the store-writer lock and
    /// deferring successful current-snapshot promotion to the operation runner's
    /// durable completion decision.
    pub async fn scan_deferred_cancellable(
        &self,
        request: &ScanRequest,
        cancellation: CancellationToken,
    ) -> DepgraphServiceResult<DeferredScanServiceOutcome> {
        self.scan_deferred_cancellable_with_id(request, None, cancellation)
            .await
    }

    /// Run a deferred scan whose staging identity is recoverably bound to one
    /// durable operation.
    pub async fn scan_deferred_cancellable_for_operation(
        &self,
        request: &ScanRequest,
        operation_id: &str,
        cancellation: CancellationToken,
    ) -> DepgraphServiceResult<DeferredScanServiceOutcome> {
        self.scan_deferred_cancellable_with_id(request, Some(operation_id), cancellation)
            .await
    }

    async fn scan_deferred_cancellable_with_id(
        &self,
        request: &ScanRequest,
        operation_id: Option<&str>,
        cancellation: CancellationToken,
    ) -> DepgraphServiceResult<DeferredScanServiceOutcome> {
        self.require_store_write()?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let writer = acquire_store_writer_lock(self.config().store_path())
            .map_err(|_| DepgraphServiceError::StoreWriterConflict)?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let config = Config::load(self.config().canonical_root())
            .map_err(DepgraphServiceError::store_operation)?;
        let operation_identity = if operation_id.is_some() {
            Some(DeferredScanOperationIdentity {
                repository_binding_digest: self.config().repository_root_seal().binding_digest(),
                configuration_digest: scan_configuration_digest(&config)?,
                cache_enabled: request.cache_mode == ScanCacheMode::Enabled,
            })
        } else {
            None
        };
        let operation =
            operation_id
                .zip(operation_identity.as_ref())
                .map(|(operation_id, identity)| DeferredScanOperation {
                    operation_id,
                    identity,
                });
        let mut store = Store::open(self.config().store_path())
            .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?;
        let prepared = prepare_deferred_scan_with_cache_mode_and_cancellation(
            &mut store,
            self.config().canonical_root().to_path_buf(),
            &config,
            request.strict,
            request.cache_mode,
            cancellation,
            operation,
        )
        .await
        .map_err(DepgraphServiceError::store_operation)?;
        let Some(promotion) = prepared.promotion else {
            return Ok(DeferredScanServiceOutcome::Finished(Box::new(
                ScanServiceOutcome {
                    outcome: prepared.outcome,
                    completed_snapshot_id: None,
                },
            )));
        };
        if prepared.outcome.status != "completed" {
            return Err(DepgraphServiceError::Integrity);
        }
        let prospective_snapshot_id = store
            .prospective_scan_snapshot_id(&prepared.outcome.scan_id)
            .map_err(DepgraphServiceError::store_operation)?;
        if let Some(operation_id) = operation_id {
            store
                .seal_scan_operation_staging(
                    operation_id,
                    promotion.validation(),
                    &prospective_snapshot_id,
                )
                .map_err(DepgraphServiceError::store_operation)?;
        }
        let outcome = ScanServiceOutcome {
            outcome: prepared.outcome,
            completed_snapshot_id: Some(ResolvedSnapshotId::from_completed(
                prospective_snapshot_id,
            )?),
        };
        Ok(DeferredScanServiceOutcome::Pending(Box::new(
            DeferredScanCompletion {
                _writer: writer,
                store,
                outcome,
                promotion,
                operation_id: operation_id.map(ToOwned::to_owned),
            },
        )))
    }

    /// Idempotently cancel the staging scan owned by a durable operation and
    /// retain the writer guard until the caller terminalizes that operation.
    pub fn cancel_deferred_scan_for_operation(
        &self,
        operation_id: &str,
    ) -> DepgraphServiceResult<StoreLockGuard> {
        self.require_store_write()?;
        let writer = acquire_store_writer_lock(self.config().store_path())
            .map_err(|_| DepgraphServiceError::StoreWriterConflict)?;
        if !self.config().store_path().exists() {
            return Ok(writer);
        }
        let legacy_store = Store::open_read_only_for_migration(self.config().store_path())
            .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?;
        if !legacy_store
            .scan_operation_cleanup_requires_writable_store(operation_id)
            .map_err(DepgraphServiceError::store_operation)?
        {
            return Ok(writer);
        }
        drop(legacy_store);
        let mut store = Store::open(self.config().store_path())
            .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?;
        store
            .cancel_scan_for_operation(operation_id)
            .map_err(DepgraphServiceError::store_operation)?;
        Ok(writer)
    }

    /// Remove a retained scan cancellation proof only after its journal record
    /// has reached the corresponding terminal state.
    pub fn finalize_deferred_scan_cancellation(
        &self,
        operation_id: &str,
    ) -> DepgraphServiceResult<()> {
        self.require_store_write()?;
        let writer = acquire_store_writer_lock(self.config().store_path())
            .map_err(|_| DepgraphServiceError::StoreWriterConflict)?;
        let mut store = Store::open(self.config().store_path())
            .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?;
        let result = store
            .finalize_cancelled_scan_for_operation(operation_id)
            .map(drop)
            .map_err(DepgraphServiceError::store_operation);
        drop(store);
        // Release the sidecar lock explicitly after closing the SQLite store so
        // the next cleanup page can reacquire it without a host-dependent
        // close-on-drop race. Preserve the store operation error if both fail.
        let unlock_result = writer
            .unlock()
            .map_err(|source| DepgraphServiceError::store_operation(source.into()));
        result?;
        unlock_result?;
        Ok(())
    }

    /// Load fixed-size cancellation proofs that need their terminal journal
    /// acknowledgement reconciled after a runner crash.
    pub fn pending_deferred_scan_cancellations(
        &self,
        after_operation_id: Option<&str>,
    ) -> DepgraphServiceResult<PendingCancelledScanOperations> {
        self.require_store_write()?;
        if !self.config().store_path().exists() {
            return Ok(PendingCancelledScanOperations::empty());
        }
        let store = Store::open_read_only_for_migration(self.config().store_path())
            .map_err(DepgraphServiceError::store_operation)?;
        if store
            .schema_version()
            .map_err(DepgraphServiceError::store_operation)?
            < 17
        {
            return Ok(PendingCancelledScanOperations::empty());
        }
        store
            .pending_cancelled_scan_operations_after(after_operation_id)
            .map_err(DepgraphServiceError::store_operation)
    }

    /// Under the repository writer exclusion, cancel one bounded page of
    /// pre-v17 scan candidates that no validated completion intent adopted.
    /// This is runner coordination, not a generic store-open side effect.
    pub fn reconcile_legacy_scan_operation_staging(&self) -> DepgraphServiceResult<bool> {
        self.require_store_write()?;
        let _writer = acquire_store_writer_lock(self.config().store_path())
            .map_err(|_| DepgraphServiceError::StoreWriterConflict)?;
        if !self.config().store_path().exists() {
            return Ok(false);
        }
        let legacy_store = Store::open_read_only_for_migration(self.config().store_path())
            .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?;
        if !legacy_store
            .legacy_scan_reconciliation_requires_writable_store()
            .map_err(DepgraphServiceError::store_operation)?
        {
            return Ok(false);
        }
        drop(legacy_store);
        let mut store = Store::open(self.config().store_path())
            .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?;
        store
            .reconcile_legacy_scan_operation_candidates()
            .map_err(DepgraphServiceError::store_operation)
    }

    /// Recover a durable operation completion intent after a runner crash. A
    /// staging scan is revalidated and promoted; an already-promoted scan is
    /// accepted idempotently. No other terminal scan state can be promoted.
    pub fn recover_deferred_scan_completion(
        &self,
        recovery: &DeferredScanRecovery<'_>,
    ) -> DepgraphServiceResult<()> {
        self.require_store_write()?;
        let _writer = acquire_store_writer_lock(self.config().store_path())
            .map_err(|_| DepgraphServiceError::StoreWriterConflict)?;
        let mut store = Store::open(self.config().store_path())
            .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?;
        let repository_binding_digest = self.config().repository_root_seal().binding_digest();
        store
            .recover_scan_completion_for_operation(&ScanCompletionRecoveryIdentity {
                operation_id: recovery.operation_id,
                scan_id: recovery.scan_id,
                repository_root: self.config().canonical_root(),
                repository_binding_digest: &repository_binding_digest,
                strict: recovery.strict,
                cache_enabled: recovery.cache_enabled,
                snapshot_id: recovery.snapshot_id,
                result_digest: recovery.result_digest,
            })
            .map_err(DepgraphServiceError::store_operation)
    }

    pub fn snapshot_name_create(
        &self,
        request: &SnapshotNameCreateRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<NamedCompletedSnapshot> {
        self.require_store_write()?;
        validate_name(request.name())?;
        validate_selector(request.selector())?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let _writer = acquire_store_writer_lock(self.config().store_path())
            .map_err(|_| DepgraphServiceError::StoreWriterConflict)?;
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let mut store = Store::open(self.config().store_path())
            .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?;
        if store
            .snapshot_id_for_name(request.name())
            .map_err(DepgraphServiceError::store_operation)?
            .is_some()
        {
            return Err(DepgraphServiceError::Conflict);
        }
        let snapshot_id = resolve_completed_snapshot(&store, request.selector())?
            .ok_or(DepgraphServiceError::NotFound)?;
        let details = store
            .completed_snapshot_details(&snapshot_id)
            .map_err(DepgraphServiceError::store_operation)?;
        if details.snapshot.status != "completed" {
            return Err(DepgraphServiceError::Integrity);
        }
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }
        let named = store
            .create_snapshot_name(request.name(), &snapshot_id)
            .map_err(DepgraphServiceError::store_operation)?;
        let details = store
            .completed_snapshot_details(&snapshot_id)
            .map_err(DepgraphServiceError::store_operation)?;
        Ok(NamedCompletedSnapshot::from_created_name(
            named.name,
            named.named_at,
            CompletedSnapshotView::from_store(details)?,
        ))
    }

    fn require_store_write(&self) -> DepgraphServiceResult<()> {
        if self
            .config()
            .capabilities()
            .contains(DepgraphCapability::StoreWrite)
        {
            Ok(())
        } else {
            Err(DepgraphServiceError::CapabilityDenied {
                required: DepgraphCapability::StoreWrite,
            })
        }
    }
}

fn scan_configuration_digest(config: &Config) -> DepgraphServiceResult<[u8; 32]> {
    let value = serde_json::to_value(config).map_err(|_| DepgraphServiceError::Internal)?;
    let canonical = depgraph_protocol::canonical_json(&value);
    Ok(Sha256::digest(canonical.as_bytes()).into())
}

fn runtime_import_outcome(
    scan_id: String,
    result: RuntimeImportResult,
) -> DepgraphServiceResult<RuntimeImportServiceOutcome> {
    let completed_snapshot_id = ResolvedSnapshotId::from_completed(result.snapshot_id.clone())?;
    Ok(RuntimeImportServiceOutcome {
        scan_id,
        completed_snapshot_id,
        result,
    })
}

fn validate_name(name: &str) -> DepgraphServiceResult<()> {
    match SnapshotLocator::parse(name)? {
        SnapshotLocator::Name(parsed) if parsed == name => Ok(()),
        _ => Err(DepgraphServiceError::InvalidInput),
    }
}

fn validate_selector(selector: &SnapshotNameCreateSelector) -> DepgraphServiceResult<()> {
    match selector {
        SnapshotNameCreateSelector::Completed(SnapshotLocator::Current) => Ok(()),
        SnapshotNameCreateSelector::Completed(SnapshotLocator::Name(name)) => {
            SnapshotLocator::parse(name).map(|_| ())
        }
        SnapshotNameCreateSelector::Completed(SnapshotLocator::StableId(id)) => {
            SnapshotLocator::parse(id).map(|_| ())
        }
        SnapshotNameCreateSelector::CompletedForScan(scan_id)
            if !scan_id.is_empty()
                && scan_id.len() <= 256
                && !scan_id.chars().any(char::is_control) =>
        {
            Ok(())
        }
        SnapshotNameCreateSelector::CompletedForScan(_) => Err(DepgraphServiceError::InvalidInput),
    }
}

fn resolve_completed_snapshot(
    store: &Store,
    selector: &SnapshotNameCreateSelector,
) -> DepgraphServiceResult<Option<String>> {
    let resolved = match selector {
        SnapshotNameCreateSelector::Completed(SnapshotLocator::Current) => {
            store.current_snapshot_id()
        }
        SnapshotNameCreateSelector::Completed(SnapshotLocator::Name(name)) => {
            store.snapshot_id_for_name(name)
        }
        SnapshotNameCreateSelector::Completed(SnapshotLocator::StableId(snapshot_id)) => store
            .completed_snapshot(snapshot_id)
            .map(|snapshot| snapshot.map(|snapshot| snapshot.id)),
        SnapshotNameCreateSelector::CompletedForScan(scan_id) => {
            store.snapshot_id_for_scan_selection(scan_id)
        }
    }
    .map_err(DepgraphServiceError::store_operation)?;
    Ok(resolved)
}
