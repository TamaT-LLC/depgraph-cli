use crate::{
    CancellationToken, Config, ScanCacheMode, ScanOutcome, acquire_store_writer_lock,
    run_scan_with_cache_mode_and_cancellation,
    scan::{PendingScanPromotion, prepare_deferred_scan_with_cache_mode_and_cancellation},
};
use depgraph_store::Store;

use crate::service::{
    CompletedSnapshotView, DepgraphCapability, DepgraphService, DepgraphServiceError,
    DepgraphServiceResult, NamedCompletedSnapshot, ResolvedSnapshotId, SnapshotLocator,
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
    _writer: std::fs::File,
    store: Store,
    outcome: ScanServiceOutcome,
    promotion: PendingScanPromotion,
}

impl DeferredScanCompletion {
    #[must_use]
    pub const fn outcome(&self) -> &ScanServiceOutcome {
        &self.outcome
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
        self.store
            .finish_scan(
                &self.outcome.outcome.scan_id,
                "cancelled",
                Some("operation cancelled before scan promotion"),
                false,
            )
            .map_err(DepgraphServiceError::store_operation)
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
        let _writer = acquire_store_writer_lock(self.config().store_path())
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
        Ok(ScanServiceOutcome {
            outcome,
            completed_snapshot_id,
        })
    }

    /// Run and validate a scan while retaining the store-writer lock and
    /// deferring successful current-snapshot promotion to the operation runner's
    /// durable completion decision.
    pub async fn scan_deferred_cancellable(
        &self,
        request: &ScanRequest,
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
        let mut store = Store::open(self.config().store_path())
            .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?;
        let prepared = prepare_deferred_scan_with_cache_mode_and_cancellation(
            &mut store,
            self.config().canonical_root().to_path_buf(),
            &config,
            request.strict,
            request.cache_mode,
            cancellation,
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
            },
        )))
    }

    /// Recover a durable operation completion intent after a runner crash. A
    /// staging scan is revalidated and promoted; an already-promoted scan is
    /// accepted idempotently. No other terminal scan state can be promoted.
    pub fn recover_deferred_scan_completion(
        &self,
        scan_id: &str,
        expected_snapshot_id: &str,
    ) -> DepgraphServiceResult<()> {
        self.require_store_write()?;
        let _writer = acquire_store_writer_lock(self.config().store_path())
            .map_err(|_| DepgraphServiceError::StoreWriterConflict)?;
        let mut store = Store::open(self.config().store_path())
            .map_err(|source| DepgraphServiceError::MutatingStoreUnavailable { source })?;
        let scan = store
            .scan(scan_id)
            .map_err(DepgraphServiceError::store_operation)?
            .ok_or(DepgraphServiceError::Integrity)?;
        match scan.status.as_str() {
            "staging" => {
                let validation = store
                    .validate_scan_for_completion(scan_id)
                    .map_err(DepgraphServiceError::store_operation)?;
                let prospective = store
                    .prospective_scan_snapshot_id(scan_id)
                    .map_err(DepgraphServiceError::store_operation)?;
                if prospective != expected_snapshot_id {
                    return Err(DepgraphServiceError::Integrity);
                }
                store
                    .finish_validated_scan(validation, true)
                    .map_err(DepgraphServiceError::store_operation)?;
            }
            "completed" => {
                let snapshot_id = store
                    .snapshot_id_for_source("scan", scan_id)
                    .map_err(DepgraphServiceError::store_operation)?
                    .ok_or(DepgraphServiceError::Integrity)?;
                if snapshot_id != expected_snapshot_id {
                    return Err(DepgraphServiceError::Integrity);
                }
                // This recovery API is reachable only from a durable completion
                // intent created while the deferred completion still owned the
                // staging scan. A completed scan with the expected identity
                // therefore proves that promotion committed before the runner
                // stopped. A later successful scan may legitimately have
                // superseded current, so never move current backwards here.
                return Ok(());
            }
            _ => return Err(DepgraphServiceError::Integrity),
        }
        if store
            .current_snapshot_id()
            .map_err(DepgraphServiceError::store_operation)?
            .as_deref()
            != Some(expected_snapshot_id)
        {
            return Err(DepgraphServiceError::Integrity);
        }
        Ok(())
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
