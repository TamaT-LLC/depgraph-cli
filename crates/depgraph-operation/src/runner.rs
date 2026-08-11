use std::{
    sync::{Arc, Condvar, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use depgraph_core::{
    CancellationToken, DepgraphCapability, DepgraphService, DepgraphServiceConfig,
    DepgraphServiceError, GraphQueryFilter, ScanCacheMode,
    service::{
        DeferredExportFileCompletion, DeferredExportFileRecovery, DeferredRuntimeImportCompletion,
        DeferredRuntimeImportRecovery, DeferredRuntimeImportServiceOutcome, DeferredScanCompletion,
        DeferredScanRecovery, DeferredScanServiceOutcome, ExportFileRequest, GraphExportFormat,
        GraphExportRequest, RepositoryOutputPrecondition, RepositoryOverwritePolicy,
        RepositoryRelativePath, RuntimeValidateRequest, ScanRequest, ServiceSnapshotSelector,
        SnapshotLocator,
    },
};
use depgraph_mcp_tools::{
    AgentDaemonControlAction, AgentDaemonControlOutcome, AgentDaemonControlPhase, AgentError,
    AgentErrorCode, AgentExportOutcome, AgentGraphExportFormat, AgentRemediation,
    AgentRuntimeOutcome, AgentRuntimeStatus, AgentScanOutcome, ErrorEnvelope, LogicalRepositoryId,
    OperationId, SnapshotId, SuccessEnvelope,
};

use crate::{
    CanonicalInput, CanonicalJson, CompletionDecision, CompletionIntent, DaemonExecutableLauncher,
    JournalDigest, JournalError, LeaseOwner, MAX_OPERATION_INPUT_BYTES, OperationJournal,
    OperationKind, OperationStatus, RunnerLaunchError,
};

pub const UNSUPPORTED_OPERATION_ERROR_JSON: &str = r#"{"code":"OPERATION_EXECUTION_UNSUPPORTED"}"#;
const DEFAULT_LEASE_DURATION_MS: i64 = 10_000;
// Renewal starts before SQLite's five-second busy timeout can consume the
// remainder of the lease. A competing writer remains serialized while the
// guardian waits for the database lock.
const DEFAULT_RENEWAL_MARGIN_MS: i64 = 6_000;

#[derive(Clone)]
pub struct RunnerStartupConfig {
    service: DepgraphServiceConfig,
}

impl RunnerStartupConfig {
    pub fn new(service: DepgraphServiceConfig) -> Result<Self, RunnerError> {
        let startup = Self { service };
        OperationJournal::open(&startup.service)?;
        Ok(startup)
    }

    #[must_use]
    pub const fn service_config(&self) -> &DepgraphServiceConfig {
        &self.service
    }
}

impl std::fmt::Debug for RunnerStartupConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunnerStartupConfig")
            .field("repository_id", &self.service.logical_repository_id())
            .field("capabilities", &self.service.capabilities())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    #[error("operation runner journal validation failed")]
    Journal(#[from] JournalError),
    #[error("operation runner startup authority is invalid")]
    InvalidStartupAuthority,
    #[error("operation runner clock is unavailable")]
    ClockUnavailable,
    #[error("operation runner secure lease generation failed")]
    EntropyUnavailable,
    #[error("operation runner service finalization failed")]
    Service(#[from] DepgraphServiceError),
    #[error("operation runner daemon launch failed")]
    DaemonLaunch(#[from] RunnerLaunchError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerWork {
    operation_id: OperationId,
    kind: OperationKind,
    input: CanonicalInput,
    execution_deadline_ms: i64,
}

impl RunnerWork {
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    #[must_use]
    pub const fn kind(&self) -> OperationKind {
        self.kind
    }

    #[must_use]
    pub const fn input(&self) -> &CanonicalInput {
        &self.input
    }

    #[must_use]
    pub const fn execution_deadline_ms(&self) -> i64 {
        self.execution_deadline_ms
    }
}

pub enum DispatchOutcome {
    Completed(CanonicalJson),
    CompletionPending {
        result: CanonicalJson,
        completion: DeferredOperationCompletion,
    },
    CancellationCleanupPending {
        completion: DeferredOperationCompletion,
    },
    FailureCleanupPending {
        error: CanonicalJson,
        completion: DeferredOperationCompletion,
    },
    Failed(CanonicalJson),
    Cancelled,
}

pub enum DeferredOperationCompletion {
    Scan(Box<DeferredScanCompletion>),
    RuntimeImport(Box<DeferredRuntimeImportCompletion>),
    ExportFile(Box<DeferredExportFileCompletion>),
    Daemon(Box<DeferredDaemonCompletion>),
}

impl DeferredOperationCompletion {
    fn bind_recovery_result(&mut self, result: &CanonicalJson) -> Result<(), RunnerError> {
        if let Self::Scan(completion) = self {
            let digest = JournalDigest::sha256(result.as_str().as_bytes());
            completion.bind_recovery_result_digest(digest.as_bytes())?;
        }
        Ok(())
    }

    fn promote(self) -> Result<(), RunnerError> {
        match self {
            Self::Scan(completion) => completion.promote().map(|_| ()).map_err(Into::into),
            Self::RuntimeImport(completion) => completion.promote().map(|_| ()).map_err(Into::into),
            Self::ExportFile(completion) => completion.promote().map_err(Into::into),
            Self::Daemon(completion) => completion.promote(),
        }
    }

    fn cancel(self) -> Result<Option<std::fs::File>, RunnerError> {
        match self {
            Self::Scan(completion) => completion
                .cancel_with_writer_guard()
                .map(Some)
                .map_err(Into::into),
            Self::RuntimeImport(completion) => completion
                .cancel_with_writer_guard()
                .map(Some)
                .map_err(Into::into),
            Self::ExportFile(completion) => completion.cancel().map(|()| None).map_err(Into::into),
            Self::Daemon(completion) => completion.cancel().map(|()| None),
        }
    }
}

pub struct DeferredDaemonCompletion {
    config: DepgraphServiceConfig,
    action: DeferredDaemonAction,
}

#[cfg(test)]
type TestDaemonStartPromoter =
    Arc<dyn Fn(&DepgraphServiceConfig, bool) -> Result<(), RunnerError> + Send + Sync>;

enum DeferredDaemonAction {
    Start {
        strict: bool,
        launcher: Option<DaemonExecutableLauncher>,
        #[cfg(test)]
        promoter: Option<TestDaemonStartPromoter>,
    },
    Stop,
}

impl DeferredDaemonCompletion {
    fn start(
        config: DepgraphServiceConfig,
        strict: bool,
        launcher: Option<DaemonExecutableLauncher>,
    ) -> Self {
        Self {
            config,
            action: DeferredDaemonAction::Start {
                strict,
                launcher,
                #[cfg(test)]
                promoter: None,
            },
        }
    }

    #[cfg(test)]
    fn with_daemon_start_promoter_for_test(mut self, promoter: TestDaemonStartPromoter) -> Self {
        let DeferredDaemonAction::Start {
            promoter: configured,
            ..
        } = &mut self.action
        else {
            panic!("daemon start promoter can only be bound to start completion");
        };
        *configured = Some(promoter);
        self
    }

    fn stop(config: DepgraphServiceConfig) -> Self {
        Self {
            config,
            action: DeferredDaemonAction::Stop,
        }
    }

    fn promote(self) -> Result<(), RunnerError> {
        match self.action {
            DeferredDaemonAction::Start {
                strict,
                launcher,
                #[cfg(test)]
                promoter,
            } => {
                #[cfg(test)]
                if let Some(promoter) = promoter {
                    return promoter(&self.config, strict);
                }
                promote_daemon_start(&self.config, strict, launcher)
            }
            DeferredDaemonAction::Stop => promote_daemon_stop(&self.config),
        }
    }

    fn cancel(self) -> Result<(), RunnerError> {
        Ok(())
    }
}

impl std::fmt::Debug for DeferredDaemonCompletion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeferredDaemonCompletion")
            .field("action", &"closed")
            .finish()
    }
}

fn promote_daemon_start(
    config: &DepgraphServiceConfig,
    strict: bool,
    launcher: Option<DaemonExecutableLauncher>,
) -> Result<(), RunnerError> {
    let service = DepgraphService::new(config.clone());
    let cancellation = CancellationToken::new();
    match service.daemon_running_cancellable(&cancellation) {
        Ok(true) => return Ok(()),
        Ok(false) | Err(DepgraphServiceError::NotFound) | Err(DepgraphServiceError::Conflict) => {}
        Err(error) => return Err(error.into()),
    }
    let launcher = launcher.ok_or(RunnerError::Journal(JournalError::IntegrityFailure))?;
    let startup = RunnerStartupConfig::new(config.clone())?;
    let mut child = launcher.launch(&startup, strict)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if child.has_exited()? {
            return Err(RunnerError::Service(DepgraphServiceError::Internal));
        }
        match service.daemon_running_cancellable(&cancellation) {
            Ok(true) => {
                child.detach();
                return Ok(());
            }
            Ok(false)
            | Err(DepgraphServiceError::NotFound)
            | Err(DepgraphServiceError::Conflict)
                if std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(25));
            }
            Ok(false) | Err(DepgraphServiceError::NotFound) => {
                child.terminate_and_reap()?;
                return Err(RunnerError::Service(
                    DepgraphServiceError::ResourceExhausted,
                ));
            }
            Err(error) => {
                child.terminate_and_reap()?;
                return Err(error.into());
            }
        }
    }
}

fn promote_daemon_stop(config: &DepgraphServiceConfig) -> Result<(), RunnerError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| RunnerError::Service(DepgraphServiceError::Internal))?;
    let service = DepgraphService::new(config.clone());
    let cancellation = CancellationToken::new();
    runtime
        .block_on(service.daemon_stop_cancellable(&cancellation))
        .map(|_| ())
        .map_err(Into::into)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionRecovery {
    Finalized,
    Busy,
}

pub trait OperationDispatcher {
    fn dispatch(
        &mut self,
        work: &RunnerWork,
        control: &mut ExecutionControl<'_>,
    ) -> DispatchOutcome;

    fn recover_completion(
        &mut self,
        _intent: &CompletionIntent,
    ) -> Result<CompletionRecovery, RunnerError> {
        Err(RunnerError::Journal(JournalError::IntegrityFailure))
    }

    /// Clean external staging and return any exclusion guard that must remain
    /// held until the runner's corresponding journal transition is terminal.
    fn cleanup_abandoned(
        &mut self,
        _work: &RunnerWork,
    ) -> Result<Option<std::fs::File>, RunnerError> {
        Ok(None)
    }

    /// Return fixed-size external cleanup proofs that may need a terminal
    /// journal acknowledgement reconciled after a crash.
    fn pending_cleanup_acknowledgements(
        &mut self,
        _after_operation_id: Option<&str>,
    ) -> Result<(Vec<OperationId>, Option<String>), RunnerError> {
        Ok((Vec::new(), None))
    }

    /// Reconcile one bounded page of explicitly marked pre-ownership scan
    /// staging after durable completion intents have had the first chance to
    /// adopt their exact candidates. `Some(true)` requests another ordered
    /// page, while `None` reports writer contention.
    fn reconcile_legacy_staging(&mut self) -> Result<Option<bool>, RunnerError> {
        Ok(Some(false))
    }

    /// Retire one external cleanup proof after the matching journal transition
    /// has committed. Implementations must be idempotent.
    fn finalize_cleanup_acknowledgement(
        &mut self,
        _kind: OperationKind,
        _operation_id: &OperationId,
    ) -> Result<(), RunnerError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionCheckpoint {
    Continue,
    CancellationRequested,
    DeadlineExceeded,
    LeaseLost,
}

impl ExecutionCheckpoint {
    #[must_use]
    pub const fn may_continue(self) -> bool {
        matches!(self, Self::Continue)
    }
}

pub struct ExecutionControl<'a> {
    journal: &'a mut OperationJournal,
    repository_id: &'a LogicalRepositoryId,
    operation_id: &'a OperationId,
    lease_token: &'a [u8],
    execution_deadline_ms: i64,
    cancellation: &'a CancellationToken,
    now: &'a dyn Fn() -> Result<i64, RunnerError>,
}

impl ExecutionControl<'_> {
    #[must_use]
    pub const fn cancellation_token(&self) -> &CancellationToken {
        self.cancellation
    }

    pub fn checkpoint(&mut self) -> Result<ExecutionCheckpoint, RunnerError> {
        let now_ms = (self.now)()?;
        if now_ms >= self.execution_deadline_ms {
            return Ok(ExecutionCheckpoint::DeadlineExceeded);
        }
        let record = self
            .journal
            .get(self.repository_id, self.operation_id, now_ms)?;
        if record.execution_deadline_ms() != self.execution_deadline_ms {
            return Err(RunnerError::Journal(JournalError::IntegrityFailure));
        }
        if now_ms >= record.execution_deadline_ms() {
            return Ok(ExecutionCheckpoint::DeadlineExceeded);
        }
        if record.status().is_terminal() {
            return Ok(ExecutionCheckpoint::LeaseLost);
        }
        let Some(lease) = record.lease() else {
            return Ok(ExecutionCheckpoint::LeaseLost);
        };
        if lease.token_digest() != JournalDigest::sha256(self.lease_token)
            || lease.expires_at_ms() <= now_ms
        {
            return Ok(ExecutionCheckpoint::LeaseLost);
        }
        if record.status() == OperationStatus::Cancelling {
            Ok(ExecutionCheckpoint::CancellationRequested)
        } else {
            Ok(ExecutionCheckpoint::Continue)
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RunnerReport {
    claimed: u64,
    completed: u64,
    failed: u64,
    cancelled: u64,
    lease_lost: u64,
}

impl RunnerReport {
    #[must_use]
    pub const fn claimed(self) -> u64 {
        self.claimed
    }

    #[must_use]
    pub const fn completed(self) -> u64 {
        self.completed
    }

    #[must_use]
    pub const fn failed(self) -> u64 {
        self.failed
    }

    #[must_use]
    pub const fn cancelled(self) -> u64 {
        self.cancelled
    }

    #[must_use]
    pub const fn lease_lost(self) -> u64 {
        self.lease_lost
    }
}

pub struct OperationRunner<D> {
    startup: RunnerStartupConfig,
    dispatcher: D,
    lease_timing: LeaseTiming,
    #[cfg(test)]
    guardian_events: Option<mpsc::Sender<LeaseGuardianEvent>>,
    #[cfg(test)]
    completion_decision_barrier: Option<CompletionDecisionBarrier>,
    #[cfg(test)]
    cleanup_terminal_barrier: Option<CleanupTerminalBarrier>,
    #[cfg(test)]
    cleanup_acknowledgement_barrier: Option<CleanupTerminalBarrier>,
}

#[cfg(test)]
struct CompletionDecisionBarrier {
    ready: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
}

#[cfg(test)]
struct CleanupTerminalBarrier {
    ready: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
}

impl<D: OperationDispatcher> OperationRunner<D> {
    #[must_use]
    pub const fn new(startup: RunnerStartupConfig, dispatcher: D) -> Self {
        Self {
            startup,
            dispatcher,
            lease_timing: LeaseTiming::DEFAULT,
            #[cfg(test)]
            guardian_events: None,
            #[cfg(test)]
            completion_decision_barrier: None,
            #[cfg(test)]
            cleanup_terminal_barrier: None,
            #[cfg(test)]
            cleanup_acknowledgement_barrier: None,
        }
    }

    #[cfg(test)]
    fn with_lease_timing_for_test(
        mut self,
        duration_ms: i64,
        renewal_margin_ms: i64,
        guardian_events: mpsc::Sender<LeaseGuardianEvent>,
    ) -> Self {
        self.lease_timing = LeaseTiming::new(duration_ms, renewal_margin_ms)
            .expect("test lease timing must be valid");
        self.guardian_events = Some(guardian_events);
        self
    }

    #[cfg(test)]
    fn with_completion_decision_barrier_for_test(
        mut self,
        ready: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    ) -> Self {
        self.completion_decision_barrier = Some(CompletionDecisionBarrier { ready, release });
        self
    }

    #[cfg(test)]
    fn with_cleanup_terminal_barrier_for_test(
        mut self,
        ready: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    ) -> Self {
        self.cleanup_terminal_barrier = Some(CleanupTerminalBarrier { ready, release });
        self
    }

    #[cfg(test)]
    fn with_cleanup_acknowledgement_barrier_for_test(
        mut self,
        ready: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    ) -> Self {
        self.cleanup_acknowledgement_barrier = Some(CleanupTerminalBarrier { ready, release });
        self
    }

    fn terminalize_after_cleanup<T>(
        &mut self,
        work: &RunnerWork,
        cleanup_guard: Option<std::fs::File>,
        terminalize: impl FnOnce() -> Result<T, RunnerError>,
    ) -> Result<T, RunnerError> {
        let cleanup_guard = match cleanup_guard {
            Some(guard) => Some(guard),
            None => self.dispatcher.cleanup_abandoned(work)?,
        };
        #[cfg(test)]
        if let Some(barrier) = &self.cleanup_terminal_barrier {
            barrier.ready.send(()).expect("test cleanup receiver");
            barrier
                .release
                .recv_timeout(Duration::from_secs(5))
                .expect("test cleanup release");
        }
        let result = terminalize();
        drop(cleanup_guard);
        let value = result?;
        #[cfg(test)]
        if let Some(barrier) = &self.cleanup_acknowledgement_barrier {
            barrier.ready.send(()).expect("test cleanup receiver");
            barrier
                .release
                .recv_timeout(Duration::from_secs(5))
                .expect("test cleanup release");
        }
        self.dispatcher
            .finalize_cleanup_acknowledgement(work.kind(), work.operation_id())?;
        Ok(value)
    }

    fn reconcile_cleanup_acknowledgements(
        &mut self,
        journal: &OperationJournal,
        repository_id: &LogicalRepositoryId,
        after_operation_id: Option<&str>,
    ) -> Result<Option<String>, RunnerError> {
        let (operation_ids, next_after_operation_id) = self
            .dispatcher
            .pending_cleanup_acknowledgements(after_operation_id)?;
        for operation_id in operation_ids {
            if journal.scan_cleanup_acknowledged(repository_id, &operation_id)? {
                self.dispatcher
                    .finalize_cleanup_acknowledgement(OperationKind::ScanSubmit, &operation_id)?;
            }
        }
        Ok(next_after_operation_id)
    }

    pub fn run_until_idle(mut self) -> Result<RunnerReport, RunnerError> {
        let repository_id =
            LogicalRepositoryId::parse(self.startup.service.logical_repository_id())
                .map_err(|_| RunnerError::InvalidStartupAuthority)?;
        let owner = new_lease_owner()?;
        let mut journal = OperationJournal::open(&self.startup.service)?;
        let mut report = RunnerReport::default();
        let Some(runner_purge_guard) = journal.try_acquire_runner_purge_guard()? else {
            return Ok(report);
        };
        let mut cleanup_after_operation_id = None;
        loop {
            cleanup_after_operation_id = self.reconcile_cleanup_acknowledgements(
                &journal,
                &repository_id,
                cleanup_after_operation_id.as_deref(),
            )?;
            loop {
                let recovery_now_ms = system_now_ms()?;
                let Some(intent) =
                    journal.next_completion_intent(&repository_id, recovery_now_ms)?
                else {
                    break;
                };
                match self.dispatcher.recover_completion(&intent)? {
                    CompletionRecovery::Finalized => {
                        journal.finish_completion_intent(
                            &repository_id,
                            intent.operation_id(),
                            system_now_ms()?,
                        )?;
                        report.completed += 1;
                    }
                    CompletionRecovery::Busy => return Ok(report),
                }
            }
            let Some(legacy_staging_more_work) = self.dispatcher.reconcile_legacy_staging()? else {
                return Ok(report);
            };
            let now_ms = system_now_ms()?;
            while let Some(expired) =
                journal.next_expired_external_store_operation(&repository_id, now_ms)?
            {
                let (record, handoff) = expired.into_parts();
                let work = RunnerWork {
                    operation_id: record.operation_id().clone(),
                    kind: *record.kind(),
                    input: handoff.payload().clone(),
                    execution_deadline_ms: record.execution_deadline_ms(),
                };
                self.terminalize_after_cleanup(&work, None, || {
                    record_deadline_failure(
                        &mut journal,
                        &repository_id,
                        work.operation_id(),
                        work.execution_deadline_ms(),
                        &mut report,
                    )
                })?;
            }
            if cleanup_after_operation_id.is_none() {
                journal.purge_with_runner_guard(now_ms, &runner_purge_guard)?;
            }
            if legacy_staging_more_work {
                continue;
            }
            let lease_expires_at_ms = now_ms
                .checked_add(self.lease_timing.duration_ms)
                .ok_or(RunnerError::ClockUnavailable)?;
            let token = LeaseToken::generate()?;
            let Some(claimed) = journal.claim_next_runner_handoff(
                &repository_id,
                &owner,
                token.as_ref(),
                now_ms,
                lease_expires_at_ms,
            )?
            else {
                if cleanup_after_operation_id.is_some() {
                    continue;
                }
                return Ok(report);
            };
            report.claimed += 1;
            let (record, handoff) = claimed.into_parts();
            let work = RunnerWork {
                operation_id: record.operation_id().clone(),
                kind: *record.kind(),
                input: handoff.payload().clone(),
                execution_deadline_ms: record.execution_deadline_ms(),
            };
            let initial_lease_expires_at_ms = record
                .lease()
                .ok_or(RunnerError::Journal(JournalError::IntegrityFailure))?
                .expires_at_ms();
            let execution_cancellation = CancellationToken::new();
            let guardian = match LeaseGuardian::start(
                self.startup.clone(),
                repository_id.clone(),
                work.operation_id().clone(),
                token.copy_for_guardian(),
                initial_lease_expires_at_ms,
                work.execution_deadline_ms(),
                self.lease_timing,
                execution_cancellation.clone(),
                #[cfg(test)]
                self.guardian_events.clone(),
            )? {
                LeaseGuardianStart::Active(guardian) => guardian,
                LeaseGuardianStart::Inactive(LeaseGuardianExit::CancellationRequested) => {
                    let terminal_at_ms = system_now_ms()?;
                    self.terminalize_after_cleanup(&work, None, || {
                        journal
                            .mark_cancelled(
                                &repository_id,
                                work.operation_id(),
                                token.as_ref(),
                                terminal_at_ms,
                            )
                            .map_err(RunnerError::from)
                    })?;
                    report.cancelled += 1;
                    continue;
                }
                LeaseGuardianStart::Inactive(LeaseGuardianExit::DeadlineExceeded) => {
                    self.terminalize_after_cleanup(&work, None, || {
                        record_deadline_failure(
                            &mut journal,
                            &repository_id,
                            work.operation_id(),
                            work.execution_deadline_ms(),
                            &mut report,
                        )
                    })?;
                    continue;
                }
                LeaseGuardianStart::Inactive(LeaseGuardianExit::LeaseLost) => {
                    report.lease_lost += 1;
                    continue;
                }
                LeaseGuardianStart::Inactive(LeaseGuardianExit::Stopped) => {
                    return Err(guardian_failure());
                }
            };
            enum ControlledDispatch {
                DeadlineExceeded,
                LeaseLost,
                Outcome(DispatchOutcome, ExecutionCheckpoint),
            }
            let controlled_dispatch: Result<ControlledDispatch, RunnerError> = (|| {
                let mut control = ExecutionControl {
                    journal: &mut journal,
                    repository_id: &repository_id,
                    operation_id: work.operation_id(),
                    lease_token: token.as_ref(),
                    execution_deadline_ms: work.execution_deadline_ms(),
                    cancellation: &execution_cancellation,
                    now: &system_now_ms,
                };
                Ok(match control.checkpoint()? {
                    ExecutionCheckpoint::Continue => {
                        let outcome = self.dispatcher.dispatch(&work, &mut control);
                        ControlledDispatch::Outcome(outcome, control.checkpoint()?)
                    }
                    ExecutionCheckpoint::CancellationRequested => ControlledDispatch::Outcome(
                        DispatchOutcome::Cancelled,
                        control.checkpoint()?,
                    ),
                    ExecutionCheckpoint::DeadlineExceeded => ControlledDispatch::DeadlineExceeded,
                    ExecutionCheckpoint::LeaseLost => ControlledDispatch::LeaseLost,
                })
            })();
            // Always stop and join before using the dispatch outcome. Guardian
            // failures take precedence, and no renewal can race finalization.
            let guardian_exit = guardian.stop_and_join()?;
            let controlled_dispatch = controlled_dispatch?;
            match guardian_exit {
                LeaseGuardianExit::Stopped => {}
                LeaseGuardianExit::CancellationRequested => {
                    let cleanup_guard =
                        if let ControlledDispatch::Outcome(outcome, _) = controlled_dispatch {
                            discard_pending_completion(outcome)?
                        } else {
                            None
                        };
                    let terminal_at_ms = system_now_ms()?;
                    self.terminalize_after_cleanup(&work, cleanup_guard, || {
                        journal
                            .mark_cancelled(
                                &repository_id,
                                work.operation_id(),
                                token.as_ref(),
                                terminal_at_ms,
                            )
                            .map_err(RunnerError::from)
                    })?;
                    report.cancelled += 1;
                    continue;
                }
                LeaseGuardianExit::DeadlineExceeded => {
                    let cleanup_guard =
                        if let ControlledDispatch::Outcome(outcome, _) = controlled_dispatch {
                            discard_pending_completion(outcome)?
                        } else {
                            None
                        };
                    self.terminalize_after_cleanup(&work, cleanup_guard, || {
                        record_deadline_failure(
                            &mut journal,
                            &repository_id,
                            work.operation_id(),
                            work.execution_deadline_ms(),
                            &mut report,
                        )
                    })?;
                    continue;
                }
                LeaseGuardianExit::LeaseLost => {
                    if let ControlledDispatch::Outcome(outcome, _) = controlled_dispatch {
                        drop(discard_pending_completion(outcome)?);
                    }
                    report.lease_lost += 1;
                    continue;
                }
            }
            let ControlledDispatch::Outcome(outcome, final_checkpoint) = controlled_dispatch else {
                match controlled_dispatch {
                    ControlledDispatch::DeadlineExceeded => {
                        self.terminalize_after_cleanup(&work, None, || {
                            record_deadline_failure(
                                &mut journal,
                                &repository_id,
                                work.operation_id(),
                                work.execution_deadline_ms(),
                                &mut report,
                            )
                        })?;
                    }
                    ControlledDispatch::LeaseLost => report.lease_lost += 1,
                    ControlledDispatch::Outcome(_, _) => unreachable!(),
                }
                continue;
            };
            #[cfg(test)]
            if matches!(outcome, DispatchOutcome::CompletionPending { .. })
                && let Some(barrier) = &self.completion_decision_barrier
            {
                barrier
                    .ready
                    .send(())
                    .expect("test completion-decision receiver");
                barrier
                    .release
                    .recv_timeout(Duration::from_secs(5))
                    .expect("test completion-decision release");
            }
            match final_checkpoint {
                ExecutionCheckpoint::DeadlineExceeded => {
                    let cleanup_guard = discard_pending_completion(outcome)?;
                    self.terminalize_after_cleanup(&work, cleanup_guard, || {
                        record_deadline_failure(
                            &mut journal,
                            &repository_id,
                            work.operation_id(),
                            work.execution_deadline_ms(),
                            &mut report,
                        )
                    })?;
                }
                ExecutionCheckpoint::LeaseLost => {
                    drop(discard_pending_completion(outcome)?);
                    report.lease_lost += 1;
                }
                ExecutionCheckpoint::CancellationRequested => {
                    let cleanup_guard = discard_pending_completion(outcome)?;
                    let terminal_at_ms = system_now_ms()?;
                    self.terminalize_after_cleanup(&work, cleanup_guard, || {
                        journal
                            .mark_cancelled(
                                &repository_id,
                                work.operation_id(),
                                token.as_ref(),
                                terminal_at_ms,
                            )
                            .map_err(RunnerError::from)
                    })?;
                    report.cancelled += 1;
                }
                ExecutionCheckpoint::Continue => {
                    let terminal_at_ms = system_now_ms()?;
                    if terminal_at_ms >= work.execution_deadline_ms() {
                        let cleanup_guard = discard_pending_completion(outcome)?;
                        self.terminalize_after_cleanup(&work, cleanup_guard, || {
                            record_deadline_failure(
                                &mut journal,
                                &repository_id,
                                work.operation_id(),
                                work.execution_deadline_ms(),
                                &mut report,
                            )
                        })?;
                        continue;
                    }
                    match outcome {
                        DispatchOutcome::Completed(result) => {
                            journal.complete(
                                &repository_id,
                                work.operation_id(),
                                token.as_ref(),
                                result,
                                terminal_at_ms,
                            )?;
                            report.completed += 1;
                        }
                        DispatchOutcome::CompletionPending {
                            result,
                            mut completion,
                        } => {
                            completion.bind_recovery_result(&result)?;
                            match journal.commit_completion_intent(
                                &repository_id,
                                work.operation_id(),
                                token.as_ref(),
                                result,
                                terminal_at_ms,
                            )? {
                                CompletionDecision::Committed => {
                                    completion.promote()?;
                                    journal.finish_completion_intent(
                                        &repository_id,
                                        work.operation_id(),
                                        system_now_ms()?,
                                    )?;
                                    report.completed += 1;
                                }
                                CompletionDecision::CancellationWon => {
                                    let cleanup_guard = completion.cancel()?;
                                    self.terminalize_after_cleanup(&work, cleanup_guard, || {
                                        journal
                                            .mark_cancelled(
                                                &repository_id,
                                                work.operation_id(),
                                                token.as_ref(),
                                                system_now_ms()?,
                                            )
                                            .map_err(RunnerError::from)
                                    })?;
                                    report.cancelled += 1;
                                }
                            }
                        }
                        DispatchOutcome::CancellationCleanupPending { completion } => {
                            let cleanup_guard = completion.cancel()?;
                            self.terminalize_after_cleanup(&work, cleanup_guard, || {
                                journal
                                    .mark_cancelled(
                                        &repository_id,
                                        work.operation_id(),
                                        token.as_ref(),
                                        terminal_at_ms,
                                    )
                                    .map_err(RunnerError::from)
                            })?;
                            report.cancelled += 1;
                        }
                        DispatchOutcome::FailureCleanupPending { error, completion } => {
                            let cleanup_guard = completion.cancel()?;
                            self.terminalize_after_cleanup(&work, cleanup_guard, || {
                                journal
                                    .fail(
                                        &repository_id,
                                        work.operation_id(),
                                        token.as_ref(),
                                        error,
                                        terminal_at_ms,
                                    )
                                    .map_err(RunnerError::from)
                            })?;
                            report.failed += 1;
                        }
                        DispatchOutcome::Failed(error) => {
                            self.terminalize_after_cleanup(&work, None, || {
                                journal
                                    .fail(
                                        &repository_id,
                                        work.operation_id(),
                                        token.as_ref(),
                                        error,
                                        terminal_at_ms,
                                    )
                                    .map_err(RunnerError::from)
                            })?;
                            report.failed += 1;
                        }
                        DispatchOutcome::Cancelled => {
                            self.terminalize_after_cleanup(&work, None, || {
                                journal
                                    .mark_cancelled(
                                        &repository_id,
                                        work.operation_id(),
                                        token.as_ref(),
                                        terminal_at_ms,
                                    )
                                    .map_err(RunnerError::from)
                            })?;
                            report.cancelled += 1;
                        }
                    }
                }
            }
        }
    }
}

fn discard_pending_completion(
    outcome: DispatchOutcome,
) -> Result<Option<std::fs::File>, RunnerError> {
    match outcome {
        DispatchOutcome::CompletionPending { completion, .. }
        | DispatchOutcome::CancellationCleanupPending { completion }
        | DispatchOutcome::FailureCleanupPending { completion, .. } => completion.cancel(),
        DispatchOutcome::Completed(_) | DispatchOutcome::Failed(_) | DispatchOutcome::Cancelled => {
            Ok(None)
        }
    }
}

#[derive(Clone, Copy)]
struct LeaseTiming {
    duration_ms: i64,
    renewal_margin_ms: i64,
}

impl LeaseTiming {
    const DEFAULT: Self = Self {
        duration_ms: DEFAULT_LEASE_DURATION_MS,
        renewal_margin_ms: DEFAULT_RENEWAL_MARGIN_MS,
    };

    #[cfg(test)]
    const fn new(duration_ms: i64, renewal_margin_ms: i64) -> Option<Self> {
        if duration_ms > 0 && renewal_margin_ms > 0 && renewal_margin_ms < duration_ms {
            Some(Self {
                duration_ms,
                renewal_margin_ms,
            })
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaseGuardianExit {
    Stopped,
    CancellationRequested,
    DeadlineExceeded,
    LeaseLost,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaseGuardianEvent {
    Started {
        lease_expires_at_ms: i64,
    },
    Renewed {
        renewed_at_ms: i64,
        lease_expires_at_ms: i64,
    },
}

struct LeaseGuardian {
    stop: Arc<(Mutex<bool>, Condvar)>,
    join: Option<JoinHandle<Result<LeaseGuardianExit, RunnerError>>>,
}

enum LeaseGuardianStart {
    Active(LeaseGuardian),
    Inactive(LeaseGuardianExit),
}

impl LeaseGuardian {
    #[allow(clippy::too_many_arguments)]
    fn start(
        startup: RunnerStartupConfig,
        repository_id: LogicalRepositoryId,
        operation_id: OperationId,
        lease_token: LeaseToken,
        initial_lease_expires_at_ms: i64,
        execution_deadline_ms: i64,
        timing: LeaseTiming,
        cancellation: CancellationToken,
        #[cfg(test)] events: Option<mpsc::Sender<LeaseGuardianEvent>>,
    ) -> Result<LeaseGuardianStart, RunnerError> {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let thread_stop = Arc::clone(&stop);
        let (startup_ready, startup_waiter) = mpsc::sync_channel(0);
        let join = thread::Builder::new()
            .name("depgraph-operation-lease-guardian".to_owned())
            .spawn(move || {
                if initial_lease_expires_at_ms <= 0
                    || initial_lease_expires_at_ms > execution_deadline_ms
                {
                    return Err(RunnerError::Journal(JournalError::IntegrityFailure));
                }
                let mut journal = OperationJournal::open(startup.service_config())?;
                #[cfg(test)]
                if let Some(events) = &events {
                    let _ = events.send(LeaseGuardianEvent::Started {
                        lease_expires_at_ms: initial_lease_expires_at_ms,
                    });
                }
                let renewed_at_ms = system_now_ms()?;
                if renewed_at_ms >= execution_deadline_ms {
                    let exit = signal_execution_cancellation(
                        &cancellation,
                        LeaseGuardianExit::DeadlineExceeded,
                    );
                    startup_ready
                        .send(Err(exit))
                        .map_err(|_| guardian_failure())?;
                    return Ok(exit);
                }
                let renewed_until_ms = renewed_at_ms
                    .checked_add(timing.duration_ms)
                    .ok_or(RunnerError::ClockUnavailable)?
                    .min(execution_deadline_ms);
                let record = match journal.renew_lease(
                    &repository_id,
                    &operation_id,
                    lease_token.as_ref(),
                    renewed_at_ms,
                    renewed_until_ms,
                ) {
                    Ok(record) => record,
                    Err(JournalError::DeadlineExceeded) => {
                        let exit = signal_execution_cancellation(
                            &cancellation,
                            LeaseGuardianExit::DeadlineExceeded,
                        );
                        startup_ready
                            .send(Err(exit))
                            .map_err(|_| guardian_failure())?;
                        return Ok(exit);
                    }
                    Err(JournalError::LeaseExpired | JournalError::LeaseMismatch) => {
                        let exit = signal_execution_cancellation(
                            &cancellation,
                            LeaseGuardianExit::LeaseLost,
                        );
                        startup_ready
                            .send(Err(exit))
                            .map_err(|_| guardian_failure())?;
                        return Ok(exit);
                    }
                    Err(error) => return Err(RunnerError::Journal(error)),
                };
                if record.status() == OperationStatus::Cancelling {
                    let exit = signal_execution_cancellation(
                        &cancellation,
                        LeaseGuardianExit::CancellationRequested,
                    );
                    startup_ready
                        .send(Err(exit))
                        .map_err(|_| guardian_failure())?;
                    return Ok(exit);
                }
                let lease_expires_at_ms = record
                    .lease()
                    .ok_or(RunnerError::Journal(JournalError::IntegrityFailure))?
                    .expires_at_ms();
                #[cfg(test)]
                if let Some(events) = &events {
                    let _ = events.send(LeaseGuardianEvent::Renewed {
                        renewed_at_ms,
                        lease_expires_at_ms,
                    });
                }
                startup_ready.send(Ok(())).map_err(|_| guardian_failure())?;
                guard_lease(
                    journal,
                    &repository_id,
                    &operation_id,
                    &lease_token,
                    lease_expires_at_ms,
                    execution_deadline_ms,
                    timing,
                    &thread_stop,
                    &cancellation,
                    #[cfg(test)]
                    events.as_ref(),
                )
            })
            .map_err(|error| RunnerError::Journal(JournalError::Io(error)))?;
        match startup_waiter.recv() {
            Ok(Ok(())) => Ok(LeaseGuardianStart::Active(Self {
                stop,
                join: Some(join),
            })),
            Ok(Err(expected_exit)) => match join_guardian(join) {
                Ok(actual_exit) if actual_exit == expected_exit => {
                    Ok(LeaseGuardianStart::Inactive(actual_exit))
                }
                Ok(_) => Err(guardian_failure()),
                Err(error) => Err(error),
            },
            Err(_) => match join.join() {
                Ok(Err(error)) => Err(error),
                Ok(Ok(_)) | Err(_) => Err(guardian_failure()),
            },
        }
    }

    fn stop_and_join(mut self) -> Result<LeaseGuardianExit, RunnerError> {
        self.request_stop();
        join_guardian(self.join.take().ok_or_else(guardian_failure)?)
    }

    fn request_stop(&self) {
        let (lock, wake) = &*self.stop;
        let mut stopped = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *stopped = true;
        wake.notify_one();
    }
}

impl Drop for LeaseGuardian {
    fn drop(&mut self) {
        self.request_stop();
        if let Some(join) = self.join.take() {
            let _ = join_guardian(join);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn guard_lease(
    mut journal: OperationJournal,
    repository_id: &LogicalRepositoryId,
    operation_id: &OperationId,
    lease_token: &LeaseToken,
    mut lease_expires_at_ms: i64,
    execution_deadline_ms: i64,
    timing: LeaseTiming,
    stop: &Arc<(Mutex<bool>, Condvar)>,
    cancellation: &CancellationToken,
    #[cfg(test)] events: Option<&mpsc::Sender<LeaseGuardianEvent>>,
) -> Result<LeaseGuardianExit, RunnerError> {
    loop {
        if stop_requested(stop) {
            return Ok(LeaseGuardianExit::Stopped);
        }
        let now_ms = system_now_ms()?;
        if now_ms >= execution_deadline_ms {
            return Ok(signal_execution_cancellation(
                cancellation,
                LeaseGuardianExit::DeadlineExceeded,
            ));
        }
        let wake_at_ms = if lease_expires_at_ms >= execution_deadline_ms {
            execution_deadline_ms
        } else {
            lease_expires_at_ms.saturating_sub(timing.renewal_margin_ms)
        };
        if wake_at_ms > now_ms {
            let wait_ms =
                u64::try_from(wake_at_ms - now_ms).map_err(|_| RunnerError::ClockUnavailable)?;
            if wait_for_stop(stop, Duration::from_millis(wait_ms)) {
                return Ok(LeaseGuardianExit::Stopped);
            }
            continue;
        }

        let renewed_at_ms = system_now_ms()?;
        if renewed_at_ms >= execution_deadline_ms {
            return Ok(signal_execution_cancellation(
                cancellation,
                LeaseGuardianExit::DeadlineExceeded,
            ));
        }
        let renewed_until_ms = renewed_at_ms
            .checked_add(timing.duration_ms)
            .ok_or(RunnerError::ClockUnavailable)?
            .min(execution_deadline_ms);
        let record = match journal.renew_lease(
            repository_id,
            operation_id,
            lease_token.as_ref(),
            renewed_at_ms,
            renewed_until_ms,
        ) {
            Ok(record) => record,
            Err(JournalError::DeadlineExceeded) => {
                return Ok(signal_execution_cancellation(
                    cancellation,
                    LeaseGuardianExit::DeadlineExceeded,
                ));
            }
            Err(JournalError::LeaseExpired | JournalError::LeaseMismatch) => {
                return Ok(signal_execution_cancellation(
                    cancellation,
                    LeaseGuardianExit::LeaseLost,
                ));
            }
            Err(error) => return Err(RunnerError::Journal(error)),
        };
        if record.status() == OperationStatus::Cancelling {
            return Ok(signal_execution_cancellation(
                cancellation,
                LeaseGuardianExit::CancellationRequested,
            ));
        }
        lease_expires_at_ms = record
            .lease()
            .ok_or(RunnerError::Journal(JournalError::IntegrityFailure))?
            .expires_at_ms();
        #[cfg(test)]
        if let Some(events) = events {
            let _ = events.send(LeaseGuardianEvent::Renewed {
                renewed_at_ms,
                lease_expires_at_ms,
            });
        }
    }
}

fn stop_requested(stop: &Arc<(Mutex<bool>, Condvar)>) -> bool {
    *stop
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn wait_for_stop(stop: &Arc<(Mutex<bool>, Condvar)>, duration: Duration) -> bool {
    let (lock, wake) = &**stop;
    let stopped = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if *stopped {
        return true;
    }
    let (stopped, _) = wake
        .wait_timeout(stopped, duration)
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *stopped
}

fn join_guardian(
    join: JoinHandle<Result<LeaseGuardianExit, RunnerError>>,
) -> Result<LeaseGuardianExit, RunnerError> {
    join.join().map_err(|_| guardian_failure())?
}

fn signal_execution_cancellation(
    cancellation: &CancellationToken,
    exit: LeaseGuardianExit,
) -> LeaseGuardianExit {
    cancellation.cancel();
    exit
}

fn guardian_failure() -> RunnerError {
    RunnerError::Journal(JournalError::IntegrityFailure)
}

fn record_deadline_failure(
    journal: &mut OperationJournal,
    repository_id: &LogicalRepositoryId,
    operation_id: &OperationId,
    execution_deadline_ms: i64,
    report: &mut RunnerReport,
) -> Result<(), RunnerError> {
    let record = journal.get(repository_id, operation_id, execution_deadline_ms)?;
    if record.status().is_terminal() {
        report.lease_lost += 1;
        return Ok(());
    }
    match journal.fail_deadline_after_runner_cleanup(
        repository_id,
        operation_id,
        execution_deadline_ms,
    ) {
        Ok(_) => report.failed += 1,
        Err(JournalError::InvalidTransition) => {
            let record = journal.get(repository_id, operation_id, execution_deadline_ms)?;
            if record.status().is_terminal() {
                report.lease_lost += 1;
            } else {
                return Err(RunnerError::Journal(JournalError::InvalidTransition));
            }
        }
        Err(error) => return Err(RunnerError::Journal(error)),
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnsupportedOperationDispatcher;

impl OperationDispatcher for UnsupportedOperationDispatcher {
    fn dispatch(
        &mut self,
        _work: &RunnerWork,
        _control: &mut ExecutionControl<'_>,
    ) -> DispatchOutcome {
        let error = CanonicalJson::from_database(UNSUPPORTED_OPERATION_ERROR_JSON.to_owned())
            .expect("the compiled unsupported-operation error is canonical and bounded");
        DispatchOutcome::Failed(error)
    }
}

#[derive(Clone)]
pub struct ScanOperationDispatcher {
    config: DepgraphServiceConfig,
    #[cfg(test)]
    runtime_dispatch_barrier: Option<Arc<RuntimeDispatchBarrier>>,
    #[cfg(test)]
    daemon_start_promoter: Option<TestDaemonStartPromoter>,
}

#[cfg(test)]
struct RuntimeDispatchBarrier {
    ready: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeImportInput {
    #[serde(default)]
    trace: Option<serde_json::Value>,
    #[serde(default)]
    trace_file: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    runtime_trace_digest: Option<String>,
    snapshot_id: SnapshotId,
    trace_digest: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanInput {
    #[serde(default)]
    strict: bool,
    #[serde(default)]
    no_cache: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportFileInput {
    output_path: String,
    #[serde(default)]
    overwrite: bool,
    format: GraphExportFormat,
    snapshot_id: SnapshotId,
    #[serde(default)]
    selector: Option<String>,
    max_nodes: usize,
    max_edges: usize,
    #[serde(default)]
    destination_precondition: Option<RepositoryOutputPrecondition>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DaemonStartInput {
    #[serde(default)]
    strict: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DaemonStopInput {}

impl RuntimeImportInput {
    fn retained_runtime_identity(&self) -> Result<Option<(String, String)>, ()> {
        match (
            self.session_id.as_deref(),
            self.runtime_trace_digest.as_deref(),
        ) {
            (Some(session_id), Some(runtime_trace_digest)) => Ok(Some((
                session_id.to_owned(),
                runtime_trace_digest.to_owned(),
            ))),
            (None, None) => Ok(None),
            _ => Err(()),
        }
    }
}

/// Immutable recovery binding reconstructed from a digest-checked completion
/// intent. The closed success envelope already retains every public runtime
/// outcome identity, so legacy input needs no second journal schema. A missing
/// trace digest remains explicit: the store must reconstruct and verify it from
/// the envelope-selected session inside the promotion transaction.
struct RuntimeCompletionRecoveryBinding {
    base_snapshot_id: SnapshotId,
    runtime_trace_digest: Option<String>,
    envelope: SuccessEnvelope<AgentRuntimeOutcome>,
}

impl ScanOperationDispatcher {
    fn export_file_request(
        &self,
        input: &ExportFileInput,
    ) -> Result<ExportFileRequest, DepgraphServiceError> {
        if input.overwrite && input.destination_precondition.is_none() {
            return Err(DepgraphServiceError::InvalidInput);
        }
        let snapshot = match SnapshotLocator::parse(input.snapshot_id.as_str())? {
            SnapshotLocator::StableId(snapshot_id) => SnapshotLocator::StableId(snapshot_id),
            _ => return Err(DepgraphServiceError::Integrity),
        };
        let graph = GraphExportRequest::try_new(
            snapshot,
            input.format,
            input.selector.clone(),
            GraphQueryFilter::default(),
            input.max_nodes,
            input.max_edges,
        )?;
        let output_path = RepositoryRelativePath::parse(&input.output_path)?;
        let request = ExportFileRequest::new(
            graph,
            output_path,
            if input.overwrite {
                RepositoryOverwritePolicy::Overwrite
            } else {
                RepositoryOverwritePolicy::NoReplace
            },
        );
        Ok(match &input.destination_precondition {
            Some(precondition) => request.with_destination_precondition(precondition.clone()),
            None => request,
        })
    }

    #[must_use]
    pub const fn new(config: DepgraphServiceConfig) -> Self {
        Self {
            config,
            #[cfg(test)]
            runtime_dispatch_barrier: None,
            #[cfg(test)]
            daemon_start_promoter: None,
        }
    }

    #[cfg(test)]
    fn with_runtime_dispatch_barrier_for_test(
        mut self,
        ready: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    ) -> Self {
        self.runtime_dispatch_barrier = Some(Arc::new(RuntimeDispatchBarrier {
            ready,
            release: Mutex::new(release),
        }));
        self
    }

    #[cfg(test)]
    fn with_daemon_start_promoter_for_test(mut self, promoter: TestDaemonStartPromoter) -> Self {
        self.daemon_start_promoter = Some(promoter);
        self
    }

    fn resolve_daemon_start_launcher(
        &self,
    ) -> Result<Option<DaemonExecutableLauncher>, RunnerLaunchError> {
        #[cfg(test)]
        if self.daemon_start_promoter.is_some() {
            return Ok(None);
        }
        DaemonExecutableLauncher::resolve().map(Some)
    }

    fn daemon_start_completion(
        &self,
        strict: bool,
        launcher: Option<DaemonExecutableLauncher>,
    ) -> DeferredDaemonCompletion {
        let completion = DeferredDaemonCompletion::start(self.config.clone(), strict, launcher);
        #[cfg(test)]
        if let Some(promoter) = &self.daemon_start_promoter {
            return completion.with_daemon_start_promoter_for_test(Arc::clone(promoter));
        }
        completion
    }

    fn dispatch_scan(
        &self,
        work: &RunnerWork,
        control: &mut ExecutionControl<'_>,
    ) -> DispatchOutcome {
        let input = match serde_json::from_str::<ScanInput>(work.input().as_str()) {
            Ok(input) => input,
            Err(_) => return self.failed(AgentErrorCode::InvalidArgument),
        };
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => return self.failed(AgentErrorCode::Internal),
        };
        let cancellation = CancellationToken::new();
        let request = ScanRequest::new(
            input.strict,
            if input.no_cache {
                ScanCacheMode::Disabled
            } else {
                ScanCacheMode::Enabled
            },
        );
        let service = DepgraphService::new(self.config.clone());
        let execution = service.scan_deferred_cancellable_for_operation(
            &request,
            work.operation_id().as_str(),
            cancellation.clone(),
        );
        tokio::pin!(execution);
        let mut forced_cancel = false;
        let result = runtime.block_on(async {
            let mut checkpoints = tokio::time::interval(Duration::from_millis(25));
            checkpoints.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    result = &mut execution => break result,
                    _ = checkpoints.tick() => {
                        match control.checkpoint() {
                            Ok(ExecutionCheckpoint::Continue) => {}
                            Ok(
                                ExecutionCheckpoint::CancellationRequested
                                | ExecutionCheckpoint::DeadlineExceeded
                                | ExecutionCheckpoint::LeaseLost,
                            )
                            | Err(_) => {
                                forced_cancel = true;
                                cancellation.cancel();
                            }
                        }
                    }
                }
            }
        });
        if forced_cancel {
            if let Ok(DeferredScanServiceOutcome::Pending(completion)) = result {
                return DispatchOutcome::CancellationCleanupPending {
                    completion: DeferredOperationCompletion::Scan(completion),
                };
            }
            return DispatchOutcome::Cancelled;
        }
        match result {
            Ok(DeferredScanServiceOutcome::Pending(completion)) => {
                let result = match self.completed_output(completion.outcome()) {
                    Ok(result) => result,
                    Err(error) => {
                        return DispatchOutcome::FailureCleanupPending {
                            error,
                            completion: DeferredOperationCompletion::Scan(completion),
                        };
                    }
                };
                DispatchOutcome::CompletionPending {
                    result,
                    completion: DeferredOperationCompletion::Scan(completion),
                }
            }
            Ok(DeferredScanServiceOutcome::Finished(result))
                if result.outcome().status == "cancelled" =>
            {
                DispatchOutcome::Cancelled
            }
            Ok(DeferredScanServiceOutcome::Finished(_)) => self.failed(AgentErrorCode::Internal),
            Err(DepgraphServiceError::Cancelled) => DispatchOutcome::Cancelled,
            Err(DepgraphServiceError::Conflict | DepgraphServiceError::StoreWriterConflict) => {
                self.failed(AgentErrorCode::Conflict)
            }
            Err(DepgraphServiceError::CapabilityDenied { .. }) => {
                self.failed(AgentErrorCode::CapabilityDenied)
            }
            Err(_) => self.failed(AgentErrorCode::Internal),
        }
    }

    fn dispatch_export_file(
        &self,
        work: &RunnerWork,
        control: &mut ExecutionControl<'_>,
    ) -> DispatchOutcome {
        let input = match serde_json::from_str::<ExportFileInput>(work.input().as_str()) {
            Ok(input) => input,
            Err(_) => return self.failed(AgentErrorCode::InvalidArgument),
        };
        if !matches!(control.checkpoint(), Ok(ExecutionCheckpoint::Continue)) {
            return DispatchOutcome::Cancelled;
        }
        let request = match self.export_file_request(&input) {
            Ok(request) => request,
            Err(error) => return self.failed_service(&error),
        };
        let service = DepgraphService::new(self.config.clone());
        let cancellation = control.cancellation_token().clone();
        let completion = match service.export_file_deferred_for_operation(
            &request,
            work.operation_id().as_str(),
            &cancellation,
        ) {
            Ok(completion) => completion,
            Err(DepgraphServiceError::Cancelled) => return DispatchOutcome::Cancelled,
            Err(error) => return self.failed_service(&error),
        };
        if !matches!(control.checkpoint(), Ok(ExecutionCheckpoint::Continue)) {
            return DispatchOutcome::CancellationCleanupPending {
                completion: DeferredOperationCompletion::ExportFile(Box::new(completion)),
            };
        }
        let result = match self.completed_export_output(&completion) {
            Ok(result) => result,
            Err(error) => {
                return DispatchOutcome::FailureCleanupPending {
                    error,
                    completion: DeferredOperationCompletion::ExportFile(Box::new(completion)),
                };
            }
        };
        DispatchOutcome::CompletionPending {
            result,
            completion: DeferredOperationCompletion::ExportFile(Box::new(completion)),
        }
    }

    fn dispatch_runtime_import(
        &self,
        work: &RunnerWork,
        control: &mut ExecutionControl<'_>,
    ) -> DispatchOutcome {
        let input = match serde_json::from_str::<RuntimeImportInput>(work.input().as_str()) {
            Ok(input) => input,
            Err(_) => return self.failed(AgentErrorCode::InvalidArgument),
        };
        let retained_runtime_identity = match input.retained_runtime_identity() {
            Ok(identity) => identity,
            Err(()) => return self.failed(AgentErrorCode::Conflict),
        };
        if !matches!(control.checkpoint(), Ok(ExecutionCheckpoint::Continue)) {
            return DispatchOutcome::Cancelled;
        }
        let trace = match input.trace.as_ref() {
            Some(trace) => match serde_json::to_string(trace) {
                Ok(trace) => Some(trace),
                Err(_) => return self.failed(AgentErrorCode::IntegrityFailure),
            },
            None => None,
        };
        let trace_file = match input.trace_file {
            Some(path) => match RepositoryRelativePath::parse(path) {
                Ok(path) => Some(path),
                Err(_) => return self.failed(AgentErrorCode::InvalidArgument),
            },
            None => None,
        };
        let snapshot = match SnapshotLocator::parse(input.snapshot_id.as_str()) {
            Ok(SnapshotLocator::StableId(snapshot_id)) => {
                ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(snapshot_id))
            }
            _ => return self.failed(AgentErrorCode::IntegrityFailure),
        };
        let request = RuntimeValidateRequest {
            trace,
            trace_file,
            snapshot,
        };
        let cancellation = CancellationToken::new();
        let service = DepgraphService::new(self.config.clone());
        let prevalidated = match (&input.trace, &request.trace_file) {
            (Some(trace), None) => service.prevalidate_retained_normalized_runtime_trace(
                trace,
                MAX_OPERATION_INPUT_BYTES,
                &cancellation,
            ),
            (None, Some(_)) => {
                service.prevalidate_runtime_trace_source(&request.source(), &cancellation)
            }
            _ => Err(DepgraphServiceError::InvalidInput),
        };
        let prevalidated = match prevalidated {
            Ok(prevalidated) => prevalidated,
            Err(DepgraphServiceError::Cancelled) => return DispatchOutcome::Cancelled,
            Err(error) => return self.failed_service(&error),
        };
        if prevalidated.input_digest() != input.trace_digest {
            return self.failed(AgentErrorCode::Conflict);
        }
        match retained_runtime_identity.as_ref() {
            Some((session_id, runtime_trace_digest))
                if prevalidated
                    .matches_retained_runtime_identity(session_id, runtime_trace_digest) => {}
            None => {}
            _ => return self.failed(AgentErrorCode::Conflict),
        }
        let retained_identity = retained_runtime_identity
            .as_ref()
            .map(|(session_id, trace_digest)| (session_id.as_str(), trace_digest.as_str()));
        let prepared = match service.prepare_runtime_import_prevalidated_with_retained_identity(
            prevalidated,
            &request.snapshot,
            request.trace_file.clone(),
            retained_identity,
            &cancellation,
        ) {
            Ok(prepared) => prepared,
            Err(DepgraphServiceError::Cancelled) => return DispatchOutcome::Cancelled,
            Err(error) => return self.failed_service(&error),
        };
        if prepared.base_snapshot_id().as_str() != input.snapshot_id.as_str()
            || input
                .session_id
                .as_deref()
                .is_some_and(|session_id| session_id != prepared.session_id())
            || input
                .runtime_trace_digest
                .as_deref()
                .is_some_and(|trace_digest| trace_digest != prepared.runtime_trace_digest())
        {
            return self.failed(AgentErrorCode::Conflict);
        }
        if !matches!(control.checkpoint(), Ok(ExecutionCheckpoint::Continue)) {
            return DispatchOutcome::Cancelled;
        }
        let result = service.runtime_import_deferred_prepared(
            prepared,
            work.operation_id().as_str(),
            &cancellation,
        );
        #[cfg(test)]
        if matches!(&result, Ok(DeferredRuntimeImportServiceOutcome::Pending(_)))
            && let Some(barrier) = &self.runtime_dispatch_barrier
        {
            barrier
                .ready
                .send(())
                .expect("runtime dispatch test receiver");
            barrier
                .release
                .lock()
                .expect("runtime dispatch test mutex")
                .recv_timeout(Duration::from_secs(5))
                .expect("runtime dispatch test release");
        }
        if !matches!(control.checkpoint(), Ok(ExecutionCheckpoint::Continue)) {
            if let Ok(DeferredRuntimeImportServiceOutcome::Pending(completion)) = result {
                return DispatchOutcome::CancellationCleanupPending {
                    completion: DeferredOperationCompletion::RuntimeImport(completion),
                };
            }
            return DispatchOutcome::Cancelled;
        }
        match result {
            Ok(DeferredRuntimeImportServiceOutcome::Pending(completion)) => {
                let result = match self.completed_runtime_output(completion.outcome()) {
                    Ok(result) => result,
                    Err(error) => {
                        return DispatchOutcome::FailureCleanupPending {
                            error,
                            completion: DeferredOperationCompletion::RuntimeImport(completion),
                        };
                    }
                };
                DispatchOutcome::CompletionPending {
                    result,
                    completion: DeferredOperationCompletion::RuntimeImport(completion),
                }
            }
            Ok(DeferredRuntimeImportServiceOutcome::Finished(outcome)) => {
                match self.completed_runtime_output(&outcome) {
                    Ok(result) => DispatchOutcome::Completed(result),
                    Err(error) => DispatchOutcome::Failed(error),
                }
            }
            Err(DepgraphServiceError::Cancelled) => DispatchOutcome::Cancelled,
            Err(error) => self.failed_service(&error),
        }
    }

    fn dispatch_daemon_start(
        &self,
        work: &RunnerWork,
        control: &mut ExecutionControl<'_>,
    ) -> DispatchOutcome {
        let input = match serde_json::from_str::<DaemonStartInput>(work.input().as_str()) {
            Ok(input) => input,
            Err(_) => return self.failed(AgentErrorCode::InvalidArgument),
        };
        if !matches!(control.checkpoint(), Ok(ExecutionCheckpoint::Continue)) {
            return DispatchOutcome::Cancelled;
        }
        let service = DepgraphService::new(self.config.clone());
        let launcher = match service.daemon_running_cancellable(control.cancellation_token()) {
            Ok(true) => None,
            Ok(false) | Err(DepgraphServiceError::NotFound) => {
                match self.resolve_daemon_start_launcher() {
                    Ok(launcher) => launcher,
                    Err(_) => return self.failed(AgentErrorCode::Internal),
                }
            }
            Err(error) => return self.failed_service(&error),
        };
        if !matches!(control.checkpoint(), Ok(ExecutionCheckpoint::Continue)) {
            return DispatchOutcome::Cancelled;
        }
        match self.completed_daemon_output(AgentDaemonControlOutcome::running()) {
            Ok(result) => DispatchOutcome::CompletionPending {
                result,
                completion: DeferredOperationCompletion::Daemon(Box::new(
                    self.daemon_start_completion(input.strict, launcher),
                )),
            },
            Err(error) => DispatchOutcome::Failed(error),
        }
    }

    fn dispatch_daemon_stop(
        &self,
        work: &RunnerWork,
        control: &mut ExecutionControl<'_>,
    ) -> DispatchOutcome {
        if serde_json::from_str::<DaemonStopInput>(work.input().as_str()).is_err() {
            return self.failed(AgentErrorCode::InvalidArgument);
        }
        if !matches!(control.checkpoint(), Ok(ExecutionCheckpoint::Continue)) {
            return DispatchOutcome::Cancelled;
        }
        let service = DepgraphService::new(self.config.clone());
        if let Err(error) = service.daemon_running_cancellable(control.cancellation_token()) {
            return self.failed_service(&error);
        }
        if !matches!(control.checkpoint(), Ok(ExecutionCheckpoint::Continue)) {
            return DispatchOutcome::Cancelled;
        }
        match self.completed_daemon_output(AgentDaemonControlOutcome::stopped()) {
            Ok(result) => DispatchOutcome::CompletionPending {
                result,
                completion: DeferredOperationCompletion::Daemon(Box::new(
                    DeferredDaemonCompletion::stop(self.config.clone()),
                )),
            },
            Err(error) => DispatchOutcome::Failed(error),
        }
    }

    fn completed_output(
        &self,
        result: &depgraph_core::service::ScanServiceOutcome,
    ) -> Result<CanonicalJson, CanonicalJson> {
        let snapshot_id = result
            .completed_snapshot_id()
            .ok_or_else(|| self.canonical_error(AgentErrorCode::IntegrityFailure))?;
        let outcome = AgentScanOutcome::try_from(result)
            .map_err(|_| self.canonical_error(AgentErrorCode::IntegrityFailure))?;
        let snapshot_id = snapshot_id
            .as_str()
            .parse::<SnapshotId>()
            .map_err(|_| self.canonical_error(AgentErrorCode::IntegrityFailure))?;
        let repository_id = LogicalRepositoryId::parse(self.config.logical_repository_id())
            .map_err(|_| self.canonical_error(AgentErrorCode::IntegrityFailure))?;
        CanonicalJson::new(
            serde_json::to_value(SuccessEnvelope::new(
                repository_id,
                Some(snapshot_id),
                outcome,
            ))
            .expect("closed scan output serializes"),
        )
        .map_err(|_| self.canonical_error(AgentErrorCode::IntegrityFailure))
    }

    fn completed_runtime_output(
        &self,
        result: &depgraph_core::service::RuntimeImportServiceOutcome,
    ) -> Result<CanonicalJson, CanonicalJson> {
        let outcome = AgentRuntimeOutcome::try_from(result)
            .map_err(|_| self.canonical_error(AgentErrorCode::IntegrityFailure))?;
        let snapshot_id = result
            .completed_snapshot_id()
            .as_str()
            .parse::<SnapshotId>()
            .map_err(|_| self.canonical_error(AgentErrorCode::IntegrityFailure))?;
        let repository_id = LogicalRepositoryId::parse(self.config.logical_repository_id())
            .map_err(|_| self.canonical_error(AgentErrorCode::IntegrityFailure))?;
        CanonicalJson::new(
            serde_json::to_value(SuccessEnvelope::new(
                repository_id,
                Some(snapshot_id),
                outcome,
            ))
            .expect("closed runtime import output serializes"),
        )
        .map_err(|_| self.canonical_error(AgentErrorCode::IntegrityFailure))
    }

    fn completed_export_output(
        &self,
        completion: &DeferredExportFileCompletion,
    ) -> Result<CanonicalJson, CanonicalJson> {
        let outcome = AgentExportOutcome::try_from(completion.result())
            .map_err(|_| self.canonical_error(AgentErrorCode::IntegrityFailure))?;
        let snapshot_id = SnapshotId::parse(completion.snapshot_id())
            .map_err(|_| self.canonical_error(AgentErrorCode::IntegrityFailure))?;
        let repository_id = LogicalRepositoryId::parse(self.config.logical_repository_id())
            .map_err(|_| self.canonical_error(AgentErrorCode::IntegrityFailure))?;
        CanonicalJson::new(
            serde_json::to_value(SuccessEnvelope::new(
                repository_id,
                Some(snapshot_id),
                outcome,
            ))
            .expect("closed export output serializes"),
        )
        .map_err(|_| self.canonical_error(AgentErrorCode::IntegrityFailure))
    }

    fn completed_daemon_output(
        &self,
        outcome: AgentDaemonControlOutcome,
    ) -> Result<CanonicalJson, CanonicalJson> {
        let repository_id = LogicalRepositoryId::parse(self.config.logical_repository_id())
            .map_err(|_| self.canonical_error(AgentErrorCode::IntegrityFailure))?;
        CanonicalJson::new(
            serde_json::to_value(SuccessEnvelope::new(repository_id, None, outcome))
                .expect("closed daemon control output serializes"),
        )
        .map_err(|_| self.canonical_error(AgentErrorCode::IntegrityFailure))
    }

    fn runtime_completion_recovery_binding(
        &self,
        intent: &CompletionIntent,
    ) -> Result<RuntimeCompletionRecoveryBinding, RunnerError> {
        let input = serde_json::from_str::<RuntimeImportInput>(intent.normalized_input().as_str())
            .map_err(|_| RunnerError::Journal(JournalError::IntegrityFailure))?;
        // CompletionIntent decoding has already verified the canonical result
        // digest. Deserialize the whole closed envelope before using any field;
        // recovery never selects staging from ad-hoc result JSON.
        let envelope = serde_json::from_value::<SuccessEnvelope<AgentRuntimeOutcome>>(
            intent.result().value().clone(),
        )
        .map_err(|_| RunnerError::Journal(JournalError::IntegrityFailure))?;
        let repository_id = LogicalRepositoryId::parse(self.config.logical_repository_id())
            .map_err(|_| RunnerError::Journal(JournalError::IntegrityFailure))?;
        let outcome = envelope.result();
        if envelope.repository_id() != &repository_id
            || envelope.snapshot_id() != Some(outcome.snapshot_id())
            || outcome.deduplicated()
        {
            return Err(RunnerError::Journal(JournalError::IntegrityFailure));
        }
        let runtime_trace_digest = match input.retained_runtime_identity() {
            Ok(Some((session_id, runtime_trace_digest)))
                if session_id == outcome.session_id().as_str() =>
            {
                Some(runtime_trace_digest)
            }
            Ok(None) => None,
            _ => return Err(RunnerError::Journal(JournalError::IntegrityFailure)),
        };
        Ok(RuntimeCompletionRecoveryBinding {
            base_snapshot_id: input.snapshot_id,
            runtime_trace_digest,
            envelope,
        })
    }

    fn failed_service(&self, error: &DepgraphServiceError) -> DispatchOutcome {
        use depgraph_core::service::DepgraphServiceErrorCategory;

        let code = if matches!(
            error,
            DepgraphServiceError::RepositoryFile {
                reason: depgraph_core::service::RepositoryFileError::NotFound,
            }
        ) {
            AgentErrorCode::NotFound
        } else {
            match error.category() {
                DepgraphServiceErrorCategory::Authorization => AgentErrorCode::CapabilityDenied,
                DepgraphServiceErrorCategory::Input => AgentErrorCode::InvalidArgument,
                DepgraphServiceErrorCategory::NotFound => AgentErrorCode::SnapshotNotFound,
                DepgraphServiceErrorCategory::Conflict => AgentErrorCode::Conflict,
                DepgraphServiceErrorCategory::Resource => AgentErrorCode::ResourceExhausted,
                DepgraphServiceErrorCategory::Cancelled => return DispatchOutcome::Cancelled,
                DepgraphServiceErrorCategory::Integrity => AgentErrorCode::IntegrityFailure,
                DepgraphServiceErrorCategory::Configuration
                | DepgraphServiceErrorCategory::Store
                | DepgraphServiceErrorCategory::Internal => AgentErrorCode::Internal,
            }
        };
        self.failed(code)
    }

    fn failed(&self, code: AgentErrorCode) -> DispatchOutcome {
        DispatchOutcome::Failed(self.canonical_error(code))
    }

    fn canonical_error(&self, code: AgentErrorCode) -> CanonicalJson {
        let repository_id = LogicalRepositoryId::parse(self.config.logical_repository_id())
            .expect("runner startup validates the logical repository identity");
        let remediation = match code {
            AgentErrorCode::InvalidArgument => AgentRemediation::CorrectInput,
            AgentErrorCode::SnapshotNotFound => AgentRemediation::SelectCompletedSnapshot,
            AgentErrorCode::CapabilityDenied => AgentRemediation::EnableRequiredCapability,
            AgentErrorCode::Conflict => AgentRemediation::Retry,
            AgentErrorCode::ResourceExhausted => AgentRemediation::IncreaseLimit,
            AgentErrorCode::IntegrityFailure | AgentErrorCode::Internal => {
                AgentRemediation::ContactOperator
            }
            _ => AgentRemediation::Retry,
        };
        let envelope = ErrorEnvelope::new(
            repository_id,
            AgentError::new(code, false, remediation, None),
        );
        CanonicalJson::new(serde_json::to_value(envelope).expect("closed scan error serializes"))
            .expect("closed scan error is canonical and bounded")
    }
}

impl OperationDispatcher for ScanOperationDispatcher {
    fn dispatch(
        &mut self,
        work: &RunnerWork,
        control: &mut ExecutionControl<'_>,
    ) -> DispatchOutcome {
        match work.kind() {
            OperationKind::ScanSubmit => self.dispatch_scan(work, control),
            OperationKind::RuntimeTraceImportSubmit => self.dispatch_runtime_import(work, control),
            OperationKind::ExportFile => self.dispatch_export_file(work, control),
            OperationKind::DaemonStartSubmit => self.dispatch_daemon_start(work, control),
            OperationKind::DaemonStop => self.dispatch_daemon_stop(work, control),
            _ => UnsupportedOperationDispatcher.dispatch(work, control),
        }
    }

    fn recover_completion(
        &mut self,
        intent: &CompletionIntent,
    ) -> Result<CompletionRecovery, RunnerError> {
        if matches!(
            intent.kind(),
            OperationKind::DaemonStartSubmit | OperationKind::DaemonStop
        ) {
            let envelope = serde_json::from_value::<SuccessEnvelope<AgentDaemonControlOutcome>>(
                intent.result().value().clone(),
            )
            .map_err(|_| RunnerError::Journal(JournalError::IntegrityFailure))?;
            let repository_id = LogicalRepositoryId::parse(self.config.logical_repository_id())
                .map_err(|_| RunnerError::Journal(JournalError::IntegrityFailure))?;
            if envelope.repository_id() != &repository_id
                || envelope.snapshot_id().is_some()
                || !envelope.result().is_valid()
            {
                return Err(RunnerError::Journal(JournalError::IntegrityFailure));
            }
            let completion = match intent.kind() {
                OperationKind::DaemonStartSubmit => {
                    let input = serde_json::from_str::<DaemonStartInput>(
                        intent.normalized_input().as_str(),
                    )
                    .map_err(|_| RunnerError::Journal(JournalError::IntegrityFailure))?;
                    if envelope.result().action() != AgentDaemonControlAction::Start
                        || envelope.result().phase() != AgentDaemonControlPhase::Running
                    {
                        return Err(RunnerError::Journal(JournalError::IntegrityFailure));
                    }
                    let service = DepgraphService::new(self.config.clone());
                    let launcher =
                        match service.daemon_running_cancellable(&CancellationToken::new()) {
                            Ok(true) => None,
                            Ok(false) | Err(DepgraphServiceError::NotFound) => {
                                self.resolve_daemon_start_launcher()?
                            }
                            Err(error) => return Err(error.into()),
                        };
                    self.daemon_start_completion(input.strict, launcher)
                }
                OperationKind::DaemonStop => {
                    serde_json::from_str::<DaemonStopInput>(intent.normalized_input().as_str())
                        .map_err(|_| RunnerError::Journal(JournalError::IntegrityFailure))?;
                    if envelope.result().action() != AgentDaemonControlAction::Stop
                        || envelope.result().phase() != AgentDaemonControlPhase::Stopped
                    {
                        return Err(RunnerError::Journal(JournalError::IntegrityFailure));
                    }
                    DeferredDaemonCompletion::stop(self.config.clone())
                }
                _ => unreachable!("daemon recovery branch is closed"),
            };
            completion.promote()?;
            return Ok(CompletionRecovery::Finalized);
        }
        if intent.kind() == OperationKind::ExportFile {
            let input = serde_json::from_str::<ExportFileInput>(intent.normalized_input().as_str())
                .map_err(|_| RunnerError::Journal(JournalError::IntegrityFailure))?;
            let envelope = serde_json::from_value::<SuccessEnvelope<AgentExportOutcome>>(
                intent.result().value().clone(),
            )
            .map_err(|_| RunnerError::Journal(JournalError::IntegrityFailure))?;
            let repository_id = LogicalRepositoryId::parse(self.config.logical_repository_id())
                .map_err(|_| RunnerError::Journal(JournalError::IntegrityFailure))?;
            let expected_format = match input.format {
                GraphExportFormat::Json => AgentGraphExportFormat::Json,
                GraphExportFormat::Dot => AgentGraphExportFormat::Dot,
                GraphExportFormat::Mermaid => AgentGraphExportFormat::Mermaid,
                GraphExportFormat::Graphml => AgentGraphExportFormat::Graphml,
            };
            let outcome = envelope.result();
            if envelope.repository_id() != &repository_id
                || envelope.snapshot_id() != Some(&input.snapshot_id)
                || outcome.output_path().as_str() != input.output_path
                || outcome.format() != expected_format
            {
                return Err(RunnerError::Journal(JournalError::IntegrityFailure));
            }
            let output_path = RepositoryRelativePath::parse(&input.output_path)
                .map_err(|_| RunnerError::Journal(JournalError::IntegrityFailure))?;
            DepgraphService::new(self.config.clone()).recover_deferred_export_file_completion(
                &DeferredExportFileRecovery {
                    operation_id: intent.operation_id().as_str(),
                    output_path: &output_path,
                    overwrite: if input.overwrite {
                        RepositoryOverwritePolicy::Overwrite
                    } else {
                        RepositoryOverwritePolicy::NoReplace
                    },
                    format: input.format,
                    output_bytes: outcome.output_bytes(),
                    content_sha256: outcome.content_sha256().as_str(),
                    destination_precondition: input.destination_precondition.as_ref(),
                },
            )?;
            return Ok(CompletionRecovery::Finalized);
        }
        if intent.kind() == OperationKind::RuntimeTraceImportSubmit {
            let binding = self.runtime_completion_recovery_binding(intent)?;
            let outcome = binding.envelope.result();
            let status = match outcome.status() {
                AgentRuntimeStatus::Completed => "completed",
                AgentRuntimeStatus::Partial => "partial",
            };
            let recovery = DeferredRuntimeImportRecovery {
                operation_id: intent.operation_id().as_str(),
                base_snapshot_id: binding.base_snapshot_id.as_str(),
                runtime_trace_digest: binding.runtime_trace_digest.as_deref(),
                import_id: outcome.import_id().as_str(),
                session_id: outcome.session_id().as_str(),
                snapshot_id: outcome.snapshot_id().as_str(),
                status,
                deduplicated: outcome.deduplicated(),
            };
            let service = DepgraphService::new(self.config.clone());
            return match service.recover_deferred_runtime_import_completion(&recovery) {
                Ok(()) => Ok(CompletionRecovery::Finalized),
                Err(DepgraphServiceError::StoreWriterConflict) => Ok(CompletionRecovery::Busy),
                Err(error) => Err(RunnerError::Service(error)),
            };
        }
        if intent.kind() != OperationKind::ScanSubmit {
            return Err(RunnerError::Journal(JournalError::IntegrityFailure));
        }
        let input = serde_json::from_str::<ScanInput>(intent.normalized_input().as_str())
            .map_err(|_| RunnerError::Journal(JournalError::IntegrityFailure))?;
        let envelope = serde_json::from_value::<SuccessEnvelope<AgentScanOutcome>>(
            intent.result().value().clone(),
        )
        .map_err(|_| RunnerError::Journal(JournalError::IntegrityFailure))?;
        let repository_id = LogicalRepositoryId::parse(self.config.logical_repository_id())
            .map_err(|_| RunnerError::Journal(JournalError::IntegrityFailure))?;
        if envelope.repository_id() != &repository_id {
            return Err(RunnerError::Journal(JournalError::IntegrityFailure));
        }
        let snapshot_id = envelope
            .snapshot_id()
            .ok_or(RunnerError::Journal(JournalError::IntegrityFailure))?;
        let result_digest = JournalDigest::sha256(intent.result().as_str().as_bytes());
        let recovery = DeferredScanRecovery {
            operation_id: intent.operation_id().as_str(),
            scan_id: envelope.result().scan_id().as_str(),
            snapshot_id: snapshot_id.as_str(),
            strict: input.strict,
            cache_enabled: !input.no_cache,
            result_digest: result_digest.as_bytes(),
        };
        let service = DepgraphService::new(self.config.clone());
        match service.recover_deferred_scan_completion(&recovery) {
            Ok(()) => Ok(CompletionRecovery::Finalized),
            Err(DepgraphServiceError::StoreWriterConflict) => Ok(CompletionRecovery::Busy),
            Err(error) => Err(RunnerError::Service(error)),
        }
    }

    fn cleanup_abandoned(
        &mut self,
        work: &RunnerWork,
    ) -> Result<Option<std::fs::File>, RunnerError> {
        if work.kind() == OperationKind::ScanSubmit {
            return DepgraphService::new(self.config.clone())
                .cancel_deferred_scan_for_operation(work.operation_id().as_str())
                .map(Some)
                .map_err(Into::into);
        }
        if work.kind() == OperationKind::ExportFile {
            let input = serde_json::from_str::<ExportFileInput>(work.input().as_str())
                .map_err(|_| RunnerError::Journal(JournalError::IntegrityFailure))?;
            let request = self.export_file_request(&input)?;
            DepgraphService::new(self.config.clone()).cancel_deferred_export_file_for_operation(
                &request,
                work.operation_id().as_str(),
                &CancellationToken::new(),
            )?;
            return Ok(None);
        }
        if work.kind() != OperationKind::RuntimeTraceImportSubmit {
            return Ok(None);
        }
        DepgraphService::new(self.config.clone())
            .cancel_staged_runtime_import_for_operation(work.operation_id().as_str())
            .map(Some)
            .map_err(Into::into)
    }

    fn pending_cleanup_acknowledgements(
        &mut self,
        after_operation_id: Option<&str>,
    ) -> Result<(Vec<OperationId>, Option<String>), RunnerError> {
        if !self
            .config
            .capabilities()
            .contains(DepgraphCapability::StoreWrite)
        {
            return Ok((Vec::new(), None));
        }
        let pending = DepgraphService::new(self.config.clone())
            .pending_deferred_scan_cancellations(after_operation_id)?;
        let next_after_operation_id = pending.next_after_operation_id().map(ToOwned::to_owned);
        let operation_ids = pending
            .into_operation_ids()
            .into_iter()
            .map(|operation_id| {
                OperationId::parse(operation_id)
                    .map_err(|_| RunnerError::Journal(JournalError::IntegrityFailure))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((operation_ids, next_after_operation_id))
    }

    fn reconcile_legacy_staging(&mut self) -> Result<Option<bool>, RunnerError> {
        if !self
            .config
            .capabilities()
            .contains(DepgraphCapability::StoreWrite)
        {
            return Ok(Some(false));
        }
        if self
            .config
            .capabilities()
            .contains(DepgraphCapability::DaemonControl)
        {
            match DepgraphService::new(self.config.clone())
                .daemon_running_cancellable(&CancellationToken::new())
            {
                // A live daemon owns the store writer lock. Legacy scan
                // reconciliation cannot make progress, but daemon stop/control
                // claims must remain runnable under that ownership.
                Ok(true) => return Ok(Some(false)),
                Ok(false) | Err(DepgraphServiceError::NotFound) => {}
                Err(error) => return Err(RunnerError::Service(error)),
            }
        }
        match DepgraphService::new(self.config.clone()).reconcile_legacy_scan_operation_staging() {
            Ok(more_work) => Ok(Some(more_work)),
            Err(DepgraphServiceError::StoreWriterConflict) => Ok(None),
            Err(error) => Err(RunnerError::Service(error)),
        }
    }

    fn finalize_cleanup_acknowledgement(
        &mut self,
        kind: OperationKind,
        operation_id: &OperationId,
    ) -> Result<(), RunnerError> {
        if kind == OperationKind::ScanSubmit {
            DepgraphService::new(self.config.clone())
                .finalize_deferred_scan_cancellation(operation_id.as_str())?;
        }
        Ok(())
    }
}

struct LeaseToken([u8; 32]);

impl LeaseToken {
    fn generate() -> Result<Self, RunnerError> {
        let mut token = [0_u8; 32];
        getrandom::fill(&mut token).map_err(|_| RunnerError::EntropyUnavailable)?;
        Ok(Self(token))
    }

    fn copy_for_guardian(&self) -> Self {
        Self(self.0)
    }
}

impl AsRef<[u8]> for LeaseToken {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for LeaseToken {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn new_lease_owner() -> Result<LeaseOwner, RunnerError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| RunnerError::EntropyUnavailable)?;
    let mut suffix = String::with_capacity(32);
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut suffix, "{byte:02x}").expect("writing to a String cannot fail");
    }
    LeaseOwner::parse(format!("runner:{}:{suffix}", std::process::id())).map_err(RunnerError::from)
}

fn system_now_ms() -> Result<i64, RunnerError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RunnerError::ClockUnavailable)?
        .as_millis();
    i64::try_from(millis).map_err(|_| RunnerError::ClockUnavailable)
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        path::Path,
        sync::{
            Arc, Barrier,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        time::Duration,
    };

    use depgraph_core::{
        DepgraphCapability, DepgraphCapabilitySet, DepgraphServiceConfig, DepgraphServiceLimits,
    };
    use serde_json::json;

    use super::*;
    use crate::{
        CapabilitySet, OperationManager, OperationOutcome, SubmitRequest, TERMINAL_RETENTION_MS,
    };

    const NOW: i64 = 1_800_000_000_000;

    fn config(root: &Path) -> DepgraphServiceConfig {
        let repository = root.join("repository");
        std::fs::create_dir_all(&repository).unwrap();
        DepgraphServiceConfig::new(
            repository,
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

    fn daemon_config(root: &Path) -> DepgraphServiceConfig {
        let repository = root.join("repository");
        std::fs::create_dir_all(&repository).unwrap();
        DepgraphServiceConfig::new(
            repository,
            root.join("graph.sqlite"),
            DepgraphCapabilitySet::try_new([
                DepgraphCapability::Read,
                DepgraphCapability::StoreWrite,
                DepgraphCapability::DaemonControl,
            ])
            .unwrap(),
            DepgraphServiceLimits::default(),
        )
        .unwrap()
    }

    fn daemon_start_result(config: &DepgraphServiceConfig) -> CanonicalJson {
        let repository_id = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        CanonicalJson::new(
            serde_json::to_value(SuccessEnvelope::new(
                repository_id,
                None,
                AgentDaemonControlOutcome::running(),
            ))
            .unwrap(),
        )
        .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn issue_315_daemon_start_fails_closed_when_child_exits_before_publication() {
        let root = tempfile::tempdir().unwrap();
        let config = daemon_config(root.path());
        let launcher =
            DaemonExecutableLauncher::for_test_executable(Path::new("/usr/bin/false")).unwrap();
        let started = std::time::Instant::now();

        assert!(matches!(
            promote_daemon_start(&config, false, Some(launcher)),
            Err(RunnerError::Service(DepgraphServiceError::Internal))
        ));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "early daemon exit must not consume the 30-second publication timeout"
        );
    }

    fn counting_daemon_dispatcher(
        config: DepgraphServiceConfig,
        expected_strict: bool,
        launches: Arc<AtomicUsize>,
    ) -> ScanOperationDispatcher {
        let expected_root = config.canonical_root().to_path_buf();
        let expected_store = config.store_path().to_path_buf();
        ScanOperationDispatcher::new(config).with_daemon_start_promoter_for_test(Arc::new(
            move |observed, strict| {
                assert_eq!(observed.canonical_root(), expected_root);
                assert_eq!(observed.store_path(), expected_store);
                assert_eq!(strict, expected_strict);
                launches.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        ))
    }

    #[test]
    fn repository_file_not_found_is_distinct_from_snapshot_not_found() {
        let root = tempfile::tempdir().unwrap();
        let dispatcher = ScanOperationDispatcher::new(config(root.path()));
        let error_code = |outcome| match outcome {
            DispatchOutcome::Failed(error) => error.value()["error"]["code"].clone(),
            _ => panic!("service error must produce a terminal failure"),
        };

        assert_eq!(
            error_code(
                dispatcher.failed_service(&DepgraphServiceError::RepositoryFile {
                    reason: depgraph_core::service::RepositoryFileError::NotFound,
                })
            ),
            json!("NOT_FOUND")
        );
        assert_eq!(
            error_code(dispatcher.failed_service(&DepgraphServiceError::NotFound)),
            json!("SNAPSHOT_NOT_FOUND")
        );
    }

    #[test]
    fn overwrite_export_input_requires_a_durable_destination_precondition() {
        let root = tempfile::tempdir().unwrap();
        let dispatcher = ScanOperationDispatcher::new(config(root.path()));
        let input = ExportFileInput {
            output_path: "artifacts/graph.json".to_owned(),
            overwrite: true,
            format: GraphExportFormat::Json,
            snapshot_id: SnapshotId::parse(
                "snapshot:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            selector: None,
            max_nodes: 100,
            max_edges: 100,
            destination_precondition: None,
        };

        let error = dispatcher.export_file_request(&input).unwrap_err();

        assert_eq!(
            error.category(),
            depgraph_core::service::DepgraphServiceErrorCategory::Input
        );
    }

    fn runtime_import_fixture(
        config: &DepgraphServiceConfig,
        source_session_id: &str,
    ) -> (String, String, serde_json::Value) {
        let coverage = json!({
            "profiles":1,
            "files_discovered":0,
            "files_analyzed":0,
            "files_skipped":0,
            "dependency_sites":0,
            "resolved":0,
            "candidates":0,
            "external":0,
            "unresolved":0,
            "unsupported_syntax":0,
            "project_code_executed":false,
            "completeness":["syntax-complete"],
            "reasons":[]
        });
        let common = |event: &str, seq: u64| {
            json!({
                "event":event,
                "protocol_version":"1.0",
                "scan_id":"runtime-runner-base",
                "adapter":"fixture",
                "adapter_version":"1.0",
                "seq":seq
            })
        };
        let mut store = depgraph_core::open_store(config.store_path()).unwrap();
        store
            .start_scan_with_revision(
                "runtime-runner-base",
                config.canonical_root(),
                false,
                Some("runtime-runner-revision"),
            )
            .unwrap();
        let mut started = common("scan_started", 1);
        started["root"] = json!(config.canonical_root());
        started["project_code_executed"] = json!(false);
        started["safe_mode"] = json!(true);
        store.ingest_event(&started).unwrap();
        let mut profile = common("profile_declared", 2);
        profile["profile"] = json!({
            "id":"profile:runtime-runner",
            "language":"runtime-fixture",
            "features":[],
            "environment":{},
            "properties":{}
        });
        store.ingest_event(&profile).unwrap();
        for (seq, (id, kind, locator, path)) in [
            (
                "workspace:runtime-runner",
                "workspace",
                "repo://runtime-runner",
                "workspace",
            ),
            (
                "file:runtime-source",
                "file",
                "repo://runtime-source.js",
                "runtime-source.js",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let mut node = common("node_upsert", seq as u64 + 3);
            node["node"] = json!({
                "id":id,
                "kind":kind,
                "locator":locator,
                "display_name":id,
                "properties":{
                    "path":path,
                    "repository_identity":if kind == "workspace" {
                        Some("workspace:runtime-runner")
                    } else {
                        None
                    }
                }
            });
            store.ingest_event(&node).unwrap();
        }
        let mut profile_completed = common("profile_completed", 5);
        profile_completed["profile_id"] = json!("profile:runtime-runner");
        profile_completed["coverage"] = coverage.clone();
        store.ingest_event(&profile_completed).unwrap();
        let mut completed = common("scan_completed", 6);
        completed["coverage"] = coverage;
        store.ingest_event(&completed).unwrap();
        store
            .finish_scan("runtime-runner-base", "completed", None, true)
            .unwrap();
        drop(store);

        let service = DepgraphService::new(config.clone());
        let store = depgraph_core::open_store_read_only(config.store_path()).unwrap();
        let base_snapshot_id = store.current_snapshot_id().unwrap().unwrap();
        let snapshot = store.load_completed_snapshot(&base_snapshot_id).unwrap();
        let workspace = snapshot
            .nodes
            .iter()
            .find(|node| node.kind == "workspace")
            .expect("safe scan creates the workspace node");
        let repository_identity = workspace
            .properties
            .get("repository_identity")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(workspace.id.as_str());
        let mut repository = json!({"identity": repository_identity});
        if let Some(revision) = snapshot.scan.source_revision.as_deref() {
            repository["revision"] = json!(revision);
        }
        let trace = json!({
            "schema_version":"1.0",
            "repository":repository,
            "session":{
                "id":source_session_id,
                "started_at":"2026-08-08T00:00:00Z",
                "ended_at":"2026-08-08T00:00:01Z",
                "profile":{"language":"runtime-fixture","features":[]},
                "environment":{"name":"test"},
                "redaction":{"redacted_value_count":0}
            },
            "events":[{
                "sequence":1,
                "timestamp":"2026-08-08T00:00:00Z",
                "dependency_kind":"imports",
                "source":{"kind":"node","node_id":workspace.id},
                "target":{"kind":"external","namespace":"fixture","name":"dependency"},
                "count":1
            }]
        })
        .to_string();
        let request = RuntimeValidateRequest {
            trace: Some(trace.clone()),
            trace_file: None,
            snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                base_snapshot_id.clone(),
            )),
        };
        let durable_input = service
            .prepare_runtime_import(&request, &CancellationToken::new())
            .unwrap()
            .durable_input();
        (base_snapshot_id, trace, durable_input)
    }

    fn legacy_runtime_import_input(mut durable_input: serde_json::Value) -> serde_json::Value {
        let input = durable_input
            .as_object_mut()
            .expect("runtime durable input is an object");
        assert!(input.remove("session_id").is_some());
        assert!(input.remove("runtime_trace_digest").is_some());
        durable_input
    }

    fn cancellable_capabilities() -> CapabilitySet {
        CapabilitySet::new([
            depgraph_mcp_tools::AgentCapability::Read,
            depgraph_mcp_tools::AgentCapability::StoreWrite,
        ])
        .unwrap()
    }

    fn downgrade_store_to_v15(config: &DepgraphServiceConfig) -> Vec<u8> {
        let connection = rusqlite::Connection::open(config.store_path()).unwrap();
        connection
            .execute_batch(
                "PRAGMA wal_checkpoint(TRUNCATE);
                 DROP TABLE scan_operation_staging;
                 DROP TABLE runtime_import_operation_owners;
                 PRAGMA user_version=15;
                 PRAGMA journal_mode=DELETE;",
            )
            .unwrap();
        drop(connection);
        std::fs::read(config.store_path()).unwrap()
    }

    #[test]
    fn cooperative_checkpoint_observes_without_owning_lease_renewal() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"lease": "renew"}),
                    b"checkpoint-renewal",
                    NOW + 1_000,
                )
                .unwrap(),
                NOW,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("renewing-runner").unwrap(),
                b"renewing-token",
                NOW + 1,
                NOW + 100,
            )
            .unwrap();
        let clock = Cell::new(NOW + 70);
        let now = || Ok(clock.get());
        {
            let mut control = ExecutionControl {
                journal: &mut journal,
                repository_id: &repository,
                operation_id: &operation_id,
                lease_token: b"renewing-token",
                execution_deadline_ms: NOW + 1_000,
                cancellation: &CancellationToken::new(),
                now: &now,
            };

            assert_eq!(control.checkpoint().unwrap(), ExecutionCheckpoint::Continue);
        }
        let observed = journal.get(&repository, &operation_id, NOW + 71).unwrap();
        assert_eq!(observed.lease().unwrap().expires_at_ms(), NOW + 100);
    }

    #[test]
    fn cooperative_checkpoint_observes_cancel_and_deadline() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"cooperative": true}),
                    b"checkpoint-cancel-deadline",
                    NOW + 100,
                )
                .unwrap(),
                NOW,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("cooperative-runner").unwrap(),
                b"cooperative-token",
                NOW + 1,
                NOW + 90,
            )
            .unwrap();
        journal
            .cancel(
                &repository,
                &operation_id,
                &CapabilitySet::new([
                    depgraph_mcp_tools::AgentCapability::Read,
                    depgraph_mcp_tools::AgentCapability::StoreWrite,
                ])
                .unwrap(),
                NOW + 2,
            )
            .unwrap();
        let clock = Cell::new(NOW + 3);
        let now = || Ok(clock.get());
        let mut control = ExecutionControl {
            journal: &mut journal,
            repository_id: &repository,
            operation_id: &operation_id,
            lease_token: b"cooperative-token",
            execution_deadline_ms: NOW + 100,
            cancellation: &CancellationToken::new(),
            now: &now,
        };

        assert_eq!(
            control.checkpoint().unwrap(),
            ExecutionCheckpoint::CancellationRequested
        );
        clock.set(NOW + 100);
        assert_eq!(
            control.checkpoint().unwrap(),
            ExecutionCheckpoint::DeadlineExceeded
        );
    }

    #[test]
    fn issue_315_restarted_runner_recovers_daemon_start_completion_intent_once() {
        let root = tempfile::tempdir().unwrap();
        let config = daemon_config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 60_000;
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::DaemonStartSubmit,
                    &json!({"strict": true}),
                    b"issue-315-daemon-completion-recovery",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        let crashed_lease = b"issue-315-crashed-daemon-lease";
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("issue-315-crashed-daemon-owner").unwrap(),
                crashed_lease,
                submitted_at_ms + 1,
                deadline_ms,
            )
            .unwrap();
        let expected_result = daemon_start_result(&config);
        assert_eq!(
            journal
                .commit_completion_intent(
                    &repository,
                    &operation_id,
                    crashed_lease,
                    expected_result.clone(),
                    submitted_at_ms + 2,
                )
                .unwrap(),
            CompletionDecision::Committed
        );
        drop(journal);

        let launches = Arc::new(AtomicUsize::new(0));
        let recovered = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            counting_daemon_dispatcher(config.clone(), true, Arc::clone(&launches)),
        )
        .run_until_idle()
        .unwrap();

        assert_eq!(recovered.claimed(), 0);
        assert_eq!(recovered.completed(), 1);
        assert_eq!(launches.load(Ordering::SeqCst), 1);
        let journal = OperationJournal::open(&config).unwrap();
        assert_eq!(
            journal
                .result(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Completed(expected_result)
        );
        assert!(
            journal
                .next_completion_intent(&repository, system_now_ms().unwrap())
                .unwrap()
                .is_none()
        );
        drop(journal);

        let settled_replay = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            counting_daemon_dispatcher(config, true, Arc::clone(&launches)),
        )
        .run_until_idle()
        .unwrap();
        assert_eq!(settled_replay, RunnerReport::default());
        assert_eq!(launches.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn issue_315_daemon_cancellation_before_completion_decision_never_launches_and_settles() {
        let root = tempfile::tempdir().unwrap();
        let config = daemon_config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let submitted_at_ms = system_now_ms().unwrap();
        let mut manager = OperationManager::open(&config).unwrap();
        let operation_id = manager
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::DaemonStartSubmit,
                    &json!({"strict": false}),
                    b"issue-315-cancel-before-daemon-launch",
                    submitted_at_ms + 60_000,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        drop(manager);

        let launches = Arc::new(AtomicUsize::new(0));
        let (decision_ready, wait_for_decision) = mpsc::sync_channel(0);
        let (release_decision, decision_release) = mpsc::sync_channel(0);
        let runner = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            counting_daemon_dispatcher(config.clone(), false, Arc::clone(&launches)),
        )
        .with_completion_decision_barrier_for_test(decision_ready, decision_release);
        let runner_thread = std::thread::spawn(move || runner.run_until_idle());

        wait_for_decision
            .recv_timeout(Duration::from_secs(5))
            .expect("daemon completion reaches the durable decision boundary");
        let mut manager = OperationManager::open(&config).unwrap();
        manager
            .cancel(&operation_id, system_now_ms().unwrap())
            .unwrap();
        release_decision.send(()).unwrap();

        let report = runner_thread.join().unwrap().unwrap();
        assert_eq!(report.completed(), 0);
        assert_eq!(report.cancelled(), 1);
        assert_eq!(launches.load(Ordering::SeqCst), 0);
        assert_eq!(
            OperationJournal::open(&config)
                .unwrap()
                .result(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Cancelled
        );
        assert!(!root.path().join("graph.sqlite.daemon-status.json").exists());
        assert!(!root.path().join("graph.sqlite.daemon-lock").exists());
    }

    #[test]
    fn issue_315_concurrent_daemon_requests_have_one_owner_one_launch_and_closed_settlement() {
        let root = tempfile::tempdir().unwrap();
        let config = daemon_config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let submitted_at_ms = system_now_ms().unwrap();
        OperationJournal::open(&config).unwrap();
        let submit_barrier = Arc::new(Barrier::new(3));
        let mut submitters = Vec::new();
        for _ in 0..2 {
            let config = config.clone();
            let barrier = Arc::clone(&submit_barrier);
            submitters.push(std::thread::spawn(move || {
                barrier.wait();
                OperationManager::open(&config)
                    .unwrap()
                    .submit(
                        &SubmitRequest::new(
                            &config,
                            OperationKind::DaemonStartSubmit,
                            &json!({"strict": false}),
                            b"issue-315-simultaneous-daemon-start",
                            submitted_at_ms + 60_000,
                        )
                        .unwrap(),
                        submitted_at_ms,
                    )
                    .unwrap()
            }));
        }
        submit_barrier.wait();
        let handles = submitters
            .into_iter()
            .map(|submitter| submitter.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(handles.iter().filter(|handle| handle.created()).count(), 1);
        assert_eq!(handles[0].operation_id(), handles[1].operation_id());
        let operation_id = handles[0].operation_id().clone();

        let launches = Arc::new(AtomicUsize::new(0));
        let runner_barrier = Arc::new(Barrier::new(3));
        let mut runners = Vec::new();
        for _ in 0..2 {
            let config = config.clone();
            let launches = Arc::clone(&launches);
            let barrier = Arc::clone(&runner_barrier);
            runners.push(std::thread::spawn(move || {
                let runner = OperationRunner::new(
                    RunnerStartupConfig::new(config.clone()).unwrap(),
                    counting_daemon_dispatcher(config, false, launches),
                );
                barrier.wait();
                runner.run_until_idle().unwrap()
            }));
        }
        runner_barrier.wait();
        let reports = runners
            .into_iter()
            .map(|runner| runner.join().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            reports.iter().map(|report| report.claimed()).sum::<u64>(),
            1
        );
        assert_eq!(
            reports.iter().map(|report| report.completed()).sum::<u64>(),
            1
        );
        assert_eq!(launches.load(Ordering::SeqCst), 1);
        match OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap()
        {
            OperationOutcome::Completed(result) => {
                assert_eq!(result, daemon_start_result(&config));
                assert_eq!(
                    result.value()["result"],
                    json!({"action":"start", "phase":"running"})
                );
            }
            other => panic!("concurrent daemon request did not settle closed: {other:?}"),
        }
    }

    struct BlockingDispatcher {
        calls: Arc<AtomicUsize>,
        started: mpsc::SyncSender<i64>,
        release: mpsc::Receiver<()>,
    }

    impl OperationDispatcher for BlockingDispatcher {
        fn dispatch(
            &mut self,
            _work: &RunnerWork,
            _control: &mut ExecutionControl<'_>,
        ) -> DispatchOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.send(system_now_ms().unwrap()).unwrap();
            self.release
                .recv_timeout(Duration::from_secs(5))
                .expect("test dispatcher release signal");
            DispatchOutcome::Completed(CanonicalJson::new(json!({"completed": true})).unwrap())
        }
    }

    #[test]
    fn cancellation_requested_after_dispatch_wins_over_completed_outcome() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 10_000;
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"cancel_race": true}),
                    b"cancel-after-dispatch",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        drop(journal);

        let calls = Arc::new(AtomicUsize::new(0));
        let (dispatch_started, wait_for_dispatch) = mpsc::sync_channel(0);
        let (release_dispatch, wait_for_release) = mpsc::sync_channel(0);
        let runner = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            BlockingDispatcher {
                calls: Arc::clone(&calls),
                started: dispatch_started,
                release: wait_for_release,
            },
        );
        let runner_thread = std::thread::spawn(move || runner.run_until_idle());

        wait_for_dispatch
            .recv_timeout(Duration::from_secs(5))
            .expect("dispatcher start signal");
        let mut journal = OperationJournal::open(&config).unwrap();
        journal
            .cancel(
                &repository,
                &operation_id,
                &CapabilitySet::new([
                    depgraph_mcp_tools::AgentCapability::Read,
                    depgraph_mcp_tools::AgentCapability::StoreWrite,
                ])
                .unwrap(),
                system_now_ms().unwrap(),
            )
            .unwrap();
        release_dispatch.send(()).unwrap();

        let report = runner_thread.join().unwrap().unwrap();
        assert_eq!(report.completed(), 0);
        assert_eq!(report.cancelled(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            journal
                .result(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Cancelled
        ));
    }

    #[test]
    fn cancellation_in_scan_completion_window_keeps_previous_current_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let service = DepgraphService::new(config.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(service.scan_cancellable(
                &ScanRequest::new(false, ScanCacheMode::Disabled),
                CancellationToken::new(),
            ))
            .unwrap();
        let previous_current = service
            .start_snapshot_request("current")
            .unwrap()
            .snapshot_id()
            .as_str()
            .to_owned();
        std::fs::write(
            config.canonical_root().join("changed.rs"),
            "pub fn changed() {}\n",
        )
        .unwrap();

        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 10_000;
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"cancel-in-scan-completion-window",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        drop(journal);

        let (dispatch_completed, wait_for_dispatch) = mpsc::sync_channel(0);
        let (release_completion, wait_for_release) = mpsc::sync_channel(0);
        let runner = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .with_completion_decision_barrier_for_test(dispatch_completed, wait_for_release);
        let runner_thread = std::thread::spawn(move || runner.run_until_idle());

        wait_for_dispatch
            .recv_timeout(Duration::from_secs(5))
            .expect("scan dispatch completion signal");
        let mut journal = OperationJournal::open(&config).unwrap();
        journal
            .cancel(
                &repository,
                &operation_id,
                &CapabilitySet::new([
                    depgraph_mcp_tools::AgentCapability::Read,
                    depgraph_mcp_tools::AgentCapability::StoreWrite,
                ])
                .unwrap(),
                system_now_ms().unwrap(),
            )
            .unwrap();
        assert_eq!(
            service
                .start_snapshot_request("current")
                .unwrap()
                .snapshot_id()
                .as_str(),
            previous_current
        );
        release_completion.send(()).unwrap();

        let report = runner_thread.join().unwrap().unwrap();
        assert_eq!(report.completed(), 0);
        assert_eq!(report.cancelled(), 1);
        assert!(matches!(
            journal
                .result(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Cancelled
        ));
        assert_eq!(
            service
                .start_snapshot_request("current")
                .unwrap()
                .snapshot_id()
                .as_str(),
            previous_current
        );
    }

    #[test]
    fn scan_cancel_cleanup_failure_is_retried_before_terminalizing() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let service = DepgraphService::new(config.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(service.scan_cancellable(
                &ScanRequest::new(false, ScanCacheMode::Disabled),
                CancellationToken::new(),
            ))
            .unwrap();
        std::fs::write(
            config.canonical_root().join("scan-cancel-retry.rs"),
            "pub fn changed() {}\n",
        )
        .unwrap();
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 30_000;
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"scan-cancel-cleanup-retry",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        drop(journal);

        let (dispatch_completed, wait_for_dispatch) = mpsc::sync_channel(0);
        let (release_completion, wait_for_release) = mpsc::sync_channel(0);
        let runner = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .with_completion_decision_barrier_for_test(dispatch_completed, wait_for_release);
        let runner_thread = std::thread::spawn(move || runner.run_until_idle());
        wait_for_dispatch
            .recv_timeout(Duration::from_secs(5))
            .expect("scan completion signal");

        let store = rusqlite::Connection::open(config.store_path()).unwrap();
        let (scan_id, scan_status) = store
            .query_row(
                "SELECT owner.scan_id, scan.status
                   FROM scan_operation_staging AS owner
                   JOIN scans AS scan ON scan.id=owner.scan_id
                  WHERE owner.operation_id=?1",
                [operation_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .unwrap();
        assert_eq!(scan_status, "staging");
        store
            .execute_batch(
                "CREATE TRIGGER fail_first_scan_cancel
                 BEFORE UPDATE OF status ON scans
                 WHEN OLD.status='staging' AND NEW.status='cancelled'
                 BEGIN SELECT RAISE(ABORT, 'injected scan cancel failure'); END;",
            )
            .unwrap();
        drop(store);
        let mut journal = OperationJournal::open(&config).unwrap();
        journal
            .cancel(
                &repository,
                &operation_id,
                &CapabilitySet::new([
                    depgraph_mcp_tools::AgentCapability::Read,
                    depgraph_mcp_tools::AgentCapability::StoreWrite,
                ])
                .unwrap(),
                system_now_ms().unwrap(),
            )
            .unwrap();
        release_completion.send(()).unwrap();

        let first_error = runner_thread.join().unwrap().unwrap_err();
        assert!(matches!(first_error, RunnerError::Service(_)));
        let retryable = journal
            .get(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap();
        assert_eq!(retryable.status(), OperationStatus::Cancelling);
        assert!(retryable.lease().is_some());
        assert_eq!(retryable.terminal_at_ms(), None);
        assert_eq!(
            journal
                .runner_handoff(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap()
                .completed_at_ms(),
            None
        );
        let store = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            store
                .query_row("SELECT status FROM scans WHERE id=?1", [&scan_id], |row| {
                    row.get::<_, String>(0)
                },)
                .unwrap(),
            "staging"
        );
        store
            .execute_batch("DROP TRIGGER fail_first_scan_cancel")
            .unwrap();
        drop(store);

        std::thread::sleep(Duration::from_millis(2));
        let retry_at_ms = system_now_ms().unwrap();
        rusqlite::Connection::open(crate::operation_journal_path(&config))
            .unwrap()
            .execute(
                "UPDATE operations SET lease_expires_at_ms=?1 WHERE operation_id=?2",
                rusqlite::params![retry_at_ms - 1, operation_id.as_str()],
            )
            .unwrap();
        drop(journal);

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();
        assert_eq!(report.claimed(), 1);
        assert_eq!(report.cancelled(), 1);
        assert!(matches!(
            OperationJournal::open(&config)
                .unwrap()
                .result(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Cancelled
        ));
        assert_eq!(
            rusqlite::Connection::open(config.store_path())
                .unwrap()
                .query_row("SELECT status FROM scans WHERE id=?1", [&scan_id], |row| {
                    row.get::<_, String>(0)
                },)
                .unwrap(),
            "cancelled"
        );
    }

    #[test]
    fn cancellation_in_runtime_import_completion_window_keeps_base_snapshot_current() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let (base_snapshot_id, _, durable_input) =
            runtime_import_fixture(&config, "runtime-cancel-window");
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 10_000;
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &durable_input,
                    b"cancel-in-runtime-completion-window",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        drop(journal);

        let (dispatch_completed, wait_for_dispatch) = mpsc::sync_channel(0);
        let (release_completion, wait_for_release) = mpsc::sync_channel(0);
        let runner = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .with_completion_decision_barrier_for_test(dispatch_completed, wait_for_release);
        let runner_thread = std::thread::spawn(move || runner.run_until_idle());

        wait_for_dispatch
            .recv_timeout(Duration::from_secs(5))
            .expect("runtime import dispatch completion signal");
        let mut journal = OperationJournal::open(&config).unwrap();
        journal
            .cancel(
                &repository,
                &operation_id,
                &CapabilitySet::new([
                    depgraph_mcp_tools::AgentCapability::Read,
                    depgraph_mcp_tools::AgentCapability::StoreWrite,
                ])
                .unwrap(),
                system_now_ms().unwrap(),
            )
            .unwrap();
        assert_eq!(
            depgraph_core::open_store_read_only(config.store_path())
                .unwrap()
                .current_snapshot_id()
                .unwrap()
                .as_deref(),
            Some(base_snapshot_id.as_str())
        );
        release_completion.send(()).unwrap();

        let report = runner_thread.join().unwrap().unwrap();
        assert_eq!(report.completed(), 0);
        assert_eq!(report.cancelled(), 1);
        assert!(matches!(
            journal
                .result(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Cancelled
        ));
        assert_eq!(
            depgraph_core::open_store_read_only(config.store_path())
                .unwrap()
                .current_snapshot_id()
                .unwrap()
                .as_deref(),
            Some(base_snapshot_id.as_str())
        );
    }

    #[test]
    fn cancellation_winner_retries_runtime_cleanup_before_terminalizing() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let (_, _, durable_input) = runtime_import_fixture(&config, "runtime-cancel-cleanup-retry");
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 30_000;
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &durable_input,
                    b"runtime-cancel-cleanup-retry",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        drop(journal);

        let (dispatch_completed, wait_for_dispatch) = mpsc::sync_channel(0);
        let (release_completion, wait_for_release) = mpsc::sync_channel(0);
        let runner = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .with_completion_decision_barrier_for_test(dispatch_completed, wait_for_release);
        let runner_thread = std::thread::spawn(move || runner.run_until_idle());

        wait_for_dispatch
            .recv_timeout(Duration::from_secs(5))
            .expect("runtime completion signal");
        let store = rusqlite::Connection::open(config.store_path()).unwrap();
        let import_id = store
            .query_row(
                "SELECT id FROM runtime_imports WHERE status='staging'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        store
            .execute_batch(
                "CREATE TRIGGER fail_first_runtime_cancel
                 BEFORE DELETE ON runtime_import_operation_owners
                 BEGIN SELECT RAISE(ABORT, 'injected runtime cancel failure'); END;",
            )
            .unwrap();
        drop(store);
        let mut journal = OperationJournal::open(&config).unwrap();
        journal
            .cancel(
                &repository,
                &operation_id,
                &CapabilitySet::new([
                    depgraph_mcp_tools::AgentCapability::Read,
                    depgraph_mcp_tools::AgentCapability::StoreWrite,
                ])
                .unwrap(),
                system_now_ms().unwrap(),
            )
            .unwrap();
        release_completion.send(()).unwrap();

        let first_error = runner_thread.join().unwrap().unwrap_err();
        assert!(matches!(first_error, RunnerError::Service(_)));
        let retryable = journal
            .get(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap();
        assert_eq!(retryable.status(), OperationStatus::Cancelling);
        assert!(retryable.lease().is_some());
        assert_eq!(retryable.terminal_at_ms(), None);
        assert_eq!(
            journal
                .runner_handoff(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap()
                .completed_at_ms(),
            None
        );
        let store = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            store
                .query_row(
                    "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                    [&import_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .query_row(
                    "SELECT COUNT(*) FROM runtime_import_operation_owners
                     WHERE import_id=?1 AND operation_id=?2",
                    rusqlite::params![import_id, operation_id.as_str()],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            1
        );
        store
            .execute_batch("DROP TRIGGER fail_first_runtime_cancel")
            .unwrap();
        drop(store);

        std::thread::sleep(Duration::from_millis(2));
        let retry_at_ms = system_now_ms().unwrap();
        rusqlite::Connection::open(crate::operation_journal_path(&config))
            .unwrap()
            .execute(
                "UPDATE operations SET lease_expires_at_ms=?1 WHERE operation_id=?2",
                rusqlite::params![retry_at_ms - 1, operation_id.as_str()],
            )
            .unwrap();
        drop(journal);

        let (cleanup_completed, wait_for_cleanup) = mpsc::sync_channel(0);
        let (release_terminal, wait_for_terminal) = mpsc::sync_channel(0);
        let retry_runner = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .with_cleanup_terminal_barrier_for_test(cleanup_completed, wait_for_terminal);
        let retry_thread = std::thread::spawn(move || retry_runner.run_until_idle());
        wait_for_cleanup
            .recv_timeout(Duration::from_secs(5))
            .expect("runtime cleanup completion");

        let journal = OperationJournal::open(&config).unwrap();
        let before_terminal = journal
            .get(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap();
        assert_eq!(before_terminal.status(), OperationStatus::Cancelling);
        assert!(before_terminal.lease().is_some());
        assert_eq!(before_terminal.terminal_at_ms(), None);
        let store = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            store
                .query_row(
                    "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                    [&import_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .query_row(
                    "SELECT COUNT(*) FROM runtime_import_operation_owners WHERE import_id=?1",
                    [&import_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
        drop(store);
        release_terminal.send(()).unwrap();

        let report = retry_thread.join().unwrap().unwrap();
        assert_eq!(report.claimed(), 1);
        assert_eq!(report.cancelled(), 1);
        assert!(matches!(
            journal
                .result(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Cancelled
        ));
    }

    #[test]
    fn dispatch_time_runtime_cancel_cleanup_error_is_retryable() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let (_, _, durable_input) =
            runtime_import_fixture(&config, "runtime-dispatch-cancel-failure");
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 30_000;
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &durable_input,
                    b"runtime-dispatch-cancel-failure",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        drop(journal);

        let (staged, wait_for_stage) = mpsc::sync_channel(0);
        let (release_dispatch, wait_for_release) = mpsc::sync_channel(0);
        let dispatcher = ScanOperationDispatcher::new(config.clone())
            .with_runtime_dispatch_barrier_for_test(staged, wait_for_release);
        let runner = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            dispatcher,
        );
        let runner_thread = std::thread::spawn(move || runner.run_until_idle());
        wait_for_stage
            .recv_timeout(Duration::from_secs(5))
            .expect("runtime staging signal");

        let store = rusqlite::Connection::open(config.store_path()).unwrap();
        let import_id = store
            .query_row(
                "SELECT id FROM runtime_imports WHERE status='staging'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        store
            .execute_batch(
                "CREATE TRIGGER fail_dispatch_runtime_cancel
                 BEFORE DELETE ON runtime_import_operation_owners
                 BEGIN SELECT RAISE(ABORT, 'injected dispatch cancel failure'); END;",
            )
            .unwrap();
        drop(store);
        let mut journal = OperationJournal::open(&config).unwrap();
        journal
            .cancel(
                &repository,
                &operation_id,
                &CapabilitySet::new([
                    depgraph_mcp_tools::AgentCapability::Read,
                    depgraph_mcp_tools::AgentCapability::StoreWrite,
                ])
                .unwrap(),
                system_now_ms().unwrap(),
            )
            .unwrap();
        release_dispatch.send(()).unwrap();

        let error = runner_thread.join().unwrap().unwrap_err();
        assert!(matches!(error, RunnerError::Service(_)));
        let retryable = journal
            .get(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap();
        assert_eq!(retryable.status(), OperationStatus::Cancelling);
        assert!(retryable.lease().is_some());
        assert_eq!(retryable.terminal_at_ms(), None);
        assert_eq!(
            journal
                .runner_handoff(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap()
                .completed_at_ms(),
            None
        );
        let store = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            store
                .query_row(
                    "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                    [&import_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .query_row(
                    "SELECT COUNT(*) FROM runtime_import_operation_owners
                     WHERE import_id=?1 AND operation_id=?2",
                    rusqlite::params![import_id, operation_id.as_str()],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn cancellation_reclaim_after_runtime_stage_crash_removes_only_staging_evidence() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let (base_snapshot_id, trace, durable_input) =
            runtime_import_fixture(&config, "runtime-stage-crash-cancel");
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 10_000;
        let lease_token = b"runtime-stage-crash-cancel-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &durable_input,
                    b"runtime-stage-crash-cancel",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("crashing-runtime-stage-runner").unwrap(),
                lease_token,
                submitted_at_ms + 1,
                submitted_at_ms + 2,
            )
            .unwrap();

        let service = DepgraphService::new(config.clone());
        let prepared = service
            .prepare_runtime_import(
                &RuntimeValidateRequest {
                    trace: Some(trace),
                    trace_file: None,
                    snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                        base_snapshot_id.clone(),
                    )),
                },
                &CancellationToken::new(),
            )
            .unwrap();
        let completion = match service
            .runtime_import_deferred_prepared(
                prepared,
                operation_id.as_str(),
                &CancellationToken::new(),
            )
            .unwrap()
        {
            DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
            DeferredRuntimeImportServiceOutcome::Finished(_) => {
                panic!("runtime import did not leave staging evidence")
            }
        };
        let import_id = completion.outcome().result().import_id.clone();
        let session_id = completion.outcome().result().session_id.clone();
        drop(completion);

        let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            evidence
                .query_row(
                    "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                    [&import_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            evidence
                .query_row(
                    "SELECT COUNT(*) FROM runtime_sessions WHERE id=?1",
                    [&session_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            1
        );
        drop(evidence);
        journal
            .cancel(
                &repository,
                &operation_id,
                &CapabilitySet::new([
                    depgraph_mcp_tools::AgentCapability::Read,
                    depgraph_mcp_tools::AgentCapability::StoreWrite,
                ])
                .unwrap(),
                system_now_ms().unwrap(),
            )
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();

        assert_eq!(report.cancelled(), 1);
        assert!(matches!(
            OperationJournal::open(&config)
                .unwrap()
                .result(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Cancelled
        ));
        let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            evidence
                .query_row(
                    "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                    [&import_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            evidence
                .query_row(
                    "SELECT COUNT(*) FROM runtime_sessions WHERE id=?1",
                    [&session_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            depgraph_core::open_store_read_only(config.store_path())
                .unwrap()
                .current_snapshot_id()
                .unwrap()
                .as_deref(),
            Some(base_snapshot_id.as_str())
        );
    }

    #[test]
    fn legacy_runtime_input_cancellation_reclaims_v17_stage_by_operation_owner() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let (base_snapshot_id, trace, durable_input) =
            runtime_import_fixture(&config, "legacy-v17-cancel-cleanup");
        let durable_input = legacy_runtime_import_input(durable_input);
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 60_000;
        let expired_at_ms = submitted_at_ms + 50;
        let lease = b"legacy-v17-cancel-cleanup-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &durable_input,
                    b"legacy-v17-cancel-cleanup",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("legacy-v17-cancel-crash").unwrap(),
                lease,
                submitted_at_ms + 1,
                expired_at_ms,
            )
            .unwrap();
        let service = DepgraphService::new(config.clone());
        let prepared = service
            .prepare_runtime_import(
                &RuntimeValidateRequest {
                    trace: Some(trace),
                    trace_file: None,
                    snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                        base_snapshot_id,
                    )),
                },
                &CancellationToken::new(),
            )
            .unwrap();
        let completion = match service
            .runtime_import_deferred_prepared(
                prepared,
                operation_id.as_str(),
                &CancellationToken::new(),
            )
            .unwrap()
        {
            DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
            DeferredRuntimeImportServiceOutcome::Finished(_) => {
                panic!("legacy operation did not leave v17 staging")
            }
        };
        let import_id = completion.outcome().result().import_id.clone();
        let session_id = completion.outcome().result().session_id.clone();
        drop(completion);
        journal
            .cancel(
                &repository,
                &operation_id,
                &cancellable_capabilities(),
                submitted_at_ms + 2,
            )
            .unwrap();
        drop(journal);
        while system_now_ms().unwrap() <= expired_at_ms {
            std::thread::yield_now();
        }

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();
        assert_eq!(report.cancelled(), 1);
        let store = rusqlite::Connection::open(config.store_path()).unwrap();
        for (table, column, identity) in [
            ("runtime_imports", "id", import_id.as_str()),
            ("runtime_sessions", "id", session_id.as_str()),
            (
                "runtime_import_operation_owners",
                "operation_id",
                operation_id.as_str(),
            ),
        ] {
            assert_eq!(
                store
                    .query_row(
                        &format!("SELECT COUNT(*) FROM {table} WHERE {column}=?1"),
                        [identity],
                        |row| row.get::<_, u64>(0),
                    )
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn legacy_runtime_file_failure_reclaims_v17_stage_by_operation_owner() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let (base_snapshot_id, trace, _) =
            runtime_import_fixture(&config, "legacy-v17-failure-cleanup");
        std::fs::create_dir_all(config.canonical_root().join("traces")).unwrap();
        let trace_path = config.canonical_root().join("traces/legacy-runtime.json");
        std::fs::write(&trace_path, &trace).unwrap();
        let trace_file = RepositoryRelativePath::parse("traces/legacy-runtime.json").unwrap();
        let service = DepgraphService::new(config.clone());
        let prepared = service
            .prepare_runtime_import(
                &RuntimeValidateRequest {
                    trace: None,
                    trace_file: Some(trace_file),
                    snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                        base_snapshot_id,
                    )),
                },
                &CancellationToken::new(),
            )
            .unwrap();
        let durable_input = legacy_runtime_import_input(prepared.durable_input());
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 60_000;
        let expired_at_ms = submitted_at_ms + 50;
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &durable_input,
                    b"legacy-v17-failure-cleanup",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("legacy-v17-failure-crash").unwrap(),
                b"legacy-v17-failure-cleanup-token",
                submitted_at_ms + 1,
                expired_at_ms,
            )
            .unwrap();
        let completion = match service
            .runtime_import_deferred_prepared(
                prepared,
                operation_id.as_str(),
                &CancellationToken::new(),
            )
            .unwrap()
        {
            DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
            DeferredRuntimeImportServiceOutcome::Finished(_) => {
                panic!("legacy operation did not leave v17 staging")
            }
        };
        let import_id = completion.outcome().result().import_id.clone();
        let session_id = completion.outcome().result().session_id.clone();
        drop(completion);
        std::fs::write(
            trace_path,
            trace.replace("legacy-v17-failure-cleanup", "legacy-v17-failure-drifted"),
        )
        .unwrap();
        drop(journal);
        while system_now_ms().unwrap() <= expired_at_ms {
            std::thread::yield_now();
        }

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();
        assert_eq!(report.failed(), 1);
        assert!(matches!(
            OperationJournal::open(&config)
                .unwrap()
                .result(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Failed(_)
        ));
        let store = rusqlite::Connection::open(config.store_path()).unwrap();
        for (table, column, identity) in [
            ("runtime_imports", "id", import_id.as_str()),
            ("runtime_sessions", "id", session_id.as_str()),
            (
                "runtime_import_operation_owners",
                "operation_id",
                operation_id.as_str(),
            ),
        ] {
            assert_eq!(
                store
                    .query_row(
                        &format!("SELECT COUNT(*) FROM {table} WHERE {column}=?1"),
                        [identity],
                        |row| row.get::<_, u64>(0),
                    )
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn deadline_reclaim_after_runtime_stage_crash_removes_only_staging_evidence() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let (base_snapshot_id, trace, durable_input) =
            runtime_import_fixture(&config, "runtime-stage-crash-deadline");
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 200;
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &durable_input,
                    b"runtime-stage-crash-deadline",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("crashing-runtime-deadline-runner").unwrap(),
                b"runtime-stage-crash-deadline-token",
                submitted_at_ms + 1,
                deadline_ms,
            )
            .unwrap();

        let service = DepgraphService::new(config.clone());
        let prepared = service
            .prepare_runtime_import(
                &RuntimeValidateRequest {
                    trace: Some(trace.clone()),
                    trace_file: None,
                    snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                        base_snapshot_id.clone(),
                    )),
                },
                &CancellationToken::new(),
            )
            .unwrap();
        let completion = match service
            .runtime_import_deferred_prepared(
                prepared,
                operation_id.as_str(),
                &CancellationToken::new(),
            )
            .unwrap()
        {
            DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
            DeferredRuntimeImportServiceOutcome::Finished(_) => {
                panic!("runtime import did not leave staging evidence")
            }
        };
        let import_id = completion.outcome().result().import_id.clone();
        let session_id = completion.outcome().result().session_id.clone();
        drop(completion);
        let competing_prepared = service
            .prepare_runtime_import(
                &RuntimeValidateRequest {
                    trace: Some(trace),
                    trace_file: None,
                    snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                        base_snapshot_id.clone(),
                    )),
                },
                &CancellationToken::new(),
            )
            .unwrap();
        while system_now_ms().unwrap() < deadline_ms {
            std::thread::sleep(Duration::from_millis(5));
        }

        let (cleanup_finished, wait_for_cleanup) = mpsc::sync_channel(0);
        let (release_terminal, wait_for_terminal_release) = mpsc::sync_channel(0);
        let runner = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .with_cleanup_terminal_barrier_for_test(cleanup_finished, wait_for_terminal_release);
        let runner_thread = std::thread::spawn(move || runner.run_until_idle());

        wait_for_cleanup
            .recv_timeout(Duration::from_secs(5))
            .expect("runtime cleanup completion signal");
        // The runner is paused after store cleanup while the returned writer
        // guard is still held, but before its journal transition is terminal.
        assert_eq!(
            journal
                .get(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap()
                .status(),
            OperationStatus::Running
        );
        assert!(matches!(
            service.runtime_import_deferred_prepared(
                competing_prepared,
                operation_id.as_str(),
                &CancellationToken::new(),
            ),
            Err(DepgraphServiceError::StoreWriterConflict)
        ));
        let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            evidence
                .query_row(
                    "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                    [&import_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            evidence
                .query_row(
                    "SELECT COUNT(*) FROM runtime_import_operation_owners WHERE import_id=?1",
                    [&import_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
        drop(evidence);
        release_terminal.send(()).unwrap();
        let report = runner_thread.join().unwrap().unwrap();

        assert_eq!(report.failed(), 1);
        assert!(matches!(
            OperationJournal::open(&config)
                .unwrap()
                .result(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Failed(_)
        ));
        let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            evidence
                .query_row(
                    "SELECT COUNT(*) FROM runtime_import_operation_owners WHERE import_id=?1",
                    [&import_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            evidence
                .query_row(
                    "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                    [&import_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            evidence
                .query_row(
                    "SELECT COUNT(*) FROM runtime_sessions WHERE id=?1",
                    [&session_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            depgraph_core::open_store_read_only(config.store_path())
                .unwrap()
                .current_snapshot_id()
                .unwrap()
                .as_deref(),
            Some(base_snapshot_id.as_str())
        );
    }

    #[test]
    fn runtime_deadline_cleanup_bypasses_elapsed_observability_and_unblocks_the_queue() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let (base_snapshot_id, trace, durable_input) =
            runtime_import_fixture(&config, "runtime-expired-after-retention");
        let reference_ms = system_now_ms().unwrap();
        let submitted_at_ms = reference_ms - TERMINAL_RETENTION_MS - 10_000;
        let deadline_ms = submitted_at_ms + 1_000;
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &durable_input,
                    b"runtime-expired-after-retention",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("expired-retention-runtime-runner").unwrap(),
                b"expired-retention-runtime-token",
                submitted_at_ms + 1,
                deadline_ms,
            )
            .unwrap();

        let service = DepgraphService::new(config.clone());
        let prepared = service
            .prepare_runtime_import(
                &RuntimeValidateRequest {
                    trace: Some(trace),
                    trace_file: None,
                    snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                        base_snapshot_id,
                    )),
                },
                &CancellationToken::new(),
            )
            .unwrap();
        let completion = match service
            .runtime_import_deferred_prepared(
                prepared,
                operation_id.as_str(),
                &CancellationToken::new(),
            )
            .unwrap()
        {
            DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
            DeferredRuntimeImportServiceOutcome::Finished(_) => {
                panic!("runtime import did not leave staging evidence")
            }
        };
        let import_id = completion.outcome().result().import_id.clone();
        drop(completion);
        assert!(matches!(
            journal.runner_handoff(&repository, &operation_id, reference_ms),
            Err(JournalError::Expired)
        ));

        let queued_at_ms = system_now_ms().unwrap();
        let queued_operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"queued-after-expired-retention-runtime",
                    queued_at_ms + 60_000,
                )
                .unwrap(),
                queued_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        drop(journal);

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();
        assert_eq!(report.failed(), 1);
        assert_eq!(report.completed(), 1);
        let journal = OperationJournal::open(&config).unwrap();
        assert!(matches!(
            journal
                .result(&repository, &queued_operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Completed(_)
        ));
        let journal_connection =
            rusqlite::Connection::open(crate::operation_journal_path(&config)).unwrap();
        assert_eq!(
            journal_connection
                .query_row(
                    "SELECT COUNT(*) FROM operation_tombstones WHERE operation_id=?1",
                    [operation_id.as_str()],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            rusqlite::Connection::open(config.store_path())
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM runtime_import_operation_owners WHERE import_id=?1",
                    [&import_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn failed_first_attempt_file_runtime_import_cleans_staging_before_terminalization() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let (base_snapshot_id, trace, _) =
            runtime_import_fixture(&config, "runtime-stage-crash-file-drift");
        std::fs::create_dir_all(config.canonical_root().join("traces")).unwrap();
        std::fs::write(config.canonical_root().join("traces/runtime.json"), &trace).unwrap();
        let trace_file = RepositoryRelativePath::parse("traces/runtime.json").unwrap();
        let service = DepgraphService::new(config.clone());
        let prepared = service
            .prepare_runtime_import(
                &RuntimeValidateRequest {
                    trace: None,
                    trace_file: Some(trace_file.clone()),
                    snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                        base_snapshot_id.clone(),
                    )),
                },
                &CancellationToken::new(),
            )
            .unwrap();
        let durable_input = prepared.durable_input();
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 10_000;
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &durable_input,
                    b"runtime-stage-crash-file-drift",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        let completion = match service
            .runtime_import_deferred_prepared(
                prepared,
                operation_id.as_str(),
                &CancellationToken::new(),
            )
            .unwrap()
        {
            DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
            DeferredRuntimeImportServiceOutcome::Finished(_) => {
                panic!("runtime import did not leave staging evidence")
            }
        };
        let import_id = completion.outcome().result().import_id.clone();
        let session_id = completion.outcome().result().session_id.clone();
        drop(completion);
        let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
        for (query, identity) in [
            (
                "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                import_id.as_str(),
            ),
            (
                "SELECT COUNT(*) FROM runtime_import_operation_owners WHERE import_id=?1",
                import_id.as_str(),
            ),
            (
                "SELECT COUNT(*) FROM runtime_sessions WHERE id=?1",
                session_id.as_str(),
            ),
        ] {
            assert_eq!(
                evidence
                    .query_row(query, [identity], |row| row.get::<_, u64>(0))
                    .unwrap(),
                1
            );
        }
        drop(evidence);
        let competing_prepared = service
            .prepare_runtime_import(
                &RuntimeValidateRequest {
                    trace: Some(trace.clone()),
                    trace_file: None,
                    snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                        base_snapshot_id.clone(),
                    )),
                },
                &CancellationToken::new(),
            )
            .unwrap();
        std::fs::write(
            config.canonical_root().join("traces/runtime.json"),
            trace.replace(
                "runtime-stage-crash-file-drift",
                "runtime-stage-crash-file-drifted",
            ),
        )
        .unwrap();
        let queued_operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"queued-after-first-runtime-failure",
                    submitted_at_ms + 60_000,
                )
                .unwrap(),
                submitted_at_ms + 1,
            )
            .unwrap()
            .operation_id()
            .clone();

        let (cleanup_finished, wait_for_cleanup) = mpsc::sync_channel(0);
        let (release_terminal, wait_for_terminal_release) = mpsc::sync_channel(0);
        let runner = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .with_cleanup_terminal_barrier_for_test(cleanup_finished, wait_for_terminal_release);
        let runner_thread = std::thread::spawn(move || runner.run_until_idle());

        wait_for_cleanup
            .recv_timeout(Duration::from_secs(5))
            .expect("failed-dispatch cleanup completion signal");
        assert_eq!(
            journal
                .get(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap()
                .status(),
            OperationStatus::Running
        );
        assert!(matches!(
            service.runtime_import_deferred_prepared(
                competing_prepared,
                operation_id.as_str(),
                &CancellationToken::new(),
            ),
            Err(DepgraphServiceError::StoreWriterConflict)
        ));
        let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
        for (query, identity) in [
            (
                "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                import_id.as_str(),
            ),
            (
                "SELECT COUNT(*) FROM runtime_import_operation_owners WHERE import_id=?1",
                import_id.as_str(),
            ),
            (
                "SELECT COUNT(*) FROM runtime_sessions WHERE id=?1",
                session_id.as_str(),
            ),
        ] {
            assert_eq!(
                evidence
                    .query_row(query, [identity], |row| row.get::<_, u64>(0))
                    .unwrap(),
                0
            );
        }
        drop(evidence);

        release_terminal.send(()).unwrap();
        let report = runner_thread.join().unwrap().unwrap();
        assert_eq!(report.claimed(), 2);
        assert_eq!(report.failed(), 1);
        assert_eq!(report.completed(), 1);
        match OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap()
        {
            OperationOutcome::Failed(error) => {
                let value: serde_json::Value = serde_json::from_str(error.as_str()).unwrap();
                assert_eq!(value["error"]["code"], "CONFLICT");
            }
            outcome => panic!("unexpected reclaimed file-drift outcome: {outcome:?}"),
        }
        assert!(matches!(
            OperationJournal::open(&config)
                .unwrap()
                .result(&repository, &queued_operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Completed(_)
        ));
        let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            evidence
                .query_row(
                    "SELECT COUNT(*) FROM completed_snapshots WHERE runtime_import_id=?1",
                    [&import_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn runtime_import_digest_drift_fails_without_publishing_a_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let (base_snapshot_id, _, mut durable_input) =
            runtime_import_fixture(&config, "runtime-digest-drift");
        durable_input["trace_digest"] = json!("runtime-trace:sha256:invalid-drift");
        let submitted_at_ms = system_now_ms().unwrap();
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &durable_input,
                    b"runtime-digest-drift",
                    submitted_at_ms + 10_000,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        drop(journal);

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();

        assert_eq!(report.failed(), 1);
        let journal = OperationJournal::open(&config).unwrap();
        match journal
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap()
        {
            OperationOutcome::Failed(error) => {
                let value: serde_json::Value = serde_json::from_str(error.as_str()).unwrap();
                assert_eq!(value["error"]["code"], "CONFLICT");
            }
            outcome => panic!("unexpected runtime drift outcome: {outcome:?}"),
        }
        assert_eq!(
            depgraph_core::open_store_read_only(config.store_path())
                .unwrap()
                .current_snapshot_id()
                .unwrap()
                .as_deref(),
            Some(base_snapshot_id.as_str())
        );
    }

    #[test]
    fn runner_accepts_retained_normalized_runtime_trace_larger_than_transport_limit() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let (base_snapshot_id, trace, _) =
            runtime_import_fixture(&config, "runtime-normalized-over-transport");
        let mut raw_trace: serde_json::Value = serde_json::from_str(&trace).unwrap();
        let session = raw_trace["session"].as_object_mut().unwrap();
        session.remove("redaction");
        session["profile"]
            .as_object_mut()
            .unwrap()
            .remove("features");
        session["environment"]
            .as_object_mut()
            .unwrap()
            .remove("environment_keys");
        let mut event = raw_trace["events"][0].clone();
        let event_object = event.as_object_mut().unwrap();
        event_object.remove("count");
        event_object.remove("redaction");
        raw_trace["events"] = serde_json::Value::Array(
            (1..=3_400)
                .map(|sequence| {
                    let mut event = event.clone();
                    event["sequence"] = json!(sequence);
                    event
                })
                .collect(),
        );
        let raw_trace = serde_json::to_string(&raw_trace).unwrap();
        assert!(
            raw_trace.len() <= depgraph_core::DEFAULT_SERVICE_MAX_INLINE_INPUT_BYTES,
            "raw transport input is {} bytes",
            raw_trace.len()
        );

        let durable_input = DepgraphService::new(config.clone())
            .prepare_runtime_import(
                &RuntimeValidateRequest {
                    trace: Some(raw_trace),
                    trace_file: None,
                    snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                        base_snapshot_id,
                    )),
                },
                &CancellationToken::new(),
            )
            .unwrap()
            .durable_input();
        let normalized_trace = serde_json::to_string(&durable_input["trace"]).unwrap();
        assert!(
            normalized_trace.len() > depgraph_core::DEFAULT_SERVICE_MAX_INLINE_INPUT_BYTES,
            "normalized retained trace is only {} bytes",
            normalized_trace.len()
        );
        let canonical_input = CanonicalInput::new(&durable_input).unwrap();
        assert!(canonical_input.as_str().len() <= crate::MAX_OPERATION_INPUT_BYTES);

        let submitted_at_ms = system_now_ms().unwrap();
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &durable_input,
                    b"runtime-normalized-over-transport",
                    submitted_at_ms + 60_000,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        drop(journal);

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();
        let outcome = OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap();
        match outcome {
            OperationOutcome::Completed(_) => {}
            OperationOutcome::Failed(error) => {
                let value: serde_json::Value = serde_json::from_str(error.as_str()).unwrap();
                panic!(
                    "retained normalized trace was terminally rejected: {}",
                    value["error"]["code"]
                );
            }
            outcome => panic!("unexpected expanding runtime trace outcome: {outcome:?}"),
        }
        assert_eq!(report.claimed(), 1);
        assert_eq!(report.completed(), 1);
        assert_eq!(report.failed(), 0);
    }

    #[test]
    fn changed_valid_queued_file_fails_before_migrating_a_v15_store() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let (base_snapshot_id, trace, _) =
            runtime_import_fixture(&config, "runtime-v15-file-original");
        std::fs::create_dir_all(config.canonical_root().join("traces")).unwrap();
        let trace_path = config.canonical_root().join("traces/runtime.json");
        std::fs::write(&trace_path, &trace).unwrap();
        let trace_file = RepositoryRelativePath::parse("traces/runtime.json").unwrap();
        let service = DepgraphService::new(config.clone());
        let durable_input = service
            .prepare_runtime_import(
                &RuntimeValidateRequest {
                    trace: None,
                    trace_file: Some(trace_file),
                    snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                        base_snapshot_id,
                    )),
                },
                &CancellationToken::new(),
            )
            .unwrap()
            .durable_input();

        let connection = rusqlite::Connection::open(config.store_path()).unwrap();
        connection
            .execute_batch(
                "PRAGMA wal_checkpoint(TRUNCATE);
                 DROP TABLE scan_operation_staging;
                 DROP TABLE runtime_import_operation_owners;
                 PRAGMA user_version=15;
                 PRAGMA journal_mode=DELETE;",
            )
            .unwrap();
        drop(connection);
        let store_bytes_before = std::fs::read(config.store_path()).unwrap();

        std::fs::write(
            &trace_path,
            trace.replace("runtime-v15-file-original", "runtime-v15-file-different"),
        )
        .unwrap();
        let submitted_at_ms = system_now_ms().unwrap();
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &durable_input,
                    b"runtime-v15-valid-file-drift",
                    submitted_at_ms + 10_000,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        drop(journal);

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();

        assert_eq!(report.claimed(), 1);
        assert_eq!(report.failed(), 1);
        match OperationJournal::open(&config)
            .unwrap()
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap()
        {
            OperationOutcome::Failed(error) => {
                let value: serde_json::Value = serde_json::from_str(error.as_str()).unwrap();
                assert_eq!(value["error"]["code"], "CONFLICT");
            }
            outcome => panic!("unexpected v15 file-drift outcome: {outcome:?}"),
        }
        assert_eq!(
            std::fs::read(config.store_path()).unwrap(),
            store_bytes_before
        );
        let connection = rusqlite::Connection::open_with_flags(
            config.store_path(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            15
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                      WHERE type='table' AND name='runtime_import_operation_owners'",
                    [],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn retained_runtime_identity_mismatches_fail_before_migrating_v15() {
        for mismatch in [
            "session_id",
            "runtime_trace_digest",
            "paired_validated_trace_identity",
        ] {
            let root = tempfile::tempdir().unwrap();
            let config = config(root.path());
            let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
            let (base_snapshot_id, _, mut durable_input) =
                runtime_import_fixture(&config, "runtime-v15-binding-mismatch");
            if mismatch == "paired_validated_trace_identity" {
                durable_input["trace"]["session"]["started_at"] = json!("2026-08-07T23:59:59Z");
                let request = RuntimeValidateRequest {
                    trace: Some(serde_json::to_string(&durable_input["trace"]).unwrap()),
                    trace_file: None,
                    snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                        base_snapshot_id,
                    )),
                };
                let prevalidated = DepgraphService::new(config.clone())
                    .prevalidate_runtime_trace_source(&request.source(), &CancellationToken::new())
                    .unwrap();
                durable_input["trace_digest"] = json!(prevalidated.input_digest());
            } else {
                durable_input[mismatch] = json!(format!("forged-{mismatch}"));
            }
            let store_bytes_before = downgrade_store_to_v15(&config);
            let submitted_at_ms = system_now_ms().unwrap();
            let mut journal = OperationJournal::open(&config).unwrap();
            let operation_id = journal
                .submit(
                    &SubmitRequest::new(
                        &config,
                        OperationKind::RuntimeTraceImportSubmit,
                        &durable_input,
                        format!("runtime-v15-binding-mismatch-{mismatch}").as_bytes(),
                        submitted_at_ms + 10_000,
                    )
                    .unwrap(),
                    submitted_at_ms,
                )
                .unwrap()
                .operation_id()
                .clone();
            drop(journal);

            let report = OperationRunner::new(
                RunnerStartupConfig::new(config.clone()).unwrap(),
                ScanOperationDispatcher::new(config.clone()),
            )
            .run_until_idle()
            .unwrap();
            assert_eq!(report.failed(), 1, "{mismatch}");
            match OperationJournal::open(&config)
                .unwrap()
                .result(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap()
            {
                OperationOutcome::Failed(error) => {
                    let value: serde_json::Value = serde_json::from_str(error.as_str()).unwrap();
                    assert_eq!(value["error"]["code"], "CONFLICT", "{mismatch}");
                }
                outcome => {
                    panic!("unexpected binding mismatch outcome for {mismatch}: {outcome:?}")
                }
            }
            assert_eq!(
                std::fs::read(config.store_path()).unwrap(),
                store_bytes_before,
                "{mismatch}"
            );
            let store = rusqlite::Connection::open_with_flags(
                config.store_path(),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .unwrap();
            assert_eq!(
                store
                    .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                15,
                "{mismatch}"
            );
        }
    }

    #[test]
    fn legacy_runtime_completion_intent_recovers_after_crash_and_unblocks_queued_work() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let (base_snapshot_id, trace, durable_input) =
            runtime_import_fixture(&config, "runtime-completion-crash");
        let legacy_input = legacy_runtime_import_input(durable_input);
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 10_000;
        let lease_token = b"runtime-completion-intent-crash-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &legacy_input,
                    b"recover-committed-runtime-completion",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        let subsequent_operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &legacy_input,
                    b"runtime-work-queued-behind-completion",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("crashing-runtime-completion-runner").unwrap(),
                lease_token,
                submitted_at_ms + 1,
                deadline_ms,
            )
            .unwrap();

        let service = DepgraphService::new(config.clone());
        let prepared = service
            .prepare_runtime_import(
                &RuntimeValidateRequest {
                    trace: Some(trace),
                    trace_file: None,
                    snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                        base_snapshot_id,
                    )),
                },
                &CancellationToken::new(),
            )
            .unwrap();
        let completion = match service
            .runtime_import_deferred_prepared(
                prepared,
                operation_id.as_str(),
                &CancellationToken::new(),
            )
            .unwrap()
        {
            DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
            DeferredRuntimeImportServiceOutcome::Finished(_) => {
                panic!("runtime import did not defer completion")
            }
        };
        let expected_snapshot = completion
            .outcome()
            .completed_snapshot_id()
            .as_str()
            .to_owned();
        let dispatcher = ScanOperationDispatcher::new(config.clone());
        let result = dispatcher
            .completed_runtime_output(completion.outcome())
            .ok()
            .unwrap();
        assert_eq!(
            journal
                .commit_completion_intent(
                    &repository,
                    &operation_id,
                    lease_token,
                    result,
                    system_now_ms().unwrap(),
                )
                .unwrap(),
            CompletionDecision::Committed
        );
        drop(completion);
        drop(journal);

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();

        assert_eq!(report.claimed(), 1);
        assert_eq!(report.completed(), 2);
        let reopened_journal = OperationJournal::open(&config).unwrap();
        for completed_operation in [&operation_id, &subsequent_operation_id] {
            assert!(matches!(
                reopened_journal
                    .result(&repository, completed_operation, system_now_ms().unwrap(),)
                    .unwrap(),
                OperationOutcome::Completed(_)
            ));
        }
        assert_eq!(
            depgraph_core::open_store_read_only(config.store_path())
                .unwrap()
                .current_snapshot_id()
                .unwrap()
                .as_deref(),
            Some(expected_snapshot.as_str())
        );
    }

    #[test]
    fn committed_runtime_completion_recovers_v15_staging_through_exact_legacy_owner() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let (base_snapshot_id, trace, durable_input) =
            runtime_import_fixture(&config, "runtime-v15-completion-recovery");
        let legacy_input = legacy_runtime_import_input(durable_input);
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 10_000;
        let lease_token = b"runtime-v15-completion-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &legacy_input,
                    b"runtime-v15-completion-recovery",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("v15-runtime-completion-runner").unwrap(),
                lease_token,
                submitted_at_ms + 1,
                deadline_ms,
            )
            .unwrap();

        let service = DepgraphService::new(config.clone());
        let completion = match service
            .runtime_import_deferred_prepared(
                service
                    .prepare_runtime_import(
                        &RuntimeValidateRequest {
                            trace: Some(trace),
                            trace_file: None,
                            snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                                base_snapshot_id,
                            )),
                        },
                        &CancellationToken::new(),
                    )
                    .unwrap(),
                operation_id.as_str(),
                &CancellationToken::new(),
            )
            .unwrap()
        {
            DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
            DeferredRuntimeImportServiceOutcome::Finished(_) => {
                panic!("runtime import did not leave v15 recovery staging")
            }
        };
        let expected_snapshot = completion
            .outcome()
            .completed_snapshot_id()
            .as_str()
            .to_owned();
        let result = ScanOperationDispatcher::new(config.clone())
            .completed_runtime_output(completion.outcome())
            .ok()
            .unwrap();
        assert_eq!(
            journal
                .commit_completion_intent(
                    &repository,
                    &operation_id,
                    lease_token,
                    result,
                    system_now_ms().unwrap(),
                )
                .unwrap(),
            CompletionDecision::Committed
        );
        drop(completion);
        drop(journal);

        let connection = rusqlite::Connection::open(config.store_path()).unwrap();
        connection
            .execute_batch(
                "DROP TABLE scan_operation_staging;
                 DROP TABLE runtime_import_operation_owners;
                 PRAGMA user_version=15;",
            )
            .unwrap();
        drop(connection);

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();
        assert_eq!(report.completed(), 1);
        assert!(matches!(
            OperationJournal::open(&config)
                .unwrap()
                .result(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Completed(_)
        ));
        let store = depgraph_core::open_store_read_only(config.store_path()).unwrap();
        assert_eq!(store.schema_version().unwrap(), 17);
        assert_eq!(
            store.current_snapshot_id().unwrap().as_deref(),
            Some(expected_snapshot.as_str())
        );
    }

    #[test]
    fn runtime_completion_recovery_rejects_envelope_identity_tampering_before_promotion() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let (base_snapshot_id, trace, durable_input) =
            runtime_import_fixture(&config, "runtime-envelope-recovery");
        let legacy_input = legacy_runtime_import_input(durable_input);
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 10_000;
        let lease_token = b"runtime-envelope-recovery-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &legacy_input,
                    b"runtime-envelope-recovery",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("runtime-envelope-recovery-runner").unwrap(),
                lease_token,
                submitted_at_ms + 1,
                deadline_ms,
            )
            .unwrap();

        let service = DepgraphService::new(config.clone());
        let completion = match service
            .runtime_import_deferred_prepared(
                service
                    .prepare_runtime_import(
                        &RuntimeValidateRequest {
                            trace: Some(trace),
                            trace_file: None,
                            snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                                base_snapshot_id,
                            )),
                        },
                        &CancellationToken::new(),
                    )
                    .unwrap(),
                operation_id.as_str(),
                &CancellationToken::new(),
            )
            .unwrap()
        {
            DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
            DeferredRuntimeImportServiceOutcome::Finished(_) => {
                panic!("runtime import did not leave envelope recovery staging")
            }
        };
        let import_id = completion.outcome().result().import_id.clone();
        let session_id = completion.outcome().result().session_id.clone();
        let valid_result = ScanOperationDispatcher::new(config.clone())
            .completed_runtime_output(completion.outcome())
            .ok()
            .unwrap();
        journal
            .commit_completion_intent(
                &repository,
                &operation_id,
                lease_token,
                valid_result.clone(),
                system_now_ms().unwrap(),
            )
            .unwrap();
        drop(completion);

        let valid_value = valid_result.value().clone();
        let invalid_snapshot =
            "snapshot:sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let mut tampered_values = Vec::new();
        let mut invalid_contract = valid_value.clone();
        invalid_contract["contract_version"] = json!("depgraph-mcp-tools-v2");
        tampered_values.push(invalid_contract);
        let mut wrong_repository = valid_value.clone();
        wrong_repository["repository_id"] = json!("repo:other");
        tampered_values.push(wrong_repository);
        let mut wrong_envelope_snapshot = valid_value.clone();
        wrong_envelope_snapshot["snapshot_id"] = json!(invalid_snapshot);
        tampered_values.push(wrong_envelope_snapshot);
        let mut wrong_result_snapshot = valid_value.clone();
        wrong_result_snapshot["result"]["snapshot_id"] = json!(invalid_snapshot);
        tampered_values.push(wrong_result_snapshot);

        let mut dispatcher = ScanOperationDispatcher::new(config.clone());
        let replace_intent_result = |value| {
            let encoded = CanonicalJson::new(value).unwrap();
            let digest = JournalDigest::sha256(encoded.as_str());
            rusqlite::Connection::open(journal.path())
                .unwrap()
                .execute(
                    "UPDATE operation_completion_intents
                        SET result_json=?1, result_digest=?2
                      WHERE operation_id=?3",
                    rusqlite::params![
                        encoded.as_str(),
                        digest.as_bytes().as_slice(),
                        operation_id.as_str(),
                    ],
                )
                .unwrap();
        };
        for tampered in tampered_values {
            replace_intent_result(tampered);
            let intent = journal
                .next_completion_intent(&repository, system_now_ms().unwrap())
                .unwrap()
                .unwrap();
            assert!(matches!(
                dispatcher.recover_completion(&intent),
                Err(RunnerError::Journal(JournalError::IntegrityFailure))
            ));
            assert_eq!(
                rusqlite::Connection::open(config.store_path())
                    .unwrap()
                    .query_row(
                        "SELECT status FROM runtime_imports WHERE id=?1",
                        [&import_id],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap(),
                "staging"
            );
        }

        for (field, forged) in [
            ("session_id", "runtime-session:forged"),
            ("import_id", "runtime-import:forged"),
        ] {
            let mut tampered = valid_value.clone();
            tampered["result"][field] = json!(forged);
            replace_intent_result(tampered);
            let intent = journal
                .next_completion_intent(&repository, system_now_ms().unwrap())
                .unwrap()
                .unwrap();
            assert!(matches!(
                dispatcher.recover_completion(&intent),
                Err(RunnerError::Service(
                    DepgraphServiceError::StoreOperation { .. }
                ))
            ));
            assert_eq!(
                rusqlite::Connection::open(config.store_path())
                    .unwrap()
                    .query_row(
                        "SELECT status FROM runtime_imports WHERE id=?1",
                        [&import_id],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap(),
                "staging"
            );
        }

        replace_intent_result(valid_value);
        rusqlite::Connection::open(config.store_path())
            .unwrap()
            .execute(
                "UPDATE runtime_sessions SET trace_digest=?1 WHERE id=?2",
                rusqlite::params!["runtime-trace:sha256:forged", session_id],
            )
            .unwrap();
        let intent = journal
            .next_completion_intent(&repository, system_now_ms().unwrap())
            .unwrap()
            .unwrap();
        assert!(matches!(
            dispatcher.recover_completion(&intent),
            Err(RunnerError::Service(
                DepgraphServiceError::StoreOperation { .. }
            ))
        ));
        assert_eq!(
            rusqlite::Connection::open(config.store_path())
                .unwrap()
                .query_row(
                    "SELECT status FROM runtime_imports WHERE id=?1",
                    [&import_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "staging"
        );
    }

    #[test]
    fn runtime_completion_intent_cannot_promote_another_operations_staging_import() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let (base_snapshot_id, trace, durable_input) =
            runtime_import_fixture(&config, "runtime-cross-operation-recovery");
        let legacy_input = legacy_runtime_import_input(durable_input.clone());
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 10_000;
        let lease_a = b"runtime-cross-operation-a-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_a = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &legacy_input,
                    b"runtime-cross-operation-a",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        let operation_b = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &durable_input,
                    b"runtime-cross-operation-b",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_a,
                &LeaseOwner::parse("cross-operation-intent-a").unwrap(),
                lease_a,
                submitted_at_ms + 1,
                deadline_ms,
            )
            .unwrap();

        let service = DepgraphService::new(config.clone());
        let completion_b = match service
            .runtime_import_deferred_prepared(
                service
                    .prepare_runtime_import(
                        &RuntimeValidateRequest {
                            trace: Some(trace),
                            trace_file: None,
                            snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                                base_snapshot_id.clone(),
                            )),
                        },
                        &CancellationToken::new(),
                    )
                    .unwrap(),
                operation_b.as_str(),
                &CancellationToken::new(),
            )
            .unwrap()
        {
            DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
            DeferredRuntimeImportServiceOutcome::Finished(_) => {
                panic!("operation B did not stage its runtime import")
            }
        };
        let import_id = completion_b.outcome().result().import_id.clone();
        let expected_snapshot = completion_b
            .outcome()
            .completed_snapshot_id()
            .as_str()
            .to_owned();
        let forged_for_a = ScanOperationDispatcher::new(config.clone())
            .completed_runtime_output(completion_b.outcome())
            .ok()
            .unwrap();
        assert_eq!(
            journal
                .commit_completion_intent(
                    &repository,
                    &operation_a,
                    lease_a,
                    forged_for_a,
                    system_now_ms().unwrap(),
                )
                .unwrap(),
            CompletionDecision::Committed
        );
        drop(completion_b);
        drop(journal);

        let error = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap_err();
        assert!(matches!(
            error,
            RunnerError::Service(DepgraphServiceError::StoreOperation { .. })
        ));

        let journal = OperationJournal::open(&config).unwrap();
        assert_eq!(
            journal
                .get(&repository, &operation_a, system_now_ms().unwrap())
                .unwrap()
                .status(),
            OperationStatus::Running
        );
        assert_eq!(
            journal
                .next_completion_intent(&repository, system_now_ms().unwrap())
                .unwrap()
                .unwrap()
                .operation_id(),
            &operation_a
        );
        let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            evidence
                .query_row(
                    "SELECT status FROM runtime_imports WHERE id=?1",
                    [&import_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "staging"
        );
        assert_eq!(
            evidence
                .query_row(
                    "SELECT operation_id FROM runtime_import_operation_owners
                      WHERE import_id=?1",
                    [&import_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            operation_b.as_str()
        );
        assert_eq!(
            evidence
                .query_row(
                    "SELECT COUNT(*) FROM completed_snapshots WHERE id=?1",
                    [&expected_snapshot],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            evidence
                .query_row(
                    "SELECT snapshot_id FROM current_completed_snapshot WHERE singleton=1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            base_snapshot_id
        );
    }

    #[test]
    fn operation_owned_runtime_stage_survives_other_operation_cleanup_and_recovers() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let (base_snapshot_id, trace, durable_input) =
            runtime_import_fixture(&config, "runtime-shared-operation-stage");
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 10_000;
        let lease_a = b"runtime-shared-stage-a-token";
        let lease_b = b"runtime-shared-stage-b-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_a = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &durable_input,
                    b"runtime-shared-stage-a",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        let operation_b = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::RuntimeTraceImportSubmit,
                    &durable_input,
                    b"runtime-shared-stage-b",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        assert_ne!(operation_a, operation_b);
        journal
            .acquire_lease(
                &repository,
                &operation_a,
                &LeaseOwner::parse("crashing-shared-stage-a").unwrap(),
                lease_a,
                submitted_at_ms + 1,
                deadline_ms,
            )
            .unwrap();
        journal
            .acquire_lease(
                &repository,
                &operation_b,
                &LeaseOwner::parse("cancelling-shared-stage-b").unwrap(),
                lease_b,
                submitted_at_ms + 1,
                deadline_ms,
            )
            .unwrap();

        let service = DepgraphService::new(config.clone());
        let runtime_request = || RuntimeValidateRequest {
            trace: Some(trace.clone()),
            trace_file: None,
            snapshot: ServiceSnapshotSelector::Locator(SnapshotLocator::StableId(
                base_snapshot_id.clone(),
            )),
        };
        let completion_a = match service
            .runtime_import_deferred_prepared(
                service
                    .prepare_runtime_import(&runtime_request(), &CancellationToken::new())
                    .unwrap(),
                operation_a.as_str(),
                &CancellationToken::new(),
            )
            .unwrap()
        {
            DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
            DeferredRuntimeImportServiceOutcome::Finished(_) => {
                panic!("operation A did not stage its runtime import")
            }
        };
        let import_id = completion_a.outcome().result().import_id.clone();
        let session_id = completion_a.outcome().result().session_id.clone();
        let expected_snapshot = completion_a
            .outcome()
            .completed_snapshot_id()
            .as_str()
            .to_owned();
        let result_a = ScanOperationDispatcher::new(config.clone())
            .completed_runtime_output(completion_a.outcome())
            .ok()
            .unwrap();
        assert_eq!(
            journal
                .commit_completion_intent(
                    &repository,
                    &operation_a,
                    lease_a,
                    result_a,
                    system_now_ms().unwrap(),
                )
                .unwrap(),
            CompletionDecision::Committed
        );
        // Simulate the crash after A's completion decision but before store
        // promotion. Dropping releases only the process-local writer lock.
        drop(completion_a);

        let completion_b = match service
            .runtime_import_deferred_prepared(
                service
                    .prepare_runtime_import(&runtime_request(), &CancellationToken::new())
                    .unwrap(),
                operation_b.as_str(),
                &CancellationToken::new(),
            )
            .unwrap()
        {
            DeferredRuntimeImportServiceOutcome::Pending(completion) => completion,
            DeferredRuntimeImportServiceOutcome::Finished(_) => {
                panic!("operation B did not attach to A's staged runtime import")
            }
        };
        assert_eq!(completion_b.outcome().result().import_id, import_id);
        drop(completion_b);

        let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            evidence
                .query_row(
                    "SELECT COUNT(*) FROM runtime_import_operation_owners WHERE import_id=?1",
                    [&import_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            2
        );
        drop(evidence);

        assert_eq!(
            journal
                .cancel(
                    &repository,
                    &operation_b,
                    &CapabilitySet::new([
                        depgraph_mcp_tools::AgentCapability::Read,
                        depgraph_mcp_tools::AgentCapability::StoreWrite,
                    ])
                    .unwrap(),
                    system_now_ms().unwrap(),
                )
                .unwrap(),
            crate::CancelOutcome::Requested
        );
        let record_b = journal
            .get(&repository, &operation_b, system_now_ms().unwrap())
            .unwrap();
        let cleanup_guard = ScanOperationDispatcher::new(config.clone())
            .cleanup_abandoned(&RunnerWork {
                operation_id: operation_b.clone(),
                kind: OperationKind::RuntimeTraceImportSubmit,
                input: record_b.normalized_input().clone(),
                execution_deadline_ms: deadline_ms,
            })
            .unwrap();
        journal
            .mark_cancelled(&repository, &operation_b, lease_b, system_now_ms().unwrap())
            .unwrap();
        drop(cleanup_guard);

        let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            evidence
                .query_row(
                    "SELECT COUNT(*) FROM runtime_imports WHERE id=?1 AND status='staging'",
                    [&import_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            evidence
                .query_row(
                    "SELECT operation_id FROM runtime_import_operation_owners WHERE import_id=?1",
                    [&import_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            operation_a.as_str()
        );
        drop(evidence);
        drop(journal);

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();
        assert_eq!(report.claimed(), 0);
        assert_eq!(report.completed(), 1);
        assert!(matches!(
            OperationJournal::open(&config)
                .unwrap()
                .result(&repository, &operation_a, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Completed(_)
        ));
        assert!(matches!(
            OperationJournal::open(&config)
                .unwrap()
                .result(&repository, &operation_b, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Cancelled
        ));
        let evidence = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            evidence
                .query_row(
                    "SELECT COUNT(*) FROM runtime_import_operation_owners WHERE import_id=?1",
                    [&import_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            evidence
                .query_row(
                    "SELECT COUNT(*) FROM runtime_imports
                      WHERE id=?1 AND status='completed' AND result_snapshot_id=?2",
                    rusqlite::params![import_id, expected_snapshot],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            evidence
                .query_row(
                    "SELECT COUNT(*) FROM runtime_sessions WHERE id=?1",
                    [&session_id],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            depgraph_core::open_store_read_only(config.store_path())
                .unwrap()
                .current_snapshot_id()
                .unwrap()
                .as_deref(),
            Some(expected_snapshot.as_str())
        );
    }

    #[test]
    fn reclaimed_pre_intent_scan_attempt_completes_and_unblocks_the_queue() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 60_000;
        let expired_at_ms = submitted_at_ms + 50;
        let lease = b"pre-intent-scan-crash-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"pre-intent-scan-crash",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("pre-intent-crashing-runner").unwrap(),
                lease,
                submitted_at_ms + 1,
                expired_at_ms,
            )
            .unwrap();
        let queued_operation = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"queued-after-pre-intent-scan-crash",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms + 2,
            )
            .unwrap()
            .operation_id()
            .clone();

        let service = DepgraphService::new(config.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let abandoned = match runtime
            .block_on(service.scan_deferred_cancellable_for_operation(
                &ScanRequest::new(false, ScanCacheMode::Disabled),
                operation_id.as_str(),
                CancellationToken::new(),
            ))
            .unwrap()
        {
            DeferredScanServiceOutcome::Pending(completion) => completion,
            DeferredScanServiceOutcome::Finished(_) => panic!("scan did not leave staging"),
        };
        let abandoned_scan_id = abandoned.outcome().outcome().scan_id.clone();
        drop(abandoned);
        drop(journal);
        while system_now_ms().unwrap() <= expired_at_ms {
            std::thread::yield_now();
        }

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();

        assert_eq!(report.claimed(), 2);
        assert_eq!(report.completed(), 2);
        let journal = OperationJournal::open(&config).unwrap();
        for operation in [&operation_id, &queued_operation] {
            assert!(matches!(
                journal
                    .result(&repository, operation, system_now_ms().unwrap())
                    .unwrap(),
                OperationOutcome::Completed(_)
            ));
        }
        let store = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            store
                .query_row(
                    "SELECT status FROM scans WHERE id=?1",
                    [&abandoned_scan_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "cancelled"
        );
        let completed_scan_id: String = store
            .query_row(
                "SELECT scan_id FROM scan_operation_staging WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_ne!(completed_scan_id, abandoned_scan_id);
    }

    #[test]
    fn failed_first_scan_attempt_cleans_operation_owned_staging_and_unblocks_the_queue() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 60_000;
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": "invalid"}),
                    b"first-scan-attempt-fails-after-stage",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        let queued_operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"queued-after-first-scan-failure",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms + 1,
            )
            .unwrap()
            .operation_id()
            .clone();

        let service = DepgraphService::new(config.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let staged = match runtime
            .block_on(service.scan_deferred_cancellable_for_operation(
                &ScanRequest::new(false, ScanCacheMode::Disabled),
                operation_id.as_str(),
                CancellationToken::new(),
            ))
            .unwrap()
        {
            DeferredScanServiceOutcome::Pending(completion) => completion,
            DeferredScanServiceOutcome::Finished(_) => panic!("scan did not leave staging"),
        };
        let staged_scan_id = staged.outcome().outcome().scan_id.clone();
        drop(staged);
        drop(journal);

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();
        assert_eq!(report.claimed(), 2);
        assert_eq!(report.failed(), 1);
        assert_eq!(report.completed(), 1);
        let journal = OperationJournal::open(&config).unwrap();
        assert!(matches!(
            journal
                .result(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Failed(_)
        ));
        assert!(matches!(
            journal
                .result(&repository, &queued_operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Completed(_)
        ));
        let store = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            store
                .query_row(
                    "SELECT status FROM scans WHERE id=?1",
                    [&staged_scan_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "cancelled"
        );
        assert_eq!(
            store
                .query_row(
                    "SELECT COUNT(*) FROM scan_operation_staging WHERE operation_id=?1",
                    [operation_id.as_str()],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn expired_staged_scan_is_cleaned_before_deadline_failure_and_unblocks_the_queue() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 100;
        let queued_deadline_ms = submitted_at_ms + 60_000;
        let lease = b"expired-staged-scan-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"expired-staged-scan",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("expired-staged-scan-runner").unwrap(),
                lease,
                submitted_at_ms + 1,
                deadline_ms,
            )
            .unwrap();
        let queued_operation = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"queued-after-expired-staged-scan",
                    queued_deadline_ms,
                )
                .unwrap(),
                submitted_at_ms + 2,
            )
            .unwrap()
            .operation_id()
            .clone();

        let service = DepgraphService::new(config.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let staged = match runtime
            .block_on(service.scan_deferred_cancellable_for_operation(
                &ScanRequest::new(false, ScanCacheMode::Disabled),
                operation_id.as_str(),
                CancellationToken::new(),
            ))
            .unwrap()
        {
            DeferredScanServiceOutcome::Pending(completion) => completion,
            DeferredScanServiceOutcome::Finished(_) => panic!("scan did not leave staging"),
        };
        let staged_scan_id = staged.outcome().outcome().scan_id.clone();
        drop(staged);
        drop(journal);
        while system_now_ms().unwrap() <= deadline_ms {
            std::thread::yield_now();
        }

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();

        assert_eq!(report.failed(), 1);
        assert_eq!(report.completed(), 1);
        let journal = OperationJournal::open(&config).unwrap();
        assert!(matches!(
            journal
                .result(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Failed(_)
        ));
        assert!(matches!(
            journal
                .result(&repository, &queued_operation, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Completed(_)
        ));
        let store = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            store
                .query_row(
                    "SELECT status FROM scans WHERE id=?1",
                    [&staged_scan_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "cancelled"
        );
        assert_eq!(
            store
                .query_row(
                    "SELECT COUNT(*) FROM scan_operation_staging WHERE operation_id=?1",
                    [operation_id.as_str()],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn cancelled_scan_store_commit_retries_before_journal_terminal_and_unblocks_queue() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 60_000;
        let expired_at_ms = submitted_at_ms + 50;
        let lease = b"scan-cancel-store-first-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"scan-cancel-store-first",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("scan-cancel-store-first-runner").unwrap(),
                lease,
                submitted_at_ms + 1,
                expired_at_ms,
            )
            .unwrap();
        let queued_operation = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"queued-after-scan-cancel-store-first",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms + 2,
            )
            .unwrap()
            .operation_id()
            .clone();
        let service = DepgraphService::new(config.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let staged = match runtime
            .block_on(service.scan_deferred_cancellable_for_operation(
                &ScanRequest::new(false, ScanCacheMode::Disabled),
                operation_id.as_str(),
                CancellationToken::new(),
            ))
            .unwrap()
        {
            DeferredScanServiceOutcome::Pending(completion) => completion,
            DeferredScanServiceOutcome::Finished(_) => panic!("scan did not leave staging"),
        };
        let scan_id = staged.outcome().outcome().scan_id.clone();
        drop(staged);
        journal
            .cancel(
                &repository,
                &operation_id,
                &cancellable_capabilities(),
                submitted_at_ms + 3,
            )
            .unwrap();
        drop(
            service
                .cancel_deferred_scan_for_operation(operation_id.as_str())
                .unwrap(),
        );
        assert_eq!(
            rusqlite::Connection::open(config.store_path())
                .unwrap()
                .query_row(
                    "SELECT scan.status FROM scan_operation_staging owner
                     JOIN scans scan ON scan.id=owner.scan_id
                     WHERE owner.operation_id=?1",
                    [operation_id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "cancelled"
        );
        drop(journal);
        while system_now_ms().unwrap() <= expired_at_ms {
            std::thread::yield_now();
        }

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();
        assert_eq!(report.cancelled(), 1);
        assert_eq!(report.completed(), 1);
        let journal = OperationJournal::open(&config).unwrap();
        assert!(matches!(
            journal
                .result(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Cancelled
        ));
        assert!(matches!(
            journal
                .result(&repository, &queued_operation, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Completed(_)
        ));
        let store = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            store
                .query_row(
                    "SELECT COUNT(*) FROM scan_operation_staging WHERE operation_id=?1",
                    [operation_id.as_str()],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .query_row("SELECT status FROM scans WHERE id=?1", [&scan_id], |row| {
                    row.get::<_, String>(0)
                })
                .unwrap(),
            "cancelled"
        );
    }

    #[test]
    fn terminal_journal_scan_cancellation_recovers_unacknowledged_store_proof() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 60_000;
        let lease = b"scan-cancel-journal-first-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"scan-cancel-journal-first",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("scan-cancel-journal-first-runner").unwrap(),
                lease,
                submitted_at_ms + 1,
                deadline_ms,
            )
            .unwrap();
        let service = DepgraphService::new(config.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let staged = match runtime
            .block_on(service.scan_deferred_cancellable_for_operation(
                &ScanRequest::new(false, ScanCacheMode::Disabled),
                operation_id.as_str(),
                CancellationToken::new(),
            ))
            .unwrap()
        {
            DeferredScanServiceOutcome::Pending(completion) => completion,
            DeferredScanServiceOutcome::Finished(_) => panic!("scan did not leave staging"),
        };
        drop(staged);
        journal
            .cancel(
                &repository,
                &operation_id,
                &cancellable_capabilities(),
                submitted_at_ms + 2,
            )
            .unwrap();
        drop(
            service
                .cancel_deferred_scan_for_operation(operation_id.as_str())
                .unwrap(),
        );
        journal
            .mark_cancelled(&repository, &operation_id, lease, submitted_at_ms + 3)
            .unwrap();
        assert_eq!(
            rusqlite::Connection::open(config.store_path())
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM scan_operation_staging WHERE operation_id=?1",
                    [operation_id.as_str()],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            1
        );
        drop(journal);

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();
        assert_eq!(report.claimed(), 0);
        assert_eq!(
            rusqlite::Connection::open(config.store_path())
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM scan_operation_staging WHERE operation_id=?1",
                    [operation_id.as_str()],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn p1c_concurrent_purge_cannot_delete_unacknowledged_external_store_terminal_row() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let reference_ms = system_now_ms().unwrap();
        let terminal_at_ms = reference_ms - TERMINAL_RETENTION_MS - 10_000;
        let submitted_at_ms = terminal_at_ms - 3;
        let deadline_ms = terminal_at_ms + 1;
        let lease = b"p1c-unacknowledged-cleanup-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"p1c-unacknowledged-cleanup",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("p1c-unacknowledged-cleanup-runner").unwrap(),
                lease,
                terminal_at_ms - 1,
                deadline_ms,
            )
            .unwrap();
        journal
            .cancel(
                &repository,
                &operation_id,
                &cancellable_capabilities(),
                terminal_at_ms,
            )
            .unwrap();

        let service = DepgraphService::new(config.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let staged = match runtime
            .block_on(service.scan_deferred_cancellable_for_operation(
                &ScanRequest::new(false, ScanCacheMode::Disabled),
                operation_id.as_str(),
                CancellationToken::new(),
            ))
            .unwrap()
        {
            DeferredScanServiceOutcome::Pending(completion) => completion,
            DeferredScanServiceOutcome::Finished(_) => panic!("scan did not leave staging"),
        };
        drop(staged);

        let queued_at_ms = system_now_ms().unwrap();
        let queued_operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"queued-after-p1c-purge-race",
                    queued_at_ms + 60_000,
                )
                .unwrap(),
                queued_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        drop(journal);

        let (terminal_committed, wait_for_terminal) = mpsc::sync_channel(0);
        let (release_acknowledgement, wait_for_acknowledgement) = mpsc::sync_channel(0);
        let runner = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .with_cleanup_acknowledgement_barrier_for_test(
            terminal_committed,
            wait_for_acknowledgement,
        );
        let runner_thread = std::thread::spawn(move || runner.run_until_idle());

        wait_for_terminal
            .recv_timeout(Duration::from_secs(5))
            .expect("terminal journal transition signal");
        let store = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            store
                .query_row(
                    "SELECT COUNT(*) FROM scan_operation_staging WHERE operation_id=?1",
                    [operation_id.as_str()],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            1
        );
        let mut competing_journal = OperationJournal::open(&config).unwrap();
        assert_eq!(
            rusqlite::Connection::open(competing_journal.path())
                .unwrap()
                .query_row(
                    "SELECT status FROM operations WHERE operation_id=?1",
                    [operation_id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            OperationStatus::Failed.as_str()
        );
        let competing_purge = competing_journal.purge(system_now_ms().unwrap()).unwrap();
        assert_eq!(competing_purge.purged_operations(), 0);
        assert!(competing_purge.more_work());
        assert_eq!(
            rusqlite::Connection::open(competing_journal.path())
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM operations WHERE operation_id=?1",
                    [operation_id.as_str()],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            1
        );
        drop(competing_journal);
        release_acknowledgement.send(()).unwrap();

        let report = runner_thread.join().unwrap().unwrap();
        assert_eq!(report.failed(), 1);
        assert_eq!(report.completed(), 1);
        assert_eq!(
            store
                .query_row(
                    "SELECT COUNT(*) FROM scan_operation_staging WHERE operation_id=?1",
                    [operation_id.as_str()],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
        assert!(matches!(
            OperationJournal::open(&config).unwrap().result(
                &repository,
                &queued_operation_id,
                system_now_ms().unwrap(),
            ),
            Ok(OperationOutcome::Completed(_))
        ));
    }

    #[test]
    fn expired_scan_cleanup_pages_are_reconciled_before_purge_and_unblock_queue() {
        const CLEANUP_PROOF_COUNT: usize = 65;

        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let reconciliation_reference_ms = system_now_ms().unwrap();
        let terminal_at_ms = reconciliation_reference_ms - TERMINAL_RETENTION_MS - 10_000;
        let submitted_at_ms = terminal_at_ms - 3;
        let deadline_ms = terminal_at_ms + 1;
        let lease_owner = LeaseOwner::parse("expired-scan-cleanup-runner").unwrap();
        let lease_token = b"expired-scan-cleanup-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let service = DepgraphService::new(config.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut cleanup_operation_ids = Vec::with_capacity(CLEANUP_PROOF_COUNT);

        for index in 0..CLEANUP_PROOF_COUNT {
            let idempotency_key = format!("expired-scan-cleanup-{index}");
            let operation_id = journal
                .submit(
                    &SubmitRequest::new(
                        &config,
                        OperationKind::ScanSubmit,
                        &json!({"strict": false, "no_cache": true}),
                        idempotency_key.as_bytes(),
                        deadline_ms,
                    )
                    .unwrap(),
                    submitted_at_ms,
                )
                .unwrap()
                .operation_id()
                .clone();
            journal
                .acquire_lease(
                    &repository,
                    &operation_id,
                    &lease_owner,
                    lease_token,
                    terminal_at_ms - 2,
                    deadline_ms,
                )
                .unwrap();
            let staged = match runtime
                .block_on(service.scan_deferred_cancellable_for_operation(
                    &ScanRequest::new(false, ScanCacheMode::Disabled),
                    operation_id.as_str(),
                    CancellationToken::new(),
                ))
                .unwrap()
            {
                DeferredScanServiceOutcome::Pending(completion) => completion,
                DeferredScanServiceOutcome::Finished(_) => panic!("scan did not leave staging"),
            };
            drop(staged);
            journal
                .cancel(
                    &repository,
                    &operation_id,
                    &cancellable_capabilities(),
                    terminal_at_ms - 1,
                )
                .unwrap();
            drop(
                service
                    .cancel_deferred_scan_for_operation(operation_id.as_str())
                    .unwrap(),
            );
            journal
                .mark_cancelled(&repository, &operation_id, lease_token, terminal_at_ms)
                .unwrap();
            cleanup_operation_ids.push(operation_id);
        }

        assert!(cleanup_operation_ids.iter().all(|operation_id| {
            matches!(
                journal.result(&repository, operation_id, reconciliation_reference_ms),
                Err(JournalError::Expired)
            )
        }));
        let first_cleanup_page = service.pending_deferred_scan_cancellations(None).unwrap();
        assert_eq!(first_cleanup_page.operation_ids().len(), 64);
        assert!(first_cleanup_page.more_work());
        assert_eq!(
            service
                .pending_deferred_scan_cancellations(first_cleanup_page.next_after_operation_id())
                .unwrap()
                .operation_ids()
                .len(),
            1
        );

        let queued_at_ms = system_now_ms().unwrap();
        let queued_operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"queued-after-expired-scan-cleanup-pages",
                    queued_at_ms + 60_000,
                )
                .unwrap(),
                queued_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        drop(journal);

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();

        assert_eq!(report.claimed(), 1);
        assert_eq!(report.completed(), 1);
        assert!(matches!(
            OperationJournal::open(&config)
                .unwrap()
                .result(&repository, &queued_operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Completed(_)
        ));
        assert!(
            service
                .pending_deferred_scan_cancellations(None)
                .unwrap()
                .operation_ids()
                .is_empty()
        );
    }

    #[test]
    fn finalized_scan_intent_recovers_after_retention_and_unblocks_queued_work() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let recovery_reference_ms = system_now_ms().unwrap();
        let decided_at_ms = recovery_reference_ms - TERMINAL_RETENTION_MS - 10_000;
        let submitted_at_ms = decided_at_ms - 1_000;
        let deadline_ms = decided_at_ms + 1_000;
        let lease_token = b"completion-intent-crash-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let submitted = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"recover-committed-scan-completion",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap();
        let operation_id = submitted.operation_id().clone();
        let original_retain_until_ms = submitted.record().retain_until_ms();
        assert!(original_retain_until_ms < recovery_reference_ms);
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("crashing-completion-runner").unwrap(),
                lease_token,
                decided_at_ms - 1,
                deadline_ms,
            )
            .unwrap();

        let service = DepgraphService::new(config.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut completion = match runtime
            .block_on(service.scan_deferred_cancellable_for_operation(
                &ScanRequest::new(false, ScanCacheMode::Disabled),
                operation_id.as_str(),
                CancellationToken::new(),
            ))
            .unwrap()
        {
            DeferredScanServiceOutcome::Pending(completion) => completion,
            DeferredScanServiceOutcome::Finished(_) => panic!("scan did not defer completion"),
        };
        let expected_snapshot = completion
            .outcome()
            .completed_snapshot_id()
            .unwrap()
            .as_str()
            .to_owned();
        let dispatcher = ScanOperationDispatcher::new(config.clone());
        let result = dispatcher
            .completed_output(completion.outcome())
            .ok()
            .unwrap();
        completion
            .bind_recovery_result_digest(
                JournalDigest::sha256(result.as_str().as_bytes()).as_bytes(),
            )
            .unwrap();
        assert_eq!(
            journal
                .commit_completion_intent(
                    &repository,
                    &operation_id,
                    lease_token,
                    result,
                    decided_at_ms,
                )
                .unwrap(),
            CompletionDecision::Committed
        );
        completion.promote().unwrap();
        assert_eq!(
            service
                .start_snapshot_request("current")
                .unwrap()
                .snapshot_id()
                .as_str(),
            expected_snapshot
        );

        let queued_at_ms = system_now_ms().unwrap();
        let queued_operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"queued-behind-expired-completion-intent",
                    queued_at_ms + 60_000,
                )
                .unwrap(),
                queued_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        drop(journal);

        let recovery_started_ms = system_now_ms().unwrap();
        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();

        assert_eq!(report.claimed(), 1);
        assert_eq!(report.completed(), 2);
        let reopened = OperationJournal::open(&config).unwrap();
        let recovered = reopened
            .get(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap();
        assert_eq!(recovered.status(), OperationStatus::Completed);
        assert_eq!(recovered.updated_at_ms(), decided_at_ms);
        assert_eq!(recovered.terminal_at_ms(), Some(decided_at_ms));
        assert!(
            recovered.retain_until_ms() >= recovery_started_ms + TERMINAL_RETENTION_MS,
            "recovered completion must remain observable for a full terminal retention window"
        );
        assert!(matches!(
            reopened
                .result(&repository, &queued_operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Completed(_)
        ));
        assert!(
            reopened
                .next_completion_intent(&repository, system_now_ms().unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn legacy_scan_intent_without_operation_staging_binding_keeps_retry_evidence() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 10_000;
        let lease = b"legacy-unbound-scan-intent-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"legacy-unbound-scan-intent",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("legacy-unbound-scan-runner").unwrap(),
                lease,
                submitted_at_ms + 1,
                deadline_ms,
            )
            .unwrap();
        let service = DepgraphService::new(config.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let completion = match runtime
            .block_on(service.scan_deferred_cancellable(
                &ScanRequest::new(false, ScanCacheMode::Disabled),
                CancellationToken::new(),
            ))
            .unwrap()
        {
            DeferredScanServiceOutcome::Pending(completion) => completion,
            DeferredScanServiceOutcome::Finished(_) => panic!("scan did not defer completion"),
        };
        let scan_id = completion.outcome().outcome().scan_id.clone();
        let result = ScanOperationDispatcher::new(config.clone())
            .completed_output(completion.outcome())
            .unwrap();
        journal
            .commit_completion_intent(
                &repository,
                &operation_id,
                lease,
                result,
                submitted_at_ms + 2,
            )
            .unwrap();
        drop(completion);
        drop(journal);

        let error = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap_err();
        assert!(matches!(
            error,
            RunnerError::Service(DepgraphServiceError::StoreOperation { .. })
        ));
        let journal = OperationJournal::open(&config).unwrap();
        assert_eq!(
            journal
                .get(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap()
                .status(),
            OperationStatus::Running
        );
        assert_eq!(
            journal
                .next_completion_intent(&repository, system_now_ms().unwrap())
                .unwrap()
                .unwrap()
                .operation_id(),
            &operation_id
        );
        assert_eq!(
            rusqlite::Connection::open(config.store_path())
                .unwrap()
                .query_row("SELECT status FROM scans WHERE id=?1", [&scan_id], |row| {
                    row.get::<_, String>(0)
                },)
                .unwrap(),
            "staging"
        );
    }

    #[test]
    fn p1a_genuine_v15_v16_scan_completion_intent_adopts_legacy_staging() {
        for legacy_version in [15_i64, 16_i64] {
            let root = tempfile::tempdir().unwrap();
            let config = config(root.path());
            let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
            let submitted_at_ms = system_now_ms().unwrap();
            let deadline_ms = submitted_at_ms + 10_000;
            let lease = b"legacy-scan-completion-token";
            let mut journal = OperationJournal::open(&config).unwrap();
            let operation_id = journal
                .submit(
                    &SubmitRequest::new(
                        &config,
                        OperationKind::ScanSubmit,
                        &json!({"strict": false, "no_cache": true}),
                        format!("legacy-scan-completion-v{legacy_version}").as_bytes(),
                        deadline_ms,
                    )
                    .unwrap(),
                    submitted_at_ms,
                )
                .unwrap()
                .operation_id()
                .clone();
            journal
                .acquire_lease(
                    &repository,
                    &operation_id,
                    &LeaseOwner::parse("legacy-scan-completion-runner").unwrap(),
                    lease,
                    submitted_at_ms + 1,
                    deadline_ms,
                )
                .unwrap();

            let service = DepgraphService::new(config.clone());
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            // This is the genuine pre-v17 path: the deferred scan UUID was
            // generated independently and no operation ownership row existed.
            let completion = match runtime
                .block_on(service.scan_deferred_cancellable(
                    &ScanRequest::new(false, ScanCacheMode::Disabled),
                    CancellationToken::new(),
                ))
                .unwrap()
            {
                DeferredScanServiceOutcome::Pending(completion) => completion,
                DeferredScanServiceOutcome::Finished(_) => panic!("scan did not defer completion"),
            };
            let scan_id = completion.outcome().outcome().scan_id.clone();
            assert_ne!(scan_id, operation_id.as_str());
            let expected_snapshot_id = completion
                .outcome()
                .completed_snapshot_id()
                .unwrap()
                .as_str()
                .to_owned();
            let result = ScanOperationDispatcher::new(config.clone())
                .completed_output(completion.outcome())
                .unwrap();
            assert_eq!(
                journal
                    .commit_completion_intent(
                        &repository,
                        &operation_id,
                        lease,
                        result,
                        submitted_at_ms + 2,
                    )
                    .unwrap(),
                CompletionDecision::Committed
            );
            drop(completion);
            drop(journal);

            let connection = rusqlite::Connection::open(config.store_path()).unwrap();
            let downgrade = if legacy_version == 15 {
                "DROP TABLE scan_operation_staging;
                 DROP TABLE runtime_import_operation_owners;
                 PRAGMA user_version=15;"
            } else {
                "DROP TABLE scan_operation_staging;
                 PRAGMA user_version=16;"
            };
            connection.execute_batch(downgrade).unwrap();
            drop(connection);

            let report = OperationRunner::new(
                RunnerStartupConfig::new(config.clone()).unwrap(),
                ScanOperationDispatcher::new(config.clone()),
            )
            .run_until_idle()
            .unwrap();
            assert_eq!(report.completed(), 1, "legacy schema v{legacy_version}");
            assert!(matches!(
                OperationJournal::open(&config).unwrap().result(
                    &repository,
                    &operation_id,
                    system_now_ms().unwrap(),
                ),
                Ok(OperationOutcome::Completed(_))
            ));
            let store = depgraph_core::open_store_read_only(config.store_path()).unwrap();
            assert_eq!(store.schema_version().unwrap(), 17);
            assert_eq!(
                store.current_snapshot_id().unwrap().as_deref(),
                Some(expected_snapshot_id.as_str()),
                "legacy schema v{legacy_version}"
            );
        }
    }

    #[test]
    fn p1a_runner_cancels_unclaimed_legacy_scan_staging_before_expiry_terminalization() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let reference_ms = system_now_ms().unwrap();
        let submitted_at_ms = reference_ms - 2_000;
        let deadline_ms = reference_ms - 1_000;
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"unclaimed-legacy-scan-staging",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();

        let service = DepgraphService::new(config.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let completion = match runtime
            .block_on(service.scan_deferred_cancellable(
                &ScanRequest::new(false, ScanCacheMode::Disabled),
                CancellationToken::new(),
            ))
            .unwrap()
        {
            DeferredScanServiceOutcome::Pending(completion) => completion,
            DeferredScanServiceOutcome::Finished(_) => panic!("scan did not defer completion"),
        };
        let scan_id = completion.outcome().outcome().scan_id.clone();
        assert_ne!(scan_id, operation_id.as_str());
        drop(completion);
        drop(journal);

        let connection = rusqlite::Connection::open(config.store_path()).unwrap();
        connection
            .execute_batch(
                "DROP TABLE scan_operation_staging;
                 PRAGMA user_version=16;",
            )
            .unwrap();
        drop(connection);

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();
        assert_eq!(report.failed(), 1);
        let journal = OperationJournal::open(&config).unwrap();
        assert_eq!(
            journal
                .get(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap()
                .status(),
            OperationStatus::Failed
        );
        let connection = rusqlite::Connection::open(config.store_path()).unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            17
        );
        assert_eq!(
            connection
                .query_row("SELECT status FROM scans WHERE id=?1", [&scan_id], |row| {
                    row.get::<_, String>(0)
                })
                .unwrap(),
            "cancelled"
        );
    }

    #[test]
    fn p1a_runner_drains_legacy_candidates_in_bounded_pages_before_unblocking_queue() {
        const LEGACY_CANDIDATE_COUNT: usize = 65;

        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let service = DepgraphService::new(config.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let completion = match runtime
            .block_on(service.scan_deferred_cancellable(
                &ScanRequest::new(false, ScanCacheMode::Disabled),
                CancellationToken::new(),
            ))
            .unwrap()
        {
            DeferredScanServiceOutcome::Pending(completion) => completion,
            DeferredScanServiceOutcome::Finished(_) => panic!("scan did not leave staging"),
        };
        let original_scan_id = completion.outcome().outcome().scan_id.clone();
        drop(completion);

        let connection = rusqlite::Connection::open(config.store_path()).unwrap();
        let columns = connection
            .prepare("PRAGMA table_info(scans)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let column_list = columns.join(", ");
        let selected_columns = columns
            .iter()
            .map(|column| {
                if column == "id" {
                    "?1".to_owned()
                } else {
                    column.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        let clone_scan = format!(
            "INSERT INTO scans ({column_list})
             SELECT {selected_columns} FROM scans WHERE id=?2"
        );
        for index in 1..LEGACY_CANDIDATE_COUNT {
            connection
                .execute(
                    &clone_scan,
                    rusqlite::params![format!("legacy-page-scan-{index:03}"), original_scan_id],
                )
                .unwrap();
        }
        connection
            .execute_batch(
                "DROP TABLE scan_operation_staging;
                 PRAGMA user_version=16;",
            )
            .unwrap();
        drop(connection);

        let submitted_at_ms = system_now_ms().unwrap();
        let mut journal = OperationJournal::open(&config).unwrap();
        let queued_operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"queued-after-legacy-scan-pages",
                    submitted_at_ms + 60_000,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        drop(journal);

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();
        assert_eq!(report.claimed(), 1);
        assert_eq!(report.completed(), 1);
        assert!(matches!(
            OperationJournal::open(&config).unwrap().result(
                &repository,
                &queued_operation_id,
                system_now_ms().unwrap(),
            ),
            Ok(OperationOutcome::Completed(_))
        ));
        let store = rusqlite::Connection::open(config.store_path()).unwrap();
        let sentinel_prefix = "__depgraph_reserved_legacy_scan_operation_candidate__:";
        assert_eq!(
            store
                .query_row(
                    "SELECT COUNT(*) FROM scan_operation_staging
                      WHERE substr(operation_id, 1, length(?1))=?1",
                    [sentinel_prefix],
                    |row| row.get::<_, u64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .query_row(
                    "SELECT COUNT(*) FROM scans
                      WHERE status='cancelled'
                        AND (id=?1 OR id GLOB 'legacy-page-scan-*')",
                    [&original_scan_id],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap(),
            LEGACY_CANDIDATE_COUNT
        );
    }

    #[test]
    fn scan_completion_recovery_rejects_forged_envelope_and_staging_bindings() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let service = DepgraphService::new(config.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(service.scan_cancellable(
                &ScanRequest::new(false, ScanCacheMode::Disabled),
                CancellationToken::new(),
            ))
            .unwrap();
        std::fs::write(
            config.canonical_root().join("scan-recovery-binding.rs"),
            "pub fn changed() {}\n",
        )
        .unwrap();
        let base_snapshot_id = service
            .start_snapshot_request("current")
            .unwrap()
            .snapshot_id()
            .as_str()
            .to_owned();
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 30_000;
        let lease = b"scan-recovery-binding-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"scan-recovery-binding",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("scan-recovery-binding-runner").unwrap(),
                lease,
                submitted_at_ms + 1,
                deadline_ms,
            )
            .unwrap();
        let mut completion = match runtime
            .block_on(service.scan_deferred_cancellable_for_operation(
                &ScanRequest::new(false, ScanCacheMode::Disabled),
                operation_id.as_str(),
                CancellationToken::new(),
            ))
            .unwrap()
        {
            DeferredScanServiceOutcome::Pending(completion) => completion,
            DeferredScanServiceOutcome::Finished(_) => panic!("scan did not defer completion"),
        };
        let dispatcher = ScanOperationDispatcher::new(config.clone());
        let valid_result = dispatcher.completed_output(completion.outcome()).unwrap();
        let scan_id = completion.outcome().outcome().scan_id.clone();
        let expected_snapshot_id = completion
            .outcome()
            .completed_snapshot_id()
            .unwrap()
            .as_str()
            .to_owned();
        completion
            .bind_recovery_result_digest(
                JournalDigest::sha256(valid_result.as_str().as_bytes()).as_bytes(),
            )
            .unwrap();
        journal
            .commit_completion_intent(
                &repository,
                &operation_id,
                lease,
                valid_result.clone(),
                submitted_at_ms + 2,
            )
            .unwrap();
        drop(completion);

        let replace_intent_result = |value: serde_json::Value| {
            let result = CanonicalJson::new(value).unwrap();
            let digest = JournalDigest::sha256(result.as_str().as_bytes());
            rusqlite::Connection::open(journal.path())
                .unwrap()
                .execute(
                    "UPDATE operation_completion_intents
                        SET result_json=?1, result_digest=?2
                      WHERE operation_id=?3",
                    rusqlite::params![
                        result.as_str(),
                        digest.as_bytes().as_slice(),
                        operation_id.as_str()
                    ],
                )
                .unwrap();
        };
        let assert_still_staging = || {
            let store = rusqlite::Connection::open(config.store_path()).unwrap();
            assert_eq!(
                store
                    .query_row("SELECT status FROM scans WHERE id=?1", [&scan_id], |row| {
                        row.get::<_, String>(0)
                    },)
                    .unwrap(),
                "staging"
            );
            assert_eq!(
                depgraph_core::open_store_read_only(config.store_path())
                    .unwrap()
                    .current_snapshot_id()
                    .unwrap()
                    .as_deref(),
                Some(base_snapshot_id.as_str())
            );
        };

        let valid_value = valid_result.value().clone();
        let mut forged_results = Vec::new();
        let mut forged = valid_value.clone();
        forged["contract_version"] = json!("depgraph-mcp-tools-v2");
        forged_results.push(forged);
        let mut forged = valid_value.clone();
        forged["repository_id"] = json!("repo:forged");
        forged_results.push(forged);
        let mut forged = valid_value.clone();
        forged["snapshot_id"] = json!(
            "snapshot:sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        forged_results.push(forged);
        let mut forged = valid_value.clone();
        forged["result"]["scan_id"] = json!("forged-scan");
        forged_results.push(forged);
        let mut forged = valid_value.clone();
        forged["result"]["status"] = json!("partial");
        forged_results.push(forged);
        let mut forged = valid_value.clone();
        forged["result"]["project_code_executed"] = json!(true);
        forged_results.push(forged);
        let mut forged = valid_value.clone();
        forged["result"]["cache"]["hits"] = json!(1);
        forged_results.push(forged);
        let mut forged = valid_value.clone();
        forged["result"]["cache"]["misses"] = json!(1);
        forged_results.push(forged);
        let mut forged = valid_value.clone();
        forged["result"]["coverage"]["files_discovered"] = json!(1);
        forged_results.push(forged);

        let mut recovery_dispatcher = ScanOperationDispatcher::new(config.clone());
        for forged in forged_results {
            replace_intent_result(forged);
            let intent = journal
                .next_completion_intent(&repository, submitted_at_ms + 3)
                .unwrap()
                .unwrap();
            assert!(recovery_dispatcher.recover_completion(&intent).is_err());
            assert_still_staging();
        }
        replace_intent_result(valid_value);

        let store_binding = rusqlite::Connection::open(config.store_path()).unwrap();
        for (column, forged_sql) in [
            ("repository_binding_digest", "zeroblob(32)"),
            ("configuration_digest", "zeroblob(32)"),
            ("strict", "1-strict"),
            ("cache_enabled", "1-cache_enabled"),
            ("base_snapshot_id", "'forged-base'"),
            ("validated_mutation_count", "validated_mutation_count+1"),
            ("prospective_snapshot_id", "'forged-snapshot'"),
            ("result_digest", "zeroblob(32)"),
        ] {
            let original: rusqlite::types::Value = store_binding
                .query_row(
                    &format!("SELECT {column} FROM scan_operation_staging WHERE operation_id=?1"),
                    [operation_id.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            store_binding
                .execute(
                    &format!(
                        "UPDATE scan_operation_staging SET {column}={forged_sql}
                          WHERE operation_id=?1"
                    ),
                    [operation_id.as_str()],
                )
                .unwrap();
            let intent = journal
                .next_completion_intent(&repository, submitted_at_ms + 3)
                .unwrap()
                .unwrap();
            assert!(recovery_dispatcher.recover_completion(&intent).is_err());
            assert_still_staging();
            store_binding
                .execute(
                    &format!(
                        "UPDATE scan_operation_staging SET {column}=?1
                          WHERE operation_id=?2"
                    ),
                    rusqlite::params![original, operation_id.as_str()],
                )
                .unwrap();
        }
        drop(store_binding);

        let intent = journal
            .next_completion_intent(&repository, submitted_at_ms + 3)
            .unwrap()
            .unwrap();
        assert_eq!(
            recovery_dispatcher.recover_completion(&intent).unwrap(),
            CompletionRecovery::Finalized
        );
        assert_eq!(
            recovery_dispatcher.recover_completion(&intent).unwrap(),
            CompletionRecovery::Finalized
        );
        journal
            .finish_completion_intent(&repository, &operation_id, submitted_at_ms + 3)
            .unwrap();
        assert_eq!(
            service
                .start_snapshot_request("current")
                .unwrap()
                .snapshot_id()
                .as_str(),
            expected_snapshot_id
        );
    }

    #[test]
    fn p1b_decided_scan_recovers_after_live_configuration_changes_without_current_rollback() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 60_000;
        let lease = b"decision-config-recovery-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"decision-config-recovery",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("decision-config-recovery-runner").unwrap(),
                lease,
                submitted_at_ms + 1,
                deadline_ms,
            )
            .unwrap();

        let service = DepgraphService::new(config.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut completion = match runtime
            .block_on(service.scan_deferred_cancellable_for_operation(
                &ScanRequest::new(false, ScanCacheMode::Disabled),
                operation_id.as_str(),
                CancellationToken::new(),
            ))
            .unwrap()
        {
            DeferredScanServiceOutcome::Pending(completion) => completion,
            DeferredScanServiceOutcome::Finished(_) => panic!("scan did not defer completion"),
        };
        let scan_id = completion.outcome().outcome().scan_id.clone();
        let decided_snapshot_id = completion
            .outcome()
            .completed_snapshot_id()
            .unwrap()
            .as_str()
            .to_owned();
        let result = ScanOperationDispatcher::new(config.clone())
            .completed_output(completion.outcome())
            .unwrap();
        completion
            .bind_recovery_result_digest(
                JournalDigest::sha256(result.as_str().as_bytes()).as_bytes(),
            )
            .unwrap();
        assert_eq!(
            journal
                .commit_completion_intent(
                    &repository,
                    &operation_id,
                    lease,
                    result,
                    submitted_at_ms + 2,
                )
                .unwrap(),
            CompletionDecision::Committed
        );
        drop(completion);
        drop(journal);

        std::fs::write(
            config.canonical_root().join(".depgraph.toml"),
            "schema_version = 1\n[scan]\nworker_timeout_seconds = 301\n",
        )
        .unwrap();
        let newer_scan_id = "decision-config-newer-current";
        let coverage = json!({
            "profiles": 0,
            "files_discovered": 0,
            "files_analyzed": 0,
            "files_skipped": 0,
            "dependency_sites": 0,
            "resolved": 0,
            "candidates": 0,
            "external": 0,
            "unresolved": 0,
            "unsupported_syntax": 0,
            "project_code_executed": false,
            "completeness": ["syntax-complete"],
            "reasons": []
        });
        let mut store = depgraph_core::open_store(config.store_path()).unwrap();
        store
            .start_scan_with_revision(
                newer_scan_id,
                config.canonical_root(),
                false,
                Some("decision-config-newer-current-revision"),
            )
            .unwrap();
        for event in [
            json!({
                "event": "scan_started",
                "protocol_version": "1.0",
                "scan_id": newer_scan_id,
                "adapter": "fixture",
                "adapter_version": "1.0",
                "seq": 1,
                "root": config.canonical_root(),
                "project_code_executed": false,
                "safe_mode": true
            }),
            json!({
                "event": "scan_completed",
                "protocol_version": "1.0",
                "scan_id": newer_scan_id,
                "adapter": "fixture",
                "adapter_version": "1.0",
                "seq": 2,
                "coverage": coverage
            }),
        ] {
            store.ingest_event(&event).unwrap();
        }
        store
            .finish_scan(newer_scan_id, "completed", None, true)
            .unwrap();
        let newer_snapshot_id = store.current_snapshot_id().unwrap().unwrap();
        drop(store);
        assert_ne!(newer_snapshot_id, decided_snapshot_id);

        let report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap();
        assert_eq!(report.completed(), 1);
        let journal = OperationJournal::open(&config).unwrap();
        assert!(matches!(
            journal.result(&repository, &operation_id, system_now_ms().unwrap()),
            Ok(OperationOutcome::Completed(_))
        ));
        assert!(
            journal
                .next_completion_intent(&repository, system_now_ms().unwrap())
                .unwrap()
                .is_none()
        );
        let store = depgraph_core::open_store_read_only(config.store_path()).unwrap();
        assert_eq!(
            store.current_snapshot_id().unwrap().as_deref(),
            Some(newer_snapshot_id.as_str())
        );
        assert_eq!(
            rusqlite::Connection::open(config.store_path())
                .unwrap()
                .query_row("SELECT status FROM scans WHERE id=?1", [&scan_id], |row| {
                    row.get::<_, String>(0)
                })
                .unwrap(),
            "completed"
        );
    }

    #[test]
    fn p1b_tampered_decision_time_configuration_evidence_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 60_000;
        let lease = b"tampered-config-evidence-token";
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"strict": false, "no_cache": true}),
                    b"tampered-config-evidence",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        journal
            .acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("tampered-config-evidence-runner").unwrap(),
                lease,
                submitted_at_ms + 1,
                deadline_ms,
            )
            .unwrap();
        let service = DepgraphService::new(config.clone());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut completion = match runtime
            .block_on(service.scan_deferred_cancellable_for_operation(
                &ScanRequest::new(false, ScanCacheMode::Disabled),
                operation_id.as_str(),
                CancellationToken::new(),
            ))
            .unwrap()
        {
            DeferredScanServiceOutcome::Pending(completion) => completion,
            DeferredScanServiceOutcome::Finished(_) => panic!("scan did not defer completion"),
        };
        let scan_id = completion.outcome().outcome().scan_id.clone();
        let result = ScanOperationDispatcher::new(config.clone())
            .completed_output(completion.outcome())
            .unwrap();
        completion
            .bind_recovery_result_digest(
                JournalDigest::sha256(result.as_str().as_bytes()).as_bytes(),
            )
            .unwrap();
        journal
            .commit_completion_intent(
                &repository,
                &operation_id,
                lease,
                result,
                submitted_at_ms + 2,
            )
            .unwrap();
        drop(completion);
        drop(journal);

        rusqlite::Connection::open(config.store_path())
            .unwrap()
            .execute(
                "UPDATE scan_operation_staging
                    SET configuration_digest=zeroblob(32)
                  WHERE operation_id=?1",
                [operation_id.as_str()],
            )
            .unwrap();

        let recovery_error = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            ScanOperationDispatcher::new(config.clone()),
        )
        .run_until_idle()
        .unwrap_err();
        assert!(matches!(
            recovery_error,
            RunnerError::Service(
                DepgraphServiceError::MutatingStoreUnavailable { .. }
                    | DepgraphServiceError::StoreOperation { .. }
            )
        ));
        let journal = OperationJournal::open(&config).unwrap();
        assert_eq!(
            journal
                .next_completion_intent(&repository, system_now_ms().unwrap())
                .unwrap()
                .unwrap()
                .operation_id(),
            &operation_id
        );
        assert_eq!(
            rusqlite::Connection::open(config.store_path())
                .unwrap()
                .query_row("SELECT status FROM scans WHERE id=?1", [&scan_id], |row| {
                    row.get::<_, String>(0)
                })
                .unwrap(),
            "staging"
        );
    }

    #[test]
    fn guardian_cancels_the_dispatch_token_when_cancellation_is_requested() {
        const LEASE_DURATION_MS: i64 = 200;
        const RENEWAL_MARGIN_MS: i64 = 150;

        struct CancellationAwareDispatcher {
            started: mpsc::SyncSender<()>,
        }

        impl OperationDispatcher for CancellationAwareDispatcher {
            fn dispatch(
                &mut self,
                _work: &RunnerWork,
                control: &mut ExecutionControl<'_>,
            ) -> DispatchOutcome {
                let cancellation = control.cancellation_token().clone();
                self.started.send(()).expect("dispatcher start signal");
                let timeout = std::time::Instant::now() + Duration::from_secs(5);
                while !cancellation.is_cancelled() {
                    assert!(
                        std::time::Instant::now() < timeout,
                        "guardian did not cancel the dispatch token"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                DispatchOutcome::Cancelled
            }
        }

        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 10_000;
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"guardian_cancellation": true}),
                    b"guardian-cancellation-token",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        drop(journal);

        let (dispatch_started, wait_for_dispatch) = mpsc::sync_channel(0);
        let (guardian_events, _wait_for_guardian) = mpsc::channel();
        let runner = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            CancellationAwareDispatcher {
                started: dispatch_started,
            },
        )
        .with_lease_timing_for_test(LEASE_DURATION_MS, RENEWAL_MARGIN_MS, guardian_events);
        let runner_thread = std::thread::spawn(move || runner.run_until_idle());
        wait_for_dispatch
            .recv_timeout(Duration::from_secs(5))
            .expect("dispatcher starts");

        let mut journal = OperationJournal::open(&config).unwrap();
        journal
            .cancel(
                &repository,
                &operation_id,
                &CapabilitySet::new([
                    depgraph_mcp_tools::AgentCapability::Read,
                    depgraph_mcp_tools::AgentCapability::StoreWrite,
                ])
                .unwrap(),
                system_now_ms().unwrap(),
            )
            .unwrap();

        let report = runner_thread.join().unwrap().unwrap();
        assert_eq!(report.claimed(), 1);
        assert_eq!(report.cancelled(), 1);
        assert_eq!(report.completed(), 0);
        assert!(matches!(
            journal
                .result(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap(),
            OperationOutcome::Cancelled
        ));
    }

    #[test]
    fn guardian_prevents_reclaim_while_dispatch_blocks_past_original_lease() {
        const LEASE_DURATION_MS: i64 = 500;
        const RENEWAL_MARGIN_MS: i64 = 400;

        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
        let submitted_at_ms = system_now_ms().unwrap();
        let deadline_ms = submitted_at_ms + 10_000;
        let mut journal = OperationJournal::open(&config).unwrap();
        let operation_id = journal
            .submit(
                &SubmitRequest::new(
                    &config,
                    OperationKind::ScanSubmit,
                    &json!({"blocking": true}),
                    b"guardian-blocking-dispatch",
                    deadline_ms,
                )
                .unwrap(),
                submitted_at_ms,
            )
            .unwrap()
            .operation_id()
            .clone();
        drop(journal);

        let calls = Arc::new(AtomicUsize::new(0));
        let competing_calls = Arc::new(AtomicUsize::new(0));
        let (dispatch_started, wait_for_dispatch) = mpsc::sync_channel(0);
        let (release_dispatch, wait_for_release) = mpsc::sync_channel(0);
        let (guardian_events, wait_for_guardian) = mpsc::channel();
        let runner = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            BlockingDispatcher {
                calls: Arc::clone(&calls),
                started: dispatch_started,
                release: wait_for_release,
            },
        )
        .with_lease_timing_for_test(LEASE_DURATION_MS, RENEWAL_MARGIN_MS, guardian_events);
        let runner_thread = std::thread::spawn(move || runner.run_until_idle());

        let dispatch_started_at_ms = wait_for_dispatch
            .recv_timeout(Duration::from_secs(5))
            .expect("dispatcher start signal");
        let original_lease_expires_at_ms = match wait_for_guardian
            .recv_timeout(Duration::from_secs(5))
            .expect("guardian start signal")
        {
            LeaseGuardianEvent::Started {
                lease_expires_at_ms,
            } => lease_expires_at_ms,
            event => panic!("unexpected first guardian event: {event:?}"),
        };
        assert!(dispatch_started_at_ms < original_lease_expires_at_ms);

        let active_lease_expires_at_ms = loop {
            match wait_for_guardian
                .recv_timeout(Duration::from_secs(5))
                .expect("guardian renewal signal")
            {
                LeaseGuardianEvent::Renewed {
                    renewed_at_ms,
                    lease_expires_at_ms,
                } if renewed_at_ms >= original_lease_expires_at_ms => {
                    break lease_expires_at_ms;
                }
                LeaseGuardianEvent::Renewed { .. } => {}
                event => panic!("unexpected guardian event after startup: {event:?}"),
            }
        };
        let competing_at_ms = system_now_ms().unwrap();
        assert!(competing_at_ms >= original_lease_expires_at_ms);
        assert!(active_lease_expires_at_ms > competing_at_ms);

        let mut competing_journal = OperationJournal::open(&config).unwrap();
        assert!(matches!(
            competing_journal.acquire_lease(
                &repository,
                &operation_id,
                &LeaseOwner::parse("competing-blocked-runner").unwrap(),
                b"competing-blocked-token",
                competing_at_ms,
                (competing_at_ms + LEASE_DURATION_MS).min(deadline_ms),
            ),
            Err(JournalError::LeaseHeld)
        ));

        struct CompetingDispatcher(Arc<AtomicUsize>);
        impl OperationDispatcher for CompetingDispatcher {
            fn dispatch(
                &mut self,
                _work: &RunnerWork,
                _control: &mut ExecutionControl<'_>,
            ) -> DispatchOutcome {
                self.0.fetch_add(1, Ordering::SeqCst);
                DispatchOutcome::Cancelled
            }
        }
        let competing_report = OperationRunner::new(
            RunnerStartupConfig::new(config.clone()).unwrap(),
            CompetingDispatcher(Arc::clone(&competing_calls)),
        )
        .run_until_idle()
        .unwrap();
        assert_eq!(competing_report.claimed(), 0);
        assert_eq!(competing_calls.load(Ordering::SeqCst), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        release_dispatch.send(()).unwrap();
        let report = runner_thread.join().unwrap().unwrap();
        assert_eq!(report.claimed(), 1);
        assert_eq!(report.completed(), 1);
        assert_eq!(report.failed(), 0);
        assert_eq!(report.cancelled(), 0);
        assert_eq!(report.lease_lost(), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let journal = OperationJournal::open(&config).unwrap();
        match journal
            .result(&repository, &operation_id, system_now_ms().unwrap())
            .unwrap()
        {
            OperationOutcome::Completed(result) => {
                assert_eq!(result.as_str(), r#"{"completed":true}"#);
            }
            outcome => panic!("unexpected terminal outcome: {outcome:?}"),
        }
        assert!(
            journal
                .runner_handoff(&repository, &operation_id, system_now_ms().unwrap())
                .unwrap()
                .completed_at_ms()
                .is_some()
        );
    }
}
