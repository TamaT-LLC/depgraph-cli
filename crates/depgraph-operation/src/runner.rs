use std::{
    sync::{Arc, Condvar, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use depgraph_core::{
    CancellationToken, CompilerPackRequirement, DepgraphCapability, DepgraphService,
    DepgraphServiceConfig, DepgraphServiceError, GraphQueryFilter, ScanCacheMode,
    service::{
        DeferredExportFileCompletion, DeferredExportFileRecovery, DeferredRuntimeImportCompletion,
        DeferredRuntimeImportRecovery, DeferredRuntimeImportServiceOutcome, DeferredScanCompletion,
        DeferredScanRecovery, DeferredScanServiceOutcome, ExportFileRequest, GraphExportFormat,
        GraphExportRequest, RepositoryOutputPrecondition, RepositoryOverwritePolicy,
        RepositoryRelativePath, ResolveBuildRequest, RuntimeValidateRequest, ScanRequest,
        ServiceSnapshotSelector, SnapshotLocator,
    },
};
use depgraph_mcp_tools::{
    AgentBuildOutcome, AgentDaemonControlAction, AgentDaemonControlOutcome,
    AgentDaemonControlPhase, AgentError, AgentErrorCode, AgentExportOutcome,
    AgentGraphExportFormat, AgentRemediation, AgentRuntimeOutcome, AgentRuntimeStatus,
    AgentScanOutcome, ErrorEnvelope, LogicalRepositoryId, OperationId, SnapshotId, SuccessEnvelope,
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
    compiler_pack_requirement: Option<CompilerPackRequirement>,
    compiler_pack_requirement_path: Option<std::path::PathBuf>,
}

impl RunnerStartupConfig {
    pub fn new(service: DepgraphServiceConfig) -> Result<Self, RunnerError> {
        let startup = Self {
            service,
            compiler_pack_requirement: None,
            compiler_pack_requirement_path: None,
        };
        OperationJournal::open(&startup.service)?;
        Ok(startup)
    }

    pub fn new_with_compiler_pack_requirement(
        service: DepgraphServiceConfig,
        requirement_path: impl AsRef<std::path::Path>,
    ) -> Result<Self, RunnerError> {
        let requirement_path = requirement_path.as_ref();
        let requirement = depgraph_core::read_compiler_pack_requirement(requirement_path)
            .and_then(|requirement| {
                depgraph_core::verify_compiler_pack(&requirement)?;
                Ok(requirement)
            })
            .map_err(|_| RunnerError::InvalidStartupAuthority)?;
        let requirement_path = requirement_path
            .canonicalize()
            .map_err(|_| RunnerError::InvalidStartupAuthority)?;
        let startup = Self {
            service,
            compiler_pack_requirement: Some(requirement),
            compiler_pack_requirement_path: Some(requirement_path),
        };
        OperationJournal::open(&startup.service)?;
        Ok(startup)
    }

    #[must_use]
    pub const fn service_config(&self) -> &DepgraphServiceConfig {
        &self.service
    }

    #[must_use]
    pub const fn compiler_pack_requirement(&self) -> Option<&CompilerPackRequirement> {
        self.compiler_pack_requirement.as_ref()
    }

    #[must_use]
    pub fn compiler_pack_requirement_path(&self) -> Option<&std::path::Path> {
        self.compiler_pack_requirement_path.as_deref()
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
    let mut child_exit_observed_at = None;
    loop {
        let now = std::time::Instant::now();
        let child_exited = child.has_exited()?;
        match classify_daemon_start_poll(
            service.daemon_running_cancellable(&cancellation),
            child_exited,
            &mut child_exit_observed_at,
            now,
            deadline,
        ) {
            DaemonStartPoll::Running => {
                child.detach();
                return Ok(());
            }
            DaemonStartPoll::Waiting => {
                std::thread::sleep(Duration::from_millis(25));
            }
            DaemonStartPoll::ChildExited => {
                return Err(RunnerError::Service(DepgraphServiceError::Internal));
            }
            DaemonStartPoll::Exhausted => {
                child.terminate_and_reap()?;
                return Err(RunnerError::Service(
                    DepgraphServiceError::ResourceExhausted,
                ));
            }
            DaemonStartPoll::Failed(error) => {
                child.terminate_and_reap()?;
                return Err(error.into());
            }
        }
    }
}

const DAEMON_START_EXIT_GRACE: Duration = Duration::from_millis(750);

#[derive(Debug)]
enum DaemonStartPoll {
    Running,
    Waiting,
    ChildExited,
    Exhausted,
    Failed(DepgraphServiceError),
}

fn classify_daemon_start_poll(
    status: Result<bool, DepgraphServiceError>,
    child_exited: bool,
    child_exit_observed_at: &mut Option<std::time::Instant>,
    now: std::time::Instant,
    deadline: std::time::Instant,
) -> DaemonStartPoll {
    match status {
        Ok(true) => DaemonStartPoll::Running,
        Ok(false) | Err(DepgraphServiceError::NotFound) | Err(DepgraphServiceError::Conflict) => {
            if child_exited {
                let observed_at = child_exit_observed_at.get_or_insert(now);
                if now.duration_since(*observed_at) >= DAEMON_START_EXIT_GRACE {
                    return DaemonStartPoll::ChildExited;
                }
            }
            if now < deadline {
                DaemonStartPoll::Waiting
            } else {
                match status {
                    Ok(false) | Err(DepgraphServiceError::NotFound) => DaemonStartPoll::Exhausted,
                    Err(error) => DaemonStartPoll::Failed(error),
                    Ok(true) => unreachable!("running status returned above"),
                }
            }
        }
        Err(error) => DaemonStartPoll::Failed(error),
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
        .block_on(service.recover_daemon_stop_completion_cancellable(&cancellation))
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
        let unlock_result = if result.is_ok()
            && let Some(guard) = cleanup_guard.as_ref()
        {
            // Release exclusion synchronously before cleanup acknowledgement
            // reacquires the same sidecar lock; relying on close-on-drop can
            // leave a transient self-conflict on some hosts.
            guard.unlock()
        } else {
            Ok(())
        };
        drop(cleanup_guard);
        let value = result?;
        unlock_result.map_err(JournalError::Io)?;
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
    compiler_pack_requirement: Option<CompilerPackRequirement>,
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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveBuildInput {
    acknowledgement: bool,
    rust_compiler_precise: bool,
    compiler_pack_manifest_sha256: String,
}

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
            compiler_pack_requirement: None,
            #[cfg(test)]
            runtime_dispatch_barrier: None,
            #[cfg(test)]
            daemon_start_promoter: None,
        }
    }

    #[must_use]
    pub fn from_startup(startup: &RunnerStartupConfig) -> Self {
        Self {
            config: startup.service_config().clone(),
            compiler_pack_requirement: startup.compiler_pack_requirement().cloned(),
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

    fn launcher_for_daemon_start(
        &self,
        service: &DepgraphService,
        cancellation: &CancellationToken,
    ) -> Result<Option<DaemonExecutableLauncher>, RunnerError> {
        match service.daemon_running_cancellable(cancellation) {
            Ok(true) => Ok(None),
            Ok(false) | Err(DepgraphServiceError::NotFound | DepgraphServiceError::Conflict) => {
                Ok(self.resolve_daemon_start_launcher()?)
            }
            Err(error) => Err(error.into()),
        }
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
        let launcher = match self.launcher_for_daemon_start(&service, control.cancellation_token())
        {
            Ok(launcher) => launcher,
            Err(RunnerError::Service(error)) => return self.failed_service(&error),
            Err(_) => return self.failed(AgentErrorCode::Internal),
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
        match service.daemon_running_cancellable(control.cancellation_token()) {
            Ok(_) | Err(DepgraphServiceError::Conflict) => {}
            Err(error) => return self.failed_service(&error),
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

    fn dispatch_resolve_build(
        &self,
        work: &RunnerWork,
        control: &mut ExecutionControl<'_>,
    ) -> DispatchOutcome {
        let input = match serde_json::from_str::<ResolveBuildInput>(work.input().as_str()) {
            Ok(input) => input,
            Err(_) => return self.failed(AgentErrorCode::InvalidArgument),
        };
        if !input.acknowledgement || !input.rust_compiler_precise {
            return self.failed(AgentErrorCode::InvalidArgument);
        }
        let requirement = match self.compiler_pack_requirement.as_ref() {
            Some(requirement) => requirement.clone(),
            None => return self.failed(AgentErrorCode::CapabilityDenied),
        };
        let pack = match depgraph_core::verify_compiler_pack(&requirement) {
            Ok(pack) => pack,
            Err(_) => return self.failed(AgentErrorCode::IntegrityFailure),
        };
        if pack.attestation.manifest_sha256 != input.compiler_pack_manifest_sha256 {
            return self.failed(AgentErrorCode::IntegrityFailure);
        }
        if !matches!(control.checkpoint(), Ok(ExecutionCheckpoint::Continue)) {
            return DispatchOutcome::Cancelled;
        }
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => return self.failed(AgentErrorCode::Internal),
        };
        let service = DepgraphService::new(self.config.clone());
        let cancellation = CancellationToken::new();
        let request = ResolveBuildRequest::new(true, true, Some(requirement));
        let execution = service.resolve_build_cancellable(&request, &cancellation);
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
            return DispatchOutcome::Cancelled;
        }
        match result {
            Ok(outcome)
                if matches!(
                    outcome.audit().outcome,
                    depgraph_core::BuildOutcomeKind::Cancelled
                ) =>
            {
                DispatchOutcome::Cancelled
            }
            Ok(outcome) => match self.completed_build_output(&outcome) {
                Ok(result) => DispatchOutcome::Completed(result),
                Err(error) => DispatchOutcome::Failed(error),
            },
            Err(DepgraphServiceError::Cancelled) => DispatchOutcome::Cancelled,
            Err(error) => self.failed_service(&error),
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

    fn completed_build_output(
        &self,
        source: &depgraph_core::service::ResolveBuildServiceOutcome,
    ) -> Result<CanonicalJson, CanonicalJson> {
        let outcome = AgentBuildOutcome::try_from(source)
            .map_err(|_| self.canonical_error(AgentErrorCode::IntegrityFailure))?;
        let snapshot_id = outcome.snapshot_id().cloned();
        let repository_id = LogicalRepositoryId::parse(self.config.logical_repository_id())
            .map_err(|_| self.canonical_error(AgentErrorCode::IntegrityFailure))?;
        CanonicalJson::new(
            serde_json::to_value(SuccessEnvelope::new(repository_id, snapshot_id, outcome))
                .expect("closed build output serializes"),
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
            OperationKind::ResolveBuildSubmit => self.dispatch_resolve_build(work, control),
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
                        self.launcher_for_daemon_start(&service, &CancellationToken::new())?;
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
                Ok(false)
                | Err(DepgraphServiceError::NotFound | DepgraphServiceError::Conflict) => {}
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
mod tests;
