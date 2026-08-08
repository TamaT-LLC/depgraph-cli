use std::{
    sync::{Arc, Condvar, Mutex, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use depgraph_core::DepgraphServiceConfig;
use depgraph_mcp_tools::{LogicalRepositoryId, OperationId};

use crate::{
    CanonicalInput, CanonicalJson, JournalDigest, JournalError, LeaseOwner, OperationJournal,
    OperationKind, OperationStatus,
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
    pub(crate) const fn service_config(&self) -> &DepgraphServiceConfig {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchOutcome {
    Completed(CanonicalJson),
    Failed(CanonicalJson),
    Cancelled,
}

pub trait OperationDispatcher {
    fn dispatch(
        &mut self,
        work: &RunnerWork,
        control: &mut ExecutionControl<'_>,
    ) -> DispatchOutcome;
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
    now: &'a dyn Fn() -> Result<i64, RunnerError>,
}

impl ExecutionControl<'_> {
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

    pub fn run_until_idle(mut self) -> Result<RunnerReport, RunnerError> {
        let repository_id =
            LogicalRepositoryId::parse(self.startup.service.logical_repository_id())
                .map_err(|_| RunnerError::InvalidStartupAuthority)?;
        let owner = new_lease_owner()?;
        let mut journal = OperationJournal::open(&self.startup.service)?;
        let mut report = RunnerReport::default();
        loop {
            let now_ms = system_now_ms()?;
            journal.purge(now_ms)?;
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
            let guardian = match LeaseGuardian::start(
                self.startup.clone(),
                repository_id.clone(),
                work.operation_id().clone(),
                token.copy_for_guardian(),
                initial_lease_expires_at_ms,
                work.execution_deadline_ms(),
                self.lease_timing,
                #[cfg(test)]
                self.guardian_events.clone(),
            )? {
                LeaseGuardianStart::Active(guardian) => guardian,
                LeaseGuardianStart::Inactive(LeaseGuardianExit::DeadlineExceeded) => {
                    record_deadline_failure(
                        &mut journal,
                        &repository_id,
                        work.operation_id(),
                        work.execution_deadline_ms(),
                        &mut report,
                    )?;
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
                LeaseGuardianExit::DeadlineExceeded => {
                    record_deadline_failure(
                        &mut journal,
                        &repository_id,
                        work.operation_id(),
                        work.execution_deadline_ms(),
                        &mut report,
                    )?;
                    continue;
                }
                LeaseGuardianExit::LeaseLost => {
                    report.lease_lost += 1;
                    continue;
                }
            }
            let ControlledDispatch::Outcome(outcome, final_checkpoint) = controlled_dispatch else {
                match controlled_dispatch {
                    ControlledDispatch::DeadlineExceeded => {
                        record_deadline_failure(
                            &mut journal,
                            &repository_id,
                            work.operation_id(),
                            work.execution_deadline_ms(),
                            &mut report,
                        )?;
                    }
                    ControlledDispatch::LeaseLost => report.lease_lost += 1,
                    ControlledDispatch::Outcome(_, _) => unreachable!(),
                }
                continue;
            };
            match final_checkpoint {
                ExecutionCheckpoint::DeadlineExceeded => {
                    record_deadline_failure(
                        &mut journal,
                        &repository_id,
                        work.operation_id(),
                        work.execution_deadline_ms(),
                        &mut report,
                    )?;
                }
                ExecutionCheckpoint::LeaseLost => {
                    report.lease_lost += 1;
                }
                ExecutionCheckpoint::Continue | ExecutionCheckpoint::CancellationRequested => {
                    let terminal_at_ms = system_now_ms()?;
                    if terminal_at_ms >= work.execution_deadline_ms() {
                        record_deadline_failure(
                            &mut journal,
                            &repository_id,
                            work.operation_id(),
                            work.execution_deadline_ms(),
                            &mut report,
                        )?;
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
                        DispatchOutcome::Failed(error) => {
                            journal.fail(
                                &repository_id,
                                work.operation_id(),
                                token.as_ref(),
                                error,
                                terminal_at_ms,
                            )?;
                            report.failed += 1;
                        }
                        DispatchOutcome::Cancelled => {
                            journal.mark_cancelled(
                                &repository_id,
                                work.operation_id(),
                                token.as_ref(),
                                terminal_at_ms,
                            )?;
                            report.cancelled += 1;
                        }
                    }
                }
            }
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
                    startup_ready
                        .send(Err(LeaseGuardianExit::DeadlineExceeded))
                        .map_err(|_| guardian_failure())?;
                    return Ok(LeaseGuardianExit::DeadlineExceeded);
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
                        startup_ready
                            .send(Err(LeaseGuardianExit::DeadlineExceeded))
                            .map_err(|_| guardian_failure())?;
                        return Ok(LeaseGuardianExit::DeadlineExceeded);
                    }
                    Err(JournalError::LeaseExpired | JournalError::LeaseMismatch) => {
                        startup_ready
                            .send(Err(LeaseGuardianExit::LeaseLost))
                            .map_err(|_| guardian_failure())?;
                        return Ok(LeaseGuardianExit::LeaseLost);
                    }
                    Err(error) => return Err(RunnerError::Journal(error)),
                };
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
    #[cfg(test)] events: Option<&mpsc::Sender<LeaseGuardianEvent>>,
) -> Result<LeaseGuardianExit, RunnerError> {
    loop {
        if stop_requested(stop) {
            return Ok(LeaseGuardianExit::Stopped);
        }
        let now_ms = system_now_ms()?;
        if now_ms >= execution_deadline_ms {
            return Ok(LeaseGuardianExit::DeadlineExceeded);
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
            return Ok(LeaseGuardianExit::DeadlineExceeded);
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
                return Ok(LeaseGuardianExit::DeadlineExceeded);
            }
            Err(JournalError::LeaseExpired | JournalError::LeaseMismatch) => {
                return Ok(LeaseGuardianExit::LeaseLost);
            }
            Err(error) => return Err(RunnerError::Journal(error)),
        };
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
    match journal.fail_deadline(repository_id, operation_id, execution_deadline_ms) {
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
            Arc,
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
    use crate::{CapabilitySet, OperationOutcome, SubmitRequest};

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
