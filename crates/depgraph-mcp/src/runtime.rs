use std::{
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use depgraph_core::CancellationToken;
use depgraph_mcp_tools::{
    AgentError, AgentErrorCode, AgentErrorDetails, AgentRemediation, AgentResourceLimit,
};
use serde::Serialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const READ_CONCURRENCY: usize = 4;
pub const SUBMIT_CONCURRENCY: usize = 2;
pub const READ_QUEUE_CAPACITY: usize = 16;
pub const AUDIT_LINE_BYTES: usize = 16 * 1024;
pub const AUDIT_REQUEST_BYTES: usize = 64 * 1024;
const DEFAULT_READ_DEADLINE: Duration = Duration::from_secs(30);
const DEFAULT_SUBMIT_DEADLINE: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimit {
    requests: u64,
    period: Duration,
    burst: u64,
}

impl RateLimit {
    #[must_use]
    pub const fn new(requests: u64, period: Duration, burst: u64) -> Self {
        Self {
            requests,
            period,
            burst,
        }
    }

    #[must_use]
    pub const fn per_minute(requests: u64, burst: u64) -> Self {
        Self::new(requests, Duration::from_secs(60), burst)
    }

    #[must_use]
    pub const fn per_hour(requests: u64, burst: u64) -> Self {
        Self::new(requests, Duration::from_secs(60 * 60), burst)
    }

    fn validate(self) -> Result<(), RuntimeConfigurationError> {
        if self.requests == 0 || self.burst == 0 || self.period.is_zero() {
            return Err(RuntimeConfigurationError::InvalidRateLimit);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
    read_concurrency: usize,
    submit_concurrency: usize,
    read_queue_capacity: usize,
    read_rate: RateLimit,
    submit_rate: RateLimit,
    read_deadline: Duration,
    submit_deadline: Duration,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            read_concurrency: READ_CONCURRENCY,
            submit_concurrency: SUBMIT_CONCURRENCY,
            read_queue_capacity: READ_QUEUE_CAPACITY,
            read_rate: RateLimit::per_minute(240, 32),
            submit_rate: RateLimit::per_hour(30, 3),
            read_deadline: DEFAULT_READ_DEADLINE,
            submit_deadline: DEFAULT_SUBMIT_DEADLINE,
        }
    }
}

impl RuntimeConfig {
    #[must_use]
    pub const fn read_concurrency(&self) -> usize {
        self.read_concurrency
    }

    #[must_use]
    pub const fn submit_concurrency(&self) -> usize {
        self.submit_concurrency
    }

    #[must_use]
    pub const fn read_queue_capacity(&self) -> usize {
        self.read_queue_capacity
    }

    #[must_use]
    pub const fn read_rate(&self) -> RateLimit {
        self.read_rate
    }

    #[must_use]
    pub const fn submit_rate(&self) -> RateLimit {
        self.submit_rate
    }

    #[must_use]
    pub const fn with_read_concurrency(mut self, value: usize) -> Self {
        self.read_concurrency = value;
        self
    }

    #[must_use]
    pub const fn with_submit_concurrency(mut self, value: usize) -> Self {
        self.submit_concurrency = value;
        self
    }

    #[must_use]
    pub const fn with_read_queue_capacity(mut self, value: usize) -> Self {
        self.read_queue_capacity = value;
        self
    }

    #[must_use]
    pub const fn with_read_rate(mut self, value: RateLimit) -> Self {
        self.read_rate = value;
        self
    }

    #[must_use]
    pub const fn with_submit_rate(mut self, value: RateLimit) -> Self {
        self.submit_rate = value;
        self
    }

    #[must_use]
    pub const fn with_read_deadline(mut self, value: Duration) -> Self {
        self.read_deadline = value;
        self
    }

    #[must_use]
    pub const fn with_submit_deadline(mut self, value: Duration) -> Self {
        self.submit_deadline = value;
        self
    }

    fn validate(&self) -> Result<(), RuntimeConfigurationError> {
        if self.read_concurrency == 0
            || self.submit_concurrency == 0
            || self.read_deadline.is_zero()
            || self.submit_deadline.is_zero()
        {
            return Err(RuntimeConfigurationError::InvalidCapacityOrDeadline);
        }
        self.read_rate.validate()?;
        self.submit_rate.validate()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeConfigurationError {
    InvalidCapacityOrDeadline,
    InvalidRateLimit,
}

impl std::fmt::Display for RuntimeConfigurationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCapacityOrDeadline => {
                formatter.write_str("runtime capacities and deadlines must be non-zero")
            }
            Self::InvalidRateLimit => formatter.write_str("runtime rate limits must be non-zero"),
        }
    }
}

impl std::error::Error for RuntimeConfigurationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeClass {
    Read,
    Submit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFailure {
    ResourceExhausted,
    RateLimited,
    DeadlineExceeded,
    Cancelled,
    WorkerFailed,
}

impl RuntimeFailure {
    #[must_use]
    pub fn agent_error(self, deadline: Duration) -> AgentError {
        match self {
            Self::ResourceExhausted | Self::RateLimited => AgentError::new(
                AgentErrorCode::ResourceExhausted,
                true,
                AgentRemediation::Retry,
                None,
            ),
            Self::DeadlineExceeded => AgentError::new(
                AgentErrorCode::ResourceExhausted,
                true,
                AgentRemediation::NarrowQuery,
                Some(AgentErrorDetails::ResourceLimit {
                    limit: AgentResourceLimit::DeadlineMilliseconds,
                    maximum: u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
                }),
            ),
            Self::Cancelled => AgentError::new(
                AgentErrorCode::Cancelled,
                false,
                AgentRemediation::Retry,
                None,
            ),
            Self::WorkerFailed => AgentError::new(
                AgentErrorCode::Internal,
                false,
                AgentRemediation::ContactOperator,
                None,
            ),
        }
    }
}

#[derive(Debug)]
struct TokenBucket {
    limit: RateLimit,
    state: Mutex<TokenBucketState>,
}

#[derive(Debug)]
struct TokenBucketState {
    tokens: f64,
    updated_at: Instant,
}

impl TokenBucket {
    fn new(limit: RateLimit) -> Self {
        Self {
            limit,
            state: Mutex::new(TokenBucketState {
                tokens: limit.burst as f64,
                updated_at: Instant::now(),
            }),
        }
    }

    fn try_take(&self) -> bool {
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let refill_per_second = self.limit.requests as f64 / self.limit.period.as_secs_f64();
        state.tokens = (state.tokens
            + now.duration_since(state.updated_at).as_secs_f64() * refill_per_second)
            .min(self.limit.burst as f64);
        state.updated_at = now;
        if state.tokens < 1.0 {
            return false;
        }
        state.tokens -= 1.0;
        true
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeController {
    config: RuntimeConfig,
    read_capacity: Arc<Semaphore>,
    read_slots: Arc<Semaphore>,
    submit_slots: Arc<Semaphore>,
    read_rate: Arc<TokenBucket>,
    submit_rate: Arc<TokenBucket>,
}

impl RuntimeController {
    pub fn new(config: RuntimeConfig) -> Result<Self, RuntimeConfigurationError> {
        config.validate()?;
        let read_capacity = config
            .read_concurrency
            .checked_add(config.read_queue_capacity)
            .ok_or(RuntimeConfigurationError::InvalidCapacityOrDeadline)?;
        if read_capacity > Semaphore::MAX_PERMITS
            || config.submit_concurrency > Semaphore::MAX_PERMITS
        {
            return Err(RuntimeConfigurationError::InvalidCapacityOrDeadline);
        }
        Ok(Self {
            read_capacity: Arc::new(Semaphore::new(read_capacity)),
            read_slots: Arc::new(Semaphore::new(config.read_concurrency)),
            submit_slots: Arc::new(Semaphore::new(config.submit_concurrency)),
            read_rate: Arc::new(TokenBucket::new(config.read_rate)),
            submit_rate: Arc::new(TokenBucket::new(config.submit_rate)),
            config,
        })
    }

    #[must_use]
    pub const fn deadline(&self, class: RuntimeClass) -> Duration {
        match class {
            RuntimeClass::Read => self.config.read_deadline,
            RuntimeClass::Submit => self.config.submit_deadline,
        }
    }

    #[must_use]
    pub fn admitted_reads(&self) -> usize {
        self.config
            .read_concurrency
            .saturating_add(self.config.read_queue_capacity)
            .saturating_sub(self.read_capacity.available_permits())
    }

    #[must_use]
    pub fn active_submissions(&self) -> usize {
        self.config
            .submit_concurrency
            .saturating_sub(self.submit_slots.available_permits())
    }

    pub async fn execute_blocking<T, E, F>(
        &self,
        class: RuntimeClass,
        cancellation: CancellationToken,
        operation: F,
    ) -> Result<Result<T, E>, RuntimeFailure>
    where
        T: Send + 'static,
        E: Send + 'static,
        F: FnOnce(CancellationToken) -> Result<T, E> + Send + 'static,
    {
        if cancellation.is_cancelled() {
            return Err(RuntimeFailure::Cancelled);
        }
        let started_at = tokio::time::Instant::now();
        let deadline = self.deadline(class);
        let deadline_at = started_at
            .checked_add(deadline)
            .ok_or(RuntimeFailure::DeadlineExceeded)?;

        let (capacity, slot) = match class {
            RuntimeClass::Read => {
                let capacity = Arc::clone(&self.read_capacity)
                    .try_acquire_owned()
                    .map_err(|_| RuntimeFailure::ResourceExhausted)?;
                if !self.read_rate.try_take() {
                    return Err(RuntimeFailure::RateLimited);
                }
                let slot = acquire_before_deadline(
                    Arc::clone(&self.read_slots),
                    &cancellation,
                    deadline_at,
                )
                .await?;
                (Some(capacity), slot)
            }
            RuntimeClass::Submit => {
                let slot = Arc::clone(&self.submit_slots)
                    .try_acquire_owned()
                    .map_err(|_| RuntimeFailure::ResourceExhausted)?;
                if !self.submit_rate.try_take() {
                    return Err(RuntimeFailure::RateLimited);
                }
                (None, slot)
            }
        };

        let worker_cancellation = cancellation.clone();
        let worker = tokio::task::spawn_blocking(move || {
            let _capacity = capacity;
            let _slot = slot;
            operation(worker_cancellation)
        });
        tokio::pin!(worker);

        tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                cancellation.cancel();
                Err(RuntimeFailure::Cancelled)
            }
            () = tokio::time::sleep_until(deadline_at) => {
                cancellation.cancel();
                Err(RuntimeFailure::DeadlineExceeded)
            }
            joined = &mut worker => {
                joined.map_err(|_| RuntimeFailure::WorkerFailed)
            }
        }
    }
}

async fn acquire_before_deadline(
    semaphore: Arc<Semaphore>,
    cancellation: &CancellationToken,
    deadline_at: tokio::time::Instant,
) -> Result<OwnedSemaphorePermit, RuntimeFailure> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(RuntimeFailure::Cancelled),
        () = tokio::time::sleep_until(deadline_at) => {
            cancellation.cancel();
            Err(RuntimeFailure::DeadlineExceeded)
        },
        permit = semaphore.acquire_owned() => {
            permit.map_err(|_| RuntimeFailure::WorkerFailed)
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditPhase {
    Admitted,
    Started,
    Finished,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Accepted,
    Completed,
    Rejected,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditErrorCode {
    ResourceExhausted,
    RateLimited,
    DeadlineExceeded,
    Cancelled,
    Internal,
}

#[derive(Clone)]
pub struct AuditLogger {
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    next_request_id: Arc<AtomicU64>,
}

impl std::fmt::Debug for AuditLogger {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuditLogger")
            .finish_non_exhaustive()
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::with_writer(io::stderr())
    }
}

impl AuditLogger {
    #[must_use]
    pub fn with_writer(writer: impl Write + Send + 'static) -> Self {
        Self {
            writer: Arc::new(Mutex::new(Box::new(writer))),
            next_request_id: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn request(&self, tool: &'static str) -> Result<AuditRequest, AuditConfigurationError> {
        if tool.is_empty()
            || tool.len() > 64
            || !tool
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(AuditConfigurationError);
        }
        Ok(AuditRequest {
            logger: self.clone(),
            request_id: self.next_request_id.fetch_add(1, Ordering::Relaxed),
            tool,
            written: 0,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditConfigurationError;

impl std::fmt::Display for AuditConfigurationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("audit tool name is not a bounded catalog token")
    }
}

impl std::error::Error for AuditConfigurationError {}

pub struct AuditRequest {
    logger: AuditLogger,
    request_id: u64,
    tool: &'static str,
    written: usize,
}

#[derive(Serialize)]
struct AuditRecord {
    request_id: u64,
    tool: &'static str,
    phase: AuditPhase,
    outcome: AuditOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<AuditErrorCode>,
    elapsed_ms: u64,
}

impl AuditRequest {
    pub fn record(
        &mut self,
        phase: AuditPhase,
        outcome: AuditOutcome,
        error_code: Option<AuditErrorCode>,
        elapsed: Duration,
    ) {
        let record = AuditRecord {
            request_id: self.request_id,
            tool: self.tool,
            phase,
            outcome,
            error_code,
            elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        };
        let Ok(mut line) = serde_json::to_vec(&record) else {
            return;
        };
        line.push(b'\n');
        if line.len() > AUDIT_LINE_BYTES
            || self.written.saturating_add(line.len()) > AUDIT_REQUEST_BYTES
        {
            return;
        }
        let mut writer = self
            .logger
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if writer.write_all(&line).is_ok() {
            self.written += line.len();
        }
    }
}
