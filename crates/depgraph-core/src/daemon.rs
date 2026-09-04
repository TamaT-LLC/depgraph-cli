use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    path::{Component, Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use depgraph_protocol::{
    DeltaScope, ValidatedDelta, WORKER_DELTA_CAPABILITY, WorkerDeltaFileChange,
    WorkerDeltaFileChangeKind, WorkerDeltaRequest, WorkerProtocolMode, negotiate_worker_protocol,
};
use depgraph_store::{
    IncrementalReplacementScope, InterruptedAttemptRecovery, ScanHealthProvenance,
};
use notify::{
    Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
    event::{ModifyKind, RenameMode},
};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Instant, sleep_until},
};
use uuid::Uuid;

use crate::incremental::profile_records_profile_plan_id;
use crate::{
    CancellationToken, Config, DaemonConfig, INCREMENTAL_PLAN_SCHEMA_VERSION,
    IncrementalChangeKind, IncrementalFileChange, IncrementalInvalidationMode,
    IncrementalInvalidationPlan, IncrementalInvalidationReason, ScanCacheMode,
    health::{
        HEALTH_ANALYZER_VERSION, HEALTH_FINDING_CONTRACT_VERSION, health_policy_config_digest,
    },
    open_store, plan_incremental_invalidation, plan_repository_profiles,
    run_scan_with_cache_mode_and_cancellation,
    scan::{cancel_scan, complete_scan, git_source_revision},
    worker::{
        AdapterKind, WorkerFailureKind, execute_worker_delta_with_cancellation, is_security_error,
        locate_worker, probe_worker_version_with_cancellation, worker_capabilities,
    },
};

pub const DAEMON_STATUS_SCHEMA_VERSION: &str = "daemon-status-v1";
pub const DAEMON_INCREMENTAL_TRACE_SCHEMA_VERSION: &str = "daemon-incremental-trace-v1";

// Complete-reanalysis requests still carry their canonical graph closure and
// remain bounded. The one-file semantic no-op path uses a one-node projection
// and sparse overlay instead, so it never reaches this repository-size guard.
const MAX_WORKER_DELTA_SCOPE_PATHS: usize = 4_096;

const DEFAULT_IGNORED_COMPONENTS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".depgraph",
    "node_modules",
    "target",
    "dist",
    ".next",
    ".astro",
    ".turbo",
    ".cache",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WatchPathKind {
    Source,
    Generated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchedPath {
    pub relative_path: String,
    pub kind: WatchPathKind,
}

#[derive(Debug, Clone)]
pub struct WatchIgnoreRules {
    root: PathBuf,
    root_alias: PathBuf,
    ignored_prefixes: Vec<String>,
    store_paths: BTreeSet<String>,
    store_prefixes: Vec<String>,
}

impl WatchIgnoreRules {
    pub fn new(root: &Path, ignored_paths: &[String], store_path: Option<&Path>) -> Result<Self> {
        let root_alias = root.to_path_buf();
        let root = root
            .canonicalize()
            .with_context(|| format!("failed to canonicalize watch root {}", root.display()))?;
        let mut ignored_prefixes = ignored_paths.to_vec();
        ignored_prefixes.sort();
        ignored_prefixes.dedup();
        if ignored_prefixes.len() != ignored_paths.len() {
            bail!("daemon ignored paths must not contain duplicates");
        }
        for path in &ignored_prefixes {
            validate_ignored_prefix(path)?;
        }
        let mut store_paths = BTreeSet::new();
        let mut store_prefixes = Vec::new();
        if let Some(store_path) = store_path {
            let absolute = if store_path.is_absolute() {
                store_path.to_path_buf()
            } else {
                root.join(store_path)
            };
            let absolute = absolute.canonicalize().unwrap_or(absolute);
            let relative = repository_relative_path(&root, &absolute)?
                .or(repository_relative_path(&root_alias, &absolute)?);
            if let Some(relative) = relative {
                store_paths.insert(relative.clone());
                store_paths.insert(format!("{relative}-wal"));
                store_paths.insert(format!("{relative}-shm"));
                store_paths.insert(format!("{relative}.daemon-status.json"));
                store_paths.insert(format!("{relative}.daemon-stop"));
                store_paths.insert(format!("{relative}.daemon-lock"));
                store_paths.insert(format!("{relative}.writer-lock"));
                store_prefixes.push(format!("{relative}.daemon-status.json.tmp-"));
            }
        }
        Ok(Self {
            root,
            root_alias,
            ignored_prefixes,
            store_paths,
            store_prefixes,
        })
    }

    pub fn classify(&self, path: &Path) -> Result<Option<WatchedPath>> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        };
        let relative_path = repository_relative_path(&self.root, &absolute)?
            .or(repository_relative_path(&self.root_alias, &absolute)?);
        let relative_path = if relative_path.is_some() {
            relative_path
        } else if let Some(canonical) = canonicalize_nearest_existing_ancestor(&absolute) {
            repository_relative_path(&self.root, &canonical)?
        } else {
            None
        };
        let Some(relative_path) = relative_path else {
            return Ok(None);
        };
        if self.store_paths.contains(&relative_path)
            || self
                .store_prefixes
                .iter()
                .any(|prefix| relative_path.starts_with(prefix))
            || relative_path
                .split('/')
                .any(|component| DEFAULT_IGNORED_COMPONENTS.contains(&component))
            || self.ignored_prefixes.iter().any(|prefix| {
                relative_path == *prefix
                    || relative_path
                        .strip_prefix(prefix)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
        {
            return Ok(None);
        }
        Ok(Some(WatchedPath {
            kind: if is_generated_artifact(&relative_path) {
                WatchPathKind::Generated
            } else {
                WatchPathKind::Source
            },
            relative_path,
        }))
    }
}

fn canonicalize_nearest_existing_ancestor(path: &Path) -> Option<PathBuf> {
    let mut current = path;
    let mut suffix = Vec::new();
    loop {
        if let Ok(canonical) = current.canonicalize() {
            let mut resolved = canonical;
            for component in suffix.iter().rev() {
                resolved.push(component);
            }
            return Some(resolved);
        }
        suffix.push(current.file_name()?.to_os_string());
        current = current.parent()?;
    }
}

fn validate_ignored_prefix(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        bail!("daemon ignored path {path:?} must be a normalized repository-relative path");
    }
    Ok(())
}

fn repository_relative_path(root: &Path, path: &Path) -> Result<Option<String>> {
    let relative = match path.strip_prefix(root) {
        Ok(relative) => relative,
        Err(_) => return Ok(None),
    };
    let mut normalized = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => normalized.push(
                value
                    .to_str()
                    .context("watch event path is not valid UTF-8")?,
            ),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("watch event path is not repository-relative")
            }
        }
    }
    if normalized.is_empty() {
        return Ok(None);
    }
    Ok(Some(normalized.join("/")))
}

fn is_generated_artifact(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower
        .split('/')
        .any(|component| matches!(component, "generated" | "gen" | "codegen" | "artifacts"))
        || lower.contains(".generated.")
        || lower.ends_with(".g.rs")
        || lower.ends_with("routetree.gen.ts")
}

#[derive(Debug, Default)]
pub struct EventCoalescer {
    operations: Vec<IncrementalFileChange>,
    tracked_renames: BTreeMap<usize, (Option<String>, Option<String>)>,
    revision: u64,
}

impl EventCoalescer {
    pub fn push(&mut self, change: IncrementalFileChange) {
        self.operations.push(change);
        self.revision = self.revision.wrapping_add(1);
    }

    pub fn extend(&mut self, changes: impl IntoIterator<Item = IncrementalFileChange>) {
        for change in changes {
            self.push(change);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.operations.is_empty() && self.tracked_renames.is_empty()
    }

    pub fn len(&self) -> usize {
        self.operations.len() + self.tracked_renames.len()
    }

    pub fn clear(&mut self) {
        self.operations.clear();
        self.tracked_renames.clear();
        self.revision = 0;
    }

    pub fn drain(&mut self) -> Vec<IncrementalFileChange> {
        for (_, (from, to)) in std::mem::take(&mut self.tracked_renames) {
            match (from, to) {
                (Some(from), Some(to)) if from != to => {
                    self.operations
                        .push(IncrementalFileChange::renamed(from, to));
                }
                (Some(path), _) => self.operations.push(IncrementalFileChange::deleted(path)),
                (_, Some(path)) => self.operations.push(IncrementalFileChange::added(path)),
                (None, None) => {}
            }
        }
        self.revision = 0;
        coalesce_incremental_changes(std::mem::take(&mut self.operations))
    }

    fn track_rename_from(&mut self, tracker: usize, path: String) {
        self.tracked_renames.entry(tracker).or_default().0 = Some(path);
        self.revision = self.revision.wrapping_add(1);
    }

    fn track_rename_to(&mut self, tracker: usize, path: String) {
        self.tracked_renames.entry(tracker).or_default().1 = Some(path);
        self.revision = self.revision.wrapping_add(1);
    }

    fn revision(&self) -> u64 {
        self.revision
    }
}

#[derive(Debug)]
struct PathState {
    origin: Option<String>,
    modified: bool,
}

pub fn coalesce_incremental_changes(
    changes: impl IntoIterator<Item = IncrementalFileChange>,
) -> Vec<IncrementalFileChange> {
    let mut active = BTreeMap::<String, PathState>::new();
    let mut deleted = BTreeSet::<String>::new();
    for change in changes {
        match (change.kind, change.old_path, change.new_path) {
            (crate::IncrementalChangeKind::Added, None, Some(path)) => {
                if deleted.remove(&path) {
                    active.insert(
                        path.clone(),
                        PathState {
                            origin: Some(path),
                            modified: true,
                        },
                    );
                } else {
                    active
                        .entry(path)
                        .and_modify(|state| state.modified = true)
                        .or_insert(PathState {
                            origin: None,
                            modified: true,
                        });
                }
            }
            (crate::IncrementalChangeKind::Modified, None, Some(path)) => {
                let origin = deleted
                    .remove(&path)
                    .then(|| path.clone())
                    .or_else(|| (!active.contains_key(&path)).then(|| path.clone()));
                active
                    .entry(path)
                    .and_modify(|state| state.modified = true)
                    .or_insert(PathState {
                        origin,
                        modified: true,
                    });
            }
            (crate::IncrementalChangeKind::Deleted, Some(path), None) => {
                if let Some(state) = active.remove(&path) {
                    if let Some(origin) = state.origin {
                        deleted.insert(origin);
                    }
                } else {
                    deleted.insert(path);
                }
            }
            (crate::IncrementalChangeKind::Renamed, Some(from), Some(to)) if from != to => {
                if active
                    .get(&to)
                    .is_some_and(|state| state.origin.as_deref() == Some(from.as_str()))
                {
                    continue;
                }
                let state = active.remove(&from).unwrap_or_else(|| PathState {
                    origin: Some(from.clone()),
                    modified: false,
                });
                deleted.remove(&from);
                if let Some(displaced) = active.remove(&to)
                    && let Some(origin) = displaced.origin
                {
                    deleted.insert(origin);
                }
                active.insert(to, state);
            }
            _ => {}
        }
    }

    let mut result = deleted
        .into_iter()
        .map(IncrementalFileChange::deleted)
        .collect::<Vec<_>>();
    for (path, state) in active {
        match state.origin {
            None => result.push(IncrementalFileChange::added(path)),
            Some(origin) if origin != path => {
                result.push(IncrementalFileChange::renamed(origin, path));
            }
            Some(_) if state.modified => result.push(IncrementalFileChange::modified(path)),
            Some(_) => {}
        }
    }
    result.sort();
    result.dedup();
    result
}

struct RepositoryWatcher {
    _watcher: RecommendedWatcher,
    receiver: mpsc::UnboundedReceiver<notify::Result<Event>>,
    rules: WatchIgnoreRules,
}

impl RepositoryWatcher {
    fn start(rules: WatchIgnoreRules) -> Result<Self> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut watcher = notify::recommended_watcher(move |event| {
            let _ = sender.send(event);
        })
        .context("failed to initialize filesystem watcher")?;
        watcher
            .watch(&rules.root, RecursiveMode::Recursive)
            .with_context(|| format!("failed to watch {}", rules.root.display()))?;
        Ok(Self {
            _watcher: watcher,
            receiver,
            rules,
        })
    }

    async fn next(&mut self) -> Option<notify::Result<Event>> {
        self.receiver.recv().await
    }

    fn try_next(
        &mut self,
    ) -> std::result::Result<notify::Result<Event>, mpsc::error::TryRecvError> {
        self.receiver.try_recv()
    }

    fn ingest(&self, event: Event, coalescer: &mut EventCoalescer) -> Result<()> {
        if event.need_rescan() {
            coalescer.push(IncrementalFileChange::modified(".depgraph.toml"));
            return Ok(());
        }
        let paths = event
            .paths
            .iter()
            .map(|path| self.rules.classify(path))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|path| path.map(|path| path.relative_path))
            .collect::<Vec<_>>();
        match event.kind {
            EventKind::Access(_) => {}
            EventKind::Create(_) => {
                coalescer.extend(
                    paths
                        .into_iter()
                        .flatten()
                        .map(IncrementalFileChange::added),
                );
            }
            EventKind::Remove(_) => {
                coalescer.extend(
                    paths
                        .into_iter()
                        .flatten()
                        .map(IncrementalFileChange::deleted),
                );
            }
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
                ingest_rename_pairs(paths, coalescer);
            }
            EventKind::Modify(ModifyKind::Name(RenameMode::Any | RenameMode::Other)) => {
                if paths.len() >= 2 && paths.len().is_multiple_of(2) {
                    ingest_rename_pairs(paths, coalescer);
                } else {
                    coalescer.extend(
                        paths
                            .into_iter()
                            .flatten()
                            .map(IncrementalFileChange::modified),
                    );
                }
            }
            EventKind::Modify(ModifyKind::Name(RenameMode::From)) => {
                for path in paths.into_iter().flatten() {
                    if let Some(tracker) = event.tracker() {
                        coalescer.track_rename_from(tracker, path);
                    } else {
                        coalescer.push(IncrementalFileChange::deleted(path));
                    }
                }
            }
            EventKind::Modify(ModifyKind::Name(RenameMode::To)) => {
                for path in paths.into_iter().flatten() {
                    if let Some(tracker) = event.tracker() {
                        coalescer.track_rename_to(tracker, path);
                    } else {
                        coalescer.push(IncrementalFileChange::added(path));
                    }
                }
            }
            EventKind::Modify(_) | EventKind::Any | EventKind::Other => {
                coalescer.extend(
                    paths
                        .into_iter()
                        .flatten()
                        .map(IncrementalFileChange::modified),
                );
            }
        }
        Ok(())
    }
}

fn ingest_rename_pairs(paths: Vec<Option<String>>, coalescer: &mut EventCoalescer) {
    for pair in paths.chunks_exact(2) {
        match (&pair[0], &pair[1]) {
            (Some(from), Some(to)) if from != to => {
                coalescer.push(IncrementalFileChange::renamed(from.clone(), to.clone()));
            }
            (Some(path), None) => coalescer.push(IncrementalFileChange::deleted(path.clone())),
            (None, Some(path)) => coalescer.push(IncrementalFileChange::added(path.clone())),
            _ => {}
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DaemonPhase {
    Idle,
    Debouncing,
    Scanning,
    Cancelling,
    Stopping,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonScanRequest {
    pub attempt_id: String,
    pub changes: Vec<IncrementalFileChange>,
    pub started_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonScanOutcome {
    pub scan_id: Option<String>,
    pub status: String,
    pub completed_snapshot_id: Option<String>,
    pub base_snapshot_id: Option<String>,
    pub invalidation_plan: Option<IncrementalInvalidationPlan>,
    pub invalidation_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incremental_trace: Option<DaemonIncrementalTrace>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonIncrementalTrace {
    pub schema_version: String,
    pub mode: String,
    pub base_projection_milliseconds: u64,
    pub worker_capability_milliseconds: u64,
    pub worker_analysis_milliseconds: u64,
    pub store_commit_milliseconds: u64,
    pub total_milliseconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonAttempt {
    pub attempt_id: String,
    pub scan_id: Option<String>,
    pub status: String,
    pub started_at: String,
    pub finished_at: String,
    pub changes: Vec<IncrementalFileChange>,
    pub base_snapshot_id: Option<String>,
    pub completed_snapshot_id: Option<String>,
    pub invalidation_plan: Option<IncrementalInvalidationPlan>,
    pub invalidation_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incremental_trace: Option<DaemonIncrementalTrace>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub schema_version: String,
    pub root: String,
    pub phase: DaemonPhase,
    pub started_at: String,
    pub stopped_at: Option<String>,
    pub debounce_milliseconds: u64,
    pub pending_change_count: usize,
    pub active_attempt_id: Option<String>,
    pub last_completed_attempt: Option<DaemonAttempt>,
    pub last_failed_attempt: Option<DaemonAttempt>,
    pub last_cancelled_attempt: Option<DaemonAttempt>,
    pub last_watcher_error: Option<String>,
    pub recovered_attempts: InterruptedAttemptRecovery,
}

pub type DaemonScanFuture =
    Pin<Box<dyn Future<Output = Result<DaemonScanOutcome>> + Send + 'static>>;

pub trait DaemonScanRunner: Send + Sync + 'static {
    fn run(&self, request: DaemonScanRequest, cancellation: CancellationToken) -> DaemonScanFuture;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct IncrementalWorkerTrace {
    pub capability_probe_milliseconds: u64,
    pub analysis_milliseconds: u64,
}

#[derive(Debug)]
pub enum IncrementalWorkerOutcome {
    Unsupported {
        reason: String,
        trace: IncrementalWorkerTrace,
    },
    Delta {
        delta: Box<ValidatedDelta>,
        stderr: String,
        stderr_truncated: bool,
        trace: IncrementalWorkerTrace,
    },
}

pub type IncrementalWorkerFuture =
    Pin<Box<dyn Future<Output = Result<IncrementalWorkerOutcome>> + Send + 'static>>;

pub trait IncrementalWorkerExecutor: Send + Sync + 'static {
    fn run(
        &self,
        root: PathBuf,
        config: Config,
        request: WorkerDeltaRequest,
        cancellation: CancellationToken,
    ) -> IncrementalWorkerFuture;
}

#[derive(Debug, Default)]
struct ProcessIncrementalWorkerExecutor;

impl IncrementalWorkerExecutor for ProcessIncrementalWorkerExecutor {
    fn run(
        &self,
        root: PathBuf,
        config: Config,
        request: WorkerDeltaRequest,
        cancellation: CancellationToken,
    ) -> IncrementalWorkerFuture {
        Box::pin(async move {
            let capability_started = Instant::now();
            let Some(adapter) = AdapterKind::from_name(&request.adapter) else {
                return Ok(IncrementalWorkerOutcome::Unsupported {
                    reason: format!("unknown delta adapter {}", request.adapter),
                    trace: IncrementalWorkerTrace {
                        capability_probe_milliseconds: elapsed_milliseconds(capability_started),
                        analysis_milliseconds: 0,
                    },
                });
            };
            let spec = match locate_worker(adapter) {
                Ok(spec) => spec,
                Err(error) => {
                    return Ok(IncrementalWorkerOutcome::Unsupported {
                        reason: format!("delta worker unavailable: {error:#}"),
                        trace: IncrementalWorkerTrace {
                            capability_probe_milliseconds: elapsed_milliseconds(capability_started),
                            analysis_milliseconds: 0,
                        },
                    });
                }
            };
            let handshake =
                match probe_worker_version_with_cancellation(&spec, &root, &cancellation).await {
                    Ok(handshake) => handshake,
                    Err(error) if cancellation.is_cancelled() => {
                        return Err(error).context("delta capability probe was cancelled");
                    }
                    Err(error) => {
                        return Ok(IncrementalWorkerOutcome::Unsupported {
                            reason: format!("delta capability probe failed: {error:#}"),
                            trace: IncrementalWorkerTrace {
                                capability_probe_milliseconds: elapsed_milliseconds(
                                    capability_started,
                                ),
                                analysis_milliseconds: 0,
                            },
                        });
                    }
                };
            let capability_probe_milliseconds = elapsed_milliseconds(capability_started);
            let core_capabilities = vec![WORKER_DELTA_CAPABILITY.to_owned()];
            let worker_capabilities = worker_capabilities(&handshake);
            if negotiate_worker_protocol(&core_capabilities, &worker_capabilities)
                != WorkerProtocolMode::DeltaV1
            {
                return Ok(IncrementalWorkerOutcome::Unsupported {
                    reason: format!(
                        "{} worker does not advertise {WORKER_DELTA_CAPABILITY}",
                        adapter.name()
                    ),
                    trace: IncrementalWorkerTrace {
                        capability_probe_milliseconds,
                        analysis_milliseconds: 0,
                    },
                });
            }
            let analysis_started = Instant::now();
            let output = execute_worker_delta_with_cancellation(
                spec,
                root,
                config.scan,
                config.profiles,
                request,
                cancellation,
            )
            .await;
            let analysis_milliseconds = elapsed_milliseconds(analysis_started);
            let trace = IncrementalWorkerTrace {
                capability_probe_milliseconds,
                analysis_milliseconds,
            };
            if output.adapter != adapter {
                bail!("delta worker returned a different adapter");
            }
            if let Some(error) = output.error {
                let kind = output
                    .failure_kind
                    .map_or("other", |failure| failure.as_str());
                if output.security_violation {
                    bail!("security policy violation: delta worker failed ({kind}): {error}");
                }
                if output.failure_kind == Some(WorkerFailureKind::NonzeroExit)
                    && output
                        .stderr
                        .starts_with("depgraph-web-worker: incremental fallback required:")
                {
                    return Ok(IncrementalWorkerOutcome::Unsupported {
                        reason: output.stderr.trim().to_owned(),
                        trace,
                    });
                }
                bail!("delta worker failed ({kind}): {error}");
            }
            let delta = output
                .delta
                .context("delta-capable worker completed without a validated delta")?;
            Ok(IncrementalWorkerOutcome::Delta {
                delta: Box::new(delta),
                stderr: output.stderr,
                stderr_truncated: output.stderr_truncated,
                trace,
            })
        })
    }
}

#[derive(Clone)]
pub struct RepositoryScanRunner {
    root: PathBuf,
    store_path: PathBuf,
    config: Config,
    strict: bool,
    incremental_worker: Arc<dyn IncrementalWorkerExecutor>,
}

impl std::fmt::Debug for RepositoryScanRunner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RepositoryScanRunner")
            .field("root", &self.root)
            .field("store_path", &self.store_path)
            .field("config", &self.config)
            .field("strict", &self.strict)
            .finish_non_exhaustive()
    }
}

impl RepositoryScanRunner {
    pub fn new(root: PathBuf, store_path: PathBuf, config: Config, strict: bool) -> Self {
        Self {
            root,
            store_path,
            config,
            strict,
            incremental_worker: Arc::new(ProcessIncrementalWorkerExecutor),
        }
    }

    pub fn with_incremental_worker(mut self, worker: Arc<dyn IncrementalWorkerExecutor>) -> Self {
        self.incremental_worker = worker;
        self
    }
}

impl DaemonScanRunner for RepositoryScanRunner {
    fn run(&self, request: DaemonScanRequest, cancellation: CancellationToken) -> DaemonScanFuture {
        let root = self.root.clone();
        let store_path = self.store_path.clone();
        let config = self.config.clone();
        let strict = self.strict;
        let incremental_worker = self.incremental_worker.clone();
        Box::pin(async move {
            let attempt_started = Instant::now();
            if cancellation.is_cancelled() {
                return Ok(DaemonScanOutcome {
                    scan_id: None,
                    status: "cancelled".to_owned(),
                    completed_snapshot_id: None,
                    base_snapshot_id: None,
                    invalidation_plan: None,
                    invalidation_error: None,
                    incremental_trace: None,
                });
            }
            let mut store = open_store(&store_path)?;
            let base_snapshot_id = store.current_snapshot_id()?;
            let current_profile_plan_id =
                plan_repository_profiles(&root, &config, None)?.plan.plan_id;
            let base_profile_plan_id = base_snapshot_id
                .as_deref()
                .map(|snapshot_id| store.load_completed_snapshot_profiles(snapshot_id))
                .transpose()?
                .as_ref()
                .map(|profiles| profile_records_profile_plan_id(profiles))
                .transpose()?
                .flatten();
            let mut force_full_scan =
                base_profile_plan_id.as_deref() != Some(current_profile_plan_id.as_str());
            if let (Some(base_snapshot_id), Some(path)) = (
                base_snapshot_id.as_deref().filter(|_| !force_full_scan),
                semantic_noop_change_path(&request.changes),
            ) {
                let base_projection_started = Instant::now();
                let semantic_base = store.semantic_noop_delta_base(base_snapshot_id, path)?;
                let base_projection_milliseconds = elapsed_milliseconds(base_projection_started);
                if let Some(base) = semantic_base {
                    let scan_id = Uuid::new_v4().to_string();
                    let delta_request = build_semantic_noop_worker_delta_request(
                        &scan_id,
                        &request.changes,
                        &base,
                    )?;
                    let plan = semantic_noop_invalidation_plan(
                        base_snapshot_id,
                        &request.changes,
                        path,
                        &base,
                        &current_profile_plan_id,
                    )?;
                    match incremental_worker
                        .run(
                            root.clone(),
                            config.clone(),
                            delta_request,
                            cancellation.clone(),
                        )
                        .await
                    {
                        Ok(IncrementalWorkerOutcome::Unsupported { reason, .. }) => {
                            tracing::debug!(
                                reason,
                                "semantic no-op delta unavailable; planning complete fallback"
                            );
                        }
                        Ok(IncrementalWorkerOutcome::Delta {
                            delta,
                            stderr,
                            stderr_truncated,
                            trace,
                        }) => {
                            if cancellation.is_cancelled() {
                                return Ok(cancelled_daemon_outcome(base_snapshot_id, Some(plan)));
                            }
                            if !profile_selection_plan_matches(
                                &root,
                                &config,
                                &current_profile_plan_id,
                            ) {
                                tracing::debug!(
                                    "profile selection changed during semantic no-op analysis; using full scan"
                                );
                                force_full_scan = true;
                            } else {
                                let source_revision = git_source_revision(&root);
                                let health_provenance = ScanHealthProvenance {
                                    policy_config_digest: health_policy_config_digest(
                                        &config.policy,
                                    )?,
                                    analyzer_version: HEALTH_ANALYZER_VERSION.to_owned(),
                                    finding_contract_version: HEALTH_FINDING_CONTRACT_VERSION
                                        .to_owned(),
                                };
                                let store_commit_started = Instant::now();
                                match store.commit_semantic_noop_delta(
                                    &scan_id,
                                    &root,
                                    strict,
                                    base_snapshot_id,
                                    source_revision.as_deref(),
                                    &health_provenance,
                                    &delta,
                                    &stderr,
                                    stderr_truncated,
                                ) {
                                    Ok(completed_snapshot_id) => {
                                        return Ok(DaemonScanOutcome {
                                            scan_id: Some(scan_id),
                                            status: "completed".to_owned(),
                                            completed_snapshot_id: Some(completed_snapshot_id),
                                            base_snapshot_id: Some(base_snapshot_id.to_owned()),
                                            invalidation_plan: Some(plan),
                                            invalidation_error: None,
                                            incremental_trace: Some(DaemonIncrementalTrace {
                                                schema_version:
                                                    DAEMON_INCREMENTAL_TRACE_SCHEMA_VERSION
                                                        .to_owned(),
                                                mode: "semantic_noop".to_owned(),
                                                base_projection_milliseconds,
                                                worker_capability_milliseconds: trace
                                                    .capability_probe_milliseconds,
                                                worker_analysis_milliseconds: trace
                                                    .analysis_milliseconds,
                                                store_commit_milliseconds: elapsed_milliseconds(
                                                    store_commit_started,
                                                ),
                                                total_milliseconds: elapsed_milliseconds(
                                                    attempt_started,
                                                ),
                                            }),
                                        });
                                    }
                                    Err(error) => {
                                        return Ok(DaemonScanOutcome {
                                            scan_id: Some(scan_id),
                                            status: "failed".to_owned(),
                                            completed_snapshot_id: None,
                                            base_snapshot_id: Some(base_snapshot_id.to_owned()),
                                            invalidation_plan: Some(plan),
                                            invalidation_error: Some(format!(
                                                "semantic no-op delta failed: {error:#}"
                                            )),
                                            incremental_trace: None,
                                        });
                                    }
                                }
                            }
                        }
                        Err(error) if cancellation.is_cancelled() => {
                            let _ = error;
                            return Ok(cancelled_daemon_outcome(base_snapshot_id, Some(plan)));
                        }
                        Err(error) if !is_security_error(&format!("{error:#}")) => {
                            tracing::debug!(
                                error = %format!("{error:#}"),
                                "semantic no-op worker failed; using full scan fallback"
                            );
                            force_full_scan = true;
                        }
                        Err(error) => {
                            return Ok(DaemonScanOutcome {
                                scan_id: None,
                                status: "failed".to_owned(),
                                completed_snapshot_id: None,
                                base_snapshot_id: Some(base_snapshot_id.to_owned()),
                                invalidation_plan: Some(plan),
                                invalidation_error: Some(format!(
                                    "semantic no-op worker failed: {error:#}"
                                )),
                                incremental_trace: None,
                            });
                        }
                    }
                }
            }
            let (invalidation_plan, invalidation_error) = if let Some(base_snapshot_id) =
                base_snapshot_id.as_deref()
            {
                let snapshot = store.load_completed_snapshot(base_snapshot_id)?;
                match plan_incremental_invalidation(base_snapshot_id, &snapshot, &request.changes) {
                    Ok(plan) => (Some(plan), None),
                    Err(error) => (
                        None,
                        Some(format!(
                            "incremental planner failed; full scan used: {error:#}"
                        )),
                    ),
                }
            } else {
                (None, None)
            };

            if let (Some(base_snapshot_id), Some(plan)) =
                (base_snapshot_id.as_deref(), invalidation_plan.as_ref())
            {
                let scan_id = Uuid::new_v4().to_string();
                let base = if !force_full_scan && worker_delta_plan_is_eligible(plan) {
                    Some(store.delta_base_graph(base_snapshot_id)?)
                } else {
                    None
                };
                if let Some(base) = base.as_ref()
                    && let Some(delta_request) = build_worker_delta_request(&scan_id, plan, base)?
                {
                    match incremental_worker
                        .run(
                            root.clone(),
                            config.clone(),
                            delta_request,
                            cancellation.clone(),
                        )
                        .await
                    {
                        Ok(IncrementalWorkerOutcome::Unsupported { reason, .. }) => {
                            tracing::debug!(
                                reason,
                                "incremental delta unavailable; using full scan"
                            );
                        }
                        Ok(IncrementalWorkerOutcome::Delta {
                            delta,
                            stderr,
                            stderr_truncated,
                            ..
                        }) => {
                            if cancellation.is_cancelled() {
                                return Ok(cancelled_daemon_outcome(
                                    base_snapshot_id,
                                    Some(plan.clone()),
                                ));
                            }
                            if !profile_selection_plan_matches(
                                &root,
                                &config,
                                &current_profile_plan_id,
                            ) {
                                tracing::debug!(
                                    "profile selection changed during incremental analysis; using full scan"
                                );
                            } else {
                                let source_revision = git_source_revision(&root);
                                let health_provenance = ScanHealthProvenance {
                                    policy_config_digest: health_policy_config_digest(
                                        &config.policy,
                                    )
                                    .context("failed to normalize health policy identity")?,
                                    analyzer_version: HEALTH_ANALYZER_VERSION.to_owned(),
                                    finding_contract_version: HEALTH_FINDING_CONTRACT_VERSION
                                        .to_owned(),
                                };
                                store.start_incremental_scan_with_revision(
                                    &scan_id,
                                    &root,
                                    strict,
                                    base_snapshot_id,
                                    source_revision.as_deref(),
                                )?;
                                store.bind_scan_health_provenance(&scan_id, &health_provenance)?;
                                let result = (|| -> Result<crate::ScanOutcome> {
                                    if cancellation.is_cancelled() {
                                        return cancel_scan(&mut store, &scan_id);
                                    }
                                    store.save_adapter_log(
                                        &scan_id,
                                        &delta.scope.adapters[0],
                                        &stderr,
                                        stderr_truncated,
                                    )?;
                                    store.stage_incremental_delta(&scan_id, &delta)?;
                                    if cancellation.is_cancelled() {
                                        return cancel_scan(&mut store, &scan_id);
                                    }
                                    store.apply_staged_incremental_delta(
                                        &scan_id,
                                        &delta.delta_id,
                                    )?;
                                    if cancellation.is_cancelled() {
                                        return cancel_scan(&mut store, &scan_id);
                                    }
                                    complete_scan(
                                        &mut store,
                                        &scan_id,
                                        strict,
                                        &config,
                                        None,
                                        &cancellation,
                                    )
                                })();
                                match result {
                                    Ok(outcome) => {
                                        return daemon_outcome_from_scan(
                                            &store,
                                            outcome,
                                            base_snapshot_id,
                                            plan.clone(),
                                            None,
                                        );
                                    }
                                    Err(error) => {
                                        let message =
                                            format!("incremental delta failed: {error:#}");
                                        if store
                                            .scan(&scan_id)?
                                            .is_some_and(|scan| scan.status == "staging")
                                        {
                                            store.finish_scan(
                                                &scan_id,
                                                "failed",
                                                Some(&message),
                                                false,
                                            )?;
                                        }
                                        return Ok(DaemonScanOutcome {
                                            scan_id: Some(scan_id),
                                            status: "failed".to_owned(),
                                            completed_snapshot_id: None,
                                            base_snapshot_id: Some(base_snapshot_id.to_owned()),
                                            invalidation_plan: Some(plan.clone()),
                                            invalidation_error: Some(message),
                                            incremental_trace: None,
                                        });
                                    }
                                }
                            }
                        }
                        Err(error) if cancellation.is_cancelled() => {
                            let _ = error;
                            return Ok(cancelled_daemon_outcome(
                                base_snapshot_id,
                                Some(plan.clone()),
                            ));
                        }
                        Err(error) => {
                            return Ok(DaemonScanOutcome {
                                scan_id: None,
                                status: "failed".to_owned(),
                                completed_snapshot_id: None,
                                base_snapshot_id: Some(base_snapshot_id.to_owned()),
                                invalidation_plan: Some(plan.clone()),
                                invalidation_error: Some(format!(
                                    "incremental worker failed: {error:#}"
                                )),
                                incremental_trace: None,
                            });
                        }
                    }
                } else {
                    tracing::debug!(
                        scope_paths = plan.replacement_scope.paths.len(),
                        max_scope_paths = MAX_WORKER_DELTA_SCOPE_PATHS,
                        "incremental invalidation plan requires the full-snapshot fallback"
                    );
                }
            }

            let outcome = run_scan_with_cache_mode_and_cancellation(
                &mut store,
                root,
                &config,
                strict,
                ScanCacheMode::Enabled,
                cancellation,
            )
            .await?;
            let completed_snapshot_id = if outcome.status == "completed" {
                store.current_snapshot_id()?
            } else {
                None
            };
            Ok(DaemonScanOutcome {
                scan_id: Some(outcome.scan_id),
                status: outcome.status,
                completed_snapshot_id,
                base_snapshot_id,
                invalidation_plan,
                invalidation_error,
                incremental_trace: None,
            })
        })
    }
}

fn profile_selection_plan_matches(root: &Path, config: &Config, expected_plan_id: &str) -> bool {
    plan_repository_profiles(root, config, None)
        .is_ok_and(|preview| preview.plan.plan_id == expected_plan_id)
}

fn semantic_noop_change_path(changes: &[IncrementalFileChange]) -> Option<&str> {
    match changes {
        [change]
            if matches!(
                change.kind,
                IncrementalChangeKind::Added | IncrementalChangeKind::Modified
            ) =>
        {
            change.new_path.as_deref()
        }
        _ => None,
    }
}

fn build_semantic_noop_worker_delta_request(
    scan_id: &str,
    changes: &[IncrementalFileChange],
    base: &depgraph_protocol::DeltaBaseGraph,
) -> Result<WorkerDeltaRequest> {
    let path = semantic_noop_change_path(changes)
        .context("semantic no-op worker request requires one existing file write")?;
    WorkerDeltaRequest::new_semantic_noop(
        scan_id,
        "web",
        changes
            .iter()
            .map(|change| WorkerDeltaFileChange {
                kind: match change.kind {
                    IncrementalChangeKind::Added => WorkerDeltaFileChangeKind::Added,
                    IncrementalChangeKind::Modified => WorkerDeltaFileChangeKind::Modified,
                    IncrementalChangeKind::Deleted => WorkerDeltaFileChangeKind::Deleted,
                    IncrementalChangeKind::Renamed => WorkerDeltaFileChangeKind::Renamed,
                },
                old_path: change.old_path.clone(),
                new_path: change.new_path.clone(),
            })
            .collect(),
        DeltaScope {
            paths: vec![path.to_owned()],
            package_locators: Vec::new(),
            profile_ids: base.profiles.iter().cloned().collect(),
            artifact_node_ids: Vec::new(),
            adapters: vec!["web".to_owned()],
        },
        base,
    )
    .map_err(Into::into)
}

fn semantic_noop_invalidation_plan(
    base_snapshot_id: &str,
    changes: &[IncrementalFileChange],
    path: &str,
    base: &depgraph_protocol::DeltaBaseGraph,
    base_profile_plan_id: &str,
) -> Result<IncrementalInvalidationPlan> {
    let affected_profile_ids = base.profiles.iter().cloned().collect::<Vec<_>>();
    let affected_package_locators = base
        .nodes
        .values()
        .filter_map(|node| {
            node.properties
                .get("package_locator")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let replacement_scope = IncrementalReplacementScope::new(
        [path.to_owned()],
        affected_package_locators.iter().cloned(),
        affected_profile_ids.iter().cloned(),
        std::iter::empty(),
        std::iter::empty(),
        ["web".to_owned()],
    )?;
    Ok(IncrementalInvalidationPlan {
        schema_version: INCREMENTAL_PLAN_SCHEMA_VERSION.to_owned(),
        base_snapshot_id: base_snapshot_id.to_owned(),
        base_profile_plan_id: Some(base_profile_plan_id.to_owned()),
        mode: IncrementalInvalidationMode::ScopedReplacement,
        changes: changes.to_vec(),
        reasons: vec![IncrementalInvalidationReason::SourceChanged],
        affected_package_locators,
        affected_profile_ids,
        affected_generated_artifact_ids: Vec::new(),
        replacement_scope,
    })
}

fn worker_delta_plan_is_eligible(plan: &IncrementalInvalidationPlan) -> bool {
    plan.mode == IncrementalInvalidationMode::ScopedReplacement
        && plan.replacement_scope.replanned_profile_ids.is_empty()
        && plan.replacement_scope.adapters.len() == 1
        && plan.replacement_scope.paths.len() <= MAX_WORKER_DELTA_SCOPE_PATHS
}

fn build_worker_delta_request(
    scan_id: &str,
    plan: &IncrementalInvalidationPlan,
    base: &depgraph_protocol::DeltaBaseGraph,
) -> Result<Option<WorkerDeltaRequest>> {
    if !worker_delta_plan_is_eligible(plan) {
        return Ok(None);
    }
    let adapter = plan.replacement_scope.adapters[0].clone();
    let scope = DeltaScope {
        paths: plan.replacement_scope.paths.clone(),
        package_locators: plan.replacement_scope.package_locators.clone(),
        profile_ids: plan.replacement_scope.profile_ids.clone(),
        artifact_node_ids: plan.replacement_scope.artifact_node_ids.clone(),
        adapters: vec![adapter.clone()],
    };
    let changes = plan
        .changes
        .iter()
        .map(|change| WorkerDeltaFileChange {
            kind: match change.kind {
                IncrementalChangeKind::Added => WorkerDeltaFileChangeKind::Added,
                IncrementalChangeKind::Modified => WorkerDeltaFileChangeKind::Modified,
                IncrementalChangeKind::Deleted => WorkerDeltaFileChangeKind::Deleted,
                IncrementalChangeKind::Renamed => WorkerDeltaFileChangeKind::Renamed,
            },
            old_path: change.old_path.clone(),
            new_path: change.new_path.clone(),
        })
        .collect();
    Ok(Some(WorkerDeltaRequest::new(
        scan_id, adapter, changes, scope, base,
    )?))
}

fn cancelled_daemon_outcome(
    base_snapshot_id: &str,
    invalidation_plan: Option<IncrementalInvalidationPlan>,
) -> DaemonScanOutcome {
    DaemonScanOutcome {
        scan_id: None,
        status: "cancelled".to_owned(),
        completed_snapshot_id: None,
        base_snapshot_id: Some(base_snapshot_id.to_owned()),
        invalidation_plan,
        invalidation_error: None,
        incremental_trace: None,
    }
}

fn daemon_outcome_from_scan(
    store: &depgraph_store::Store,
    outcome: crate::ScanOutcome,
    base_snapshot_id: &str,
    invalidation_plan: IncrementalInvalidationPlan,
    invalidation_error: Option<String>,
) -> Result<DaemonScanOutcome> {
    let completed_snapshot_id = if outcome.status == "completed" {
        store.current_snapshot_id()?
    } else {
        None
    };
    Ok(DaemonScanOutcome {
        scan_id: Some(outcome.scan_id),
        status: outcome.status,
        completed_snapshot_id,
        base_snapshot_id: Some(base_snapshot_id.to_owned()),
        invalidation_plan: Some(invalidation_plan),
        invalidation_error,
        incremental_trace: None,
    })
}

pub struct DaemonHandle {
    stop_sender: Option<oneshot::Sender<()>>,
    status: watch::Receiver<DaemonStatus>,
    task: Option<JoinHandle<DaemonStatus>>,
}

impl DaemonHandle {
    pub fn status(&self) -> DaemonStatus {
        self.status.borrow().clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<DaemonStatus> {
        self.status.clone()
    }

    pub async fn stop(mut self) -> Result<DaemonStatus> {
        if let Some(sender) = self.stop_sender.take() {
            let _ = sender.send(());
        }
        let task = self.task.take().context("daemon task is unavailable")?;
        task.await.context("daemon task failed")
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        if let Some(sender) = self.stop_sender.take() {
            let _ = sender.send(());
        }
    }
}

pub fn start_repository_daemon(
    root: PathBuf,
    store_path: PathBuf,
    config: Config,
    strict: bool,
) -> Result<DaemonHandle> {
    let requested_root = root.clone();
    let root = root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize daemon root {}", root.display()))?;
    let store_path = absolute_normalized_path(store_path)?;
    let locks = acquire_daemon_locks(&store_path)?;
    let mut store = open_store(&store_path)?;
    let recovered = store.recover_interrupted_attempts(&root)?;
    let runner = Arc::new(RepositoryScanRunner::new(
        root.clone(),
        store_path.clone(),
        config.clone(),
        strict,
    ));
    start_daemon_with_runner_and_lock(
        requested_root,
        config.daemon,
        Some(store_path),
        recovered,
        runner,
        Some(locks),
    )
}

pub fn start_daemon_with_runner(
    root: PathBuf,
    config: DaemonConfig,
    store_path: Option<PathBuf>,
    recovered_attempts: InterruptedAttemptRecovery,
    runner: Arc<dyn DaemonScanRunner>,
) -> Result<DaemonHandle> {
    let store_path = store_path.map(absolute_normalized_path).transpose()?;
    let locks = store_path
        .as_deref()
        .map(acquire_daemon_locks)
        .transpose()?;
    start_daemon_with_runner_and_lock(root, config, store_path, recovered_attempts, runner, locks)
}

fn start_daemon_with_runner_and_lock(
    root: PathBuf,
    config: DaemonConfig,
    store_path: Option<PathBuf>,
    recovered_attempts: InterruptedAttemptRecovery,
    runner: Arc<dyn DaemonScanRunner>,
    locks: Option<DaemonLocks>,
) -> Result<DaemonHandle> {
    let requested_root = root.clone();
    let root = root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize daemon root {}", root.display()))?;
    let rules = WatchIgnoreRules::new(
        &requested_root,
        &config.ignored_paths,
        store_path.as_deref(),
    )?;
    let watcher = RepositoryWatcher::start(rules)?;
    let started_at = timestamp();
    let status = DaemonStatus {
        schema_version: DAEMON_STATUS_SCHEMA_VERSION.to_owned(),
        root: root.to_string_lossy().into_owned(),
        phase: DaemonPhase::Idle,
        started_at,
        stopped_at: None,
        debounce_milliseconds: config.debounce_milliseconds,
        pending_change_count: 0,
        active_attempt_id: None,
        last_completed_attempt: None,
        last_failed_attempt: None,
        last_cancelled_attempt: None,
        last_watcher_error: None,
        recovered_attempts,
    };
    let (status_sender, status_receiver) = watch::channel(status.clone());
    let (stop_sender, stop_receiver) = oneshot::channel();
    let task = tokio::spawn(run_daemon_loop(
        watcher,
        runner,
        Duration::from_millis(config.debounce_milliseconds),
        status,
        status_sender,
        stop_receiver,
        locks,
    ));
    Ok(DaemonHandle {
        stop_sender: Some(stop_sender),
        status: status_receiver,
        task: Some(task),
    })
}

/// Acquires the per-store writer lock shared by daemon and foreground scans.
///
/// The returned guard must remain alive for the full duration of the writer.
pub fn acquire_store_writer_lock(store_path: &Path) -> Result<StoreLockGuard> {
    acquire_store_sidecar_lock(
        store_path,
        ".writer-lock",
        "store writer",
        "another store writer is already running",
    )
}

/// Exclusive advisory lock on a store sidecar file.
///
/// The lock is released synchronously when the guard is dropped or when
/// [`StoreLockGuard::unlock`] is called, whichever happens first.
#[derive(Debug)]
pub struct StoreLockGuard {
    file: std::fs::File,
}

impl StoreLockGuard {
    /// Release the lock now, before the guard is dropped.
    ///
    /// Callers that must observe a release failure use this instead of
    /// relying on drop; unlocking an already-unlocked file is harmless.
    pub fn unlock(&self) -> std::io::Result<()> {
        self.file.unlock()
    }
}

impl Drop for StoreLockGuard {
    fn drop(&mut self) {
        // Closing the descriptor only releases an advisory lock once every
        // reference to the open file description is gone. A child process
        // spawned concurrently by any thread briefly inherits a duplicate of
        // this descriptor, so close-on-drop can leave the lock held until that
        // child finishes exec, and an immediate reacquire in this process then
        // fails with a spurious conflict. An explicit unlock releases the lock
        // regardless of how many references still exist.
        let _ = self.file.unlock();
    }
}

struct DaemonLocks {
    writer: StoreLockGuard,
    lifecycle: StoreLockGuard,
}

impl DaemonLocks {
    fn unlock(&self) -> Result<()> {
        // A caller may restart the daemon as soon as stop() completes. Release
        // both exclusions before publishing that completion because relying on
        // close-on-drop can leave a transient self-conflict on some hosts.
        let lifecycle = self
            .lifecycle
            .unlock()
            .context("failed to release the daemon lifecycle lock");
        let writer = self
            .writer
            .unlock()
            .context("failed to release the daemon store-writer lock");
        lifecycle?;
        writer
    }
}

fn acquire_daemon_locks(store_path: &Path) -> Result<DaemonLocks> {
    let writer = acquire_store_writer_lock(store_path)?;
    let lifecycle = acquire_store_sidecar_lock(
        store_path,
        ".daemon-lock",
        "daemon lifecycle",
        "a daemon is already running",
    )?;
    Ok(DaemonLocks { writer, lifecycle })
}

fn acquire_store_sidecar_lock(
    store_path: &Path,
    suffix: &str,
    description: &str,
    contention: &str,
) -> Result<StoreLockGuard> {
    let lock_path = with_path_suffix(store_path, suffix);
    let parent = lock_path
        .parent()
        .with_context(|| format!("{description} lock path has no parent"))?;
    std::fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create {description} lock directory {}",
            parent.display()
        )
    })?;
    if let Ok(metadata) = std::fs::symlink_metadata(&lock_path)
        && !metadata.file_type().is_file()
    {
        bail!(
            "{description} lock path {} is not a regular file",
            lock_path.display()
        );
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("failed to open {description} lock {}", lock_path.display()))?;
    file.try_lock()
        .with_context(|| format!("{contention} for store {}", store_path.display()))?;
    Ok(StoreLockGuard { file })
}

fn absolute_normalized_path(path: PathBuf) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .context("failed to resolve the current directory")?
            .join(path)
    };
    Ok(canonicalize_nearest_existing_ancestor(&absolute).unwrap_or(absolute))
}

fn with_path_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

struct ActiveAttempt {
    request: DaemonScanRequest,
    cancellation: CancellationToken,
    completion: oneshot::Receiver<Result<DaemonScanOutcome>>,
    task: JoinHandle<()>,
    shutdown_flush: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttemptDisposition {
    Completed,
    Cancelled,
    Failed,
}

async fn run_daemon_loop(
    mut watcher: RepositoryWatcher,
    runner: Arc<dyn DaemonScanRunner>,
    debounce: Duration,
    mut status: DaemonStatus,
    status_sender: watch::Sender<DaemonStatus>,
    mut stop_receiver: oneshot::Receiver<()>,
    locks: Option<DaemonLocks>,
) -> DaemonStatus {
    let mut coalescer = EventCoalescer::default();
    let mut deadline = None::<Instant>;
    let mut active = None::<ActiveAttempt>;
    let mut stopping = false;
    let mut consecutive_failures = 0_u32;
    let mut watcher_open = true;
    let mut pending_watcher_event = None;

    loop {
        if active.is_none()
            && !coalescer.is_empty()
            && (stopping || deadline.is_some_and(|deadline| deadline <= Instant::now()))
        {
            let changes = coalescer.drain();
            deadline = None;
            if !changes.is_empty() {
                active = Some(spawn_attempt(runner.clone(), changes, stopping));
                status.phase = if stopping {
                    DaemonPhase::Stopping
                } else {
                    DaemonPhase::Scanning
                };
                status.pending_change_count = 0;
                status.active_attempt_id = active
                    .as_ref()
                    .map(|active| active.request.attempt_id.clone());
                publish_status(&status_sender, &status);
                continue;
            }
        }
        if stopping && active.is_none() && coalescer.is_empty() {
            match watcher.try_next() {
                Ok(event) => pending_watcher_event = Some(event),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        let timer_deadline =
            deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400));
        let timer = sleep_until(timer_deadline);
        tokio::pin!(timer);
        tokio::select! {
            _ = &mut stop_receiver, if !stopping => {
                stopping = true;
                deadline = None;
                status.pending_change_count = coalescer.len();
                status.phase = DaemonPhase::Stopping;
                if let Some(active) = &active {
                    active.cancellation.cancel();
                }
                publish_status(&status_sender, &status);
            }
            event = async {
                if let Some(event) = pending_watcher_event.take() {
                    Some(event)
                } else {
                    watcher.next().await
                }
            }, if watcher_open || pending_watcher_event.is_some() => {
                match event {
                    Some(Ok(event)) => {
                        let revision_before = coalescer.revision();
                        if let Err(error) = watcher.ingest(event, &mut coalescer) {
                            status.last_watcher_error = Some(format!("{error:#}"));
                            publish_status(&status_sender, &status);
                        }
                        if coalescer.revision() != revision_before {
                            consecutive_failures = 0;
                            deadline = if stopping {
                                None
                            } else {
                                Some(Instant::now() + debounce)
                            };
                            status.pending_change_count = coalescer.len();
                            if let Some(active) = &active {
                                active.cancellation.cancel();
                                status.phase = if stopping {
                                    DaemonPhase::Stopping
                                } else {
                                    DaemonPhase::Cancelling
                                };
                            } else {
                                status.phase = if stopping {
                                    DaemonPhase::Stopping
                                } else {
                                    DaemonPhase::Debouncing
                                };
                            }
                            publish_status(&status_sender, &status);
                        }
                    }
                    Some(Err(error)) => {
                        status.last_watcher_error = Some(error.to_string());
                        publish_status(&status_sender, &status);
                    }
                    None => {
                        watcher_open = false;
                        stopping = true;
                        deadline = None;
                        status.last_watcher_error = Some("filesystem watcher stopped unexpectedly".to_owned());
                        status.phase = DaemonPhase::Stopping;
                        if let Some(active) = &active {
                            active.cancellation.cancel();
                        }
                        publish_status(&status_sender, &status);
                    }
                }
            }
            _ = &mut timer, if deadline.is_some() && active.is_none() => {}
            completion = async {
                (&mut active
                    .as_mut()
                    .expect("active attempt is guarded")
                    .completion)
                    .await
            }, if active.is_some() => {
                let finished = active.take().expect("active attempt exists");
                let result = match completion {
                    Ok(result) => result,
                    Err(_) => Err(anyhow::anyhow!("daemon scan task exited without an outcome")),
                };
                let disposition = match &result {
                    Ok(outcome) if outcome.status == "completed" => AttemptDisposition::Completed,
                    Ok(outcome) if outcome.status == "cancelled" => AttemptDisposition::Cancelled,
                    _ => AttemptDisposition::Failed,
                };
                let retry_changes = finished.request.changes.clone();
                let shutdown_flush = finished.shutdown_flush;
                let _ = finished.task.await;
                record_attempt(&mut status, finished.request, result);
                if disposition == AttemptDisposition::Completed {
                    consecutive_failures = 0;
                } else if !shutdown_flush || disposition == AttemptDisposition::Cancelled {
                    coalescer.extend(retry_changes);
                    if !stopping {
                        let retry_at = if disposition == AttemptDisposition::Cancelled {
                            Instant::now() + debounce
                        } else {
                            consecutive_failures = consecutive_failures.saturating_add(1);
                            Instant::now() + retry_delay(debounce, consecutive_failures)
                        };
                        deadline = Some(deadline.map_or(retry_at, |current| current.min(retry_at)));
                    }
                }
                status.active_attempt_id = None;
                status.pending_change_count = coalescer.len();
                status.phase = if stopping {
                    DaemonPhase::Stopping
                } else if coalescer.is_empty() {
                    DaemonPhase::Idle
                } else {
                    DaemonPhase::Debouncing
                };
                publish_status(&status_sender, &status);
            }
        }
    }

    if let Some(locks) = locks {
        // Explicit unlock is the fast path, while synchronous close remains
        // the fail-safe for an OS unlock error. Both finish before Stopped is
        // published so persistent lifecycle cleanup cannot be skipped.
        let _ = locks.unlock();
        drop(locks);
    }
    status.phase = DaemonPhase::Stopped;
    status.stopped_at = Some(timestamp());
    status.active_attempt_id = None;
    status.pending_change_count = 0;
    publish_status(&status_sender, &status);
    status
}

fn spawn_attempt(
    runner: Arc<dyn DaemonScanRunner>,
    changes: Vec<IncrementalFileChange>,
    shutdown_flush: bool,
) -> ActiveAttempt {
    let request = DaemonScanRequest {
        attempt_id: Uuid::new_v4().to_string(),
        changes,
        started_at: timestamp(),
    };
    let cancellation = CancellationToken::new();
    let (sender, completion) = oneshot::channel();
    let task = tokio::spawn({
        let request = request.clone();
        let cancellation = cancellation.clone();
        async move {
            let result = runner.run(request, cancellation).await;
            let _ = sender.send(result);
        }
    });
    ActiveAttempt {
        request,
        cancellation,
        completion,
        task,
        shutdown_flush,
    }
}

fn retry_delay(debounce: Duration, consecutive_failures: u32) -> Duration {
    let base = debounce.max(Duration::from_secs(1));
    let exponent = consecutive_failures.saturating_sub(1).min(5);
    base.saturating_mul(1_u32 << exponent)
        .min(Duration::from_secs(30))
}

fn record_attempt(
    status: &mut DaemonStatus,
    request: DaemonScanRequest,
    result: Result<DaemonScanOutcome>,
) {
    let finished_at = timestamp();
    let attempt = match result {
        Ok(outcome) => DaemonAttempt {
            attempt_id: request.attempt_id,
            scan_id: outcome.scan_id,
            status: outcome.status,
            started_at: request.started_at,
            finished_at,
            changes: request.changes,
            base_snapshot_id: outcome.base_snapshot_id,
            completed_snapshot_id: outcome.completed_snapshot_id,
            invalidation_plan: outcome.invalidation_plan,
            invalidation_error: outcome.invalidation_error,
            incremental_trace: outcome.incremental_trace,
            error: None,
        },
        Err(error) => DaemonAttempt {
            attempt_id: request.attempt_id,
            scan_id: None,
            status: "failed".to_owned(),
            started_at: request.started_at,
            finished_at,
            changes: request.changes,
            base_snapshot_id: None,
            completed_snapshot_id: None,
            invalidation_plan: None,
            invalidation_error: None,
            incremental_trace: None,
            error: Some(format!("{error:#}")),
        },
    };
    match attempt.status.as_str() {
        "completed" => status.last_completed_attempt = Some(attempt),
        "cancelled" => status.last_cancelled_attempt = Some(attempt),
        _ => status.last_failed_attempt = Some(attempt),
    }
}

fn publish_status(sender: &watch::Sender<DaemonStatus>, status: &DaemonStatus) {
    sender.send_replace(status.clone());
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn elapsed_milliseconds(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    #[derive(Default)]
    struct RecordingRunner {
        requests: Mutex<Vec<DaemonScanRequest>>,
    }

    impl DaemonScanRunner for RecordingRunner {
        fn run(
            &self,
            request: DaemonScanRequest,
            _cancellation: CancellationToken,
        ) -> DaemonScanFuture {
            self.requests.lock().unwrap().push(request);
            Box::pin(async {
                Ok(DaemonScanOutcome {
                    scan_id: Some("fixture-scan".to_owned()),
                    status: "completed".to_owned(),
                    completed_snapshot_id: Some("fixture-snapshot".to_owned()),
                    base_snapshot_id: None,
                    invalidation_plan: None,
                    invalidation_error: None,
                    incremental_trace: None,
                })
            })
        }
    }

    struct CancellingRunner {
        started: Arc<AtomicBool>,
        cleaned_up: Arc<AtomicBool>,
        attempts: AtomicUsize,
    }

    impl DaemonScanRunner for CancellingRunner {
        fn run(
            &self,
            _request: DaemonScanRequest,
            cancellation: CancellationToken,
        ) -> DaemonScanFuture {
            let started = self.started.clone();
            let cleaned_up = self.cleaned_up.clone();
            let attempt = self.attempts.fetch_add(1, Ordering::AcqRel);
            Box::pin(async move {
                if attempt > 0 {
                    return Ok(DaemonScanOutcome {
                        scan_id: Some("shutdown-flush".to_owned()),
                        status: "completed".to_owned(),
                        completed_snapshot_id: Some("fixture-snapshot".to_owned()),
                        base_snapshot_id: Some("stable-snapshot".to_owned()),
                        invalidation_plan: None,
                        invalidation_error: None,
                        incremental_trace: None,
                    });
                }
                started.store(true, Ordering::Release);
                cancellation.cancelled().await;
                cleaned_up.store(true, Ordering::Release);
                Ok(DaemonScanOutcome {
                    scan_id: Some("cancelled-scan".to_owned()),
                    status: "cancelled".to_owned(),
                    completed_snapshot_id: None,
                    base_snapshot_id: Some("stable-snapshot".to_owned()),
                    invalidation_plan: None,
                    invalidation_error: None,
                    incremental_trace: None,
                })
            })
        }
    }

    #[derive(Default)]
    struct ShutdownEventRunner {
        attempts: AtomicUsize,
        requests: Mutex<Vec<DaemonScanRequest>>,
    }

    impl DaemonScanRunner for ShutdownEventRunner {
        fn run(
            &self,
            request: DaemonScanRequest,
            cancellation: CancellationToken,
        ) -> DaemonScanFuture {
            let attempt = self.attempts.fetch_add(1, Ordering::AcqRel);
            self.requests.lock().unwrap().push(request);
            Box::pin(async move {
                if attempt < 2 {
                    cancellation.cancelled().await;
                    return Ok(DaemonScanOutcome {
                        scan_id: Some(format!("cancelled-{attempt}")),
                        status: "cancelled".to_owned(),
                        completed_snapshot_id: None,
                        base_snapshot_id: Some("stable-snapshot".to_owned()),
                        invalidation_plan: None,
                        invalidation_error: None,
                        incremental_trace: None,
                    });
                }
                Ok(DaemonScanOutcome {
                    scan_id: Some("final-shutdown-flush".to_owned()),
                    status: "completed".to_owned(),
                    completed_snapshot_id: Some("final-snapshot".to_owned()),
                    base_snapshot_id: Some("stable-snapshot".to_owned()),
                    invalidation_plan: None,
                    invalidation_error: None,
                    incremental_trace: None,
                })
            })
        }
    }

    #[derive(Default)]
    struct FailOnceRunner {
        attempts: AtomicUsize,
    }

    impl DaemonScanRunner for FailOnceRunner {
        fn run(
            &self,
            _request: DaemonScanRequest,
            _cancellation: CancellationToken,
        ) -> DaemonScanFuture {
            let attempt = self.attempts.fetch_add(1, Ordering::AcqRel);
            Box::pin(async move {
                if attempt == 0 {
                    bail!("transient fixture failure");
                }
                Ok(DaemonScanOutcome {
                    scan_id: Some("retried-scan".to_owned()),
                    status: "completed".to_owned(),
                    completed_snapshot_id: Some("retried-snapshot".to_owned()),
                    base_snapshot_id: None,
                    invalidation_plan: None,
                    invalidation_error: None,
                    incremental_trace: None,
                })
            })
        }
    }

    #[derive(Default)]
    struct SuccessfulIncrementalWorker {
        requests: Mutex<Vec<WorkerDeltaRequest>>,
    }

    impl IncrementalWorkerExecutor for SuccessfulIncrementalWorker {
        fn run(
            &self,
            _root: PathBuf,
            _config: Config,
            request: WorkerDeltaRequest,
            _cancellation: CancellationToken,
        ) -> IncrementalWorkerFuture {
            self.requests.lock().unwrap().push(request.clone());
            Box::pin(async move {
                Ok(IncrementalWorkerOutcome::Delta {
                    delta: Box::new(changed_source_delta(&request)?),
                    stderr: "fixture delta worker".to_owned(),
                    stderr_truncated: false,
                    trace: IncrementalWorkerTrace::default(),
                })
            })
        }
    }

    struct CancellingIncrementalWorker;

    impl IncrementalWorkerExecutor for CancellingIncrementalWorker {
        fn run(
            &self,
            _root: PathBuf,
            _config: Config,
            request: WorkerDeltaRequest,
            cancellation: CancellationToken,
        ) -> IncrementalWorkerFuture {
            Box::pin(async move {
                let delta = changed_source_delta(&request)?;
                cancellation.cancel();
                Ok(IncrementalWorkerOutcome::Delta {
                    delta: Box::new(delta),
                    stderr: String::new(),
                    stderr_truncated: false,
                    trace: IncrementalWorkerTrace::default(),
                })
            })
        }
    }

    struct FailingIncrementalWorker;

    impl IncrementalWorkerExecutor for FailingIncrementalWorker {
        fn run(
            &self,
            _root: PathBuf,
            _config: Config,
            _request: WorkerDeltaRequest,
            _cancellation: CancellationToken,
        ) -> IncrementalWorkerFuture {
            Box::pin(async { bail!("fixture delta worker failed") })
        }
    }

    struct TamperingIncrementalWorker;

    impl IncrementalWorkerExecutor for TamperingIncrementalWorker {
        fn run(
            &self,
            _root: PathBuf,
            _config: Config,
            request: WorkerDeltaRequest,
            _cancellation: CancellationToken,
        ) -> IncrementalWorkerFuture {
            Box::pin(async move {
                let mut delta = changed_source_delta(&request)?;
                delta.result_graph_digest = "0".repeat(64);
                Ok(IncrementalWorkerOutcome::Delta {
                    delta: Box::new(delta),
                    stderr: String::new(),
                    stderr_truncated: false,
                    trace: IncrementalWorkerTrace::default(),
                })
            })
        }
    }

    struct UnsupportedIncrementalWorker;

    impl IncrementalWorkerExecutor for UnsupportedIncrementalWorker {
        fn run(
            &self,
            _root: PathBuf,
            _config: Config,
            _request: WorkerDeltaRequest,
            _cancellation: CancellationToken,
        ) -> IncrementalWorkerFuture {
            Box::pin(async {
                Ok(IncrementalWorkerOutcome::Unsupported {
                    reason: "fixture worker is legacy".to_owned(),
                    trace: IncrementalWorkerTrace::default(),
                })
            })
        }
    }

    const FIXTURE_PACKAGE_ID: &str =
        "package:sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER_PACKAGE_ID: &str =
        "package:sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const SOURCE_NODE_ID: &str =
        "file:sha256:3333333333333333333333333333333333333333333333333333333333333333";
    const TARGET_NODE_ID: &str =
        "file:sha256:4444444444444444444444444444444444444444444444444444444444444444";
    const OTHER_NODE_ID: &str =
        "file:sha256:5555555555555555555555555555555555555555555555555555555555555555";
    const FIXTURE_SITE_ID: &str =
        "site:sha256:6666666666666666666666666666666666666666666666666666666666666666";
    const FIXTURE_EDGE_ID: &str =
        "edge:sha256:7777777777777777777777777777777777777777777777777777777777777777";
    const FIXTURE_PROFILE_ID: &str = "web:fixture";

    fn seed_incremental_store(root: &Path, store_path: &Path) -> Result<String> {
        let mut store = open_store(store_path)?;
        let profile_plan_id = plan_repository_profiles(root, &Config::default(), None)?
            .plan
            .plan_id;
        let scan_id = "incremental-base";
        store.start_scan(scan_id, root, false)?;
        let common = |event: &str, seq: u64| {
            serde_json::json!({
                "event": event,
                "protocol_version": "1.0",
                "scan_id": scan_id,
                "adapter": "web",
                "adapter_version": "fixture",
                "seq": seq
            })
        };
        let mut profile = common("profile_declared", 1);
        profile["profile"] = serde_json::json!({
            "id": FIXTURE_PROFILE_ID,
            "language": "web",
            "features": [],
            "environment": {},
            "properties": {
                "package_locator": "npm:fixture@1.0.0",
                "profile_selection_plan_id": profile_plan_id
            }
        });
        let mut fixture_package = common("node_upsert", 2);
        fixture_package["node"] = serde_json::json!({
            "id": FIXTURE_PACKAGE_ID,
            "kind": "package_instance",
            "locator": "npm:fixture@1.0.0",
            "display_name": "fixture",
            "properties": {
                "manifest_path": "package.json",
                "ecosystem": "web"
            }
        });
        let mut other_package = common("node_upsert", 3);
        other_package["node"] = serde_json::json!({
            "id": OTHER_PACKAGE_ID,
            "kind": "package_instance",
            "locator": "npm:other@1.0.0",
            "display_name": "other",
            "properties": {
                "manifest_path": "other/package.json",
                "ecosystem": "web"
            }
        });
        let node = |seq: u64, id: &str, path: &str, package: &str| {
            let mut event = common("node_upsert", seq);
            event["node"] = serde_json::json!({
                "id": id,
                "kind": "file",
                "locator": path,
                "display_name": path,
                "properties": {
                    "path": path,
                    "package_locator": package,
                    "content_hash": format!("sha256:{}", "1".repeat(64)),
                    "analysis_hash": format!("sha256:{}", "a".repeat(64))
                }
            });
            event
        };
        let source = node(4, SOURCE_NODE_ID, "src/index.ts", "npm:fixture@1.0.0");
        let target = node(5, TARGET_NODE_ID, "src/lib.ts", "npm:fixture@1.0.0");
        let other = node(6, OTHER_NODE_ID, "other/src/index.ts", "npm:other@1.0.0");
        let evidence = serde_json::json!([{
            "kind": "source",
            "extractor": "fixture",
            "extractor_version": "1",
            "path": "src/index.ts",
            "start_line": 1,
            "start_column": 1,
            "end_line": 1,
            "end_column": 10,
            "properties": {}
        }]);
        let mut site = common("dependency_site", 7);
        site["site"] = serde_json::json!({
            "id": FIXTURE_SITE_ID,
            "source": SOURCE_NODE_ID,
            "kind": "import",
            "specifier": "./lib",
            "resolution_status": "resolved",
            "target_ids": [TARGET_NODE_ID],
            "profile_id": FIXTURE_PROFILE_ID,
            "condition": {"op": "all", "conditions": []},
            "precision": "exact",
            "evidence": evidence
        });
        let mut edge = common("edge_upsert", 8);
        edge["edge"] = serde_json::json!({
            "id": FIXTURE_EDGE_ID,
            "source": SOURCE_NODE_ID,
            "target": TARGET_NODE_ID,
            "kind": "imports",
            "site_id": FIXTURE_SITE_ID,
            "phase": "source",
            "environment": "server",
            "profile_id": FIXTURE_PROFILE_ID,
            "condition": {"op": "all", "conditions": []},
            "resolution_status": "resolved",
            "precision": "exact",
            "generated": false,
            "evidence": evidence
        });
        let file_coverage = |seq: u64, path: &str, discovered: u64| {
            let mut event = common("file_completed", seq);
            event["path"] = serde_json::json!(path);
            event["discovered_sites"] = serde_json::json!(discovered);
            event["emitted_sites"] = serde_json::json!(discovered);
            event["skipped_sites"] = serde_json::json!(0);
            event["skipped"] = serde_json::json!(false);
            event
        };
        let source_coverage = file_coverage(9, "src/index.ts", 1);
        let target_coverage = file_coverage(10, "src/lib.ts", 0);
        let other_coverage = file_coverage(11, "other/src/index.ts", 0);
        let coverage = serde_json::json!({
            "profiles": 1,
            "files_discovered": 3,
            "files_analyzed": 3,
            "files_skipped": 0,
            "dependency_sites": 1,
            "resolved": 1,
            "candidates": 0,
            "external": 0,
            "unresolved": 0,
            "unsupported_syntax": 0,
            "project_code_executed": false,
            "completeness": ["syntax-complete"],
            "reasons": []
        });
        let mut profile_completed = common("profile_completed", 12);
        profile_completed["profile_id"] = serde_json::json!(FIXTURE_PROFILE_ID);
        profile_completed["coverage"] = coverage.clone();
        let mut scan_completed = common("scan_completed", 13);
        scan_completed["coverage"] = coverage;
        store.ingest_events(&[
            &profile,
            &fixture_package,
            &other_package,
            &source,
            &target,
            &other,
            &site,
            &edge,
            &source_coverage,
            &target_coverage,
            &other_coverage,
            &profile_completed,
            &scan_completed,
        ])?;
        store.finish_scan(scan_id, "completed", None, true)?;
        store
            .current_snapshot_id()?
            .context("fixture base snapshot was not promoted")
    }

    fn changed_source_delta(request: &WorkerDeltaRequest) -> Result<ValidatedDelta> {
        use depgraph_protocol::{
            CommonFields, DELTA_CONTRACT_VERSION, DeltaCompleted, DeltaEvent, DeltaNodeUpsert,
            DeltaStarted, DeltaValidator, build_delta_stable_id, delta_graph_digest,
        };

        request.validate()?;
        let base = request.base_graph()?;
        let mut changed = base
            .nodes
            .get(SOURCE_NODE_ID)
            .context("fixture source node is missing")?
            .clone();
        changed.properties.insert(
            "content_hash".to_owned(),
            serde_json::json!(format!("sha256:{}", "2".repeat(64))),
        );
        let common = |seq| CommonFields {
            protocol_version: "1.0".to_owned(),
            scan_id: request.scan_id.clone(),
            adapter: request.adapter.clone(),
            adapter_version: "fixture".to_owned(),
            seq,
        };
        let placeholder =
            "delta:sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let mutation = DeltaEvent::NodeUpsert(DeltaNodeUpsert {
            common: common(2),
            node: changed.clone(),
        });
        let delta_id = build_delta_stable_id(
            &request.base_snapshot_id,
            &request.base_graph_digest,
            &request.scope,
            [&mutation],
        )?;
        let mut result = base.clone();
        result.nodes.insert(changed.id.clone(), changed);
        let events = vec![
            DeltaEvent::DeltaStarted(DeltaStarted {
                common: common(1),
                delta_contract_version: DELTA_CONTRACT_VERSION.to_owned(),
                delta_id: delta_id.clone(),
                base_snapshot_id: request.base_snapshot_id.clone(),
                base_graph_digest: request.base_graph_digest.clone(),
                scope: request.scope.clone(),
            }),
            mutation,
            DeltaEvent::DeltaCompleted(DeltaCompleted {
                common: common(3),
                delta_contract_version: DELTA_CONTRACT_VERSION.to_owned(),
                delta_id,
                mutation_count: 1,
                result_graph_digest: delta_graph_digest(&result),
            }),
        ];
        let mut validator = DeltaValidator::new(base)?;
        for event in events {
            validator.push(event)?;
        }
        let delta = validator.finish()?;
        assert_ne!(delta.delta_id, placeholder);
        Ok(delta)
    }

    async fn wait_for_status(
        receiver: &mut watch::Receiver<DaemonStatus>,
        predicate: impl Fn(&DaemonStatus) -> bool,
    ) -> Result<DaemonStatus> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let status = receiver.borrow().clone();
                if predicate(&status) {
                    return Ok(status);
                }
                receiver.changed().await.context("daemon status closed")?;
            }
        })
        .await
        .context("timed out waiting for daemon status")?
    }

    #[test]
    fn event_storm_and_replacements_coalesce_deterministically() {
        let changes = coalesce_incremental_changes([
            IncrementalFileChange::modified("src/lib.rs"),
            IncrementalFileChange::modified("src/lib.rs"),
            IncrementalFileChange::deleted("src/replaced.rs"),
            IncrementalFileChange::added("src/replaced.rs"),
            IncrementalFileChange::added("src/transient.rs"),
            IncrementalFileChange::modified("src/transient.rs"),
            IncrementalFileChange::deleted("src/transient.rs"),
        ]);
        assert_eq!(
            changes,
            [
                IncrementalFileChange::modified("src/lib.rs"),
                IncrementalFileChange::modified("src/replaced.rs"),
            ]
        );
    }

    #[test]
    fn rename_chains_and_deletes_keep_the_original_identity() {
        let changes = coalesce_incremental_changes([
            IncrementalFileChange::renamed("src/old.rs", "src/middle.rs"),
            IncrementalFileChange::modified("src/middle.rs"),
            IncrementalFileChange::renamed("src/middle.rs", "src/new.rs"),
        ]);
        assert_eq!(
            changes,
            [IncrementalFileChange::renamed("src/old.rs", "src/new.rs")]
        );

        let changes = coalesce_incremental_changes([
            IncrementalFileChange::renamed("src/old.rs", "src/new.rs"),
            IncrementalFileChange::deleted("src/new.rs"),
        ]);
        assert_eq!(changes, [IncrementalFileChange::deleted("src/old.rs")]);
    }

    #[test]
    fn tracked_cross_platform_rename_halves_become_one_rename() {
        let mut coalescer = EventCoalescer::default();
        coalescer.track_rename_to(42, "src/new.rs".to_owned());
        coalescer.track_rename_from(42, "src/old.rs".to_owned());
        assert_eq!(
            coalescer.drain(),
            [IncrementalFileChange::renamed("src/old.rs", "src/new.rs")]
        );
    }

    #[test]
    fn ignore_and_generated_rules_are_repository_relative_and_stable() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store = root.path().join("state/graph.db");
        let rules = WatchIgnoreRules::new(root.path(), &["vendor/cache".to_owned()], Some(&store))?;
        assert_eq!(rules.classify(&root.path().join(".git/index"))?, None);
        assert_eq!(rules.classify(&root.path().join("target/debug/app"))?, None);
        assert_eq!(
            rules.classify(&root.path().join("vendor/cache/item"))?,
            None
        );
        assert_eq!(rules.classify(&store)?, None);
        assert_eq!(
            rules.classify(&PathBuf::from(format!("{}-wal", store.display())))?,
            None
        );
        assert_eq!(
            rules.classify(&root.path().join("src/generated/routes.g.rs"))?,
            Some(WatchedPath {
                relative_path: "src/generated/routes.g.rs".to_owned(),
                kind: WatchPathKind::Generated,
            })
        );
        assert_eq!(
            rules.classify(&root.path().join("src/lib.rs"))?,
            Some(WatchedPath {
                relative_path: "src/lib.rs".to_owned(),
                kind: WatchPathKind::Source,
            })
        );
        assert_eq!(
            rules.classify(&root.path().join("src/build/lib.rs"))?,
            Some(WatchedPath {
                relative_path: "src/build/lib.rs".to_owned(),
                kind: WatchPathKind::Source,
            })
        );
        Ok(())
    }

    #[tokio::test]
    async fn planner_failure_is_reported_without_skipping_the_full_scan_fallback() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store_path = root.path().join("graph.db");
        let config = Config::default();
        let mut store = open_store(&store_path)?;
        crate::run_scan(&mut store, root.path().to_path_buf(), &config, false).await?;
        drop(store);

        let runner =
            RepositoryScanRunner::new(root.path().to_path_buf(), store_path, config, false);
        let outcome = runner
            .run(
                DaemonScanRequest {
                    attempt_id: "planner-fallback".to_owned(),
                    changes: vec![IncrementalFileChange {
                        kind: crate::IncrementalChangeKind::Added,
                        old_path: Some("invalid-shape.rs".to_owned()),
                        new_path: None,
                    }],
                    started_at: timestamp(),
                },
                CancellationToken::new(),
            )
            .await?;

        assert_eq!(outcome.status, "completed");
        assert!(outcome.completed_snapshot_id.is_some());
        assert!(outcome.invalidation_plan.is_none());
        assert!(
            outcome
                .invalidation_error
                .as_deref()
                .is_some_and(|error| error.contains("incremental planner failed"))
        );
        Ok(())
    }

    #[test]
    fn worker_delta_request_materialization_is_limited_to_bounded_closures() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store_path = root.path().join("graph.db");
        let base_snapshot_id = seed_incremental_store(root.path(), &store_path)?;
        let store = open_store(&store_path)?;
        let snapshot = store.load_completed_snapshot(&base_snapshot_id)?;
        let mut plan = plan_incremental_invalidation(
            &base_snapshot_id,
            &snapshot,
            &[IncrementalFileChange::modified("src/index.ts")],
        )?;

        assert!(worker_delta_plan_is_eligible(&plan));
        let base = store.delta_base_graph(&base_snapshot_id)?;
        assert!(build_worker_delta_request("bounded-request", &plan, &base)?.is_some());
        plan.replacement_scope.paths = (0..=MAX_WORKER_DELTA_SCOPE_PATHS)
            .map(|index| format!("src/{index:05}.ts"))
            .collect();
        assert!(!worker_delta_plan_is_eligible(&plan));
        assert!(build_worker_delta_request("oversized-request", &plan, &base)?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn planned_closure_is_applied_as_one_transactional_worker_delta() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store_path = root.path().join("graph.db");
        let base_snapshot_id = seed_incremental_store(root.path(), &store_path)?;
        let worker = Arc::new(SuccessfulIncrementalWorker::default());
        let runner = RepositoryScanRunner::new(
            root.path().to_path_buf(),
            store_path.clone(),
            Config::default(),
            false,
        )
        .with_incremental_worker(worker.clone());

        let outcome = runner
            .run(
                DaemonScanRequest {
                    attempt_id: "delta-success".to_owned(),
                    changes: vec![IncrementalFileChange::modified("src/index.ts")],
                    started_at: timestamp(),
                },
                CancellationToken::new(),
            )
            .await?;

        assert_eq!(outcome.status, "completed");
        assert_eq!(
            outcome.base_snapshot_id.as_deref(),
            Some(base_snapshot_id.as_str())
        );
        assert_ne!(
            outcome.completed_snapshot_id.as_deref(),
            Some(base_snapshot_id.as_str())
        );
        let trace = outcome
            .incremental_trace
            .as_ref()
            .context("semantic no-op trace")?;
        assert_eq!(
            trace.schema_version,
            DAEMON_INCREMENTAL_TRACE_SCHEMA_VERSION
        );
        assert_eq!(trace.mode, "semantic_noop");
        let requests = worker.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(
            request.analysis_mode,
            depgraph_protocol::WorkerDeltaAnalysisMode::SemanticNoop
        );
        assert_eq!(request.scope.adapters, ["web"]);
        assert!(request.scope.paths.contains(&"src/index.ts".to_owned()));
        assert!(
            !request
                .scope
                .paths
                .contains(&"other/src/index.ts".to_owned())
        );
        drop(requests);

        let store = open_store(&store_path)?;
        let current = store.current_snapshot_id()?.context("current snapshot")?;
        let snapshot = store.load_completed_snapshot(&current)?;
        let source = snapshot
            .nodes
            .iter()
            .find(|node| node.id == SOURCE_NODE_ID)
            .context("updated source")?;
        assert_eq!(
            source.properties["content_hash"],
            serde_json::json!(format!("sha256:{}", "2".repeat(64)))
        );
        let untouched = snapshot
            .nodes
            .iter()
            .find(|node| node.id == OTHER_NODE_ID)
            .context("unrelated node")?;
        assert_eq!(
            untouched.properties["content_hash"],
            serde_json::json!(format!("sha256:{}", "1".repeat(64)))
        );
        let scan_id = outcome.scan_id.context("incremental scan ID")?;
        let scan = store.scan(&scan_id)?.context("incremental scan")?;
        assert_eq!(
            scan.parent_snapshot_id.as_deref(),
            Some(base_snapshot_id.as_str())
        );
        let expected_provenance = ScanHealthProvenance {
            policy_config_digest: health_policy_config_digest(&Config::default().policy)?,
            analyzer_version: HEALTH_ANALYZER_VERSION.to_owned(),
            finding_contract_version: HEALTH_FINDING_CONTRACT_VERSION.to_owned(),
        };
        assert_eq!(
            scan.health_policy_config_digest.as_deref(),
            Some(expected_provenance.policy_config_digest.as_str())
        );
        assert_eq!(
            scan.health_analyzer_version.as_deref(),
            Some(expected_provenance.analyzer_version.as_str())
        );
        assert_eq!(
            scan.health_finding_contract_version.as_deref(),
            Some(expected_provenance.finding_contract_version.as_str())
        );
        assert!(store.verify_snapshot_integrity(&current)?.valid);
        Ok(())
    }

    #[tokio::test]
    async fn invalid_policy_identity_does_not_leave_an_incremental_scan_attempt() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store_path = root.path().join("graph.db");
        seed_incremental_store(root.path(), &store_path)?;
        let worker = Arc::new(SuccessfulIncrementalWorker::default());
        let mut config = Config::default();
        config.policy.schema_version = "invalid".to_owned();
        let runner =
            RepositoryScanRunner::new(root.path().to_path_buf(), store_path.clone(), config, false)
                .with_incremental_worker(worker);

        let error = runner
            .run(
                DaemonScanRequest {
                    attempt_id: "invalid-policy-delta".to_owned(),
                    changes: vec![
                        IncrementalFileChange::modified("src/index.ts"),
                        IncrementalFileChange::modified("src/lib.ts"),
                    ],
                    started_at: timestamp(),
                },
                CancellationToken::new(),
            )
            .await
            .unwrap_err();

        assert!(
            format!("{error:#}").contains("failed to normalize health policy identity"),
            "unexpected incremental error: {error:#}"
        );
        let store = open_store(&store_path)?;
        assert_eq!(store.resolve_scan_id(None, true)?, "incremental-base");
        Ok(())
    }

    #[tokio::test]
    async fn profile_set_change_skips_delta_and_replaces_the_snapshot_transactionally() -> Result<()>
    {
        let root = tempfile::tempdir()?;
        let store_path = root.path().join("graph.db");
        let base_snapshot_id = seed_incremental_store(root.path(), &store_path)?;
        let worker = Arc::new(SuccessfulIncrementalWorker::default());
        let mut config = Config::default();
        config.profiles.web_environments = vec!["server".to_owned()];
        let runner =
            RepositoryScanRunner::new(root.path().to_path_buf(), store_path.clone(), config, false)
                .with_incremental_worker(worker.clone());

        let outcome = runner
            .run(
                DaemonScanRequest {
                    attempt_id: "profile-set-change".to_owned(),
                    changes: vec![IncrementalFileChange::modified("src/index.ts")],
                    started_at: timestamp(),
                },
                CancellationToken::new(),
            )
            .await?;

        assert_eq!(outcome.status, "completed");
        assert!(worker.requests.lock().unwrap().is_empty());
        let completed_snapshot_id = outcome
            .completed_snapshot_id
            .as_deref()
            .context("full replacement snapshot")?;
        assert_ne!(completed_snapshot_id, base_snapshot_id);
        let store = open_store(&store_path)?;
        let snapshot = store.load_completed_snapshot(completed_snapshot_id)?;
        assert!(snapshot.profiles.is_empty());
        assert_eq!(
            store.current_snapshot_id()?.as_deref(),
            Some(completed_snapshot_id)
        );
        Ok(())
    }

    #[tokio::test]
    async fn incremental_cancellation_or_tampering_never_promotes_partial_state() -> Result<()> {
        for (name, worker, expected_status) in [
            (
                "cancelled",
                Arc::new(CancellingIncrementalWorker) as Arc<dyn IncrementalWorkerExecutor>,
                "cancelled",
            ),
            (
                "tampered",
                Arc::new(TamperingIncrementalWorker) as Arc<dyn IncrementalWorkerExecutor>,
                "failed",
            ),
        ] {
            let root = tempfile::tempdir()?;
            let store_path = root.path().join(format!("{name}.db"));
            let base_snapshot_id = seed_incremental_store(root.path(), &store_path)?;
            let runner = RepositoryScanRunner::new(
                root.path().to_path_buf(),
                store_path.clone(),
                Config::default(),
                false,
            )
            .with_incremental_worker(worker);
            let outcome = runner
                .run(
                    DaemonScanRequest {
                        attempt_id: format!("delta-{name}"),
                        changes: vec![IncrementalFileChange::modified("src/index.ts")],
                        started_at: timestamp(),
                    },
                    CancellationToken::new(),
                )
                .await?;

            assert_eq!(outcome.status, expected_status);
            assert!(outcome.completed_snapshot_id.is_none());
            let store = open_store(&store_path)?;
            assert_eq!(
                store.current_snapshot_id()?.as_deref(),
                Some(base_snapshot_id.as_str())
            );
            let base = store.load_completed_snapshot(&base_snapshot_id)?;
            assert_eq!(
                base.nodes
                    .iter()
                    .find(|node| node.id == SOURCE_NODE_ID)
                    .context("base source")?
                    .properties["content_hash"],
                serde_json::json!(format!("sha256:{}", "1".repeat(64)))
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn semantic_noop_worker_failure_uses_the_atomic_full_scan_fallback() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store_path = root.path().join("graph.db");
        let base_snapshot_id = seed_incremental_store(root.path(), &store_path)?;
        let runner = RepositoryScanRunner::new(
            root.path().to_path_buf(),
            store_path.clone(),
            Config::default(),
            false,
        )
        .with_incremental_worker(Arc::new(FailingIncrementalWorker));
        let outcome = runner
            .run(
                DaemonScanRequest {
                    attempt_id: "worker-failure-fallback".to_owned(),
                    changes: vec![IncrementalFileChange::modified("src/index.ts")],
                    started_at: timestamp(),
                },
                CancellationToken::new(),
            )
            .await?;

        assert_eq!(outcome.status, "completed");
        assert_eq!(
            outcome.base_snapshot_id.as_deref(),
            Some(base_snapshot_id.as_str())
        );
        assert!(outcome.invalidation_error.is_none());
        let completed_snapshot_id = outcome
            .completed_snapshot_id
            .context("full scan fallback snapshot")?;
        assert_ne!(completed_snapshot_id, base_snapshot_id);
        let store = open_store(&store_path)?;
        assert_eq!(
            store.current_snapshot_id()?.as_deref(),
            Some(completed_snapshot_id.as_str())
        );
        Ok(())
    }

    #[tokio::test]
    async fn legacy_worker_uses_the_atomic_full_scan_fallback() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store_path = root.path().join("graph.db");
        let base_snapshot_id = seed_incremental_store(root.path(), &store_path)?;
        let runner = RepositoryScanRunner::new(
            root.path().to_path_buf(),
            store_path,
            Config::default(),
            false,
        )
        .with_incremental_worker(Arc::new(UnsupportedIncrementalWorker));
        let outcome = runner
            .run(
                DaemonScanRequest {
                    attempt_id: "legacy-fallback".to_owned(),
                    changes: vec![IncrementalFileChange::modified("src/index.ts")],
                    started_at: timestamp(),
                },
                CancellationToken::new(),
            )
            .await?;

        assert_eq!(outcome.status, "completed");
        assert_eq!(
            outcome.base_snapshot_id.as_deref(),
            Some(base_snapshot_id.as_str())
        );
        assert!(outcome.invalidation_error.is_none());
        assert!(outcome.completed_snapshot_id.is_some());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_watcher_starts_debounces_changes_and_stops_on_every_platform() -> Result<()> {
        let root = tempfile::tempdir()?;
        let runner = Arc::new(RecordingRunner::default());
        let handle = start_daemon_with_runner(
            root.path().to_path_buf(),
            DaemonConfig {
                debounce_milliseconds: 100,
                ignored_paths: Vec::new(),
            },
            None,
            InterruptedAttemptRecovery::default(),
            runner.clone(),
        )?;
        let mut status = handle.subscribe();

        std::fs::write(root.path().join("watched.rs"), "fn watched() {}\n")?;
        let completed = wait_for_status(&mut status, |status| {
            status.last_completed_attempt.is_some()
        })
        .await?;
        let changes = &completed.last_completed_attempt.unwrap().changes;
        assert!(changes.iter().any(|change| {
            change.new_path.as_deref() == Some("watched.rs")
                || change.old_path.as_deref() == Some("watched.rs")
        }));

        let stopped = handle.stop().await?;
        assert_eq!(stopped.phase, DaemonPhase::Stopped);
        assert!(stopped.stopped_at.is_some());
        assert!(!runner.requests.lock().unwrap().is_empty());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_attempt_requeues_its_changes_and_retries_with_backoff() -> Result<()> {
        let root = tempfile::tempdir()?;
        let runner = Arc::new(FailOnceRunner::default());
        let handle = start_daemon_with_runner(
            root.path().to_path_buf(),
            DaemonConfig {
                debounce_milliseconds: 10,
                ignored_paths: Vec::new(),
            },
            None,
            InterruptedAttemptRecovery::default(),
            runner.clone(),
        )?;
        let mut status = handle.subscribe();
        std::fs::write(root.path().join("retry.rs"), "fn retry() {}\n")?;

        let completed = wait_for_status(&mut status, |status| {
            status.last_failed_attempt.is_some() && status.last_completed_attempt.is_some()
        })
        .await?;
        assert!(runner.attempts.load(Ordering::Acquire) >= 2);
        assert!(
            completed
                .last_completed_attempt
                .unwrap()
                .changes
                .iter()
                .any(|change| change.new_path.as_deref() == Some("retry.rs"))
        );
        assert_eq!(handle.stop().await?.phase, DaemonPhase::Stopped);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_flushes_a_pending_debounced_batch_before_stopping() -> Result<()> {
        let root = tempfile::tempdir()?;
        let runner = Arc::new(RecordingRunner::default());
        let handle = start_daemon_with_runner(
            root.path().to_path_buf(),
            DaemonConfig {
                debounce_milliseconds: 1_000,
                ignored_paths: Vec::new(),
            },
            None,
            InterruptedAttemptRecovery::default(),
            runner.clone(),
        )?;
        let mut status = handle.subscribe();
        std::fs::write(root.path().join("flush.rs"), "fn flush() {}\n")?;
        wait_for_status(&mut status, |status| {
            status.phase == DaemonPhase::Debouncing
        })
        .await?;

        let stopped = handle.stop().await?;
        assert_eq!(stopped.phase, DaemonPhase::Stopped);
        assert!(stopped.last_completed_attempt.is_some());
        assert!(runner.requests.lock().unwrap().iter().any(|request| {
            request
                .changes
                .iter()
                .any(|change| change.new_path.as_deref() == Some("flush.rs"))
        }));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_flush_includes_events_received_while_stopping() -> Result<()> {
        let root = tempfile::tempdir()?;
        let runner = Arc::new(ShutdownEventRunner::default());
        let handle = start_daemon_with_runner(
            root.path().to_path_buf(),
            DaemonConfig {
                debounce_milliseconds: 10,
                ignored_paths: Vec::new(),
            },
            None,
            InterruptedAttemptRecovery::default(),
            runner.clone(),
        )?;
        let mut status = handle.subscribe();
        std::fs::write(root.path().join("before-stop.rs"), "fn before_stop() {}\n")?;
        wait_for_status(&mut status, |status| status.phase == DaemonPhase::Scanning).await?;

        let stopping = tokio::spawn(async move { handle.stop().await });
        tokio::time::timeout(Duration::from_secs(10), async {
            while runner.attempts.load(Ordering::Acquire) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .context("shutdown flush did not start")?;
        std::fs::write(root.path().join("during-stop.rs"), "fn during_stop() {}\n")?;

        let stopped = tokio::time::timeout(Duration::from_secs(10), stopping)
            .await
            .context("daemon did not finish the final shutdown flush")?
            .context("daemon stop task failed")??;
        assert_eq!(stopped.phase, DaemonPhase::Stopped);
        assert!(runner.attempts.load(Ordering::Acquire) >= 3);
        assert!(runner.requests.lock().unwrap().iter().any(|request| {
            request
                .changes
                .iter()
                .any(|change| change.new_path.as_deref() == Some("during-stop.rs"))
        }));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_cancels_and_awaits_the_active_scan_cleanup() -> Result<()> {
        let root = tempfile::tempdir()?;
        let started = Arc::new(AtomicBool::new(false));
        let cleaned_up = Arc::new(AtomicBool::new(false));
        let runner = Arc::new(CancellingRunner {
            started: started.clone(),
            cleaned_up: cleaned_up.clone(),
            attempts: AtomicUsize::new(0),
        });
        let handle = start_daemon_with_runner(
            root.path().to_path_buf(),
            DaemonConfig {
                debounce_milliseconds: 10,
                ignored_paths: Vec::new(),
            },
            None,
            InterruptedAttemptRecovery::default(),
            runner,
        )?;
        let mut status = handle.subscribe();
        std::fs::write(root.path().join("cancel.rs"), "fn cancel() {}\n")?;
        wait_for_status(&mut status, |status| status.phase == DaemonPhase::Scanning).await?;
        tokio::time::timeout(Duration::from_secs(10), async {
            while !started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .context("scan runner did not start")?;

        let stopped = handle.stop().await?;
        assert!(cleaned_up.load(Ordering::Acquire));
        assert_eq!(stopped.phase, DaemonPhase::Stopped);
        assert_eq!(
            stopped
                .last_cancelled_attempt
                .as_ref()
                .map(|attempt| attempt.status.as_str()),
            Some("cancelled")
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn store_lock_rejects_concurrent_daemons_and_releases_after_stop() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store_path = root.path().join("graph.db");
        let config = DaemonConfig {
            debounce_milliseconds: 10,
            ignored_paths: Vec::new(),
        };
        let runner = Arc::new(RecordingRunner::default());
        let first = start_daemon_with_runner(
            root.path().to_path_buf(),
            config.clone(),
            Some(store_path.clone()),
            InterruptedAttemptRecovery::default(),
            runner.clone(),
        )?;
        let error = match start_daemon_with_runner(
            root.path().to_path_buf(),
            config.clone(),
            Some(store_path.clone()),
            InterruptedAttemptRecovery::default(),
            runner.clone(),
        ) {
            Ok(handle) => {
                handle.stop().await?;
                bail!("a second daemon acquired the same store lock");
            }
            Err(error) => error,
        };
        assert!(error.to_string().contains("already running"));
        first.stop().await?;

        let restarted = start_daemon_with_runner(
            root.path().to_path_buf(),
            config,
            Some(store_path),
            InterruptedAttemptRecovery::default(),
            runner,
        )?;
        assert_eq!(restarted.stop().await?.phase, DaemonPhase::Stopped);
        Ok(())
    }

    #[test]
    fn daemon_locks_can_be_reacquired_before_unlocked_handles_drop() -> Result<()> {
        let root = tempfile::tempdir()?;
        let store_path = root.path().join("graph.db");
        let first = acquire_daemon_locks(&store_path)?;

        first.unlock()?;
        let second = acquire_daemon_locks(&store_path)?;
        second.unlock()?;

        // Keep both open handles alive until after reacquisition so this test
        // cannot pass merely because close-on-drop released either lock.
        drop((first, second));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn store_lock_guard_drop_releases_lock_while_child_processes_are_spawned() -> Result<()> {
        // Enough drop/reacquire rounds that a close-on-drop release would
        // collide with a concurrently inherited descriptor with near certainty.
        const REACQUISITION_ROUNDS: usize = 2_000;

        let root = tempfile::tempdir()?;
        let store_path = root.path().join("graph.db");
        let stop = Arc::new(AtomicBool::new(false));
        let spawned = Arc::new(AtomicUsize::new(0));
        let spawner = {
            let stop = Arc::clone(&stop);
            let spawned = Arc::clone(&spawned);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if std::process::Command::new("true").status().is_ok() {
                        spawned.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        };

        let reacquisitions = (|| -> Result<()> {
            for _ in 0..REACQUISITION_ROUNDS {
                let held = acquire_store_writer_lock(&store_path)?;
                // Drop without calling unlock(): the guard alone must release
                // the lock even while a child holds a duplicated descriptor.
                drop(held);
                let reacquired = acquire_store_writer_lock(&store_path)
                    .context("reacquisition immediately after drop failed")?;
                drop(reacquired);
            }
            Ok(())
        })();
        stop.store(true, Ordering::Relaxed);
        spawner.join().expect("child spawner thread panicked");

        reacquisitions?;
        assert!(
            spawned.load(Ordering::Relaxed) > 0,
            "no child process was spawned, so the test exercised nothing"
        );
        Ok(())
    }
}
