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
use depgraph_store::InterruptedAttemptRecovery;
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

use crate::{
    CancellationToken, Config, DaemonConfig, IncrementalFileChange, IncrementalInvalidationPlan,
    ScanCacheMode, open_store, plan_incremental_invalidation,
    run_scan_with_cache_mode_and_cancellation,
};

pub const DAEMON_STATUS_SCHEMA_VERSION: &str = "daemon-status-v1";

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

#[derive(Debug, Clone)]
pub struct RepositoryScanRunner {
    root: PathBuf,
    store_path: PathBuf,
    config: Config,
    strict: bool,
}

impl RepositoryScanRunner {
    pub fn new(root: PathBuf, store_path: PathBuf, config: Config, strict: bool) -> Self {
        Self {
            root,
            store_path,
            config,
            strict,
        }
    }
}

impl DaemonScanRunner for RepositoryScanRunner {
    fn run(&self, request: DaemonScanRequest, cancellation: CancellationToken) -> DaemonScanFuture {
        let root = self.root.clone();
        let store_path = self.store_path.clone();
        let config = self.config.clone();
        let strict = self.strict;
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Ok(DaemonScanOutcome {
                    scan_id: None,
                    status: "cancelled".to_owned(),
                    completed_snapshot_id: None,
                    base_snapshot_id: None,
                    invalidation_plan: None,
                    invalidation_error: None,
                });
            }
            let mut store = open_store(&store_path)?;
            let base_snapshot_id = store.current_snapshot_id()?;
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
            // Workers currently emit repository-complete protocols. The daemon
            // still feeds every coalesced batch through the incremental planner,
            // then uses a full atomic replacement as the safe execution fallback.
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
            })
        })
    }
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
    let lock = acquire_store_writer_lock(&store_path)?;
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
        Some(lock),
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
    let lock = store_path
        .as_deref()
        .map(acquire_store_writer_lock)
        .transpose()?;
    start_daemon_with_runner_and_lock(root, config, store_path, recovered_attempts, runner, lock)
}

fn start_daemon_with_runner_and_lock(
    root: PathBuf,
    config: DaemonConfig,
    store_path: Option<PathBuf>,
    recovered_attempts: InterruptedAttemptRecovery,
    runner: Arc<dyn DaemonScanRunner>,
    lock: Option<std::fs::File>,
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
        lock,
    ));
    Ok(DaemonHandle {
        stop_sender: Some(stop_sender),
        status: status_receiver,
        task: Some(task),
    })
}

/// Acquires the per-store writer lock shared by daemon and foreground scans.
///
/// The returned file must remain alive for the full duration of the writer.
pub fn acquire_store_writer_lock(store_path: &Path) -> Result<std::fs::File> {
    let lock_path = with_path_suffix(store_path, ".daemon-lock");
    let parent = lock_path
        .parent()
        .context("daemon lock path has no parent")?;
    std::fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create daemon lock directory {}",
            parent.display()
        )
    })?;
    if let Ok(metadata) = std::fs::symlink_metadata(&lock_path)
        && !metadata.file_type().is_file()
    {
        bail!(
            "daemon lock path {} is not a regular file",
            lock_path.display()
        );
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("failed to open daemon lock {}", lock_path.display()))?;
    file.try_lock().with_context(|| {
        format!(
            "another store writer is already running for store {}",
            store_path.display()
        )
    })?;
    Ok(file)
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
    _lock: Option<std::fs::File>,
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
                    });
                }
                Ok(DaemonScanOutcome {
                    scan_id: Some("final-shutdown-flush".to_owned()),
                    status: "completed".to_owned(),
                    completed_snapshot_id: Some("final-snapshot".to_owned()),
                    base_snapshot_id: Some("stable-snapshot".to_owned()),
                    invalidation_plan: None,
                    invalidation_error: None,
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
                })
            })
        }
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
}
