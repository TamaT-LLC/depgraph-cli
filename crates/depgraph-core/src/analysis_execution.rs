//! A bounded executor shared by CLI, MCP and daemon scans.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use depgraph_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::task::JoinSet;

use crate::{
    analysis_checkpoint::{
        ScanBuildCache, StagedUnitCheckpoint, UnitCheckpointKey, UnitCheckpointStore,
    },
    cancellation::CancellationToken,
    config::Config,
    scan::ScanCacheMode,
    worker::{
        AdapterKind, WorkerOutput, WorkerSpec, WorkerUnitInput, execute_worker_unit,
        replay_analysis_checkpoint,
    },
};

/// There is no deadline for the aggregate queue. Worker deadlines, output
/// budgets and process-tree cancellation apply separately to each work item.
pub(crate) struct AnalysisWorkItem {
    pub unit_id: String,
    pub request: Option<Value>,
    pub checkpoint_key: Option<UnitCheckpointKey>,
    pub spec: WorkerSpec,
}

/// Identifies why the executor is asking whether a unit's inputs are valid.
/// A checkpoint read can share one schedule-wide preflight witness, while a
/// newly produced checkpoint must be guarded by a fresh witness because the
/// repository may have changed while the worker was running.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AnalysisInputValidation {
    Reuse,
    CheckpointWrite,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AnalysisUnitProgress {
    pub unit_id: String,
    pub adapter: String,
    pub status: String,
    pub reused: bool,
    #[serde(default)]
    pub stage: String,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub protocol_events: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    /// Loader observations the worker reported for this execution unit: the
    /// negotiated split identity, whether the loader scope was applied or
    /// widened, and the package loader's target, syntax, body, and memory
    /// counters.  Canonical profiles strip these per-execution values, so the
    /// ledger is where a scan explains what each unit actually loaded.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub loader: BTreeMap<String, String>,
}

/// Worker profile properties copied into the execution ledger of one unit.
const LOADER_OBSERVATION_KEYS: [&str; 22] = [
    "analysis_execution_unit_id",
    "analysis_split_kind",
    "analysis_loader_kind",
    "analysis_loader_input_split",
    "analysis_loader_scope",
    "analysis_loader_mode",
    "analysis_scope",
    "go_call_graph_program_scope",
    "go_loader_target_packages",
    "go_loader_target_files",
    "go_loader_syntax_packages",
    "go_loader_syntax_equals_targets",
    "go_loader_loaded_packages",
    "go_loader_body_files",
    "go_loader_declaration_only_files",
    "go_loader_reference_packages_export",
    "go_loader_reference_packages_source",
    "go_loader_peak_rss_bytes",
    "go_loader_child_max_rss_bytes",
    "go_loader_build_cache",
    "go_loader_build_cache_reused",
    "go_reference_fingerprint",
];

/// The loader observations of a worker stream: the properties of its
/// source-batch profile declarations that describe what the worker loaded.
/// Several declarations of one execution unit (a typed prefix echoed on a
/// semantic stream) agree on these keys; the last declaration wins.
pub(crate) fn loader_observations(events: &[Value]) -> BTreeMap<String, String> {
    let mut observations = BTreeMap::new();
    for event in events {
        if event["event"] != "profile_declared" {
            continue;
        }
        let Some(properties) = event["profile"]["properties"].as_object() else {
            continue;
        };
        if properties
            .get("analysis_unit_contract")
            .and_then(Value::as_str)
            != Some("depgraph-analysis-unit-v2")
        {
            continue;
        }
        for key in LOADER_OBSERVATION_KEYS {
            if let Some(value) = properties.get(key).and_then(Value::as_str) {
                observations.insert(key.to_owned(), value.to_owned());
            }
        }
    }
    observations
}

/// A package-bounded Go execution unit: the logical unit, stage, and package
/// roots its negotiated `split.loader` binds.  Units of workers that did not
/// negotiate loader scope, and module-bounded units, have no binding.
struct ReferenceBinding {
    unit_id: String,
    stage: String,
    package_roots: BTreeSet<String>,
}

fn reference_binding(item: &AnalysisWorkItem) -> Option<ReferenceBinding> {
    let request = item.request.as_ref()?;
    let loader = &request["split"]["loader"];
    if loader["kind"] != "package" {
        return None;
    }
    Some(ReferenceBinding {
        unit_id: request["unit_id"].as_str()?.to_owned(),
        stage: request["stage"].as_str()?.to_owned(),
        package_roots: loader["package_roots"]
            .as_array()?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
    })
}

/// Fold the `go_reference_fingerprint` every typed prerequisite of a
/// package-bounded semantic unit reported into the unit's checkpoint key.
///
/// The static key binds the module context the planner saw.  The fingerprint
/// the typed worker reports binds the in-repository import closure it actually
/// type-checked for the same package roots, which build constraints, test
/// variants, and `replace` directives can narrow or widen beyond what static
/// discovery resolves.  A semantic checkpoint is therefore reused only when
/// the typed stage of this scan loaded the same closure content.  Typed units
/// are always ingested before their semantic stage dispatches, so the
/// fingerprints are known here for fresh and replayed typed units alike.
fn bind_reference_fingerprints(
    index: usize,
    item: &mut AnalysisWorkItem,
    bindings: &[Option<ReferenceBinding>],
    progress: &AnalysisExecutionProgress,
) {
    let Some(binding) = bindings[index].as_ref() else {
        return;
    };
    if binding.stage != "semantic" {
        return;
    }
    let Some(key) = item.checkpoint_key.as_mut() else {
        return;
    };
    let fingerprints = bindings
        .iter()
        .enumerate()
        .filter(|(other, candidate)| {
            *other != index
                && candidate.as_ref().is_some_and(|candidate| {
                    candidate.unit_id == binding.unit_id
                        && candidate.stage == "typed"
                        && !candidate.package_roots.is_disjoint(&binding.package_roots)
                })
        })
        .map(|(other, _)| {
            progress.units[other]
                .loader
                .get("go_reference_fingerprint")
                .cloned()
        })
        .collect::<BTreeSet<_>>();
    let Ok(payload) = serde_json::to_vec(&json!({
        "contract":"analysis-go-reference-binding-v1","input":key.input_digest,
        "reference_fingerprints":fingerprints,
    })) else {
        return;
    };
    key.input_digest = format!("{:x}", Sha256::digest(payload));
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AnalysisExecutionProgress {
    pub units: Vec<AnalysisUnitProgress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
}

/// Observation is scoped to one scan future, so concurrent scans cannot share
/// progress. It does not grant cancellation or Store mutation authority.
#[derive(Clone, Debug, Default)]
pub struct AnalysisProgressObserver(
    Arc<Mutex<AnalysisExecutionProgress>>,
    Arc<std::sync::atomic::AtomicU64>,
);

impl AnalysisProgressObserver {
    pub fn revision(&self) -> u64 {
        self.1.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn snapshot(&self) -> AnalysisExecutionProgress {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn counts(&self) -> (u64, u64) {
        let progress = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (
            progress
                .units
                .iter()
                .filter(|unit| matches!(unit.status.as_str(), "completed" | "failed" | "cancelled"))
                .count() as u64,
            progress.units.len() as u64,
        )
    }
}

tokio::task_local! { static ANALYSIS_PROGRESS: AnalysisProgressObserver; }

pub async fn observe_analysis_progress<F: std::future::Future>(
    observer: AnalysisProgressObserver,
    future: F,
) -> F::Output {
    ANALYSIS_PROGRESS.scope(observer, future).await
}

fn publish_progress(progress: &AnalysisExecutionProgress) {
    let _ = ANALYSIS_PROGRESS.try_with(|observer| {
        *observer
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = progress.clone();
        observer
            .1
            .fetch_add(1, std::sync::atomic::Ordering::Release);
    });
}

fn publish_unit_progress(progress: &AnalysisExecutionProgress, index: usize) {
    let _ = ANALYSIS_PROGRESS.try_with(|observer| {
        let mut observed = observer
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(unit) = observed.units.get_mut(index) {
            *unit = progress.units[index].clone();
        }
        observer
            .1
            .fetch_add(1, std::sync::atomic::Ordering::Release);
    });
}

/// The executor uses one monotonic clock for per-unit elapsed time and the
/// optional scan budget. The private seam lets scheduler tests advance time
/// without sleeping; production uses the process monotonic clock.
trait AnalysisClock: Send + Sync {
    fn now(&self) -> Instant;
}

struct MonotonicAnalysisClock;

impl AnalysisClock for MonotonicAnalysisClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// One optional scan-wide budget is shared by the real timer and the
/// scheduler's observation point. The timer remains responsible for waking a
/// scan during synchronous work; the scheduler check makes the same policy
/// deterministic for tests and catches a budget that expires between units.
struct AnalysisBudget {
    started: Option<Instant>,
    seconds: Option<u64>,
}

impl AnalysisBudget {
    fn start(seconds: Option<u64>, clock: &dyn AnalysisClock) -> Self {
        Self {
            started: seconds.map(|_| clock.now()),
            seconds,
        }
    }

    fn duration(&self) -> Option<Duration> {
        self.seconds.map(Duration::from_secs)
    }

    fn expired(&self, clock: &dyn AnalysisClock) -> bool {
        let (Some(started), Some(seconds)) = (self.started, self.seconds) else {
            return false;
        };
        clock.now().saturating_duration_since(started) >= Duration::from_secs(seconds)
    }
}

fn elapsed_millis(clock: &dyn AnalysisClock, started: Instant) -> u64 {
    clock
        .now()
        .saturating_duration_since(started)
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

/// A caller's optional total budget also runs while static discovery performs
/// synchronous IO. Dropping the guard wakes and joins its thread immediately.
pub(crate) struct ScanBudgetGuard {
    stop: std::sync::mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ScanBudgetGuard {
    pub(crate) fn start(seconds: Option<u64>, cancellation: &CancellationToken) -> Option<Self> {
        let clock = MonotonicAnalysisClock;
        let budget = AnalysisBudget::start(seconds, &clock);
        let duration = budget.duration()?;
        let cancellation = cancellation.clone();
        let (stop, receiver) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            if matches!(
                receiver.recv_timeout(duration),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) && budget.expired(&clock)
            {
                cancellation.cancel_for_budget();
            }
        });
        Some(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for ScanBudgetGuard {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(crate) struct AnalysisExecutionContext<'a> {
    pub root: &'a Path,
    pub scan_id: &'a str,
    pub config: &'a Config,
    pub cache_mode: ScanCacheMode,
    pub cancellation: &'a CancellationToken,
}

pub(crate) async fn execute_analysis_units<F, V>(
    store: &mut Store,
    context: &AnalysisExecutionContext<'_>,
    work: Vec<AnalysisWorkItem>,
    consume: F,
    validate_inputs: V,
) -> Result<AnalysisExecutionProgress>
where
    F: FnMut(&mut Store, &str, WorkerOutput) -> Result<bool>,
    V: Fn(&AnalysisWorkItem, AnalysisInputValidation) -> bool,
{
    let clock = MonotonicAnalysisClock;
    execute_analysis_units_with_clock(store, context, work, &clock, consume, validate_inputs).await
}

async fn execute_analysis_units_with_clock<F, V>(
    store: &mut Store,
    context: &AnalysisExecutionContext<'_>,
    work: Vec<AnalysisWorkItem>,
    clock: &dyn AnalysisClock,
    mut consume: F,
    validate_inputs: V,
) -> Result<AnalysisExecutionProgress>
where
    F: FnMut(&mut Store, &str, WorkerOutput) -> Result<bool>,
    V: Fn(&AnalysisWorkItem, AnalysisInputValidation) -> bool,
{
    let AnalysisExecutionContext {
        root,
        scan_id,
        config,
        cache_mode,
        cancellation,
    } = *context;
    let checkpoints = if cache_mode == ScanCacheMode::Enabled {
        store.database_path().and_then(|path| {
            match UnitCheckpointStore::open(&path, config.scan.max_protocol_bytes) {
                Ok(checkpoints) => Some(checkpoints),
                Err(error) => {
                    tracing::warn!(%error, "analysis checkpoints unavailable; continuing without reuse");
                    None
                }
            }
        })
    } else {
        None
    };
    let budget = AnalysisBudget::start(config.scan.total_budget_seconds, clock);
    let prerequisites = stage_prerequisites(&work)?;
    let reference_bindings = work.iter().map(reference_binding).collect::<Vec<_>>();
    // One build cache serves every package-scoped Go unit of this scan and is
    // removed with it; units of workers without loader scope never see it.
    let build_cache = reference_bindings
        .iter()
        .any(Option::is_some)
        .then(|| ScanBuildCache::open(store.database_path().as_deref(), root))
        .flatten();
    let mut progress = AnalysisExecutionProgress {
        units: work
            .iter()
            .map(|item| AnalysisUnitProgress {
                unit_id: item.unit_id.clone(),
                adapter: item.spec.adapter.name().into(),
                status: "queued".into(),
                reused: false,
                stage: item
                    .request
                    .as_ref()
                    .and_then(|request| request["stage"].as_str())
                    .unwrap_or("repository")
                    .to_owned(),
                duration_ms: 0,
                protocol_events: 0,
                failure_reason: None,
                loader: BTreeMap::new(),
            })
            .collect(),
        stop_reason: None,
    };
    publish_progress(&progress);
    let repository_inventory = crate::repository_inventory::write_repository_inventory_file(root)?;
    let inventory_bytes = Arc::new(std::fs::read(repository_inventory.path())?);
    drop(repository_inventory);
    let mut pending = work.into_iter().enumerate().collect::<VecDeque<_>>();
    let mut running = JoinSet::new();
    let mut running_units = BTreeMap::new();
    let mut ready =
        BTreeMap::<usize, (String, WorkerOutput, bool, Option<StagedUnitCheckpoint>)>::new();
    let mut next_ingest = 0;
    let mut started = BTreeMap::<usize, Instant>::new();
    loop {
        while let Some((unit_id, output, reused, staged)) = ready.remove(&next_ingest) {
            progress.units[next_ingest].protocol_events = output.events.len() as u64;
            progress.units[next_ingest].loader = loader_observations(&output.events);
            progress.units[next_ingest].failure_reason =
                output.failure_kind.map(|kind| kind.as_str().to_owned());
            progress.units[next_ingest].duration_ms = started
                .remove(&next_ingest)
                .map(|time| elapsed_millis(clock, time))
                .unwrap_or(0);
            let complete = consume(store, &unit_id, output)?;
            if complete
                && !cancellation.is_cancelled()
                && let (Some(checkpoints), Some(staged)) = (&checkpoints, staged)
                && let Err(error) = checkpoints.commit(staged)
            {
                tracing::warn!(unit_id, %error, "analysis unit checkpoint could not be committed");
            }
            if !complete && progress.units[next_ingest].failure_reason.is_none() {
                progress.units[next_ingest].failure_reason = Some("ingestion-failed".to_owned());
            }
            progress.units[next_ingest].status = if cancellation.is_cancelled() {
                "cancelled"
            } else if complete {
                "completed"
            } else {
                "failed"
            }
            .into();
            progress.units[next_ingest].reused = reused && complete;
            publish_unit_progress(&progress, next_ingest);
            tracing::info!(unit_id, complete, reused, "analysis unit finished");
            next_ingest += 1;
        }
        if budget.expired(clock) {
            cancellation.cancel_for_budget();
        }
        // A bounded reorder window makes Store ingestion independent of worker
        // timing without retaining outputs for the whole repository in memory.
        while running.len() < config.scan.max_concurrent_units
            && !cancellation.is_cancelled()
            && pending.front().is_some_and(|(index, _)| {
                *index < next_ingest + config.scan.max_concurrent_units
                    && prerequisites[*index].is_none_or(|previous| previous < next_ingest)
            })
        {
            let Some((index, mut item)) = pending.pop_front() else {
                break;
            };
            bind_reference_fingerprints(index, &mut item, &reference_bindings, &progress);
            if let (Some(checkpoints), Some(key)) = (&checkpoints, &item.checkpoint_key)
                && validate_inputs(&item, AnalysisInputValidation::Reuse)
            {
                let cached = checkpoints.read(key).ok().flatten().and_then(|events| {
                    let output =
                        replay_analysis_checkpoint(events, &item.spec, root, scan_id, &config.scan)
                            .ok()?;
                    validate_unit_output(&item, &output).ok()?;
                    semantic_checkpoint_complete(item.request.as_ref(), &output.events)
                        .then_some(output)
                });
                if let Some(output) = cached {
                    ready.insert(index, (item.unit_id, output, true, None));
                    continue;
                }
            }
            progress.units[index].status = "running".into();
            started.insert(index, clock.now());
            publish_unit_progress(&progress, index);
            tracing::info!(unit_id = item.unit_id, "analysis unit started");
            let root = root.to_path_buf();
            let scan_id = scan_id.to_owned();
            let scan_config = config.scan.clone();
            let profiles = config.profiles.clone();
            let cancellation = cancellation.clone();
            let inventory_bytes = inventory_bytes.clone();
            let build_cache = (item.spec.adapter == AdapterKind::Go
                && reference_bindings[index].is_some())
            .then(|| build_cache.as_ref().map(|cache| cache.path().to_path_buf()))
            .flatten();
            let task_unit = (index, item.unit_id.clone(), item.spec.adapter);
            let task = running.spawn(async move {
                let mut spec = item.spec.clone();
                let inventory_file = (|| -> Result<_> {
                    let mut file = tempfile::Builder::new().prefix("depgraph-unit-inventory-").tempfile()?;
                    file.write_all(&inventory_bytes)?;
                    file.flush()?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        file.as_file().set_permissions(std::fs::Permissions::from_mode(0o400))?;
                    }
                    Ok(file)
                })();
                let request_file = item
                    .request
                    .as_ref()
                    .map(|request| -> Result<_> {
                        let mut file = tempfile::Builder::new()
                            .prefix("depgraph-analysis-unit-")
                            .tempfile()?;
                        let parent = file
                            .path()
                            .parent()
                            .context("analysis request has no parent")?
                            .canonicalize()?;
                        if parent.starts_with(&root) {
                            anyhow::bail!(
                                "security policy violation: analysis request is inside scan root"
                            );
                        }
                        serde_json::to_writer(file.as_file_mut(), request)?;
                        file.as_file_mut().flush()?;
                        spec.leading_args.push("--analysis-unit".into());
                        spec.leading_args.push(file.path().as_os_str().to_owned());
                        Ok(file)
                    })
                    .transpose();
                let files = inventory_file.and_then(|inventory| request_file.map(|request| (inventory, request)));
                let mut output = match files {
                    Ok((inventory_file, request_file)) => {
                        let inventory = inventory_file.path().to_path_buf();
                        let mut output = execute_worker_unit(
                            spec,
                            WorkerUnitInput {
                                root,
                                scan_id,
                                config: scan_config,
                                profiles,
                                cancellation,
                                inventory,
                                build_cache,
                            },
                        )
                        .await;
                        if !inventory_unchanged(inventory_file.path(), &inventory_bytes) {
                            output.error = Some("security policy violation: worker changed its repository inventory".into());
                            output.failure_kind = Some(crate::worker::WorkerFailureKind::MalformedProtocol);
                            output.security_violation = true;
                            output.events.clear();
                        }
                        drop(request_file);
                        output
                    }
                    Err(error) => WorkerOutput {
                        adapter: spec.adapter,
                        events: Vec::new(),
                        stderr: String::new(),
                        stderr_truncated: false,
                        error: Some(error.to_string()),
                        failure_kind: Some(crate::worker::WorkerFailureKind::Other),
                        security_violation: crate::worker::is_security_error(&error.to_string()),
                    },
                };
                if let Err(error) = validate_unit_output(&item, &output) {
                    output.error = Some(format!("security policy violation: {error}"));
                    output.failure_kind = Some(crate::worker::WorkerFailureKind::MalformedProtocol);
                    output.security_violation = true;
                    output.events.clear();
                }
                (index, item, output)
            });
            running_units.insert(task.id(), task_unit);
        }
        if ready.contains_key(&next_ingest) {
            continue;
        }
        let Some(result) = running.join_next_with_id().await else {
            break;
        };
        let (index, item, output) = match result {
            Ok((task_id, result)) => {
                running_units.remove(&task_id);
                result
            }
            Err(error) => {
                let (index, unit_id, adapter) = running_units
                    .remove(&error.id())
                    .context("analysis task has no owning unit")?;
                let output = WorkerOutput {
                    adapter,
                    events: Vec::new(),
                    stderr: String::new(),
                    stderr_truncated: false,
                    error: Some(format!("analysis unit task failed: {error}")),
                    failure_kind: Some(if error.is_panic() {
                        crate::worker::WorkerFailureKind::TaskPanic
                    } else {
                        crate::worker::WorkerFailureKind::Cancelled
                    }),
                    security_violation: false,
                };
                ready.insert(index, (unit_id, output, false, None));
                continue;
            }
        };
        // Serialize without publishing. A protocol-valid stream can still be
        // rejected by the Store's cross-unit integrity and coverage checks.
        let staged = if output.error.is_none()
            && semantic_checkpoint_complete(item.request.as_ref(), &output.events)
            && !cancellation.is_cancelled()
            && validate_inputs(&item, AnalysisInputValidation::CheckpointWrite)
            && let (Some(checkpoints), Some(key)) = (&checkpoints, &item.checkpoint_key)
        {
            match checkpoints.stage(key, &output.events) {
                Ok(staged) => staged,
                Err(error) => {
                    tracing::warn!(unit_id = item.unit_id, %error, "analysis unit checkpoint could not be staged");
                    None
                }
            }
        } else {
            None
        };
        ready.insert(index, (item.unit_id, output, false, staged));
    }
    for (index, _) in pending {
        progress.units[index].status = "cancelled".into();
    }
    if cancellation.is_cancelled() {
        progress.stop_reason = Some(
            if cancellation.is_budget_exhausted() {
                "total-budget-exceeded"
            } else {
                "cancelled"
            }
            .into(),
        );
    }
    publish_progress(&progress);
    Ok(progress)
}

/// A later stage may run alongside other units, but only after all preceding
/// chunks of its own unit have been consumed. In particular, SSA must not
/// start before the typed checkpoint has reached its durable boundary.
fn stage_prerequisites(work: &[AnalysisWorkItem]) -> Result<Vec<Option<usize>>> {
    let mut last = BTreeMap::new();
    for (index, item) in work.iter().enumerate() {
        if let Some(request) = &item.request
            && let (Some(unit), Some(stage)) =
                (request["unit_id"].as_str(), request["stage"].as_str())
        {
            last.insert((unit, stage), index);
        }
    }
    work.iter()
        .enumerate()
        .map(|(index, item)| {
            let Some(request) = &item.request else {
                return Ok(None);
            };
            let unit = request["unit_id"].as_str().unwrap_or_default();
            let prior: &[&str] = match request["stage"].as_str() {
                Some("typed") => &["syntax"],
                Some("semantic") => &["syntax", "typed"],
                _ => &[],
            };
            let previous = prior
                .iter()
                .filter_map(|stage| last.get(&(unit, *stage)))
                .max()
                .copied();
            anyhow::ensure!(
                previous.is_none_or(|previous| previous < index),
                "analysis schedule has an out-of-order stage prerequisite"
            );
            Ok(previous)
        })
        .collect()
}

/// A successful protocol stream can still contain a typed graph after SSA or
/// semantic extraction failed. Keep that useful graph, but rerun its semantic
/// unit next time rather than treating the incomplete analysis as a checkpoint.
fn semantic_checkpoint_complete(request: Option<&Value>, events: &[Value]) -> bool {
    let stage = request.and_then(|request| request["stage"].as_str());
    if stage == Some("typed") {
        let declared = events
            .iter()
            .filter(|event| event["event"] == "profile_declared")
            .map(|event| (&event["profile"]["id"], &event["profile"]["properties"]))
            .collect::<Vec<_>>();
        let complete = |event: &Value| {
            event["coverage"]["completeness"]
                .as_array()
                .is_some_and(|levels| {
                    levels.iter().any(|level| level == "syntax-complete")
                        && !levels.iter().any(|level| level == "semantic-complete")
                })
        };
        let profiles = events
            .iter()
            .filter(|event| event["event"] == "profile_completed")
            .collect::<Vec<_>>();
        return !profiles.is_empty()
            && profiles.iter().all(|event| {
                complete(event)
                    && declared.iter().any(|(id, properties)| {
                        **id == event["profile_id"]
                            && properties["go_typed_stage_complete"] == "true"
                            && properties["analysis_stage"] == "typed"
                    })
            })
            && events
                .iter()
                .any(|event| event["event"] == "scan_completed" && complete(event));
    }
    if stage != Some("semantic") {
        return true;
    }
    let complete = |event: &Value| {
        event["coverage"]["completeness"]
            .as_array()
            .is_some_and(|levels| levels.iter().any(|level| level == "semantic-complete"))
    };
    let profiles = events
        .iter()
        .filter(|event| event["event"] == "profile_completed")
        .collect::<Vec<_>>();
    !profiles.is_empty()
        && profiles.into_iter().all(complete)
        && events
            .iter()
            .any(|event| event["event"] == "scan_completed" && complete(event))
}

fn inventory_unchanged(path: &Path, expected: &[u8]) -> bool {
    use std::io::Read;
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_file() || metadata.len() != expected.len() as u64 {
        return false;
    }
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut observed = Vec::new();
    file.take(expected.len() as u64 + 1)
        .read_to_end(&mut observed)
        .is_ok()
        && observed == expected
}

fn validate_unit_output(item: &AnalysisWorkItem, output: &WorkerOutput) -> Result<()> {
    let Some(request) = item.request.as_ref() else {
        return Ok(());
    };
    let contract = request["contract_version"]
        .as_str()
        .context("analysis request has no contract")?;
    let unit_id = request["unit_id"]
        .as_str()
        .context("analysis request has no unit id")?;
    let unit_root = request["unit_root"]
        .as_str()
        .context("analysis request has no unit root")?;
    let stage = request["stage"]
        .as_str()
        .context("analysis request has no stage")?;
    let paths = request["source_paths"]
        .as_array()
        .context("analysis request has no source scope")?
        .iter()
        .filter_map(Value::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let prefix = format!("{unit_root}/");
    let batched = contract == crate::analysis_schedule::SOURCE_BATCH_CONTRACT;
    let auxiliary = request["auxiliary_paths"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let manifest = if unit_root == "." {
        "go.mod".to_owned()
    } else {
        format!("{unit_root}/go.mod")
    };
    let owns = |path: &str| {
        paths.contains(path)
            || auxiliary.contains(path)
            || (!batched
                && (path == manifest
                    || (unit_root == "." && path == "go.work")
                    || ((path.ends_with(".s") || path.ends_with(".S"))
                        && (unit_root == "." || path.starts_with(&prefix)))))
    };
    for event in &output.events {
        match event["event"].as_str() {
            Some("profile_declared") => {
                let properties = &event["profile"]["properties"];
                for (key, expected) in [
                    ("analysis_unit_contract", contract),
                    ("analysis_unit_id", unit_id),
                    ("analysis_unit_root", unit_root),
                    ("analysis_stage", stage),
                ] {
                    if properties[key].as_str() != Some(expected) {
                        anyhow::bail!(
                            "worker profile is not bound to the requested analysis unit ({key})"
                        );
                    }
                }
                if batched {
                    for (property, field) in [
                        ("analysis_chunk_id", "chunk_id"),
                        ("analysis_context_fingerprint", "context_fingerprint"),
                    ] {
                        if properties[property].as_str() != request[field].as_str()
                            || properties[property].as_str().is_none()
                        {
                            anyhow::bail!(
                                "worker profile is not bound to the requested source batch ({property})"
                            );
                        }
                    }
                    for (property, field) in [
                        ("analysis_chunk_index", "chunk_index"),
                        ("analysis_chunk_count", "chunk_count"),
                    ] {
                        if properties[property]
                            .as_str()
                            .and_then(|value| value.parse::<u64>().ok())
                            != request[field].as_u64()
                            || request[field].as_u64().is_none()
                        {
                            anyhow::bail!(
                                "worker profile has mismatched source batch cardinality ({property})"
                            );
                        }
                    }
                }
            }
            Some("file_completed") => {
                if !event["path"].as_str().is_some_and(owns) {
                    anyhow::bail!("worker file coverage escapes the requested analysis unit");
                }
            }
            Some("dependency_site") => {
                if event["site"]["evidence"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|evidence| evidence["path"].as_str())
                    .any(|path| !owns(path))
                {
                    anyhow::bail!("worker dependency source escapes the requested analysis unit");
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::AdapterKind;
    use serde_json::json;

    struct AdvancingAnalysisClock {
        epoch: Instant,
        step: Duration,
        ticks: std::sync::atomic::AtomicU64,
    }

    impl AdvancingAnalysisClock {
        fn new(step: Duration) -> Self {
            Self {
                epoch: Instant::now(),
                step,
                ticks: std::sync::atomic::AtomicU64::new(0),
            }
        }

        fn elapsed(&self) -> Duration {
            self.step
                .saturating_mul(self.ticks.load(std::sync::atomic::Ordering::Relaxed) as u32)
        }
    }

    impl AnalysisClock for AdvancingAnalysisClock {
        fn now(&self) -> Instant {
            let tick = self
                .ticks
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.epoch
                .checked_add(self.step.saturating_mul(tick as u32))
                .expect("test clock must remain representable")
        }
    }

    #[tokio::test]
    async fn progress_observers_are_isolated_between_concurrent_scan_futures() {
        let first = AnalysisProgressObserver::default();
        let second = AnalysisProgressObserver::default();
        let run = |id: &'static str| async move {
            let mut progress = AnalysisExecutionProgress {
                units: vec![AnalysisUnitProgress {
                    unit_id: id.to_owned(),
                    adapter: "web".to_owned(),
                    status: "running".to_owned(),
                    reused: false,
                    stage: "syntax".to_owned(),
                    duration_ms: 0,
                    protocol_events: 0,
                    failure_reason: None,
                    loader: BTreeMap::new(),
                }],
                stop_reason: None,
            };
            publish_progress(&progress);
            tokio::task::yield_now().await;
            progress.units[0].status = "completed".to_owned();
            publish_unit_progress(&progress, 0);
        };
        tokio::join!(
            observe_analysis_progress(first.clone(), run("first")),
            observe_analysis_progress(second.clone(), run("second"))
        );
        assert_eq!(first.snapshot().units[0].unit_id, "first");
        assert_eq!(second.snapshot().units[0].unit_id, "second");
        assert_eq!(first.counts(), (1, 1));
        assert_eq!(second.counts(), (1, 1));
        assert_eq!(first.revision(), 2);
        publish_progress(&AnalysisExecutionProgress::default());
        assert_eq!(first.counts(), (1, 1));
    }

    #[tokio::test]
    async fn explicit_budget_cancels_and_dropped_or_absent_budgets_do_not() {
        let cancellation = CancellationToken::new();
        let guard = ScanBudgetGuard::start(Some(1), &cancellation);
        tokio::time::timeout(Duration::from_secs(3), cancellation.cancelled())
            .await
            .unwrap();
        assert!(cancellation.is_budget_exhausted());
        drop(guard);
        let active = CancellationToken::new();
        assert!(ScanBudgetGuard::start(None, &active).is_none());
        let start = Instant::now();
        drop(ScanBudgetGuard::start(Some(300), &active));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(!active.is_cancelled());
    }

    #[tokio::test]
    async fn progressing_scheduler_outlives_legacy_aggregate_deadline_with_fake_clock() -> Result<()>
    {
        const LEGACY_AGGREGATE_DEADLINE: Duration = Duration::from_secs(300);

        let temp = tempfile::tempdir()?;
        let root = temp.path().join("project");
        std::fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        let worker = temp.path().join("worker.mjs");
        std::fs::write(
            &worker,
            r#"
import fs from 'node:fs';
const args = process.argv.slice(2);
const arg = key => args[args.indexOf(key) + 1];
const request = JSON.parse(fs.readFileSync(arg('--analysis-unit'), 'utf8'));
const common = { protocol_version:'1.0', scan_id:arg('--scan-id'), adapter:'go', adapter_version:'0.1.0' };
const coverage = { profiles:1, files_discovered:0, files_analyzed:0, files_skipped:0, dependency_sites:0, resolved:0, candidates:0, external:0, unresolved:0, unsupported_syntax:0, project_code_executed:false, completeness:['syntax-complete'], reasons:[] };
const profile = { id:'go:'+request.unit_id, language:'go', features:[], environment:{}, properties:{ analysis_unit_contract:request.contract_version, analysis_unit_id:request.unit_id, analysis_unit_root:request.unit_root, analysis_stage:request.stage } };
for (const event of [
  { event:'scan_started', seq:1, root:arg('--root'), project_code_executed:false, safe_mode:true },
  { event:'profile_declared', seq:2, profile },
  { event:'profile_completed', seq:3, profile_id:profile.id, coverage },
  { event:'scan_completed', seq:4, coverage },
]) console.log(JSON.stringify({...common, ...event}));
"#,
        )?;
        let spec = WorkerSpec {
            adapter: AdapterKind::Go,
            program: "node".into(),
            leading_args: vec![worker.clone().into_os_string()],
            display: "fake-clock scheduler fixture".into(),
            artifact_path: worker,
            runtime_requirement: None,
            expected_version: None,
            release_attested: false,
            attested_rust_sysroot: None,
        };
        let work = || {
            (0..4)
                .map(|index| {
                    let unit_id = format!("unit-{index}");
                    AnalysisWorkItem {
                        unit_id: unit_id.clone(),
                        request: Some(json!({
                            "contract_version":"depgraph-analysis-unit-v1",
                            "unit_id":unit_id,
                            "unit_root":".",
                            "stage":"syntax",
                            "source_paths":[]
                        })),
                        checkpoint_key: None,
                        spec: spec.clone(),
                    }
                })
                .collect::<Vec<_>>()
        };
        let config = Config::default();
        assert_eq!(config.scan.total_budget_seconds, None);
        let cancellation = CancellationToken::new();
        let context = AnalysisExecutionContext {
            root: &root,
            scan_id: "fake-clock-progress",
            config: &config,
            cache_mode: ScanCacheMode::Disabled,
            cancellation: &cancellation,
        };
        let store_path = temp.path().join("store.sqlite");
        let mut store = Store::open(&store_path)?;
        let clock = AdvancingAnalysisClock::new(Duration::from_secs(600));
        let progress = execute_analysis_units_with_clock(
            &mut store,
            &context,
            work(),
            &clock,
            |_, _, output| Ok(output.error.is_none()),
            |_, _| true,
        )
        .await?;

        assert!(
            clock.elapsed() > LEGACY_AGGREGATE_DEADLINE,
            "fixture must advance beyond the removed aggregate deadline"
        );
        assert!(!cancellation.is_cancelled());
        assert_eq!(progress.stop_reason, None);
        assert_eq!(progress.units.len(), 4);
        assert!(progress.units.iter().all(|unit| unit.status == "completed"));
        assert!(
            progress
                .units
                .iter()
                .all(|unit| { unit.duration_ms >= LEGACY_AGGREGATE_DEADLINE.as_millis() as u64 })
        );

        let mut explicit_config = config.clone();
        explicit_config.scan.total_budget_seconds = Some(300);
        let explicit_cancellation = CancellationToken::new();
        let explicit_context = AnalysisExecutionContext {
            root: &root,
            scan_id: "fake-clock-explicit-budget",
            config: &explicit_config,
            cache_mode: ScanCacheMode::Disabled,
            cancellation: &explicit_cancellation,
        };
        let explicit_store_path = temp.path().join("explicit-budget.sqlite");
        let mut explicit_store = Store::open(&explicit_store_path)?;
        let explicit_clock = AdvancingAnalysisClock::new(Duration::from_secs(600));
        let explicit = execute_analysis_units_with_clock(
            &mut explicit_store,
            &explicit_context,
            work(),
            &explicit_clock,
            |_, _, output| Ok(output.error.is_none()),
            |_, _| true,
        )
        .await?;
        assert!(explicit_clock.elapsed() > LEGACY_AGGREGATE_DEADLINE);
        assert!(explicit_cancellation.is_budget_exhausted());
        assert_eq!(
            explicit.stop_reason.as_deref(),
            Some("total-budget-exceeded")
        );
        assert!(explicit.units.iter().all(|unit| unit.status == "cancelled"));
        Ok(())
    }

    #[test]
    fn incomplete_semantics_remain_readable_but_are_not_reused() {
        let request = json!({"stage":"semantic"});
        let mut events = vec![
            json!({"event":"node_upsert","node":{"id":"typed-target"}}),
            json!({"event":"profile_completed","coverage":{"completeness":["syntax-complete"]}}),
            json!({"event":"scan_completed","coverage":{"completeness":["syntax-complete"]}}),
        ];
        let original = events.clone();
        assert!(!semantic_checkpoint_complete(Some(&request), &events));
        assert_eq!(
            events, original,
            "eligibility must not discard the typed graph"
        );
        for event in &mut events[1..] {
            event["coverage"]["completeness"] = json!(["semantic-complete"]);
        }
        assert!(semantic_checkpoint_complete(Some(&request), &events));
        events.push(json!({"event":"profile_completed","coverage":{"completeness":[]}}));
        assert!(!semantic_checkpoint_complete(Some(&request), &events));
        assert!(semantic_checkpoint_complete(
            Some(&json!({"stage":"syntax"})),
            &original
        ));
    }

    #[test]
    fn typed_checkpoint_requires_a_completed_typed_graph_without_claiming_ssa() {
        let request = json!({"stage":"typed"});
        let events = vec![
            json!({"event":"profile_declared","profile":{"id":"typed-profile","properties":{
                "analysis_stage":"typed","go_typed_stage_complete":"true"}}}),
            json!({"event":"node_upsert","node":{"id":"typed-target"}}),
            json!({"event":"profile_completed","profile_id":"typed-profile","coverage":{"completeness":["syntax-complete"]}}),
            json!({"event":"scan_completed","coverage":{"completeness":["syntax-complete"]}}),
        ];
        assert!(semantic_checkpoint_complete(Some(&request), &events));
        let mut incomplete = events.clone();
        incomplete[0]["profile"]["properties"]["go_typed_stage_complete"] = json!("false");
        assert!(!semantic_checkpoint_complete(Some(&request), &incomplete));
        let mut wrong_profile = events.clone();
        wrong_profile[2]["profile_id"] = json!("other-profile");
        assert!(!semantic_checkpoint_complete(
            Some(&request),
            &wrong_profile
        ));
        let mut overclaimed = events.clone();
        overclaimed[3]["coverage"]["completeness"] =
            json!(["syntax-complete", "semantic-complete"]);
        assert!(!semantic_checkpoint_complete(Some(&request), &overclaimed));
        assert!(!semantic_checkpoint_complete(Some(&request), &events[..3]));
    }

    #[test]
    fn unit_output_cannot_claim_another_units_profile_or_source_coverage() -> Result<()> {
        let item = AnalysisWorkItem {
            unit_id: "unit:syntax".into(),
            request: Some(
                json!({"contract_version":"depgraph-analysis-unit-v1", "unit_id":"unit",
                "unit_root":"app", "stage":"syntax", "source_paths":["app/main.go"]}),
            ),
            checkpoint_key: None,
            spec: WorkerSpec {
                adapter: AdapterKind::Go,
                program: "go-worker".into(),
                leading_args: vec![],
                display: "fixture".into(),
                artifact_path: "go-worker".into(),
                runtime_requirement: None,
                expected_version: None,
                release_attested: false,
                attested_rust_sysroot: None,
            },
        };
        let mut output = WorkerOutput {
            adapter: AdapterKind::Go,
            events: vec![
                json!({"event":"profile_declared", "profile":{"properties": {
                "analysis_unit_contract":"depgraph-analysis-unit-v1", "analysis_unit_id":"unit",
                "analysis_unit_root":"app", "analysis_stage":"syntax"}}}),
                json!({"event":"file_completed", "path":"app/main.go"}),
            ],
            stderr: String::new(),
            stderr_truncated: false,
            error: None,
            failure_kind: None,
            security_violation: false,
        };
        validate_unit_output(&item, &output)?;
        output.events[1]["path"] = json!("other/main.go");
        assert!(validate_unit_output(&item, &output).is_err());
        output.events[1]["path"] = json!("app/main.go");
        output.events[0]["profile"]["properties"]["analysis_unit_id"] = json!("other");
        assert!(validate_unit_output(&item, &output).is_err());
        let directory = tempfile::tempdir()?;
        let inventory = directory.path().join("inventory.json");
        std::fs::write(&inventory, b"original")?;
        assert!(inventory_unchanged(&inventory, b"original"));
        std::fs::write(&inventory, b"modified")?;
        assert!(!inventory_unchanged(&inventory, b"original"));
        Ok(())
    }

    #[tokio::test]
    async fn typed_results_are_durable_before_ssa_and_survive_failed_semantics() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("project");
        std::fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        let worker = temp.path().join("worker.mjs");
        let typed_saved = temp.path().join("typed-saved");
        let retry = temp.path().join("retry");
        let executions = temp.path().join("executions");
        let script = r#"
import fs from 'node:fs';
const args = process.argv.slice(2);
const arg = key => args[args.indexOf(key) + 1];
const request = JSON.parse(fs.readFileSync(arg('--analysis-unit'), 'utf8'));
fs.appendFileSync(EXECUTIONS, request.stage + '\n');
if (request.stage === 'typed') await new Promise(resolve => setTimeout(resolve, 150));
if (request.stage === 'semantic') {
  if (!fs.existsSync(TYPED_SAVED)) { console.error('SSA started before typed ingestion'); process.exit(2); }
  if (!fs.existsSync(RETRY)) process.exit(1);
}
const common = { protocol_version:'1.0',scan_id:arg('--scan-id'),adapter:'go',adapter_version:'0.1.0' };
const coverage = { profiles:1,files_discovered:0,files_analyzed:0,files_skipped:0,dependency_sites:0,resolved:0,candidates:0,external:0,unresolved:0,unsupported_syntax:0,project_code_executed:false,completeness:['syntax-complete'],reasons:[] };
const properties = { analysis_unit_contract:request.contract_version,analysis_unit_id:request.unit_id,analysis_unit_root:request.unit_root,analysis_stage:request.stage,analysis_chunk_id:request.chunk_id,analysis_chunk_index:'0',analysis_chunk_count:'1',analysis_context_fingerprint:'context',go_typed_stage_complete:request.stage === 'typed' ? 'true' : 'false' };
const profile = { id:'go:'+request.stage,language:'go',features:[],environment:{},properties };
const events = [
 {event:'scan_started',seq:1,root:arg('--root'),project_code_executed:false,safe_mode:true},
 {event:'profile_declared',seq:2,profile},
 {event:'profile_completed',seq:3,profile_id:profile.id,coverage},
 {event:'scan_completed',seq:4,coverage}
];
for (const event of events) console.log(JSON.stringify({...common,...event}));
"#;
        let script = script
            .replace("EXECUTIONS", &serde_json::to_string(&executions)?)
            .replace("TYPED_SAVED", &serde_json::to_string(&typed_saved)?)
            .replace("RETRY", &serde_json::to_string(&retry)?);
        std::fs::write(&worker, script)?;
        let spec = WorkerSpec {
            adapter: AdapterKind::Go,
            program: "node".into(),
            leading_args: vec![worker.clone().into_os_string()],
            display: "typed checkpoint fixture".into(),
            artifact_path: worker,
            runtime_requirement: None,
            expected_version: None,
            release_attested: false,
            attested_rust_sysroot: None,
        };
        let work = || {
            ["syntax", "typed", "semantic"].into_iter().map(|stage| {
            let id = format!("unit:{stage}");
            AnalysisWorkItem {
                unit_id: id.clone(),
                request: Some(json!({"contract_version":"depgraph-analysis-unit-v2","unit_id":"unit","unit_root":".","stage":stage,"source_paths":[],"context_paths":[],"auxiliary_paths":[],"chunk_id":stage,"chunk_index":0,"chunk_count":1,"context_fingerprint":"context"})),
                spec: spec.clone(),
                checkpoint_key: Some(UnitCheckpointKey { unit_id:id,input_digest:"input".into(),execution_digest:"worker".into(),root_digest:"root".into() }),
            }
        }).collect()
        };
        let consume = |_: &mut Store, id: &str, output: WorkerOutput| {
            if id == "unit:typed" && output.error.is_none() {
                std::fs::write(&typed_saved, "saved")?;
            }
            Ok(output.error.is_none())
        };
        let store_path = temp.path().join("store.sqlite");
        let config = Config::default();
        let cancellation = CancellationToken::new();
        let context = AnalysisExecutionContext {
            root: &root,
            scan_id: "typed-failure",
            config: &config,
            cache_mode: ScanCacheMode::Enabled,
            cancellation: &cancellation,
        };
        let mut store = Store::open(&store_path)?;
        let first =
            execute_analysis_units(&mut store, &context, work(), consume, |_, _| true).await?;
        assert_eq!(
            first
                .units
                .iter()
                .map(|unit| unit.status.as_str())
                .collect::<Vec<_>>(),
            ["completed", "completed", "failed"]
        );
        assert_eq!(
            std::fs::read_to_string(&executions)?,
            "syntax\ntyped\nsemantic\n"
        );
        drop(store);
        std::fs::write(&retry, "retry")?;
        std::fs::remove_file(&typed_saved)?;
        let mut store = Store::open(&store_path)?;
        let resumed =
            execute_analysis_units(&mut store, &context, work(), consume, |_, _| true).await?;
        assert!(resumed.units.iter().all(|unit| unit.status == "completed"));
        assert_eq!(
            resumed
                .units
                .iter()
                .map(|unit| unit.reused)
                .collect::<Vec<_>>(),
            [true, true, false]
        );
        assert_eq!(
            std::fs::read_to_string(&executions)?,
            "syntax\ntyped\nsemantic\nsemantic\n"
        );
        Ok(())
    }

    /// Package-bounded units share one scan-scoped build cache outside the
    /// scan root that disappears with the scan, and a semantic checkpoint is
    /// reused only while the typed stage reports the same reference
    /// fingerprint: a changed in-repository closure re-runs SSA even when the
    /// semantic unit's own static key did not move.
    #[tokio::test]
    async fn package_semantic_checkpoints_bind_the_typed_reference_fingerprint() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("project");
        std::fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        let worker = temp.path().join("worker.mjs");
        let fingerprint = temp.path().join("fingerprint");
        let executions = temp.path().join("executions");
        let caches = temp.path().join("caches");
        std::fs::write(&fingerprint, "sha256:closure-a")?;
        let script = r#"
import fs from 'node:fs';
import path from 'node:path';
const args = process.argv.slice(2);
const arg = key => args[args.indexOf(key) + 1];
const request = JSON.parse(fs.readFileSync(arg('--analysis-unit'), 'utf8'));
fs.appendFileSync(EXECUTIONS, request.stage + '\n');
const cache = process.env.DEPGRAPH_GO_BUILD_CACHE ?? '';
if (!path.isAbsolute(cache) || !fs.statSync(cache).isDirectory() || cache.startsWith(arg('--root'))) {
  console.error('missing or misplaced build cache: ' + cache); process.exit(2);
}
fs.appendFileSync(CACHES, cache + '\n');
const common = { protocol_version:'1.0',scan_id:arg('--scan-id'),adapter:'go',adapter_version:'0.1.0' };
const completeness = request.stage === 'semantic' ? ['syntax-complete','semantic-complete'] : ['syntax-complete'];
const coverage = { profiles:1,files_discovered:0,files_analyzed:0,files_skipped:0,dependency_sites:0,resolved:0,candidates:0,external:0,unresolved:0,unsupported_syntax:0,project_code_executed:false,completeness,reasons:[] };
const properties = { analysis_unit_contract:request.contract_version,analysis_unit_id:request.unit_id,analysis_unit_root:request.unit_root,analysis_stage:request.stage,analysis_chunk_id:request.chunk_id,analysis_chunk_index:'0',analysis_chunk_count:'1',analysis_context_fingerprint:'context',analysis_loader_scope:'applied',go_reference_fingerprint:fs.readFileSync(FINGERPRINT,'utf8'),go_typed_stage_complete:'true' };
const profile = { id:'go:'+request.stage,language:'go',features:[],environment:{},properties };
const events = [
 {event:'scan_started',seq:1,root:arg('--root'),project_code_executed:false,safe_mode:true},
 {event:'profile_declared',seq:2,profile},
 {event:'profile_completed',seq:3,profile_id:profile.id,coverage},
 {event:'scan_completed',seq:4,coverage}
];
for (const event of events) console.log(JSON.stringify({...common,...event}));
"#;
        let script = script
            .replace("EXECUTIONS", &serde_json::to_string(&executions)?)
            .replace("FINGERPRINT", &serde_json::to_string(&fingerprint)?)
            .replace("CACHES", &serde_json::to_string(&caches)?);
        std::fs::write(&worker, script)?;
        let spec = WorkerSpec {
            adapter: AdapterKind::Go,
            program: "node".into(),
            leading_args: vec![worker.clone().into_os_string()],
            display: "package loader fixture".into(),
            artifact_path: worker,
            runtime_requirement: None,
            expected_version: None,
            release_attested: false,
            attested_rust_sysroot: None,
        };
        let work = |typed_input: &str| {
            ["typed", "semantic"].into_iter().map(|stage| {
            let id = format!("unit:{stage}");
            AnalysisWorkItem {
                unit_id: id.clone(),
                request: Some(json!({"contract_version":"depgraph-analysis-unit-v2","unit_id":"unit","unit_root":".","stage":stage,"source_paths":["app/a.go"],"context_paths":["app/a.go"],"auxiliary_paths":[],"chunk_id":stage,"chunk_index":0,"chunk_count":1,"context_fingerprint":"context",
                    "split":{"split_plan_id":"plan","execution_unit_id":format!("{stage}-app"),"split_kind":"package","loader":{"kind":"package","paths":["app/a.go"],"package_roots":["app"],"reference_depth":"declarations","reference_paths":[],"input_split":false}}})),
                spec: spec.clone(),
                checkpoint_key: Some(UnitCheckpointKey { unit_id:id,input_digest:if stage == "typed" { typed_input.to_owned() } else { "semantic-input".to_owned() },execution_digest:"worker".into(),root_digest:"root".into() }),
            }
        }).collect::<Vec<_>>()
        };
        let consume = |_: &mut Store, _: &str, output: WorkerOutput| Ok(output.error.is_none());
        let store_path = temp.path().join("store.sqlite");
        let config = Config::default();
        let cancellation = CancellationToken::new();
        let context = AnalysisExecutionContext {
            root: &root,
            scan_id: "package-binding",
            config: &config,
            cache_mode: ScanCacheMode::Enabled,
            cancellation: &cancellation,
        };
        let mut store = Store::open(&store_path)?;
        let first =
            execute_analysis_units(&mut store, &context, work("typed-a"), consume, |_, _| true)
                .await?;
        assert!(
            first.units.iter().all(|unit| unit.status == "completed"),
            "{first:?}"
        );
        assert_eq!(
            first.units[0]
                .loader
                .get("go_reference_fingerprint")
                .map(String::as_str),
            Some("sha256:closure-a")
        );
        let recorded = std::fs::read_to_string(&caches)?;
        let cache_dirs = recorded.lines().collect::<BTreeSet<_>>();
        assert_eq!(
            cache_dirs.len(),
            1,
            "one shared build cache per scan: {recorded}"
        );
        let cache_dir = Path::new(cache_dirs.iter().next().unwrap());
        assert!(cache_dir.starts_with(temp.path().canonicalize()?.join(".depgraph")));
        assert!(
            !cache_dir.exists(),
            "the scan-scoped build cache is removed with the scan"
        );

        // Same module context and same reported closure: both stages replay.
        let same =
            execute_analysis_units(&mut store, &context, work("typed-a"), consume, |_, _| true)
                .await?;
        assert_eq!(
            same.units
                .iter()
                .map(|unit| unit.reused)
                .collect::<Vec<_>>(),
            [true, true]
        );
        assert_eq!(std::fs::read_to_string(&executions)?, "typed\nsemantic\n");

        // The typed stage re-runs and reports a different in-repository closure;
        // the semantic checkpoint keyed on the old closure must not be reused.
        std::fs::write(&fingerprint, "sha256:closure-b")?;
        let changed =
            execute_analysis_units(&mut store, &context, work("typed-b"), consume, |_, _| true)
                .await?;
        assert_eq!(
            changed
                .units
                .iter()
                .map(|unit| unit.reused)
                .collect::<Vec<_>>(),
            [false, false]
        );
        assert_eq!(
            std::fs::read_to_string(&executions)?,
            "typed\nsemantic\ntyped\nsemantic\n"
        );
        // Restoring the previous closure content brings the old semantic
        // checkpoint back without re-running SSA.
        std::fs::write(&fingerprint, "sha256:closure-a")?;
        let restored =
            execute_analysis_units(&mut store, &context, work("typed-a"), consume, |_, _| true)
                .await?;
        assert_eq!(
            restored
                .units
                .iter()
                .map(|unit| unit.reused)
                .collect::<Vec<_>>(),
            [true, true]
        );
        Ok(())
    }

    #[tokio::test]
    async fn retries_failed_units_and_reuses_only_valid_completed_results() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("project");
        std::fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        let worker = temp.path().join("worker.mjs");
        let ready = temp.path().join("ready");
        let executions = temp.path().join("executions");
        let script = r#"
import fs from 'node:fs';
const args = process.argv.slice(2);
const arg = key => args[args.indexOf(key) + 1];
const request = JSON.parse(fs.readFileSync(arg('--analysis-unit'), 'utf8'));
fs.appendFileSync(EXECUTIONS, request.unit_id + '\n');
if (request.unit_id === 'first') await new Promise(resolve => setTimeout(resolve, 150));
if (request.unit_id === 'second' && !fs.existsSync(READY)) process.exit(1);
const common = { protocol_version:'1.0', scan_id:arg('--scan-id'), adapter:'go', adapter_version:'0.1.0' };
const coverage = { profiles:1,files_discovered:0,files_analyzed:0,files_skipped:0,dependency_sites:0,resolved:0,candidates:0,external:0,unresolved:0,unsupported_syntax:0,project_code_executed:false,completeness:['syntax-complete'],reasons:[] };
const events = [
 {event:'scan_started', seq:1, root:arg('--root'), project_code_executed:false, safe_mode:true},
 {event:'profile_declared', seq:2, profile:{id:'go:'+request.unit_id,language:'go',features:[],environment:{},properties:{analysis_unit_contract:request.contract_version,analysis_unit_id:request.unit_id,analysis_unit_root:request.unit_root,analysis_stage:request.stage}}},
 {event:'profile_completed', seq:3, profile_id:'go:'+request.unit_id,coverage},
 {event:'scan_completed', seq:4,coverage}
];
for (const event of events) console.log(JSON.stringify({...common,...event}));
"#;
        let script = script
            .replace("EXECUTIONS", &serde_json::to_string(&executions)?)
            .replace("READY", &serde_json::to_string(&ready)?);
        std::fs::write(&worker, script)?;
        let spec = WorkerSpec {
            adapter: AdapterKind::Go,
            program: "node".into(),
            leading_args: vec![worker.clone().into_os_string()],
            display: "test worker".into(),
            artifact_path: worker,
            runtime_requirement: None,
            expected_version: None,
            release_attested: false,
            attested_rust_sysroot: None,
        };
        let work = |changed: bool| {
            ["first", "second"]
                .into_iter()
                .map(|id| AnalysisWorkItem {
                    unit_id: id.into(),
                    request: Some(json!({"contract_version":"depgraph-analysis-unit-v1","unit_id":id,"unit_root":".","source_paths":[],"stage":"syntax"})),
                    spec: spec.clone(),
                    checkpoint_key: Some(UnitCheckpointKey {
                        unit_id: id.into(),
                        input_digest: if changed { "changed" } else { "input" }.into(),
                        execution_digest: "worker".into(),
                        root_digest: "root".into(),
                    }),
                })
                .collect()
        };
        let store_path = temp.path().join("store.sqlite");
        let mut store = Store::open(&store_path)?;
        let consumed = std::cell::RefCell::new(Vec::new());
        let consume = |_: &mut Store, id: &str, output: WorkerOutput| {
            consumed.borrow_mut().push(id.to_owned());
            Ok(output.error.is_none())
        };
        let config = Config::default();
        let cancellation = CancellationToken::new();
        let first = execute_analysis_units(
            &mut store,
            &AnalysisExecutionContext {
                root: &root,
                scan_id: "first-attempt",
                config: &config,
                cache_mode: ScanCacheMode::Enabled,
                cancellation: &cancellation,
            },
            work(false),
            consume,
            |_, _| true,
        )
        .await?;
        assert_eq!(
            first
                .units
                .iter()
                .map(|unit| unit.status.as_str())
                .collect::<Vec<_>>(),
            ["completed", "failed"]
        );
        drop(store);
        std::fs::write(&ready, "ready")?;
        let mut store = Store::open(&store_path)?;
        let resumed = execute_analysis_units(
            &mut store,
            &AnalysisExecutionContext {
                root: &root,
                scan_id: "resumed-attempt",
                config: &config,
                cache_mode: ScanCacheMode::Enabled,
                cancellation: &cancellation,
            },
            work(false),
            consume,
            |_, _| true,
        )
        .await?;
        assert!(resumed.units.iter().all(|unit| unit.status == "completed"));
        assert_eq!(
            resumed
                .units
                .iter()
                .map(|unit| unit.reused)
                .collect::<Vec<_>>(),
            [true, false]
        );
        assert_eq!(std::fs::read_to_string(&executions)?.lines().count(), 3);
        let changed = execute_analysis_units(
            &mut store,
            &AnalysisExecutionContext {
                root: &root,
                scan_id: "changed-attempt",
                config: &config,
                cache_mode: ScanCacheMode::Enabled,
                cancellation: &cancellation,
            },
            work(true),
            consume,
            |_, _| true,
        )
        .await?;
        assert!(changed.units.iter().all(|unit| !unit.reused));
        assert_eq!(std::fs::read_to_string(&executions)?.lines().count(), 5);
        assert_eq!(
            *consumed.borrow(),
            ["first", "second", "first", "second", "first", "second"]
        );
        // A complete protocol stream may still fail cross-unit Store checks.
        // It must be executed again, while a neighboring accepted unit reuses.
        let rejected_work = || {
            let mut items: Vec<AnalysisWorkItem> = work(true);
            for item in &mut items {
                item.checkpoint_key.as_mut().unwrap().input_digest = "ingestion-rejected".into();
            }
            items
        };
        let context = AnalysisExecutionContext {
            root: &root,
            scan_id: "ingestion-rejected",
            config: &config,
            cache_mode: ScanCacheMode::Enabled,
            cancellation: &cancellation,
        };
        let rejected = execute_analysis_units(
            &mut store,
            &context,
            rejected_work(),
            |_, id, output| Ok(id != "first" && output.error.is_none()),
            |_, _| true,
        )
        .await?;
        assert_eq!(rejected.units[0].status, "failed");
        let retried =
            execute_analysis_units(&mut store, &context, rejected_work(), consume, |_, _| true)
                .await?;
        assert_eq!(
            retried
                .units
                .iter()
                .map(|unit| unit.reused)
                .collect::<Vec<_>>(),
            [false, true]
        );
        assert_eq!(std::fs::read_to_string(&executions)?.lines().count(), 8);
        Ok(())
    }
}
