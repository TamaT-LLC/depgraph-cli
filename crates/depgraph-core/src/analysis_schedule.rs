//! Bind static discovery to an explicitly negotiated worker capability.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::Path,
    sync::{Arc, OnceLock},
};

use anyhow::Result;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    analysis_checkpoint::UnitCheckpointKey,
    analysis_execution::{AnalysisExecutionContext, AnalysisInputValidation, AnalysisWorkItem},
    analysis_plan::{
        AnalysisAdapter, AnalysisPlan, AnalysisUnit, AnalysisUnitKind, path_belongs_to_adapter,
        plan_analysis_units, source_path_belongs_to_adapter,
    },
    analysis_split::{
        AnalysisAdapterBoundary, AnalysisSplitBudget, AnalysisSplitInput, AnalysisSplitPlan,
        AnalysisStage, measure_source_sizes, plan_analysis_split,
    },
    cache::{
        ScanCachePreparation, fingerprint_adapters, fingerprint_scan_inputs,
        fingerprint_toolchains, prepare_scan_cache,
    },
    repository_inventory::build_repository_file_inventory,
    scan::ScanCacheMode,
    worker::{
        AdapterKind, WorkerSpec, probe_worker_version_with_cancellation, worker_capabilities,
    },
};

pub(crate) struct AnalysisSchedule {
    pub plan: Option<AnalysisPlan>,
    /// The pre-split decision for every source-batch adapter: ownership and
    /// loader scopes, estimates, split reasons, and the parallelism decision.
    /// `None` when no worker negotiated source batches.
    pub split_plan: Option<AnalysisSplitPlan>,
    pub work: Vec<AnalysisWorkItem>,
    pub input_proof: Option<Arc<AnalysisInputProof>>,
}

/// Work for one adapter, kept in worker order until the shared split plan
/// has been decided for every source-batch adapter.
enum ScheduledAdapter<'a> {
    Ready(Vec<AnalysisWorkItem>),
    SourceBatches(Box<SourceBatchSchedule<'a>>),
}

struct SourceBatchSchedule<'a> {
    adapter: AdapterKind,
    spec: WorkerSpec,
    units: Vec<&'a AnalysisUnit>,
    capabilities: Vec<String>,
    batch_contexts: Vec<SourceBatchContext>,
    execution_digest: Option<String>,
}

/// A repository-wide content witness shared by all analysis units.  The
/// initial digest may come from the bounded cache fingerprint, while
/// revalidation always uses the streamed proof so cache-size limits cannot
/// disable ordinary scans.  The first pre-reuse validation is memoized for
/// the whole schedule; the postflight check deliberately recomputes it.
pub(crate) struct AnalysisInputProof {
    expected_content_digest: String,
    preflight_content_digest: OnceLock<Option<String>>,
}

impl AnalysisInputProof {
    fn new(expected_content_digest: String) -> Self {
        Self {
            expected_content_digest,
            preflight_content_digest: OnceLock::new(),
        }
    }

    pub(crate) fn expected_content_digest(&self) -> &str {
        &self.expected_content_digest
    }

    /// Validate the repository content once before any checkpoint can be
    /// reused. All units share the result to avoid hashing the repository once
    /// per queued item.
    pub(crate) fn matches_before_reuse(&self, root: &Path, store_path: Option<&Path>) -> bool {
        self.preflight_content_digest
            .get_or_init(|| fingerprint_scan_inputs(root, store_path).ok())
            .as_deref()
            == Some(self.expected_content_digest.as_str())
    }

    /// Recompute the witness at the publication boundary. This is separate
    /// from the memoized pre-reuse check because files may change while units
    /// are running.
    pub(crate) fn matches_postflight(&self, root: &Path, store_path: Option<&Path>) -> bool {
        fingerprint_scan_inputs(root, store_path)
            .is_ok_and(|digest| digest == self.expected_content_digest)
    }

    /// Validate a newly produced checkpoint against a fresh repository
    /// witness. This must not use the pre-reuse memo because a worker can
    /// observe a different input set after that memo was populated.
    pub(crate) fn matches_checkpoint_write(&self, root: &Path, store_path: Option<&Path>) -> bool {
        self.matches_postflight(root, store_path)
    }
}

const GO_SYNTAX_CHECKPOINT_CONTRACT_VERSION: &str = "depgraph-analysis-unit-syntax-checkpoint-v1";
pub(crate) const SOURCE_BATCH_CONTRACT: &str = "depgraph-analysis-unit-v2";

fn go_syntax_checkpoint_input_digest(content_digest: &str, unit_digest: &str) -> String {
    depgraph_protocol::stable_id_from_value(
        "analysis-unit-syntax-checkpoint",
        &json!({
            "contract_version": GO_SYNTAX_CHECKPOINT_CONTRACT_VERSION,
            "repository_content": content_digest,
            "unit_ownership": unit_digest,
        }),
    )
}

pub(crate) async fn prepare_analysis_schedule(
    context: &AnalysisExecutionContext<'_>,
    workers: Vec<(AdapterKind, WorkerSpec)>,
    store_path: Option<&Path>,
    profile_plan_id: &str,
    initial_content_digest: Option<String>,
) -> Result<AnalysisSchedule> {
    let plan = match plan_analysis_units(context.root, context.config, store_path) {
        Ok(plan) => Some(plan),
        Err(error) => {
            // Discovery is an optimization boundary. Existing adapters still
            // diagnose malformed manifests using their established contracts.
            tracing::warn!(%error, "analysis discovery unavailable; using repository worker scope");
            None
        }
    };
    let mut input_proof = None;
    let mut batch_inventory = None;
    let mut scheduled = Vec::new();
    for (adapter, spec) in workers {
        let mut work = Vec::new();
        let units = plan
            .as_ref()
            .map(|plan| {
                plan.executable_units()
                    .into_iter()
                    .filter(|unit| unit.adapter.as_str() == adapter.name())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let capabilities =
            if matches!(adapter, AdapterKind::Go | AdapterKind::Web) && !units.is_empty() {
                probe_worker_version_with_cancellation(&spec, context.root, context.cancellation)
                    .await
                    .ok()
                    .map(|version| worker_capabilities(&version))
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
        let supports_batches = capabilities
            .iter()
            .any(|capability| capability == "analysis-source-batch-v1");
        let capability_supports_units = matches!(adapter, AdapterKind::Go | AdapterKind::Web)
            && !units.is_empty()
            && (adapter != AdapterKind::Go
                || plan.as_ref().is_some_and(go_module_scopes_cover_packages))
            && (supports_batches
                || (adapter == AdapterKind::Go
                    && capabilities
                        .iter()
                        .any(|capability| capability == "analysis-unit-v1")));
        // A split Go schedule needs a repository-wide witness in addition to
        // each unit's ownership fingerprint. If the witness cannot be built,
        // retain the repository-wide worker fallback instead of publishing a
        // split result whose auxiliary inputs were not proved stable.
        let supports_units = capability_supports_units
            && {
                if input_proof.is_none() {
                    input_proof = initial_content_digest
                    .clone()
                    .or_else(|| match fingerprint_scan_inputs(context.root, store_path) {
                        Ok(digest) => Some(digest),
                        Err(error) => {
                            tracing::warn!(%error, "analysis input proof unavailable; using repository worker fallback");
                            None
                        }
                    })
                    .map(|digest| Arc::new(AnalysisInputProof::new(digest)));
                }
                input_proof.is_some()
            };
        let cache = if context.cache_mode == ScanCacheMode::Enabled {
            match prepare_scan_cache(
                context.root,
                context.config,
                &[(adapter, spec.clone())],
                store_path,
                profile_plan_id,
            ) {
                ScanCachePreparation::Ready(plan) => Some(plan),
                ScanCachePreparation::Rejected(_) => None,
            }
        } else {
            None
        };
        let execution_digest = execution_digest(context, &spec, profile_plan_id);
        if !supports_units {
            let unit_id = format!("{}:repository", adapter.name());
            let checkpoint_key = cache
                .as_ref()
                .and_then(|plan| plan.semantic.as_ref())
                .zip(execution_digest.as_ref())
                .map(|(cache, execution)| UnitCheckpointKey {
                    unit_id: unit_id.clone(),
                    input_digest: cache.key.clone(),
                    execution_digest: execution.clone(),
                    root_digest: root_digest(context.root),
                });
            work.push(AnalysisWorkItem {
                unit_id,
                request: None,
                checkpoint_key,
                spec,
            });
            scheduled.push(ScheduledAdapter::Ready(work));
            continue;
        }
        if supports_batches {
            let plan = plan.as_ref().expect("unit capability requires a plan");
            if batch_inventory.is_none() {
                batch_inventory = Some(build_repository_file_inventory(context.root)?);
            }
            let inventory = &batch_inventory
                .as_ref()
                .expect("batch inventory initialized")
                .paths;
            let batch_contexts = units
                .iter()
                .map(|unit| {
                    prepare_source_batch_context(context.root, plan, unit, inventory, store_path)
                })
                .collect::<Result<Vec<_>>>()?;
            scheduled.push(ScheduledAdapter::SourceBatches(Box::new(
                SourceBatchSchedule {
                    adapter,
                    spec,
                    units,
                    capabilities,
                    batch_contexts,
                    execution_digest,
                },
            )));
            continue;
        }
        // Persist syntax before the expensive semantic queue. A semantic
        // stage retains the compiler's full dependency context in the worker.
        for stage in ["syntax", "semantic"] {
            for unit in &units {
                let unit_id = format!("{}:{stage}", unit.id);
                // Semantic reuse retains the existing external-dependency
                // proof. Static planning alone cannot certify module caches.
                let input_digest = if stage == "syntax" && adapter == AdapterKind::Go {
                    input_proof.as_ref().map(|proof| {
                        go_syntax_checkpoint_input_digest(
                            proof.expected_content_digest(),
                            &unit.input_fingerprint,
                        )
                    })
                } else {
                    cache
                        .as_ref()
                        .and_then(|plan| plan.semantic.as_ref())
                        .map(|key| key.key.clone())
                };
                let checkpoint_key = if context.cache_mode == ScanCacheMode::Enabled {
                    input_digest
                        .zip(execution_digest.as_ref())
                        .map(|(input, execution)| UnitCheckpointKey {
                            unit_id: unit_id.clone(),
                            input_digest: input,
                            execution_digest: execution.clone(),
                            root_digest: root_digest(context.root),
                        })
                } else {
                    None
                };
                work.push(AnalysisWorkItem {
                    unit_id,
                    checkpoint_key,
                    spec: spec.clone(),
                    request: Some(json!({
                        "contract_version":"depgraph-analysis-unit-v1", "unit_id":unit.id,
                        "adapter":adapter.name(), "unit_root":unit.unit_root,
                        "source_paths":unit.source_paths, "stage":stage,
                    })),
                });
            }
        }
        scheduled.push(ScheduledAdapter::Ready(work));
    }

    // Decide ownership, loader scope, estimates, and parallelism for every
    // source-batch adapter at once, before any worker starts. The decision is
    // a pure function of the discovery plan, budgets, boundaries, sizes, and
    // the worker context closure; it never reads file contents.
    let split_plan = {
        let mut boundaries = Vec::new();
        let mut contexts = BTreeMap::new();
        for entry in &scheduled {
            let ScheduledAdapter::SourceBatches(schedule) = entry else {
                continue;
            };
            let SourceBatchSchedule {
                adapter,
                units,
                capabilities,
                batch_contexts,
                ..
            } = schedule.as_ref();
            let Some(boundary) =
                AnalysisAdapterBoundary::for_capabilities(analysis_adapter(*adapter), capabilities)
            else {
                continue;
            };
            boundaries.push(boundary);
            for (unit, batch_context) in units.iter().zip(batch_contexts) {
                contexts.insert(unit.id.clone(), batch_context.source_context_paths.clone());
            }
        }
        match (plan.as_ref(), boundaries.is_empty()) {
            (Some(plan), false) => {
                let sizes = measure_source_sizes(context.root, plan)?;
                let input = AnalysisSplitInput::new(
                    AnalysisSplitBudget::from_config(context.config),
                    boundaries,
                )
                .with_sizes(sizes)
                .with_contexts(contexts);
                Some(plan_analysis_split(plan, &input)?)
            }
            _ => None,
        }
    };

    let mut work = Vec::new();
    for entry in scheduled {
        match entry {
            ScheduledAdapter::Ready(items) => work.extend(items),
            ScheduledAdapter::SourceBatches(schedule) => {
                let SourceBatchSchedule {
                    adapter,
                    spec,
                    units,
                    batch_contexts,
                    execution_digest,
                    ..
                } = *schedule;
                let split_plan = split_plan
                    .as_ref()
                    .expect("source batches require a split plan");
                let boundary = split_plan
                    .boundaries
                    .iter()
                    .find(|boundary| boundary.adapter == analysis_adapter(adapter))
                    .expect("source batches require an adapter boundary");
                // The boundary selected from the worker's capabilities already
                // records whether it negotiated loader scope; the binding and
                // the byte-bounded partition follow the same decision.
                let loader_scope = boundary.loader_scope;
                for stage in boundary.stages() {
                    for (unit, batch_context) in units.iter().zip(&batch_contexts) {
                        let requests = source_batch_requests_for_stage(
                            split_plan,
                            unit,
                            stage,
                            batch_context,
                            loader_scope,
                        );
                        for request in requests {
                            let unit_id = format!(
                                "{}:{}:{}",
                                unit.id,
                                stage.as_str(),
                                request["chunk_id"].as_str().unwrap_or_default()
                            );
                            let input_digest = if stage == AnalysisStage::Syntax
                                || batch_context.semantic_reusable
                            {
                                request["context_fingerprint"].as_str().map(str::to_owned)
                            } else {
                                None
                            };
                            let checkpoint_key = if context.cache_mode == ScanCacheMode::Enabled {
                                input_digest.zip(execution_digest.as_ref()).map(
                                    |(input, execution)| UnitCheckpointKey {
                                        unit_id: unit_id.clone(),
                                        input_digest: input,
                                        execution_digest: execution.clone(),
                                        root_digest: root_digest(context.root),
                                    },
                                )
                            } else {
                                None
                            };
                            work.push(AnalysisWorkItem {
                                unit_id,
                                request: Some(request),
                                checkpoint_key,
                                spec: spec.clone(),
                            });
                        }
                    }
                }
            }
        }
    }
    Ok(AnalysisSchedule {
        plan,
        split_plan,
        work,
        input_proof,
    })
}

fn analysis_adapter(adapter: AdapterKind) -> AnalysisAdapter {
    match adapter {
        AdapterKind::Rust => AnalysisAdapter::Rust,
        AdapterKind::Go => AnalysisAdapter::Go,
        AdapterKind::Web => AnalysisAdapter::Web,
    }
}

struct SourceBatchContext {
    context_fingerprint: String,
    semantic_reusable: bool,
    // The fingerprint includes manifests and other inputs, but worker
    // context_paths contains source files only. Keep this source-only closure
    // separately so workers can resolve imports owned by another unit without
    // widening their emitted scope.
    source_context_paths: Vec<String>,
    auxiliary_paths: Vec<String>,
}

/// Build the split plan the scheduler would use for the shipped worker
/// boundaries, with the worker context closure of every source-batch unit.
#[cfg(test)]
fn split_plan_for_default_workers(
    root: &Path,
    config: &crate::Config,
    plan: &AnalysisPlan,
    store_path: Option<&Path>,
) -> Result<(AnalysisSplitPlan, BTreeMap<String, SourceBatchContext>)> {
    split_plan_for_boundaries(
        root,
        config,
        plan,
        store_path,
        AnalysisAdapterBoundary::current_defaults(),
    )
}

/// Build the split plan the scheduler would use for the given worker
/// boundaries, with the worker context closure of every source-batch unit.
#[cfg(test)]
fn split_plan_for_boundaries(
    root: &Path,
    config: &crate::Config,
    plan: &AnalysisPlan,
    store_path: Option<&Path>,
    boundaries: Vec<AnalysisAdapterBoundary>,
) -> Result<(AnalysisSplitPlan, BTreeMap<String, SourceBatchContext>)> {
    let inventory = build_repository_file_inventory(root)?;
    let mut contexts = BTreeMap::new();
    let mut batch_contexts = BTreeMap::new();
    let mut adapters = BTreeSet::new();
    for unit in plan.executable_units() {
        if !matches!(unit.adapter, AnalysisAdapter::Go | AnalysisAdapter::Web) {
            continue;
        }
        adapters.insert(unit.adapter);
        let context = prepare_source_batch_context(root, plan, unit, &inventory.paths, store_path)?;
        contexts.insert(unit.id.clone(), context.source_context_paths.clone());
        batch_contexts.insert(unit.id.clone(), context);
    }
    // Production only declares boundaries for adapters whose worker negotiated
    // source batches; mirror that with the adapters the plan actually contains.
    let boundaries = boundaries
        .into_iter()
        .filter(|boundary| adapters.contains(&boundary.adapter))
        .collect();
    let input = AnalysisSplitInput::new(AnalysisSplitBudget::from_config(config), boundaries)
        .with_sizes(measure_source_sizes(root, plan)?)
        .with_contexts(contexts);
    Ok((plan_analysis_split(plan, &input)?, batch_contexts))
}

#[cfg(test)]
fn source_batch_requests(
    root: &Path,
    config: &crate::Config,
    plan: &AnalysisPlan,
    unit: &AnalysisUnit,
    stage: &str,
    store_path: Option<&Path>,
) -> Result<Vec<serde_json::Value>> {
    let (split_plan, contexts) = split_plan_for_default_workers(root, config, plan, store_path)?;
    let stage = match stage {
        "syntax" => AnalysisStage::Syntax,
        "typed" => AnalysisStage::Typed,
        _ => AnalysisStage::Semantic,
    };
    Ok(source_batch_requests_for_stage(
        &split_plan,
        unit,
        stage,
        &contexts[&unit.id],
        false,
    ))
}

fn prepare_source_batch_context(
    root: &Path,
    plan: &AnalysisPlan,
    unit: &AnalysisUnit,
    inventory: &[String],
    store_path: Option<&Path>,
) -> Result<SourceBatchContext> {
    let (context_fingerprint, source_context_paths, dependency_witness_paths) =
        batch_context_fingerprint(root, plan, unit, inventory, store_path)?;
    // Compiler inputs outside the repository need their own content proof.
    // Go's conservative witness permits local/workspace/vendor dependencies
    // and declines reuse for unproved module-cache inputs. Web's compiler host
    // resolves from the repository inventory and its bundled standard library.
    let (context_fingerprint, semantic_reusable) = if unit.adapter.as_str() == "go" {
        let witness = crate::go_dependency_witness::compute_go_dependency_witness(
            root,
            &dependency_witness_paths,
        );
        let payload = serde_json::to_vec(&json!({
            "contract":"analysis-go-context-v1", "context":context_fingerprint,
            "dependencies":witness.fingerprint(),
        }))?;
        (
            format!("{:x}", Sha256::digest(payload)),
            witness.is_cacheable(),
        )
    } else {
        (context_fingerprint, true)
    };
    let auxiliary_paths = inventory
        .iter()
        .filter(|path| {
            let relevant = if unit.adapter.as_str() == "go" {
                path.ends_with(".s")
                    || path.ends_with(".S")
                    || path.as_str() == "go.mod"
                    || path.ends_with("/go.mod")
                    // The repository-root go.work is read from the scan root
                    // by every Go unit, but the worker contract only permits
                    // it as an owned auxiliary for a repository-root unit.
                    // Member units still retain it in manifest_paths for
                    // invalidation; do not pass that fingerprint input as an
                    // auxiliary file they cannot own.
                    || (path.as_str() == "go.work" && unit.unit_root == ".")
            } else {
                plan.units.iter().any(|candidate| {
                    candidate.adapter == unit.adapter && candidate.manifest_paths.contains(path)
                })
            };
            relevant
                && auxiliary_owner(plan, unit.adapter, path)
                    .is_some_and(|owner| owner.id == unit.id)
        })
        .cloned()
        .collect::<Vec<_>>();
    Ok(SourceBatchContext {
        context_fingerprint,
        semantic_reusable,
        source_context_paths,
        auxiliary_paths,
    })
}

/// Turn the execution units the split plan decided for one logical unit and
/// stage into v2 worker requests.  Chunk identity, path sets, and field
/// order are unchanged for workers that did not negotiate loader scope, so
/// existing checkpoints and worker validation keep working.  A worker that
/// advertises `analysis-loader-scope-v1` additionally receives the `split`
/// binding with the loader target it must honour or reject.
fn source_batch_requests_for_stage(
    split_plan: &AnalysisSplitPlan,
    unit: &AnalysisUnit,
    stage: AnalysisStage,
    context: &SourceBatchContext,
    loader_scope_negotiated: bool,
) -> Vec<serde_json::Value> {
    let stage_name = stage.as_str();
    split_plan
        .execution_units_for(&unit.id, stage)
        .into_iter()
        .map(|execution_unit| {
            let paths = &execution_unit.ownership.source_paths;
            let chunk_id = depgraph_protocol::stable_id_from_value(
                "analysis-chunk",
                &json!({"contract":SOURCE_BATCH_CONTRACT,"unit":unit.id,"stage":stage_name,"paths":paths}),
            );
            // The Go typed stage currently receives its own sources as the
            // context; the loader scope in `split` describes the module the
            // worker actually loads.
            let context_paths = if matches!(unit.adapter, AnalysisAdapter::Go | AnalysisAdapter::Web)
                && !(unit.adapter == AnalysisAdapter::Go && stage == AnalysisStage::Typed)
            {
                &context.source_context_paths
            } else {
                &unit.source_paths
            };
            let index = execution_unit.batch_index;
            let mut request = json!({
                "contract_version":SOURCE_BATCH_CONTRACT,"unit_id":unit.id,"adapter":unit.adapter.as_str(),
                "unit_root":unit.unit_root,"source_paths":paths,"context_paths":context_paths,
                "auxiliary_paths":if index == 0 && stage == AnalysisStage::Syntax { context.auxiliary_paths.clone() } else { Vec::new() },
                "context_fingerprint":context.context_fingerprint,"stage":stage_name,
                "chunk_id":chunk_id,"chunk_index":index,"chunk_count":execution_unit.batch_count,
            });
            if loader_scope_negotiated
                && let Some(object) = request.as_object_mut()
                && let Ok(binding) =
                    serde_json::to_value(execution_unit.binding(&split_plan.split_plan_id))
            {
                object.insert("split".to_owned(), binding);
            }
            request
        })
        .collect()
}

fn auxiliary_owner<'a>(
    plan: &'a AnalysisPlan,
    adapter: crate::analysis_plan::AnalysisAdapter,
    path: &str,
) -> Option<&'a AnalysisUnit> {
    let candidates = plan
        .executable_units()
        .into_iter()
        .filter(|unit| unit.adapter == adapter)
        .collect::<Vec<_>>();
    candidates
        .iter()
        .copied()
        .filter(|unit| unit.unit_root == "." || path.starts_with(&format!("{}/", unit.unit_root)))
        .max_by_key(|unit| unit.unit_root.len())
        .or_else(|| {
            candidates
                .iter()
                .copied()
                .find(|unit| unit.manifest_paths.iter().any(|manifest| manifest == path))
        })
}

/// Bind syntax reuse to the logical unit and its dependency context, including
/// assembly, embedded assets and unclassified inputs. An unrelated module can
/// change without discarding an otherwise valid unit checkpoint.
fn batch_context_fingerprint(
    root: &Path,
    plan: &AnalysisPlan,
    unit: &AnalysisUnit,
    inventory: &[String],
    store_path: Option<&Path>,
) -> Result<(String, Vec<String>, Vec<String>)> {
    // Keep the worker's compiler context separate from the conservative
    // fingerprint context. An unknown dependency invalidates every same
    // adapter checkpoint, but it does not prove that every same-adapter
    // module belongs in the worker's local module closure. Passing that
    // conservative superset as Go context_paths makes the worker reject the
    // request before it can emit the owned source graph.
    let mut worker_ids = BTreeSet::from([unit.id.clone()]);
    let mut pending = crate::analysis_plan::input_dependency_ids(unit)
        .cloned()
        .collect::<Vec<_>>();
    while let Some(id) = pending.pop() {
        if worker_ids.insert(id.clone())
            && let Some(dependency) = plan.unit(&id)
        {
            pending.extend(crate::analysis_plan::input_dependency_ids(dependency).cloned());
        }
    }
    let owned_contexts = worker_ids
        .iter()
        .filter_map(|id| plan.unit(id))
        .filter_map(|dependency| {
            auxiliary_owner(plan, unit.adapter, &format!("{}/_", dependency.unit_root))
        })
        .map(|owner| owner.id.clone())
        .collect::<Vec<_>>();
    worker_ids.extend(owned_contexts);
    let mut fingerprint_ids = worker_ids.clone();
    if unit.unknown_dependencies {
        fingerprint_ids.extend(
            plan.units
                .iter()
                .filter(|candidate| candidate.adapter == unit.adapter)
                .map(|candidate| candidate.id.clone()),
        );
    }
    let mut digest = Sha256::new();
    digest.update(b"depgraph-unit-context-v2\0");
    digest.update(unit.input_fingerprint.as_bytes());
    let canonical_root = root.canonicalize()?;
    let mut worker_context_paths = Vec::new();
    let mut dependency_witness_paths = Vec::new();
    for path in inventory {
        let absolute = root.join(path);
        if store_path.is_some_and(|store| {
            absolute == store
                || absolute.as_os_str() == format!("{}-wal", store.display()).as_str()
                || absolute.as_os_str() == format!("{}-shm", store.display()).as_str()
        }) {
            continue;
        }
        let fingerprint_owned = path_belongs_to_adapter(path, unit.adapter)
            && auxiliary_owner(plan, unit.adapter, path)
                .is_some_and(|owner| fingerprint_ids.contains(&owner.id));
        if !fingerprint_owned
            && !unit.manifest_paths.contains(path)
            && !unit.config_paths.contains(path)
        {
            continue;
        }
        let canonical = absolute.canonicalize()?;
        if !canonical.starts_with(&canonical_root) {
            anyhow::bail!("analysis context escapes repository root");
        }
        if !canonical.is_file() {
            continue;
        }
        dependency_witness_paths.push(path.clone());
        let worker_owned = path_belongs_to_adapter(path, unit.adapter)
            && auxiliary_owner(plan, unit.adapter, path)
                .is_some_and(|owner| worker_ids.contains(&owner.id));
        if worker_owned && source_path_belongs_to_adapter(path, unit.adapter) {
            worker_context_paths.push(path.clone());
        }
        digest.update((path.len() as u64).to_le_bytes());
        digest.update(path.as_bytes());
        let mut file = std::fs::File::open(canonical)?;
        let mut content = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            content.update(&buffer[..count]);
        }
        digest.update(content.finalize());
    }
    Ok((
        format!("{:x}", digest.finalize()),
        worker_context_paths,
        dependency_witness_paths,
    ))
}

fn go_module_scopes_cover_packages(plan: &AnalysisPlan) -> bool {
    let units = plan
        .executable_units()
        .into_iter()
        .filter(|unit| unit.adapter.as_str() == "go")
        .collect::<Vec<_>>();
    if units.is_empty()
        || units
            .iter()
            .any(|unit| unit.kind != AnalysisUnitKind::GoModule)
    {
        return false;
    }
    // A module request cannot represent a loose package outside every go.mod.
    // Retain the legacy adapter's diagnostics/coverage for such repositories.
    plan.units
        .iter()
        .filter(|unit| unit.kind == AnalysisUnitKind::GoPackage)
        .all(|package| {
            units.iter().any(|module| {
                module.unit_root == "."
                    || package.unit_root == module.unit_root
                    || package
                        .unit_root
                        .starts_with(&format!("{}/", module.unit_root))
            })
        })
}

pub(crate) fn validate_work_inputs(
    context: &AnalysisExecutionContext<'_>,
    item: &AnalysisWorkItem,
    store_path: Option<&Path>,
    profile_plan_id: &str,
    input_proof: Option<&AnalysisInputProof>,
    validation: AnalysisInputValidation,
) -> bool {
    validate_work_inputs_with_execution_digest(
        context,
        item,
        store_path,
        profile_plan_id,
        input_proof,
        validation,
        None,
    )
}

fn validate_work_inputs_with_execution_digest(
    context: &AnalysisExecutionContext<'_>,
    item: &AnalysisWorkItem,
    store_path: Option<&Path>,
    profile_plan_id: &str,
    input_proof: Option<&AnalysisInputProof>,
    validation: AnalysisInputValidation,
    forced_execution_digest: Option<&str>,
) -> bool {
    let Some(key) = item.checkpoint_key.as_ref() else {
        return false;
    };
    let execution_digest = forced_execution_digest
        .map(str::to_owned)
        .or_else(|| execution_digest(context, &item.spec, profile_plan_id));
    if execution_digest.as_deref() != Some(&key.execution_digest) {
        return false;
    }
    if item
        .request
        .as_ref()
        .is_some_and(|request| request["contract_version"] == SOURCE_BATCH_CONTRACT)
    {
        // The schedule already derived this unit key from the current plan.
        // Reuse the shared content witness rather than reparsing every manifest
        // once per chunk. A fresh write/publication check still catches edits
        // during execution, while keys remain selective across separate scans.
        let request_matches = item
            .request
            .as_ref()
            .and_then(|request| request["context_fingerprint"].as_str())
            == Some(key.input_digest.as_str());
        return request_matches
            && input_proof.is_some_and(|proof| match validation {
                AnalysisInputValidation::Reuse => {
                    proof.matches_before_reuse(context.root, store_path)
                }
                AnalysisInputValidation::CheckpointWrite => {
                    proof.matches_checkpoint_write(context.root, store_path)
                }
            });
    }
    if item.spec.adapter == AdapterKind::Go
        && item
            .request
            .as_ref()
            .and_then(|request| request["stage"].as_str())
            == Some("syntax")
    {
        let Some(input_proof) = input_proof else {
            return false;
        };
        let input_matches = match validation {
            AnalysisInputValidation::Reuse => {
                input_proof.matches_before_reuse(context.root, store_path)
            }
            AnalysisInputValidation::CheckpointWrite => {
                input_proof.matches_checkpoint_write(context.root, store_path)
            }
        };
        if !input_matches {
            return false;
        }
        let Some(unit_id) = item
            .request
            .as_ref()
            .and_then(|request| request["unit_id"].as_str())
        else {
            return false;
        };
        return plan_analysis_units(context.root, context.config, store_path).is_ok_and(|plan| {
            plan.unit(unit_id).is_some_and(|unit| {
                go_syntax_checkpoint_input_digest(
                    input_proof.expected_content_digest(),
                    &unit.input_fingerprint,
                ) == key.input_digest
            })
        });
    }
    matches!(prepare_scan_cache(context.root, context.config, &[(item.spec.adapter, item.spec.clone())], store_path, profile_plan_id),
        ScanCachePreparation::Ready(observed) if observed.semantic.as_ref().is_some_and(|cache| cache.key == key.input_digest))
}

fn execution_digest(
    context: &AnalysisExecutionContext<'_>,
    spec: &WorkerSpec,
    profile_plan_id: &str,
) -> Option<String> {
    let workers = [(spec.adapter, spec.clone())];
    let adapter = fingerprint_adapters(&workers).ok()?;
    let toolchain = fingerprint_toolchains(context.root, &workers).ok()?;
    execution_digest_from_identities(context, spec, profile_plan_id, &adapter, &toolchain)
}

fn execution_digest_from_identities(
    context: &AnalysisExecutionContext<'_>,
    spec: &WorkerSpec,
    profile_plan_id: &str,
    adapter_identity: &str,
    toolchain_identity: &str,
) -> Option<String> {
    let bytes = serde_json::to_vec(&json!({"contract":"depgraph-analysis-execution-v1",
        "adapter":adapter_identity,"toolchain":toolchain_identity,"config":context.config,"profile_plan_id":profile_plan_id,
        "program":spec.program,"arguments":spec.leading_args})).ok()?;
    Some(format!("{:x}", Sha256::digest(bytes)))
}

fn root_digest(root: &Path) -> String {
    format!("{:x}", Sha256::digest(root.as_os_str().as_encoded_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis_split::ANALYSIS_LOADER_SCOPE_CAPABILITY;
    use serde_json::Value;

    #[test]
    fn source_batches_partition_syntax_and_keep_go_semantics_in_one_context() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        for name in ["a", "b"] {
            std::fs::create_dir(root.join(name))?;
            std::fs::write(
                root.join(format!("{name}/go.mod")),
                format!("module example.test/{name}\n\ngo 1.26\n"),
            )?;
            for index in 0..3 {
                std::fs::write(
                    root.join(format!("{name}/file{index}.go")),
                    format!("package {name}\nconst Value{index} = {index}\n"),
                )?;
            }
        }
        std::fs::write(root.join("go.work"), "go 1.26\nuse (\n ./a\n ./b\n)\n")?;
        std::fs::write(root.join("a/native.s"), ".text\n")?;
        std::fs::write(root.join("a/embedded.txt"), "one\n")?;
        let mut config = crate::Config::default();
        config.scan.max_unit_source_files = 2;
        let plan = plan_analysis_units(root, &config, None)?;
        let units = plan
            .executable_units()
            .into_iter()
            .filter(|unit| unit.adapter.as_str() == "go")
            .collect::<Vec<_>>();
        let unit = *units.iter().find(|unit| unit.unit_root == "a").unwrap();
        let syntax = source_batch_requests(root, &config, &plan, unit, "syntax", None)?;
        assert_eq!(syntax.len(), 2);
        let owned = syntax
            .iter()
            .flat_map(|request| {
                request["source_paths"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(Value::as_str)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            owned,
            unit.source_paths
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        );
        assert_eq!(syntax[0]["chunk_count"], 2);
        assert_eq!(syntax[1]["chunk_index"], 1);
        assert_eq!(syntax[1]["auxiliary_paths"], json!([]));
        assert!(
            syntax[0]["auxiliary_paths"]
                .as_array()
                .unwrap()
                .contains(&json!("a/native.s"))
        );
        let semantic = source_batch_requests(root, &config, &plan, unit, "semantic", None)?;
        assert_eq!(semantic.len(), 1);
        assert_eq!(semantic[0]["source_paths"], json!(unit.source_paths));
        assert_eq!(semantic[0]["auxiliary_paths"], json!([]));
        let typed = source_batch_requests(root, &config, &plan, unit, "typed", None)?;
        assert_eq!(typed.len(), 1);
        assert_eq!(typed[0]["source_paths"], semantic[0]["source_paths"]);
        assert_eq!(
            typed[0]["context_fingerprint"],
            semantic[0]["context_fingerprint"]
        );
        assert_eq!(typed[0]["auxiliary_paths"], json!([]));
        assert_ne!(typed[0]["chunk_id"], semantic[0]["chunk_id"]);
        let work_owners = units
            .iter()
            .map(|unit| source_batch_requests(root, &config, &plan, unit, "syntax", None))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .flat_map(|request| {
                request["auxiliary_paths"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
            })
            .filter(|path| path == "go.work")
            .count();
        assert_eq!(work_owners, 0);

        let before = syntax[0]["context_fingerprint"].clone();
        std::fs::write(root.join("b/file0.go"), "package b\nconst Value0 = 999\n")?;
        let changed_plan = plan_analysis_units(root, &config, None)?;
        let unchanged_unit = changed_plan.unit(&unit.id).unwrap();
        let after =
            source_batch_requests(root, &config, &changed_plan, unchanged_unit, "syntax", None)?;
        assert_eq!(before, after[0]["context_fingerprint"]);
        let after_semantic = source_batch_requests(
            root,
            &config,
            &changed_plan,
            unchanged_unit,
            "semantic",
            None,
        )?;
        assert_eq!(
            semantic[0]["context_fingerprint"],
            after_semantic[0]["context_fingerprint"]
        );
        std::fs::write(root.join("a/embedded.txt"), "changed embedded input\n")?;
        let after_asset =
            source_batch_requests(root, &config, &changed_plan, unchanged_unit, "syntax", None)?;
        assert_ne!(before, after_asset[0]["context_fingerprint"]);
        Ok(())
    }

    #[test]
    fn semantic_context_tracks_local_dependencies_and_rejects_unproved_remote_inputs() -> Result<()>
    {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        for name in ["app", "shared", "unrelated"] {
            std::fs::create_dir(root.join(name))?;
            std::fs::write(
                root.join(format!("{name}/go.mod")),
                format!("module example.test/{name}\n\ngo 1.26\n"),
            )?;
            std::fs::write(
                root.join(format!("{name}/file.go")),
                format!("package {name}\nconst Value = 1\n"),
            )?;
        }
        std::fs::create_dir(root.join("frontend"))?;
        std::fs::write(root.join("frontend/shared.ts"), "export const value = 1;\n")?;
        std::fs::write(
            root.join("app/go.mod"),
            "module example.test/app\n\ngo 1.26\nrequire example.test/shared v0.0.0\nreplace example.test/shared => ../shared\n",
        )?;
        let config = crate::Config::default();
        let context = || -> Result<SourceBatchContext> {
            let plan = plan_analysis_units(root, &config, None)?;
            let unit = plan
                .executable_units()
                .into_iter()
                .find(|unit| unit.unit_root == "app")
                .unwrap();
            let inventory = build_repository_file_inventory(root)?;
            prepare_source_batch_context(root, &plan, unit, &inventory.paths, None)
        };
        let before = context()?;
        assert!(before.semantic_reusable, "local dependency is proved");
        let plan = plan_analysis_units(root, &config, None)?;
        let app = plan
            .executable_units()
            .into_iter()
            .find(|unit| unit.unit_root == "app")
            .unwrap();
        let syntax = source_batch_requests(root, &config, &plan, app, "syntax", None)?;
        assert_eq!(
            syntax[0]["context_paths"],
            json!(["app/file.go", "shared/file.go"])
        );
        let typed = source_batch_requests(root, &config, &plan, app, "typed", None)?;
        assert_eq!(typed[0]["context_paths"], typed[0]["source_paths"]);
        let semantic = source_batch_requests(root, &config, &plan, app, "semantic", None)?;
        assert_eq!(
            semantic[0]["context_paths"],
            json!(["app/file.go", "shared/file.go"])
        );
        let before_frontend_edit = before.context_fingerprint.clone();
        std::fs::write(root.join("frontend/shared.ts"), "export const value = 2;\n")?;
        assert_eq!(before_frontend_edit, context()?.context_fingerprint);
        std::fs::write(
            root.join("unrelated/file.go"),
            "package unrelated\nconst Value = 2\n",
        )?;
        assert_eq!(before.context_fingerprint, context()?.context_fingerprint);
        std::fs::write(
            root.join("shared/file.go"),
            "package shared\nconst Value = 2\n",
        )?;
        assert_ne!(before.context_fingerprint, context()?.context_fingerprint);
        std::fs::write(
            root.join("app/go.mod"),
            "module example.test/app\n\ngo 1.26\nrequire example.test/remote v1.0.0\n",
        )?;
        std::fs::write(
            root.join("app/go.sum"),
            "example.test/remote v1.0.0 h1:checksum-is-not-content-proof\n",
        )?;
        assert!(!context()?.semantic_reusable);
        Ok(())
    }

    #[test]
    fn unknown_go_dependencies_keep_worker_context_local_but_fingerprint_conservative() -> Result<()>
    {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        for name in ["app", "shared-a", "shared-b", "unrelated"] {
            std::fs::create_dir(root.join(name))?;
            std::fs::write(
                root.join(format!("{name}/go.mod")),
                format!(
                    "module {}\n\ngo 1.26\n",
                    if name.starts_with("shared-") {
                        "example.test/shared"
                    } else {
                        name
                    }
                ),
            )?;
            std::fs::write(
                root.join(format!("{name}/file.go")),
                format!(
                    "package {}\nconst Value = 1\n",
                    if name.starts_with("shared-") {
                        "shared"
                    } else {
                        name
                    }
                ),
            )?;
        }
        std::fs::write(
            root.join("app/file.go"),
            "package app\n\nimport _ \"example.test/shared\"\n",
        )?;

        let config = crate::Config::default();
        let plan = plan_analysis_units(root, &config, None)?;
        let app = plan
            .executable_units()
            .into_iter()
            .find(|unit| unit.unit_root == "app")
            .expect("app module");
        assert!(app.unknown_dependencies);

        let syntax = source_batch_requests(root, &config, &plan, app, "syntax", None)?;
        assert_eq!(syntax.len(), 1);
        assert_eq!(syntax[0]["context_paths"], json!(["app/file.go"]));
        let before = syntax[0]["context_fingerprint"].clone();

        std::fs::write(
            root.join("unrelated/file.go"),
            "package unrelated\nconst Value = 2\n",
        )?;
        let changed_plan = plan_analysis_units(root, &config, None)?;
        let changed_app = changed_plan
            .executable_units()
            .into_iter()
            .find(|unit| unit.unit_root == "app")
            .expect("app module after edit");
        let changed =
            source_batch_requests(root, &config, &changed_plan, changed_app, "syntax", None)?;
        assert_eq!(changed[0]["context_paths"], json!(["app/file.go"]));
        assert_ne!(before, changed[0]["context_fingerprint"]);
        Ok(())
    }

    #[test]
    fn loader_scope_binding_is_attached_only_after_negotiation_and_keeps_requests_stable()
    -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        for name in ["app", "shared"] {
            std::fs::create_dir(root.join(name))?;
            std::fs::write(
                root.join(format!("{name}/go.mod")),
                format!("module example.test/{name}\n\ngo 1.26\n"),
            )?;
            for index in 0..3 {
                std::fs::write(
                    root.join(format!("{name}/file{index}.go")),
                    format!("package {name}\nconst Value{index} = {index}\n"),
                )?;
            }
        }
        // A nested package: its directory sorts after `file*.go` as a package
        // root but before them as a path, which is the order workers check.
        std::fs::create_dir(root.join("app/zed"))?;
        std::fs::write(
            root.join("app/zed/zed.go"),
            "package zed\nconst Value = 1\n",
        )?;
        std::fs::write(
            root.join("app/go.mod"),
            "module example.test/app\n\ngo 1.26\nrequire example.test/shared v0.0.0\nreplace example.test/shared => ../shared\n",
        )?;
        // One owned source above the default 8 MiB unit byte budget. A worker
        // that negotiated loader scope is partitioned against that budget; a
        // worker that did not must receive exactly the file-count chunks it
        // received before the split plan existed.
        let mut config = crate::Config::default();
        config.scan.max_unit_source_files = 2;
        std::fs::write(
            root.join("app/blob.go"),
            format!(
                "package app\n\nconst Blob = \"{}\"\n",
                "x".repeat(config.scan.max_unit_source_bytes as usize)
            ),
        )?;
        let plan = plan_analysis_units(root, &config, None)?;
        let app = plan
            .executable_units()
            .into_iter()
            .find(|unit| unit.unit_root == "app")
            .expect("app module");
        assert_eq!(app.source_paths.len(), 5);
        let capabilities = |loader_scope: bool| {
            let mut capabilities = vec![
                "analysis-unit-v1".to_owned(),
                "analysis-source-batch-v1".to_owned(),
                "analysis-unit-typed-v1".to_owned(),
            ];
            if loader_scope {
                capabilities.push(ANALYSIS_LOADER_SCOPE_CAPABILITY.to_owned());
            }
            capabilities
        };
        let boundary_for = |loader_scope: bool| {
            AnalysisAdapterBoundary::for_capabilities(
                AnalysisAdapter::Go,
                &capabilities(loader_scope),
            )
            .expect("source-batch Go worker has a boundary")
        };
        let legacy_boundary = boundary_for(false);
        let negotiated_boundary = boundary_for(true);
        assert!(!legacy_boundary.loader_scope);
        assert!(negotiated_boundary.loader_scope);
        assert_eq!(legacy_boundary.id, negotiated_boundary.id);
        let (legacy_plan, contexts) =
            split_plan_for_boundaries(root, &config, &plan, None, vec![legacy_boundary.clone()])?;
        let (negotiated_plan, _) = split_plan_for_boundaries(
            root,
            &config,
            &plan,
            None,
            vec![negotiated_boundary.clone()],
        )?;
        assert_eq!(
            legacy_plan.boundaries.len(),
            1,
            "only the Go adapter is present"
        );
        let (legacy_default, _) = split_plan_for_default_workers(root, &config, &plan, None)?;
        assert_eq!(
            legacy_default.split_plan_id, legacy_plan.split_plan_id,
            "the shipped defaults describe workers that have not negotiated loader scope"
        );

        // The chunking the scheduler performed before the split plan existed;
        // requests for a worker without loader scope must stay byte-identical
        // to it, so existing checkpoints and worker validation keep working.
        let context = &contexts[&app.id];
        let previous_requests = |stage: AnalysisStage| -> Vec<Value> {
            let stage = stage.as_str();
            let batch_size = if matches!(stage, "typed" | "semantic") {
                app.source_paths.len().max(1)
            } else {
                config.scan.max_unit_source_files.max(1)
            };
            let chunks = app.source_paths.chunks(batch_size).collect::<Vec<_>>();
            let count = chunks.len();
            chunks
                .into_iter()
                .enumerate()
                .map(|(index, paths)| {
                    let chunk_id = depgraph_protocol::stable_id_from_value(
                        "analysis-chunk",
                        &json!({"contract":SOURCE_BATCH_CONTRACT,"unit":app.id,"stage":stage,"paths":paths}),
                    );
                    let context_paths = if stage == "typed" {
                        &app.source_paths
                    } else {
                        &context.source_context_paths
                    };
                    json!({
                        "contract_version":SOURCE_BATCH_CONTRACT,"unit_id":app.id,"adapter":"go",
                        "unit_root":app.unit_root,"source_paths":paths,"context_paths":context_paths,
                        "auxiliary_paths":if index == 0 && stage == "syntax" { context.auxiliary_paths.clone() } else { Vec::new() },
                        "context_fingerprint":context.context_fingerprint,"stage":stage,
                        "chunk_id":chunk_id,"chunk_index":index,"chunk_count":count,
                    })
                })
                .collect()
        };

        for stage in [
            AnalysisStage::Syntax,
            AnalysisStage::Typed,
            AnalysisStage::Semantic,
        ] {
            let legacy = source_batch_requests_for_stage(
                &legacy_plan,
                app,
                stage,
                context,
                legacy_boundary.loader_scope,
            );
            let previous = previous_requests(stage);
            assert_eq!(
                legacy.len(),
                previous.len(),
                "{stage:?} chunk count is unchanged"
            );
            for (legacy, previous) in legacy.iter().zip(&previous) {
                assert!(legacy.get("split").is_none());
                assert_eq!(
                    serde_json::to_string(legacy)?,
                    serde_json::to_string(previous)?,
                    "{stage:?} request for a worker without loader scope is byte-identical"
                );
            }
            if stage == AnalysisStage::Syntax {
                assert_eq!(legacy.len(), 3, "five files in file-count chunks of two");
                assert_eq!(
                    legacy[0]["source_paths"],
                    json!(["app/blob.go", "app/file0.go"]),
                    "the byte budget does not re-chunk a worker without loader scope"
                );
                let over_budget = legacy_plan
                    .execution_units_for(&app.id, stage)
                    .into_iter()
                    .filter(|unit| unit.estimate.over_budget)
                    .count();
                assert_eq!(over_budget, 1, "the plan still reports the oversized chunk");
            }

            let negotiated = source_batch_requests_for_stage(
                &negotiated_plan,
                app,
                stage,
                context,
                negotiated_boundary.loader_scope,
            );
            for request in &negotiated {
                let mut stripped = request.clone();
                let split = stripped
                    .as_object_mut()
                    .unwrap()
                    .remove("split")
                    .expect("negotiated request carries the split binding");
                assert_eq!(
                    stripped.as_object().unwrap().keys().collect::<Vec<_>>(),
                    previous[0].as_object().unwrap().keys().collect::<Vec<_>>(),
                    "binding is purely additive"
                );
                assert_eq!(split["contract_version"], "depgraph-analysis-split-plan-v1");
                assert_eq!(split["split_plan_id"], negotiated_plan.split_plan_id);
                let execution_unit = negotiated_plan
                    .execution_unit(split["execution_unit_id"].as_str().unwrap())
                    .expect("binding names an execution unit of the plan");
                assert_eq!(
                    json!(execution_unit.ownership.source_paths),
                    request["source_paths"]
                );
                let loader_paths = split["loader"]["paths"].as_array().unwrap();
                for owned in request["source_paths"].as_array().unwrap() {
                    assert!(loader_paths.contains(owned), "loader covers owned files");
                }
                // The chunk identity is the pre-existing formula, so checkpoint
                // keys of unchanged chunks survive a worker starting to
                // negotiate scope.
                assert_eq!(
                    request["chunk_id"],
                    json!(depgraph_protocol::stable_id_from_value(
                        "analysis-chunk",
                        &json!({
                            "contract": SOURCE_BATCH_CONTRACT,
                            "unit": app.id,
                            "stage": stage.as_str(),
                            "paths": execution_unit.ownership.source_paths,
                        })
                    ))
                );
            }
            let split = &negotiated[0]["split"];
            match stage {
                AnalysisStage::Syntax => {
                    // The oversized file is isolated by the byte budget; the
                    // remaining four files keep the two-file chunks, so the
                    // chunks differ from the legacy ones by content, not count.
                    assert_eq!(negotiated.len(), 3);
                    assert_eq!(negotiated[0]["source_paths"], json!(["app/blob.go"]));
                    assert_eq!(
                        negotiated[1]["source_paths"],
                        json!(["app/file0.go", "app/file1.go"])
                    );
                    assert_eq!(
                        negotiated[2]["source_paths"],
                        json!(["app/file2.go", "app/zed/zed.go"])
                    );
                    assert_ne!(negotiated[0]["chunk_id"], legacy[0]["chunk_id"]);
                    assert_eq!(split["split_kind"], "input_batch");
                    assert_eq!(split["loader"]["kind"], "files");
                    assert_eq!(split["loader"]["input_split"], true);
                    assert_eq!(split["loader"]["reference_depth"], "paths_only");
                    assert!(
                        split["loader"]["reference_paths"]
                            .as_array()
                            .unwrap()
                            .contains(&json!("shared/file0.go"))
                    );
                }
                AnalysisStage::Typed | AnalysisStage::Semantic => {
                    // Output only: the shipped worker still loads the whole
                    // module, and the binding says so instead of implying a
                    // bounded loader.
                    assert_eq!(negotiated.len(), 1);
                    assert_eq!(split["split_kind"], "whole");
                    assert_eq!(split["loader"]["kind"], "module");
                    assert_eq!(split["loader"]["input_split"], false);
                    assert_eq!(split["loader"]["reference_depth"], "bodies");
                    assert_eq!(
                        split["loader"]["paths"],
                        json!(contexts[&app.id].source_context_paths)
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn loose_go_sources_keep_repository_fallback() -> Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::write(root.path().join("loose.go"), "package loose\n")?;
        let config = crate::Config::default();
        assert!(!go_module_scopes_cover_packages(&plan_analysis_units(
            root.path(),
            &config,
            None
        )?));
        std::fs::create_dir(root.path().join("app"))?;
        std::fs::write(
            root.path().join("app/go.mod"),
            "module example.test/app\n\ngo 1.26\n",
        )?;
        std::fs::write(root.path().join("app/main.go"), "package app\n")?;
        assert!(!go_module_scopes_cover_packages(&plan_analysis_units(
            root.path(),
            &config,
            None
        )?));
        std::fs::remove_file(root.path().join("loose.go"))?;
        assert!(go_module_scopes_cover_packages(&plan_analysis_units(
            root.path(),
            &config,
            None
        )?));
        Ok(())
    }

    #[test]
    fn streamed_input_proof_covers_auxiliary_files_and_matches_cache_digest() -> Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::write(
            root.path().join("go.mod"),
            "module example.test/app\n\ngo 1.26\n",
        )?;
        std::fs::write(root.path().join("main.go"), "package app\n")?;
        std::fs::write(root.path().join("assembly.s"), ".text\n")?;
        std::fs::write(root.path().join("embed.txt"), "embedded\n")?;

        let profile_plan_id = format!("profile-selection-plan:sha256:{}", "1".repeat(64));
        let ScanCachePreparation::Ready(cache) = prepare_scan_cache(
            root.path(),
            &crate::Config::default(),
            &[],
            None,
            &profile_plan_id,
        ) else {
            panic!("small fixture should remain eligible for the bounded cache");
        };
        let initial = fingerprint_scan_inputs(root.path(), None)?;
        assert_eq!(cache.syntax.dimensions.get("file_content"), Some(&initial));

        let proof = AnalysisInputProof::new(initial.clone());
        assert!(proof.matches_before_reuse(root.path(), None));
        std::fs::write(root.path().join("assembly.s"), ".text\n.byte 0\n")?;
        assert!(!proof.matches_checkpoint_write(root.path(), None));
        assert!(!AnalysisInputProof::new(initial).matches_before_reuse(root.path(), None));

        let changed = fingerprint_scan_inputs(root.path(), None)?;
        std::fs::write(root.path().join("embed.txt"), "embedded changed\n")?;
        assert_ne!(changed, fingerprint_scan_inputs(root.path(), None)?);
        Ok(())
    }

    #[test]
    fn syntax_checkpoint_digest_binds_repository_content_and_unit_ownership() {
        assert_ne!(
            go_syntax_checkpoint_input_digest("content-a", "unit-a"),
            go_syntax_checkpoint_input_digest("content-b", "unit-a")
        );
        assert_ne!(
            go_syntax_checkpoint_input_digest("content-a", "unit-a"),
            go_syntax_checkpoint_input_digest("content-a", "unit-b")
        );
    }

    #[test]
    fn analysis_unit_execution_digest_rejects_profile_config_artifact_and_toolchain_changes_for_go_and_web()
    -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().join("repository");
        std::fs::create_dir(&root)?;
        std::fs::write(root.join("main.go"), "package fixture\n")?;
        std::fs::write(root.join("main.ts"), "export const fixture = 1;\n")?;
        let input_digest = fingerprint_scan_inputs(&root, None)?;
        let proof = AnalysisInputProof::new(input_digest.clone());
        let profile_plan_id = format!("profile-selection-plan:sha256:{}", "1".repeat(64));
        let config = crate::Config::default();
        let cancellation = crate::CancellationToken::new();
        let context = AnalysisExecutionContext {
            root: &root,
            scan_id: "execution-digest-admission",
            config: &config,
            cache_mode: ScanCacheMode::Enabled,
            cancellation: &cancellation,
        };

        for adapter in [AdapterKind::Go, AdapterKind::Web] {
            let artifact = fixture.path().join(format!("{}-worker", adapter.name()));
            let artifact_bytes = format!("synthetic {} worker\n", adapter.name());
            std::fs::write(&artifact, &artifact_bytes)?;
            let spec = WorkerSpec {
                adapter,
                program: artifact.clone().into_os_string(),
                leading_args: Vec::new(),
                display: format!("synthetic {} worker", adapter.name()),
                artifact_path: artifact.clone(),
                runtime_requirement: None,
                expected_version: None,
                release_attested: false,
                attested_rust_sysroot: None,
            };
            let unit_id = format!("{}:semantic:chunk", adapter.name());
            let item = AnalysisWorkItem {
                unit_id: unit_id.clone(),
                request: Some(json!({
                    "contract_version": SOURCE_BATCH_CONTRACT,
                    "unit_id": unit_id,
                    "adapter": adapter.name(),
                    "unit_root": ".",
                    "source_paths": ["main.go", "main.ts"],
                    "context_paths": ["main.go", "main.ts"],
                    "auxiliary_paths": [],
                    "context_fingerprint": input_digest,
                    "stage": "semantic",
                    "chunk_id": "synthetic-chunk",
                    "chunk_index": 0,
                    "chunk_count": 1,
                })),
                checkpoint_key: None,
                spec: spec.clone(),
            };
            let execution = execution_digest(&context, &spec, &profile_plan_id)
                .expect("Go/Web toolchain identities must be available in the test environment");
            let actual_adapter_identity = fingerprint_adapters(&[(adapter, spec.clone())])
                .expect("synthetic worker artifact must be fingerprintable");
            let actual_toolchain_identity =
                fingerprint_toolchains(&root, &[(adapter, spec.clone())])
                    .expect("Go/Web toolchain must be fingerprintable");
            assert_eq!(
                Some(execution.clone()),
                execution_digest_from_identities(
                    &context,
                    &spec,
                    &profile_plan_id,
                    &actual_adapter_identity,
                    &actual_toolchain_identity,
                )
            );

            let mut item = item;
            item.checkpoint_key = Some(UnitCheckpointKey {
                unit_id: item.unit_id.clone(),
                input_digest: input_digest.clone(),
                execution_digest: execution,
                root_digest: root_digest(&root),
            });
            assert!(validate_work_inputs(
                &context,
                &item,
                None,
                &profile_plan_id,
                Some(&proof),
                AnalysisInputValidation::Reuse,
            ));

            let changed_profile_plan = format!("profile-selection-plan:sha256:{}", "2".repeat(64));
            assert!(!validate_work_inputs(
                &context,
                &item,
                None,
                &changed_profile_plan,
                Some(&proof),
                AnalysisInputValidation::Reuse,
            ));

            let mut changed_config = config.clone();
            changed_config.scan.max_stderr_bytes += 1;
            let changed_context = AnalysisExecutionContext {
                root: context.root,
                scan_id: context.scan_id,
                config: &changed_config,
                cache_mode: context.cache_mode,
                cancellation: context.cancellation,
            };
            assert!(!validate_work_inputs(
                &changed_context,
                &item,
                None,
                &profile_plan_id,
                Some(&proof),
                AnalysisInputValidation::Reuse,
            ));

            std::fs::write(&artifact, format!("{artifact_bytes}changed\n"))?;
            assert!(!validate_work_inputs(
                &context,
                &item,
                None,
                &profile_plan_id,
                Some(&proof),
                AnalysisInputValidation::Reuse,
            ));
            std::fs::write(&artifact, artifact_bytes)?;

            let changed_toolchain_identity = format!("{actual_toolchain_identity}:changed");
            let changed_execution = execution_digest_from_identities(
                &context,
                &spec,
                &profile_plan_id,
                &actual_adapter_identity,
                &changed_toolchain_identity,
            )
            .expect("execution digest serialization must succeed");
            assert!(!validate_work_inputs_with_execution_digest(
                &context,
                &item,
                None,
                &profile_plan_id,
                Some(&proof),
                AnalysisInputValidation::Reuse,
                Some(&changed_execution),
            ));
        }
        Ok(())
    }
}
