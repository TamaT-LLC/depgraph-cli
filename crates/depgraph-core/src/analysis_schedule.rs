//! Bind static discovery to an explicitly negotiated worker capability.

use std::{
    collections::BTreeSet,
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
        AnalysisPlan, AnalysisUnit, AnalysisUnitKind, path_belongs_to_adapter, plan_analysis_units,
        source_path_belongs_to_adapter,
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
    pub work: Vec<AnalysisWorkItem>,
    pub input_proof: Option<Arc<AnalysisInputProof>>,
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
    let mut work = Vec::new();
    for (adapter, spec) in workers {
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
            let stages: &[&str] = if adapter == AdapterKind::Go
                && capabilities
                    .iter()
                    .any(|capability| capability == "analysis-unit-typed-v1")
            {
                &["syntax", "typed", "semantic"]
            } else {
                &["syntax", "semantic"]
            };
            for &stage in stages {
                for (unit, batch_context) in units.iter().zip(&batch_contexts) {
                    let requests = source_batch_requests_with_context(
                        context.config,
                        unit,
                        stage,
                        batch_context,
                    );
                    for request in requests {
                        let unit_id = format!(
                            "{}:{stage}:{}",
                            unit.id,
                            request["chunk_id"].as_str().unwrap_or_default()
                        );
                        let input_digest = if stage == "syntax" || batch_context.semantic_reusable {
                            request["context_fingerprint"].as_str().map(str::to_owned)
                        } else {
                            None
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
                            request: Some(request),
                            checkpoint_key,
                            spec: spec.clone(),
                        });
                    }
                }
            }
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
    }
    Ok(AnalysisSchedule {
        plan,
        work,
        input_proof,
    })
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

#[cfg(test)]
fn source_batch_requests(
    root: &Path,
    config: &crate::Config,
    plan: &AnalysisPlan,
    unit: &AnalysisUnit,
    stage: &str,
    store_path: Option<&Path>,
) -> Result<Vec<serde_json::Value>> {
    let inventory = build_repository_file_inventory(root)?;
    let context = prepare_source_batch_context(root, plan, unit, &inventory.paths, store_path)?;
    Ok(source_batch_requests_with_context(
        config, unit, stage, &context,
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

fn source_batch_requests_with_context(
    config: &crate::Config,
    unit: &AnalysisUnit,
    stage: &str,
    context: &SourceBatchContext,
) -> Vec<serde_json::Value> {
    let batch_size = if unit.adapter.as_str() == "go" && matches!(stage, "typed" | "semantic") {
        unit.source_paths.len().max(1)
    } else {
        config.scan.max_unit_source_files.max(1)
    };
    let chunks = if unit.source_paths.is_empty() {
        vec![&[][..]]
    } else {
        unit.source_paths.chunks(batch_size).collect::<Vec<_>>()
    };
    let count = chunks.len();
    chunks.into_iter().enumerate().map(|(index, paths)| {
        let chunk_id = depgraph_protocol::stable_id_from_value("analysis-chunk", &json!({"contract":SOURCE_BATCH_CONTRACT,"unit":unit.id,"stage":stage,"paths":paths}));
        let context_paths = if matches!(unit.adapter.as_str(), "go" | "web")
            && !(unit.adapter.as_str() == "go" && stage == "typed")
        {
            &context.source_context_paths
        } else {
            &unit.source_paths
        };
        json!({
            "contract_version":SOURCE_BATCH_CONTRACT,"unit_id":unit.id,"adapter":unit.adapter.as_str(),
            "unit_root":unit.unit_root,"source_paths":paths,"context_paths":context_paths,
            "auxiliary_paths":if index == 0 && stage == "syntax" { context.auxiliary_paths.clone() } else { Vec::new() },
            "context_fingerprint":context.context_fingerprint,"stage":stage,
            "chunk_id":chunk_id,"chunk_index":index,"chunk_count":count,
        })
    }).collect()
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
    let Some(key) = item.checkpoint_key.as_ref() else {
        return false;
    };
    if execution_digest(context, &item.spec, profile_plan_id).as_ref()
        != Some(&key.execution_digest)
    {
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
    let bytes = serde_json::to_vec(&json!({"contract":"depgraph-analysis-execution-v1",
        "adapter":adapter,"toolchain":toolchain,"config":context.config,"profile_plan_id":profile_plan_id,
        "program":spec.program,"arguments":spec.leading_args})).ok()?;
    Some(format!("{:x}", Sha256::digest(bytes)))
}

fn root_digest(root: &Path) -> String {
    format!("{:x}", Sha256::digest(root.as_os_str().as_encoded_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
