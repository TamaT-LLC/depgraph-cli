//! Bind static discovery to an explicitly negotiated worker capability.

use std::{
    path::Path,
    sync::{Arc, OnceLock},
};

use anyhow::Result;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    analysis_checkpoint::UnitCheckpointKey,
    analysis_execution::{AnalysisExecutionContext, AnalysisInputValidation, AnalysisWorkItem},
    analysis_plan::{AnalysisPlan, AnalysisUnitKind, plan_analysis_units},
    cache::{
        ScanCachePreparation, fingerprint_adapters, fingerprint_scan_inputs,
        fingerprint_toolchains, prepare_scan_cache,
    },
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
        let capability_supports_units = adapter == AdapterKind::Go
            && !units.is_empty()
            && plan.as_ref().is_some_and(go_module_scopes_cover_packages)
            && probe_worker_version_with_cancellation(&spec, context.root, context.cancellation)
                .await
                .is_ok_and(|version| {
                    worker_capabilities(&version)
                        .iter()
                        .any(|capability| capability == "analysis-unit-v1")
                });
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
