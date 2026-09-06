//! Bind static discovery to an explicitly negotiated worker capability.

use std::path::Path;

use anyhow::Result;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    analysis_checkpoint::UnitCheckpointKey,
    analysis_execution::{AnalysisExecutionContext, AnalysisWorkItem},
    analysis_plan::{AnalysisPlan, AnalysisUnitKind, plan_analysis_units},
    cache::{
        ScanCachePreparation, fingerprint_adapters, fingerprint_toolchains, prepare_scan_cache,
    },
    scan::ScanCacheMode,
    worker::{
        AdapterKind, WorkerSpec, probe_worker_version_with_cancellation, worker_capabilities,
    },
};

pub(crate) struct AnalysisSchedule {
    pub plan: Option<AnalysisPlan>,
    pub work: Vec<AnalysisWorkItem>,
}

pub(crate) async fn prepare_analysis_schedule(
    context: &AnalysisExecutionContext<'_>,
    workers: Vec<(AdapterKind, WorkerSpec)>,
    store_path: Option<&Path>,
    profile_plan_id: &str,
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
        let supports_units = adapter == AdapterKind::Go
            && !units.is_empty()
            && plan.as_ref().is_some_and(go_module_scopes_cover_packages)
            && probe_worker_version_with_cancellation(&spec, context.root, context.cancellation)
                .await
                .is_ok_and(|version| {
                    worker_capabilities(&version)
                        .iter()
                        .any(|capability| capability == "analysis-unit-v1")
                });
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
                    Some(unit.input_fingerprint.clone())
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
    Ok(AnalysisSchedule { plan, work })
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
        let Some(unit_id) = item
            .request
            .as_ref()
            .and_then(|request| request["unit_id"].as_str())
        else {
            return false;
        };
        return plan_analysis_units(context.root, context.config, store_path).is_ok_and(|plan| {
            plan.unit(unit_id)
                .is_some_and(|unit| unit.input_fingerprint == key.input_digest)
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
}
