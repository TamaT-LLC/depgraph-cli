//! A bounded executor shared by CLI, MCP and daemon scans.

use std::{
    collections::{BTreeMap, VecDeque},
    io::Write,
    path::Path,
    sync::Arc,
};

use anyhow::{Context, Result};
use depgraph_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::task::JoinSet;

use crate::{
    analysis_checkpoint::{UnitCheckpointKey, UnitCheckpointStore},
    cancellation::CancellationToken,
    config::Config,
    scan::ScanCacheMode,
    worker::{
        WorkerOutput, WorkerSpec, WorkerUnitInput, execute_worker_unit, replay_analysis_checkpoint,
    },
};

/// There is no deadline for the aggregate queue. Worker deadlines, output
/// budgets and process-tree cancellation apply separately to each work item.
const MAX_CONCURRENT_UNITS: usize = 2;

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
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AnalysisExecutionProgress {
    pub units: Vec<AnalysisUnitProgress>,
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
    let mut progress = AnalysisExecutionProgress {
        units: work
            .iter()
            .map(|item| AnalysisUnitProgress {
                unit_id: item.unit_id.clone(),
                adapter: item.spec.adapter.name().into(),
                status: "queued".into(),
                reused: false,
            })
            .collect(),
    };
    let repository_inventory = crate::repository_inventory::write_repository_inventory_file(root)?;
    let inventory_bytes = Arc::new(std::fs::read(repository_inventory.path())?);
    drop(repository_inventory);
    let mut pending = work.into_iter().enumerate().collect::<VecDeque<_>>();
    let mut running = JoinSet::new();
    let mut running_units = BTreeMap::new();
    let mut ready = BTreeMap::<usize, (String, WorkerOutput, bool)>::new();
    let mut next_ingest = 0;
    loop {
        while let Some((unit_id, output, reused)) = ready.remove(&next_ingest) {
            let complete = consume(store, &unit_id, output)?;
            progress.units[next_ingest].status = if cancellation.is_cancelled() {
                "cancelled"
            } else if complete {
                "completed"
            } else {
                "failed"
            }
            .into();
            progress.units[next_ingest].reused = reused && complete;
            tracing::info!(unit_id, complete, reused, "analysis unit finished");
            next_ingest += 1;
        }
        // A bounded reorder window makes Store ingestion independent of worker
        // timing without retaining outputs for the whole repository in memory.
        while running.len() < MAX_CONCURRENT_UNITS
            && !cancellation.is_cancelled()
            && pending
                .front()
                .is_some_and(|(index, _)| *index < next_ingest + MAX_CONCURRENT_UNITS)
        {
            let Some((index, item)) = pending.pop_front() else {
                break;
            };
            if let (Some(checkpoints), Some(key)) = (&checkpoints, &item.checkpoint_key)
                && validate_inputs(&item, AnalysisInputValidation::Reuse)
            {
                let cached = checkpoints.read(key).ok().flatten().and_then(|events| {
                    let output =
                        replay_analysis_checkpoint(events, &item.spec, root, scan_id, &config.scan)
                            .ok()?;
                    validate_unit_output(&item, &output).ok()?;
                    Some(output)
                });
                if let Some(output) = cached {
                    ready.insert(index, (item.unit_id, output, true));
                    continue;
                }
            }
            progress.units[index].status = "running".into();
            tracing::info!(unit_id = item.unit_id, "analysis unit started");
            let root = root.to_path_buf();
            let scan_id = scan_id.to_owned();
            let scan_config = config.scan.clone();
            let profiles = config.profiles.clone();
            let cancellation = cancellation.clone();
            let inventory_bytes = inventory_bytes.clone();
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
                ready.insert(index, (unit_id, output, false));
                continue;
            }
        };
        // The supervisor has validated the full stream before it becomes
        // reusable; prefixes from killed or malformed workers are never saved.
        if output.error.is_none()
            && !cancellation.is_cancelled()
            && validate_inputs(&item, AnalysisInputValidation::CheckpointWrite)
            && let (Some(checkpoints), Some(key)) = (&checkpoints, &item.checkpoint_key)
            && let Err(error) = checkpoints.write(key, &output.events)
        {
            tracing::warn!(unit_id = item.unit_id, %error, "analysis unit checkpoint could not be saved");
        }
        ready.insert(index, (item.unit_id, output, false));
    }
    for (index, _) in pending {
        progress.units[index].status = "cancelled".into();
    }
    Ok(progress)
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
    let manifest = if unit_root == "." {
        "go.mod".to_owned()
    } else {
        format!("{unit_root}/go.mod")
    };
    let owns = |path: &str| {
        paths.contains(path)
            || path == manifest
            || (unit_root == "." && path == "go.work")
            || ((path.ends_with(".s") || path.ends_with(".S"))
                && (unit_root == "." || path.starts_with(&prefix)))
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
            }
            Some("file_completed") => {
                if !event["path"].as_str().is_some_and(owns) {
                    anyhow::bail!("worker file coverage escapes the requested analysis unit");
                }
            }
            Some("dependency_site") => {
                if let Some(path) = event["site"]["evidence"]
                    .as_array()
                    .and_then(|evidence| evidence.first())
                    .and_then(|evidence| evidence["path"].as_str())
                    && !owns(path)
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
        Ok(())
    }
}
