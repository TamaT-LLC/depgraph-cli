use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use depgraph_store::{CacheEventRecord, CacheLayer, CoverageRecord, DiagnosticRecord, Store};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::task::{Id, JoinError, JoinSet};
use uuid::Uuid;

use crate::{
    cache::{ScanCachePlan, ScanCachePreparation, prepare_scan_cache},
    cancellation::CancellationToken,
    config::Config,
    worker::{
        AdapterKind, WorkerFailureKind, WorkerOutput, WorkerSpec, detect_adapters,
        execute_worker_with_cancellation, is_security_error, locate_worker,
        resolve_safe_executable,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOutcome {
    pub scan_id: String,
    pub status: String,
    pub exit_code: u8,
    pub coverage: CoverageRecord,
    pub diagnostics: Vec<DiagnosticRecord>,
    pub cache_events: Vec<CacheEventRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanCacheMode {
    Enabled,
    Disabled,
}

#[derive(Debug)]
struct ScanFailure {
    adapter: AdapterKind,
    detail: String,
    kind: WorkerFailureKind,
    security_violation: bool,
}

impl ScanFailure {
    fn with_kind(adapter: AdapterKind, detail: String, kind: WorkerFailureKind) -> Self {
        Self::with_classification(adapter, detail, kind, false)
    }

    fn with_classification(
        adapter: AdapterKind,
        detail: String,
        kind: WorkerFailureKind,
        security_violation: bool,
    ) -> Self {
        Self {
            adapter,
            detail,
            kind,
            security_violation,
        }
    }

    fn stable_identity(&self) -> String {
        format!(
            "worker-failure:{}:{}",
            self.adapter.name(),
            self.kind.as_str()
        )
    }
}

#[derive(Debug)]
struct WorkerPreflight {
    workers_to_run: Vec<(AdapterKind, WorkerSpec)>,
    failures: Vec<ScanFailure>,
}

fn preflight_workers(
    adapters: impl IntoIterator<Item = AdapterKind>,
    mut locate: impl FnMut(AdapterKind) -> Result<WorkerSpec>,
) -> WorkerPreflight {
    let mut workers_to_run = Vec::new();
    let mut failures = Vec::new();

    for adapter in adapters {
        match locate(adapter) {
            Ok(spec) => workers_to_run.push((adapter, spec)),
            Err(error) => {
                let error = format!("{error:#}");
                let security_violation = is_security_error(&error);
                failures.push(ScanFailure::with_classification(
                    adapter,
                    error,
                    WorkerFailureKind::Other,
                    security_violation,
                ));
            }
        }
    }

    // A packaged release is a single attested unit. If any adapter discovers
    // a security failure, no successfully located worker may be launched.
    if failures.iter().any(|failure| failure.security_violation) {
        workers_to_run.clear();
    }

    WorkerPreflight {
        workers_to_run,
        failures,
    }
}

pub async fn run_scan(
    store: &mut Store,
    root: PathBuf,
    config: &Config,
    strict: bool,
) -> Result<ScanOutcome> {
    run_scan_with_cache_mode(store, root, config, strict, ScanCacheMode::Enabled).await
}

pub async fn run_scan_with_cache_mode(
    store: &mut Store,
    root: PathBuf,
    config: &Config,
    strict: bool,
    cache_mode: ScanCacheMode,
) -> Result<ScanOutcome> {
    let cancellation = CancellationToken::new();
    let scan = run_scan_with_cache_mode_and_cancellation(
        store,
        root,
        config,
        strict,
        cache_mode,
        cancellation.clone(),
    );
    tokio::pin!(scan);
    tokio::select! {
        outcome = &mut scan => outcome,
        signal = tokio::signal::ctrl_c() => {
            signal.context("failed to listen for scan cancellation")?;
            cancellation.cancel();
            scan.await
        }
    }
}

pub async fn run_scan_with_cache_mode_and_cancellation(
    store: &mut Store,
    root: PathBuf,
    config: &Config,
    strict: bool,
    cache_mode: ScanCacheMode,
    cancellation: CancellationToken,
) -> Result<ScanOutcome> {
    let root = root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", root.display()))?;
    if root.parent().is_none() {
        anyhow::bail!(
            "security policy violation: a filesystem root cannot be used as a safe scan root"
        );
    }
    let scan_id = Uuid::new_v4().to_string();
    let source_revision = git_source_revision(&root);
    store.start_scan_with_revision(&scan_id, &root, strict, source_revision.as_deref())?;
    if cancellation.is_cancelled() {
        return cancel_scan(store, &scan_id);
    }

    let adapters = match detect_adapters(&root, config.scan.follow_symlinks) {
        Ok(adapters) => adapters,
        Err(error) => {
            record_cache_rejection(store, &scan_id, "workspace-detection-failed")?;
            add_core_diagnostic(
                store,
                &scan_id,
                "error",
                "workspace-detection-failed",
                &format!("{error:#}"),
                "workspace-detection-failed",
            )?;
            store.finish_scan(&scan_id, "failed", Some(&error.to_string()), false)?;
            return snapshot_outcome(store, &scan_id, 3);
        }
    };
    if cancellation.is_cancelled() {
        return cancel_scan(store, &scan_id);
    }

    let WorkerPreflight {
        workers_to_run,
        mut failures,
    } = preflight_workers(adapters, locate_worker);
    let mut cache_plan = None;
    if cache_mode == ScanCacheMode::Disabled {
        record_cache_rejection(store, &scan_id, "disabled-by-request")?;
    } else if !failures.is_empty() {
        record_cache_rejection(store, &scan_id, "worker-preflight-failed")?;
    } else {
        match prepare_scan_cache(
            &root,
            config,
            &workers_to_run,
            store.database_path().as_deref(),
        ) {
            ScanCachePreparation::Rejected(reason) => {
                record_cache_rejection(store, &scan_id, reason)?;
            }
            ScanCachePreparation::Ready(plan) => {
                let _ = store.lookup_snapshot_cache(&plan.syntax, Some(&scan_id), None)?;
                if let Some(semantic_key) = &plan.semantic {
                    let semantic =
                        store.lookup_snapshot_cache(semantic_key, Some(&scan_id), None)?;
                    if semantic.outcome == "hit"
                        && let Some(snapshot_id) = semantic.snapshot_id
                    {
                        match store.clone_completed_scan_into_staging(&snapshot_id, &scan_id) {
                            Ok(()) => {
                                if cancellation.is_cancelled() {
                                    return cancel_scan(store, &scan_id);
                                }
                                return complete_scan(
                                    store,
                                    &scan_id,
                                    strict,
                                    config,
                                    None,
                                    &cancellation,
                                );
                            }
                            Err(_) => {
                                store.record_cache_event(
                                    Some(&scan_id),
                                    None,
                                    CacheLayer::Semantic,
                                    Some(&semantic_key.key),
                                    "reject",
                                    "clone-validation-failed",
                                )?;
                            }
                        }
                    }
                } else {
                    store.record_cache_event(
                        Some(&scan_id),
                        None,
                        CacheLayer::Semantic,
                        None,
                        "reject",
                        plan.semantic_reject_reason
                            .unwrap_or("semantic-identity-unavailable"),
                    )?;
                }
                cache_plan = Some(plan);
            }
        }
    }
    if cancellation.is_cancelled() {
        return cancel_scan(store, &scan_id);
    }

    let mut join_set = JoinSet::new();
    let mut task_adapters = BTreeMap::new();
    let cache_workers = cache_plan.as_ref().map(|_| workers_to_run.clone());
    for (adapter, spec) in workers_to_run {
        if cancellation.is_cancelled() {
            while join_set.join_next().await.is_some() {}
            return cancel_scan(store, &scan_id);
        }
        let root = root.clone();
        let scan_id = scan_id.clone();
        let scan_config = config.scan.clone();
        let profiles = config.profiles.clone();
        let cancellation = cancellation.clone();
        let task = join_set.spawn(async move {
            execute_worker_with_cancellation(
                spec,
                root,
                scan_id,
                scan_config,
                profiles,
                cancellation,
            )
            .await
        });
        task_adapters.insert(task.id(), adapter);
    }

    let mut outputs = Vec::new();
    while let Some(result) = join_set.join_next_with_id().await {
        match result {
            Ok((task_id, output)) => {
                task_adapters.remove(&task_id);
                outputs.push(output);
            }
            Err(error) => {
                let adapter = task_adapter(&mut task_adapters, error.id());
                let kind = classify_worker_task_failure(&error);
                failures.push(ScanFailure::with_kind(
                    adapter,
                    format!("worker task failed: {error}"),
                    kind,
                ));
            }
        }
    }
    outputs.sort_by_key(|output| output.adapter);

    if cancellation.is_cancelled() {
        return cancel_scan(store, &scan_id);
    }

    let mut global_upserts = BTreeMap::<(String, String), Value>::new();
    for output in outputs {
        let adapter = output.adapter;
        let failure_kind = output.failure_kind;
        let security_violation = output.security_violation;
        if let Err(error) = ingest_worker_output(store, &scan_id, output, &mut global_upserts) {
            let detail = format!("{error:#}");
            failures.push(match failure_kind {
                Some(kind) => {
                    ScanFailure::with_classification(adapter, detail, kind, security_violation)
                }
                None => ScanFailure::with_classification(
                    adapter,
                    detail,
                    WorkerFailureKind::Other,
                    security_violation,
                ),
            });
        }
    }
    failures.sort_by_key(|failure| (failure.adapter, failure.kind));
    for failure in &failures {
        let identity = failure.stable_identity();
        add_core_diagnostic(
            store,
            &scan_id,
            "error",
            if failure.security_violation {
                "security-policy"
            } else {
                "worker-failure"
            },
            &identity,
            &identity,
        )?;
    }

    if failures.is_empty() && !store.has_final_coverage(&scan_id)? {
        ingest_empty_coverage(store, &scan_id)?;
    }

    if !failures.is_empty() {
        let summary = failures
            .iter()
            .map(|failure| format!("{}: {}", failure.adapter.name(), failure.detail))
            .collect::<Vec<_>>()
            .join("; ");
        for failure in &failures {
            store.mark_coverage_incomplete(&scan_id, &failure.stable_identity())?;
        }
        let security_violation = failures.iter().any(|failure| failure.security_violation);
        store.finish_scan(
            &scan_id,
            if security_violation {
                "security_failed"
            } else {
                "partial"
            },
            Some(&summary),
            false,
        )?;
        return snapshot_outcome(store, &scan_id, if security_violation { 4 } else { 3 });
    }

    if let (Some(expected), Some(workers)) = (cache_plan.take(), cache_workers.as_deref()) {
        match prepare_scan_cache(&root, config, workers, store.database_path().as_deref()) {
            ScanCachePreparation::Ready(observed)
                if observed.syntax == expected.syntax
                    && observed.semantic == expected.semantic
                    && observed.semantic_reject_reason == expected.semantic_reject_reason =>
            {
                cache_plan = Some(expected);
            }
            _ => {
                record_cache_rejection(store, &scan_id, "input-or-toolchain-changed-during-scan")?;
            }
        }
    }

    if cancellation.is_cancelled() {
        return cancel_scan(store, &scan_id);
    }

    complete_scan(
        store,
        &scan_id,
        strict,
        config,
        cache_plan.as_ref(),
        &cancellation,
    )
}

fn cancel_scan(store: &mut Store, scan_id: &str) -> Result<ScanOutcome> {
    store.finish_scan(scan_id, "cancelled", Some("scan cancelled"), false)?;
    snapshot_outcome(store, scan_id, 3)
}

fn complete_scan(
    store: &mut Store,
    scan_id: &str,
    strict: bool,
    config: &Config,
    cache_plan: Option<&ScanCachePlan>,
    cancellation: &CancellationToken,
) -> Result<ScanOutcome> {
    if let Err(error) = store.validate_scan(scan_id) {
        add_core_diagnostic(
            store,
            scan_id,
            "error",
            "graph-validation-failed",
            &format!("{error:#}"),
            "graph-validation-failed",
        )?;
        store.finish_scan(scan_id, "failed", Some(&error.to_string()), false)?;
        return snapshot_outcome(store, scan_id, 3);
    }

    let coverage = store.load_snapshot(scan_id)?.coverage;
    let rust_hir_backend_failure = has_rust_hir_backend_failure(&coverage);
    let strict_failure = strict && violates_strict_policy(&coverage, config);
    if strict_failure {
        let message = format!(
            "strict policy failed: unresolved={} (max {}), skipped={} (max {}), unsupported={} (max {}), rust_hir_backend_failure={rust_hir_backend_failure}",
            coverage.unresolved,
            config.strict.max_unresolved,
            coverage.files_skipped,
            config.strict.max_skipped,
            coverage.unsupported_syntax,
            config.strict.max_unsupported_syntax
        );
        add_core_diagnostic(
            store,
            scan_id,
            "error",
            "strict-policy",
            &message,
            "strict-policy",
        )?;
        store.finish_scan(scan_id, "policy_failed", Some(&message), false)?;
        return snapshot_outcome(store, scan_id, 1);
    }

    // Load everything required for the successful outcome before promotion. Once
    // finish_scan promotes the graph, optional cache maintenance must not turn an
    // already-visible completed snapshot into a retryable daemon failure.
    let mut outcome = snapshot_outcome(store, scan_id, 0)?;
    outcome.status = "completed".to_owned();

    let Some(promotion) =
        cancellation.run_if_active(|| store.finish_scan(scan_id, "completed", None, true))
    else {
        return cancel_scan(store, scan_id);
    };
    promotion?;
    if let Some(plan) = cache_plan
        && let Err(error) = store_completed_scan_cache(store, scan_id, plan)
    {
        tracing::warn!(
            scan_id,
            error = %error,
            "completed scan cache population failed"
        );
    }
    match store.cache_events_for_scan(scan_id) {
        Ok(cache_events) => outcome.cache_events = cache_events,
        Err(error) => tracing::warn!(
            scan_id,
            error = %error,
            "failed to refresh cache events for completed scan outcome"
        ),
    }
    Ok(outcome)
}

fn store_completed_scan_cache(
    store: &mut Store,
    scan_id: &str,
    plan: &ScanCachePlan,
) -> Result<()> {
    let snapshot_id = store
        .snapshot_id_for_source("scan", scan_id)?
        .context("completed scan did not expose its snapshot")?;
    let _ = store.store_snapshot_cache(&plan.syntax, &snapshot_id, Some(scan_id), None)?;
    if let Some(semantic) = &plan.semantic {
        let _ = store.store_snapshot_cache(semantic, &snapshot_id, Some(scan_id), None)?;
    }
    Ok(())
}

fn record_cache_rejection(store: &Store, scan_id: &str, reason: &str) -> Result<()> {
    for layer in [CacheLayer::Syntax, CacheLayer::Semantic] {
        store.record_cache_event(Some(scan_id), None, layer, None, "reject", reason)?;
    }
    Ok(())
}

fn git_source_revision(root: &Path) -> Option<String> {
    let git = resolve_safe_executable("git", root).ok()?;
    let output = std::process::Command::new(git)
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--verify", "HEAD"])
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let revision = std::str::from_utf8(&output.stdout).ok()?.trim();
    if !(40..=64).contains(&revision.len())
        || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some(revision.to_ascii_lowercase())
}

fn task_adapter(task_adapters: &mut BTreeMap<Id, AdapterKind>, task_id: Id) -> AdapterKind {
    task_adapters
        .remove(&task_id)
        .expect("every spawned worker task must have a registered adapter")
}

fn classify_worker_task_failure(error: &JoinError) -> WorkerFailureKind {
    if error.is_panic() {
        WorkerFailureKind::TaskPanic
    } else if error.is_cancelled() {
        WorkerFailureKind::Cancelled
    } else {
        WorkerFailureKind::Other
    }
}

fn has_rust_hir_backend_failure(coverage: &CoverageRecord) -> bool {
    coverage
        .reasons
        .iter()
        .any(|reason| reason == "rust-hir-backend-failure")
}

fn violates_strict_policy(coverage: &CoverageRecord, config: &Config) -> bool {
    coverage.unresolved > config.strict.max_unresolved
        || coverage.files_skipped > config.strict.max_skipped
        || coverage.unsupported_syntax > config.strict.max_unsupported_syntax
        || has_rust_hir_backend_failure(coverage)
}

fn ingest_worker_output(
    store: &mut Store,
    scan_id: &str,
    output: WorkerOutput,
    global_upserts: &mut BTreeMap<(String, String), Value>,
) -> Result<()> {
    store.save_adapter_log(
        scan_id,
        output.adapter.name(),
        &output.stderr,
        output.stderr_truncated,
    )?;
    let worker_error = output.error.clone();
    const ORDER: &[&str] = &[
        "scan_started",
        "profile_declared",
        "node_upsert",
        "dependency_site",
        "edge_upsert",
        "diagnostic",
        "file_completed",
        "profile_completed",
        "scan_completed",
    ];
    let mut ordered = Vec::with_capacity(output.events.len());
    for event_type in ORDER {
        ordered.extend(
            output
                .events
                .iter()
                .filter(|event| event.get("event").and_then(Value::as_str) == Some(*event_type)),
        );
    }
    if worker_error.is_some() {
        let available_sites = ordered
            .iter()
            .filter_map(|event| {
                (event.get("event").and_then(Value::as_str) == Some("dependency_site"))
                    .then(|| event.get("site")?.get("id")?.as_str())
                    .flatten()
                    .map(ToOwned::to_owned)
            })
            .collect::<BTreeSet<_>>();
        // A truncated but otherwise valid protocol prefix can contain an edge
        // before its dependency_site. Do not let that edge's store FK roll
        // back independent nodes, diagnostics, and coverage from the prefix.
        ordered.retain(|event| {
            if event.get("event").and_then(Value::as_str) != Some("edge_upsert") {
                return true;
            }
            event
                .get("edge")
                .and_then(|edge| edge.get("site_id"))
                .and_then(Value::as_str)
                .is_none_or(|site_id| available_sites.contains(site_id))
        });
    }
    for event in &ordered {
        if let Some((kind, object)) = upsert_object(event) {
            let id = object
                .get("id")
                .and_then(Value::as_str)
                .context("upsert object is missing id")?;
            let key = (kind.to_owned(), id.to_owned());
            if let Some(previous) = global_upserts.get(&key) {
                if previous != object {
                    anyhow::bail!("conflicting cross-worker {kind} upsert for {id}");
                }
            } else {
                global_upserts.insert(key, object.clone());
            }
        }
    }
    store.ingest_events(&ordered)?;
    if let Some(error) = worker_error {
        anyhow::bail!("{} worker failed: {error}", output.adapter.name());
    }
    Ok(())
}

fn upsert_object(event: &Value) -> Option<(&'static str, &Value)> {
    match event.get("event").and_then(Value::as_str) {
        Some("profile_declared") => event.get("profile").map(|value| ("profile", value)),
        Some("node_upsert") => event.get("node").map(|value| ("node", value)),
        Some("dependency_site") => event.get("site").map(|value| ("site", value)),
        Some("edge_upsert") => event.get("edge").map(|value| ("edge", value)),
        Some("diagnostic") => event.get("diagnostic").map(|value| ("diagnostic", value)),
        _ => None,
    }
}

fn add_core_diagnostic(
    store: &mut Store,
    scan_id: &str,
    severity: &str,
    code: &str,
    message: &str,
    identity: &str,
) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(b"depgraph-core-diagnostic-v1\0");
    hasher.update(code.as_bytes());
    hasher.update(b"\0");
    hasher.update(identity.as_bytes());
    let id = format!("diagnostic:{}", hex::encode(hasher.finalize()));
    store.ingest_event(&json!({
        "event":"diagnostic",
        "protocol_version":"1.0",
        "scan_id":scan_id,
        "adapter":"core",
        "adapter_version":env!("CARGO_PKG_VERSION"),
        "seq":0,
        "diagnostic":{
            "id":id,
            "severity":severity,
            "code":code,
            "message":message
        }
    }))
}

fn ingest_empty_coverage(store: &mut Store, scan_id: &str) -> Result<()> {
    store.ingest_event(&json!({
        "event":"scan_completed",
        "protocol_version":"1.0",
        "scan_id":scan_id,
        "adapter":"core",
        "adapter_version":env!("CARGO_PKG_VERSION"),
        "seq":1,
        "coverage":{
            "profiles":0,
            "files_discovered":0,
            "files_analyzed":0,
            "files_skipped":0,
            "dependency_sites":0,
            "resolved":0,
            "candidates":0,
            "external":0,
            "unresolved":0,
            "unsupported_syntax":0,
            "project_code_executed":false,
            "completeness":["syntax-complete"],
            "reasons":[]
        }
    }))
}

fn snapshot_outcome(store: &Store, scan_id: &str, exit_code: u8) -> Result<ScanOutcome> {
    let snapshot = store.load_snapshot(scan_id)?;
    Ok(ScanOutcome {
        scan_id: scan_id.to_owned(),
        status: snapshot.scan.status,
        exit_code,
        coverage: snapshot.coverage,
        diagnostics: snapshot.diagnostics,
        cache_events: store.cache_events_for_scan(scan_id)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use depgraph_store::{CACHE_CONTRACT_VERSION, CacheKey};

    fn test_worker_spec(adapter: AdapterKind, program: PathBuf) -> WorkerSpec {
        WorkerSpec {
            adapter,
            program: program.clone().into_os_string(),
            leading_args: Vec::new(),
            display: program.display().to_string(),
            artifact_path: program,
            runtime_requirement: None,
            expected_version: None,
            release_attested: false,
        }
    }

    #[test]
    fn promoted_scan_remains_successful_when_cache_population_fails() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut store = Store::open_in_memory()?;
        let scan_id = "cache-write-failure";
        store.start_scan(scan_id, root.path(), false)?;
        ingest_empty_coverage(&mut store, scan_id)?;
        let invalid_key = CacheKey {
            layer: CacheLayer::Syntax,
            contract_version: CACHE_CONTRACT_VERSION + 1,
            key: "invalid-cache-contract".to_owned(),
            dimensions: BTreeMap::from([("fixture".to_owned(), "failure".to_owned())]),
        };
        let plan = ScanCachePlan {
            syntax: invalid_key,
            semantic: None,
            semantic_reject_reason: None,
        };

        let outcome = complete_scan(
            &mut store,
            scan_id,
            false,
            &Config::default(),
            Some(&plan),
            &CancellationToken::new(),
        )?;

        assert_eq!(outcome.status, "completed");
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(store.scan(scan_id)?.unwrap().status, "completed");
        assert!(store.snapshot_id_for_source("scan", scan_id)?.is_some());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn late_security_preflight_failure_prevents_an_earlier_worker_launch() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let marker = temp.path().join("rust-worker-started");
        let worker = temp.path().join("rust-worker");
        std::fs::write(&worker, "#!/bin/sh\ntouch \"$1\"\n")?;
        let mut permissions = std::fs::metadata(&worker)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&worker, permissions)?;

        let mut preflight_order = Vec::new();
        let preflight = preflight_workers([AdapterKind::Rust, AdapterKind::Web], |adapter| {
            preflight_order.push(adapter);
            match adapter {
                AdapterKind::Rust => {
                    let mut spec = test_worker_spec(adapter, worker.clone());
                    spec.leading_args.push(marker.clone().into_os_string());
                    Ok(spec)
                }
                AdapterKind::Web => {
                    anyhow::bail!("security policy violation: late Web manifest mismatch")
                }
                AdapterKind::Go => unreachable!("Go was not detected by this fixture"),
            }
        });

        assert_eq!(
            preflight_order,
            vec![AdapterKind::Rust, AdapterKind::Web],
            "all adapters must be located before the launch decision"
        );
        assert!(
            preflight.workers_to_run.is_empty(),
            "a security failure must discard every successfully located worker"
        );
        assert_eq!(preflight.failures.len(), 1);
        assert!(preflight.failures[0].security_violation);

        for (_, spec) in preflight.workers_to_run {
            std::process::Command::new(spec.program)
                .args(spec.leading_args)
                .status()?;
        }
        assert!(
            !marker.exists(),
            "the Rust worker must not start before late Web preflight completes"
        );
        Ok(())
    }

    #[test]
    fn non_security_preflight_failure_preserves_partial_worker_execution() {
        let preflight = preflight_workers(
            [AdapterKind::Rust, AdapterKind::Go, AdapterKind::Web],
            |adapter| match adapter {
                AdapterKind::Go => anyhow::bail!("Go worker is unavailable"),
                AdapterKind::Rust | AdapterKind::Web => {
                    Ok(test_worker_spec(adapter, PathBuf::from(adapter.name())))
                }
            },
        );

        assert_eq!(
            preflight
                .workers_to_run
                .iter()
                .map(|(adapter, _)| *adapter)
                .collect::<Vec<_>>(),
            vec![AdapterKind::Rust, AdapterKind::Web]
        );
        assert_eq!(preflight.failures.len(), 1);
        assert_eq!(preflight.failures[0].adapter, AdapterKind::Go);
        assert!(!preflight.failures[0].security_violation);
    }

    #[tokio::test]
    async fn empty_repository_produces_a_successful_scan() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut store = Store::open_in_memory()?;
        let outcome = run_scan(
            &mut store,
            root.path().to_path_buf(),
            &Config::default(),
            false,
        )
        .await?;
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.status, "completed");
        assert_eq!(outcome.coverage.dependency_sites, 0);
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_scan_never_replaces_the_current_completed_snapshot() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut store = Store::open_in_memory()?;
        run_scan(
            &mut store,
            root.path().to_path_buf(),
            &Config::default(),
            false,
        )
        .await?;
        let current = store.current_snapshot_id()?.context("current snapshot")?;
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let cancelled = run_scan_with_cache_mode_and_cancellation(
            &mut store,
            root.path().to_path_buf(),
            &Config::default(),
            false,
            ScanCacheMode::Enabled,
            cancellation,
        )
        .await?;

        assert_eq!(cancelled.status, "cancelled");
        assert_eq!(
            store.current_snapshot_id()?.as_deref(),
            Some(current.as_str())
        );
        assert_eq!(store.scan(&cancelled.scan_id)?.unwrap().status, "cancelled");
        Ok(())
    }

    #[tokio::test]
    async fn repeated_and_cross_checkout_scans_use_validated_semantic_cache() -> Result<()> {
        let first_root = tempfile::tempdir()?;
        let second_root = tempfile::tempdir()?;
        let mut store = Store::open_in_memory()?;
        let first = run_scan(
            &mut store,
            first_root.path().to_path_buf(),
            &Config::default(),
            false,
        )
        .await?;
        assert!(
            first
                .cache_events
                .iter()
                .any(|event| { event.layer == CacheLayer::Semantic && event.outcome == "miss" })
        );
        assert!(
            first
                .cache_events
                .iter()
                .any(|event| { event.layer == CacheLayer::Semantic && event.outcome == "stored" })
        );

        let second = run_scan(
            &mut store,
            second_root.path().to_path_buf(),
            &Config::default(),
            false,
        )
        .await?;
        assert!(second.cache_events.iter().any(|event| {
            event.layer == CacheLayer::Semantic
                && event.outcome == "hit"
                && event.reason == "validated"
        }));

        let uncached = run_scan_with_cache_mode(
            &mut store,
            second_root.path().to_path_buf(),
            &Config::default(),
            false,
            ScanCacheMode::Disabled,
        )
        .await?;
        assert!(uncached.cache_events.iter().any(|event| {
            event.layer == CacheLayer::Semantic
                && event.outcome == "reject"
                && event.reason == "disabled-by-request"
        }));

        let first_graph = store.load_snapshot(&first.scan_id)?;
        let second_graph = store.load_snapshot(&second.scan_id)?;
        let uncached_graph = store.load_snapshot(&uncached.scan_id)?;
        assert_eq!(first_graph.profiles, second_graph.profiles);
        assert_eq!(first_graph.nodes, second_graph.nodes);
        assert_eq!(first_graph.sites, second_graph.sites);
        assert_eq!(first_graph.edges, second_graph.edges);
        assert_eq!(first_graph.evidence, second_graph.evidence);
        assert_eq!(first_graph.diagnostics, second_graph.diagnostics);
        assert_eq!(first_graph.coverage, second_graph.coverage);
        assert_eq!(first_graph.profiles, uncached_graph.profiles);
        assert_eq!(first_graph.nodes, uncached_graph.nodes);
        assert_eq!(first_graph.sites, uncached_graph.sites);
        assert_eq!(first_graph.edges, uncached_graph.edges);
        assert_eq!(first_graph.evidence, uncached_graph.evidence);
        assert_eq!(first_graph.diagnostics, uncached_graph.diagnostics);
        assert_eq!(first_graph.coverage, uncached_graph.coverage);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn filesystem_root_is_rejected_before_a_scan_is_started() -> Result<()> {
        let mut store = Store::open_in_memory()?;
        let error = run_scan(&mut store, PathBuf::from("/"), &Config::default(), false)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("security policy"));
        assert_eq!(store.latest_attempt_id()?, None);
        Ok(())
    }

    #[tokio::test]
    async fn panicking_worker_task_is_attributed_to_its_adapter() {
        let mut join_set = JoinSet::<WorkerOutput>::new();
        let task = join_set.spawn(async { panic!("web worker panic fixture") });
        let mut task_adapters = BTreeMap::from([(task.id(), AdapterKind::Web)]);

        let error = join_set
            .join_next_with_id()
            .await
            .expect("worker task should complete")
            .expect_err("worker task should panic");

        assert_eq!(
            task_adapter(&mut task_adapters, error.id()),
            AdapterKind::Web
        );
        assert_eq!(
            classify_worker_task_failure(&error),
            WorkerFailureKind::TaskPanic
        );
        assert!(task_adapters.is_empty());
    }

    #[test]
    fn rust_hir_backend_failure_is_a_strict_policy_violation() {
        let config = Config::default();
        let mut coverage = CoverageRecord::default();
        assert!(!violates_strict_policy(&coverage, &config));

        coverage.reasons.push("rust-hir-backend-failure".into());
        assert!(violates_strict_policy(&coverage, &config));
    }

    #[test]
    fn orphan_edge_in_a_failed_prefix_does_not_roll_back_independent_nodes() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut store = Store::open_in_memory()?;
        store.start_scan("partial-scan", root.path(), false)?;
        let common = |event: &str, seq: u64| {
            json!({
                "event":event,"protocol_version":"1.0","scan_id":"partial-scan",
                "adapter":"go","adapter_version":"0.1.0","seq":seq
            })
        };
        let mut started = common("scan_started", 1);
        started["root"] = json!(root.path());
        started["project_code_executed"] = json!(false);
        started["safe_mode"] = json!(true);
        let mut profile = common("profile_declared", 2);
        profile["profile"] = json!({
            "id":"go:test","language":"go","features":[],"environment":{},"properties":{}
        });
        let mut node = common("node_upsert", 3);
        node["node"] = json!({
            "id":"file:kept","kind":"file","locator":"file://kept.go","properties":{}
        });
        let mut edge = common("edge_upsert", 4);
        edge["edge"] = json!({
            "id":"edge:orphan","site_id":"site:not-yet-emitted","source":"file:kept",
            "target":"file:missing","kind":"imports","phase":"source","environment":"host",
            "profile_id":"go:test","resolution_status":"resolved","precision":"exact",
            "condition":{"op":"all","conditions":[]},"generated":false,"evidence":[{
                "kind":"source","extractor":"fixture","extractor_version":"0.1.0",
                "path":"kept.go","start_line":1,"start_column":1,"end_line":1,"end_column":2,
                "properties":{}
            }]
        });
        let output = WorkerOutput {
            adapter: AdapterKind::Go,
            events: vec![started, profile, node, edge],
            stderr: String::new(),
            stderr_truncated: false,
            error: Some("malformed NDJSON after valid prefix".to_owned()),
            failure_kind: Some(WorkerFailureKind::MalformedProtocol),
            security_violation: false,
        };

        assert!(
            ingest_worker_output(&mut store, "partial-scan", output, &mut BTreeMap::new()).is_err()
        );
        let snapshot = store.load_snapshot("partial-scan")?;
        assert!(snapshot.nodes.iter().any(|node| node.id == "file:kept"));
        assert!(snapshot.edges.is_empty());
        Ok(())
    }
}
