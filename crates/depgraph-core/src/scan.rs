use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufReader, BufWriter, Seek, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use anyhow::{Context, Result};
use depgraph_protocol::canonical_json;
use depgraph_store::{
    AnalysisCoverageSummary, AnalysisUnitLedgerRecord, CacheEventRecord, CacheLayer,
    CompletedScanSnapshot, CoverageRecord, DiagnosticRecord, ScanHealthProvenance,
    ScanOperationStagingIdentity, Store, ValidatedScan, ValidatedScanCacheHit,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[cfg(test)]
use tokio::task::{Id, JoinError, JoinSet};
use uuid::Uuid;

use crate::{
    analysis_execution::{
        AnalysisExecutionContext, AnalysisExecutionProgress, AnalysisWorkItem,
        TypedReferenceFingerprint, execute_analysis_units,
        execute_analysis_units_with_retained_typed,
    },
    analysis_plan::{ANALYSIS_UNIT_WORKER_CONTRACT_VERSION, AnalysisPlan, plan_analysis_units},
    analysis_schedule::{prepare_analysis_schedule, validate_work_inputs},
    analysis_split::{
        AnalysisLoaderKind, AnalysisResplitOutcome, AnalysisResplitTrigger, AnalysisSplitPlan,
        resplit_execution_unit,
    },
    cache::{
        CacheRejection, ScanCachePlan, ScanCachePreparation, prepare_scan_cache,
        validate_scan_cache_hit_inputs,
    },
    cancellation::CancellationToken,
    config::Config,
    health::{
        HEALTH_ANALYZER_VERSION, HEALTH_FINDING_CONTRACT_VERSION, health_policy_config_digest,
    },
    policy::PolicyResult,
    policy_engine::{evaluate_policy_cancellable, is_policy_evaluation_cancelled},
    profile_selection::{
        DefaultProfileSelectionPlan, ProfileSelectionMode, validate_profile_selection_plan,
    },
    profile_selection_preview::plan_repository_profiles,
    profile_selection_rank::profile_selection_doctor_status,
    service_limits::MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
    worker::{
        AdapterKind, WorkerFailureKind, WorkerOutput, WorkerSpec, detect_adapters,
        is_security_error, locate_worker, probe_worker_version_with_cancellation,
        resolve_safe_executable, worker_capabilities,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performance: Option<ScanPerformance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis: Option<AnalysisExecutionProgress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_coverage: Option<AnalysisCoverageSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPerformance {
    pub phases: Vec<ScanPhasePerformance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPhasePerformance {
    pub phase: String,
    pub duration_ms: u64,
    pub items: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanCacheMode {
    Enabled,
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScanPromotionMode {
    Immediate,
    Deferred,
}

struct ScanPreparationMode<'a> {
    promotion: ScanPromotionMode,
    operation_id: Option<&'a str>,
    operation_identity: Option<&'a DeferredScanOperationIdentity>,
}

struct ScanPromotionContext<'pending, 'operation_id> {
    mode: ScanPromotionMode,
    pending: &'pending mut Option<PendingScanPromotion>,
    operation_id: Option<&'operation_id str>,
    operation_identity: Option<&'operation_id DeferredScanOperationIdentity>,
}

pub(crate) struct DeferredScanOperationIdentity {
    pub(crate) repository_binding_digest: [u8; 32],
    pub(crate) configuration_digest: [u8; 32],
    pub(crate) cache_enabled: bool,
}

pub(crate) struct DeferredScanOperation<'a> {
    pub(crate) operation_id: &'a str,
    pub(crate) identity: &'a DeferredScanOperationIdentity,
}

pub(crate) struct PendingScanPromotion {
    validation: ValidatedScan,
    cache_plan: Option<ScanCachePlan>,
}

impl PendingScanPromotion {
    pub(crate) const fn validation(&self) -> &ValidatedScan {
        &self.validation
    }

    pub(crate) fn promote(
        self,
        store: &mut Store,
        outcome: &mut ScanOutcome,
    ) -> Result<CompletedScanSnapshot> {
        let completed = store.finish_validated_scan(self.validation, true)?;
        if let Some(plan) = self.cache_plan.as_ref()
            && let Err(error) = store_completed_scan_cache(store, plan, &completed)
        {
            tracing::warn!(
                scan_id = outcome.scan_id,
                error = %error,
                "completed scan cache population failed"
            );
        }
        match store.cache_events_for_scan(&outcome.scan_id) {
            Ok(cache_events) => outcome.cache_events = cache_events,
            Err(error) => tracing::warn!(
                scan_id = outcome.scan_id,
                error = %error,
                "failed to refresh cache events for completed scan outcome"
            ),
        }
        Ok(completed)
    }
}

pub(crate) struct PreparedScan {
    pub(crate) outcome: ScanOutcome,
    pub(crate) promotion: Option<PendingScanPromotion>,
}

// A resource-limited prefix belongs to the attempted loader scope. Publishing
// it before re-splitting can conflict with a replacement's narrower profile.
// Spill one prefix at a time so failed units do not accumulate in memory.
struct DeferredAnalysisFailure {
    events: tempfile::NamedTempFile,
    output: WorkerOutput,
}

impl DeferredAnalysisFailure {
    fn stage(mut output: WorkerOutput) -> Result<Self> {
        let events = tempfile::NamedTempFile::new()?;
        {
            let mut writer = BufWriter::new(events.as_file());
            serde_json::to_writer(&mut writer, &output.events)?;
            writer.flush()?;
        }
        output.events = Vec::new();
        Ok(Self { events, output })
    }

    fn restore(mut self) -> Result<WorkerOutput> {
        self.events.as_file_mut().rewind()?;
        self.output.events = serde_json::from_reader(BufReader::new(self.events.as_file()))?;
        Ok(self.output)
    }
}

#[derive(Debug)]
struct ScanFailure {
    adapter: AdapterKind,
    detail: String,
    kind: WorkerFailureKind,
    security_violation: bool,
}

impl ScanFailure {
    #[cfg(test)]
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

    fn diagnostic_message(&self) -> String {
        let identity = self.stable_identity();
        let Some(phase) = self.detail.lines().rev().find_map(|line| {
            let (_, progress) = line.split_once("depgraph-progress phase=")?;
            let phase = progress.split_whitespace().next()?;
            (!phase.is_empty()
                && phase
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'))
            .then_some(phase)
        }) else {
            return identity;
        };
        format!("{identity}; last_progress_phase={phase}")
    }
}

fn analysis_unit_error_detail(detail: &str) -> String {
    // Ledger metadata is a bounded single-line explanation. Raw stderr is
    // retained separately and must not make terminalization reject the row.
    let detail = detail.split("; stderr:").next().unwrap_or(detail);
    let mut result = String::new();
    for character in detail.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if result.len() + character.len_utf8() > 16 * 1024 {
            break;
        }
        result.push(character);
    }
    result
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
    let prepared = prepare_scan_with_cache_mode_and_cancellation(
        store,
        root,
        config,
        strict,
        cache_mode,
        cancellation,
        ScanPreparationMode {
            promotion: ScanPromotionMode::Immediate,
            operation_id: None,
            operation_identity: None,
        },
    )
    .await?;
    debug_assert!(prepared.promotion.is_none());
    Ok(prepared.outcome)
}

pub(crate) async fn prepare_deferred_scan_with_cache_mode_and_cancellation(
    store: &mut Store,
    root: PathBuf,
    config: &Config,
    strict: bool,
    cache_mode: ScanCacheMode,
    cancellation: CancellationToken,
    operation: Option<DeferredScanOperation<'_>>,
) -> Result<PreparedScan> {
    prepare_scan_with_cache_mode_and_cancellation(
        store,
        root,
        config,
        strict,
        cache_mode,
        cancellation,
        ScanPreparationMode {
            promotion: ScanPromotionMode::Deferred,
            operation_id: operation.as_ref().map(|operation| operation.operation_id),
            operation_identity: operation.map(|operation| operation.identity),
        },
    )
    .await
}

async fn prepare_scan_with_cache_mode_and_cancellation(
    store: &mut Store,
    root: PathBuf,
    config: &Config,
    strict: bool,
    cache_mode: ScanCacheMode,
    cancellation: CancellationToken,
    mode: ScanPreparationMode<'_>,
) -> Result<PreparedScan> {
    let _budget = crate::analysis_execution::ScanBudgetGuard::start(
        config.scan.total_budget_seconds,
        &cancellation,
    );
    let total_started = Instant::now();
    let mut pending_promotion = None;
    let mut promotion = ScanPromotionContext {
        mode: mode.promotion,
        pending: &mut pending_promotion,
        operation_id: mode.operation_id,
        operation_identity: mode.operation_identity,
    };
    let mut outcome = run_scan_with_cache_mode_and_cancellation_inner(
        store,
        root,
        config,
        strict,
        cache_mode,
        cancellation,
        &mut promotion,
    )
    .await?;
    if scan_profile_enabled() {
        let dependency_sites = outcome.coverage.dependency_sites;
        let performance = outcome
            .performance
            .get_or_insert_with(|| ScanPerformance { phases: Vec::new() });
        performance.phases.push(ScanPhasePerformance {
            phase: "core_scan_total".into(),
            duration_ms: elapsed_ms(total_started),
            items: dependency_sites,
            bytes: 0,
        });
    }
    Ok(PreparedScan {
        outcome,
        promotion: pending_promotion,
    })
}

async fn run_scan_with_cache_mode_and_cancellation_inner(
    store: &mut Store,
    root: PathBuf,
    config: &Config,
    strict: bool,
    cache_mode: ScanCacheMode,
    cancellation: CancellationToken,
    promotion: &mut ScanPromotionContext<'_, '_>,
) -> Result<ScanOutcome> {
    let setup_started = Instant::now();
    let root = root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", root.display()))?;
    if root.parent().is_none() {
        anyhow::bail!(
            "security policy violation: a filesystem root cannot be used as a safe scan root"
        );
    }
    let profile_plan = plan_repository_profiles(&root, config, None)?.plan;
    validate_profile_selection_plan(&profile_plan)?;
    let scan_id = match promotion.operation_id {
        Some(operation_id)
            if !operation_id.is_empty()
                && operation_id.len() <= 512
                && !operation_id.chars().any(char::is_control) =>
        {
            scan_attempt_id(operation_id)
        }
        Some(_) => anyhow::bail!("deferred scan operation identity is invalid"),
        None => Uuid::new_v4().to_string(),
    };
    let source_revision = git_source_revision(&root);
    let health_provenance = ScanHealthProvenance {
        policy_config_digest: health_policy_config_digest(&config.policy)
            .context("failed to normalize health policy identity")?,
        analyzer_version: HEALTH_ANALYZER_VERSION.to_owned(),
        finding_contract_version: HEALTH_FINDING_CONTRACT_VERSION.to_owned(),
    };
    if let Some(identity) = promotion.operation_identity {
        store.start_scan_for_operation(
            &scan_id,
            &root,
            strict,
            source_revision.as_deref(),
            &ScanOperationStagingIdentity {
                operation_id: promotion
                    .operation_id
                    .context("operation-owned scan has no operation identity")?,
                repository_binding_digest: &identity.repository_binding_digest,
                configuration_digest: &identity.configuration_digest,
                cache_enabled: identity.cache_enabled,
            },
        )?;
    } else {
        store.start_scan_with_revision(&scan_id, &root, strict, source_revision.as_deref())?;
    }
    store.bind_scan_health_provenance(&scan_id, &health_provenance)?;
    let profile_status = profile_selection_doctor_status(&profile_plan, strict)?;
    if !profile_status.default_profile_matrix_complete {
        add_core_diagnostic(
            store,
            &scan_id,
            if strict { "error" } else { "warning" },
            "default-profile-matrix-incomplete",
            "default profile selection is incomplete; inspect `depgraph profiles plan`",
            &profile_plan.plan_id,
        )?;
        if strict {
            return finish_non_promoted_scan(
                store,
                &scan_id,
                "policy_failed",
                Some("strict default profile selection is incomplete"),
                1,
                &cancellation,
            );
        }
    }
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
            return finish_non_promoted_scan(
                store,
                &scan_id,
                "failed",
                Some(&error.to_string()),
                3,
                &cancellation,
            );
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
    // V2 must replay its unit checkpoints so this attempt has a verified unit
    // ledger and observable reuse. Preserve the whole-snapshot shortcut for
    // older workers; a failed capability probe cannot authorize that shortcut.
    let mut whole_snapshot_cache_allowed = true;
    if cache_mode == ScanCacheMode::Enabled {
        for (adapter, spec) in &workers_to_run {
            if !matches!(adapter, AdapterKind::Go | AdapterKind::Web) {
                continue;
            }
            match probe_worker_version_with_cancellation(spec, &root, &cancellation).await {
                Ok(version)
                    if !worker_capabilities(&version)
                        .iter()
                        .any(|capability| capability == "analysis-source-batch-v1") => {}
                _ => {
                    whole_snapshot_cache_allowed = false;
                    break;
                }
            }
        }
    }
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
            &profile_plan.plan_id,
        ) {
            ScanCachePreparation::Rejected(rejection) => {
                record_cache_preparation_rejection(store, &scan_id, &rejection)?;
            }
            ScanCachePreparation::Ready(plan) => {
                if let Some(semantic_key) = &plan.semantic {
                    if !whole_snapshot_cache_allowed {
                        store.record_cache_event(
                            Some(&scan_id),
                            None,
                            CacheLayer::Semantic,
                            Some(&semantic_key.key),
                            "reject",
                            "analysis-unit-cache-requires-unit-replay",
                        )?;
                    } else if let Some(hit) =
                        store.lookup_scan_cache(&plan.syntax, semantic_key, &scan_id)?
                    {
                        if cancellation.is_cancelled() {
                            return cancel_scan(store, &scan_id);
                        }
                        let profile_plan_unchanged = plan_repository_profiles(&root, config, None)
                            .is_ok_and(|preview| preview.plan.plan_id == profile_plan.plan_id);
                        if !profile_plan_unchanged {
                            store.clone_completed_scan_into_staging(hit.snapshot_id(), &scan_id)?;
                            record_cache_rejection(
                                store,
                                &scan_id,
                                "profile-planning-input-changed-before-cache-hit-promotion",
                            )?;
                            add_core_diagnostic(
                                store,
                                &scan_id,
                                "error",
                                "profile-planning-input-changed",
                                "profile planning input changed before the cached scan could be promoted",
                                "profile-planning-input-changed-before-cache-hit-promotion",
                            )?;
                            store.mark_coverage_incomplete(
                                &scan_id,
                                "profile-planning-input-changed-before-cache-hit-promotion",
                            )?;
                            return finish_non_promoted_scan(
                                store,
                                &scan_id,
                                "partial",
                                Some("profile planning input changed before cache-hit promotion"),
                                3,
                                &cancellation,
                            );
                        }
                        match validate_scan_cache_hit_inputs(&root, &plan) {
                            Err(rejection) => {
                                record_cache_preparation_rejection(store, &scan_id, &rejection)?;
                            }
                            Ok(()) => {
                                let cached_coverage = hit.coverage();
                                let requires_full_validation = !config.policy.rules.is_empty()
                                    || (strict && violates_strict_policy(cached_coverage, config));
                                if requires_full_validation {
                                    if plan.has_symlink_proofs() {
                                        record_cache_rejection(
                                            store,
                                            &scan_id,
                                            "symlink-cache-hit-policy-requires-rescan",
                                        )?;
                                    } else {
                                        store.clone_completed_scan_into_staging(
                                            hit.snapshot_id(),
                                            &scan_id,
                                        )?;
                                        return complete_scan_with_mode(
                                            store,
                                            &scan_id,
                                            strict,
                                            config,
                                            None,
                                            &cancellation,
                                            promotion,
                                        );
                                    }
                                } else {
                                    if promotion.mode == ScanPromotionMode::Deferred {
                                        store.clone_completed_scan_into_staging(
                                            hit.snapshot_id(),
                                            &scan_id,
                                        )?;
                                        return complete_scan_with_mode(
                                            store,
                                            &scan_id,
                                            strict,
                                            config,
                                            None,
                                            &cancellation,
                                            promotion,
                                        );
                                    }
                                    let mut outcome = ScanOutcome {
                                        scan_id: scan_id.clone(),
                                        status: "completed".to_owned(),
                                        exit_code: 0,
                                        coverage: cached_coverage.clone(),
                                        diagnostics: hit.diagnostics().to_vec(),
                                        cache_events: Vec::new(),
                                        policy: None,
                                        performance: None,
                                        analysis: None,
                                        analysis_coverage: None,
                                    };
                                    match promote_validated_scan_cache_hit_if_active(
                                        store,
                                        &scan_id,
                                        &root,
                                        &plan,
                                        &hit,
                                        &cancellation,
                                    ) {
                                        Some(Ok(())) => {
                                            outcome.cache_events =
                                                store.cache_events_for_scan(&scan_id)?;
                                            return Ok(outcome);
                                        }
                                        Some(Err(error)) => {
                                            if let Some(rejection) =
                                                error.downcast_ref::<CacheRejection>()
                                            {
                                                record_cache_preparation_rejection(
                                                    store, &scan_id, rejection,
                                                )?;
                                            } else {
                                                tracing::warn!(
                                                    scan_id,
                                                    error = %error,
                                                    "validated semantic cache hit could not be promoted"
                                                );
                                                store.record_cache_event(
                                                    Some(&scan_id),
                                                    None,
                                                    CacheLayer::Semantic,
                                                    Some(&semantic_key.key),
                                                    "reject",
                                                    "promotion-proof-invalidated",
                                                )?;
                                            }
                                        }
                                        None => return cancel_scan(store, &scan_id),
                                    }
                                }
                            }
                        }
                    }
                } else {
                    let _ = store.lookup_snapshot_cache(&plan.syntax, Some(&scan_id), None)?;
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

    let setup_ms = elapsed_ms(setup_started);
    let worker_started = Instant::now();
    let cache_workers = cache_plan.as_ref().map(|_| workers_to_run.clone());
    let initial_content_digest = cache_plan
        .as_ref()
        .and_then(|plan| plan.syntax.dimensions.get("file_content").cloned());
    let checkpoint_store_path = store.database_path();
    let execution_context = AnalysisExecutionContext {
        root: &root,
        scan_id: &scan_id,
        config,
        cache_mode,
        cancellation: &cancellation,
    };
    let schedule = prepare_analysis_schedule(
        &execution_context,
        workers_to_run,
        checkpoint_store_path.as_deref(),
        &profile_plan.plan_id,
        initial_content_digest,
    )
    .await?;
    let analysis_plan = schedule.plan;
    let mut split_plan = schedule.split_plan;
    let resplit_context = schedule.resplit;
    let mut execution_unit_ids = schedule.execution_unit_ids;
    if let Some(split_plan) = &split_plan {
        tracing::debug!(
            split_plan_id = %split_plan.split_plan_id,
            execution_units = split_plan.execution_units.len(),
            waves = split_plan.parallelism.waves.len(),
            effective_concurrency = split_plan.parallelism.effective_concurrency,
            "analysis split plan decided before worker admission"
        );
    }
    let analysis_input_proof = schedule.input_proof;
    let mut ledger_records =
        analysis_ledger_records(&scan_id, &schedule.work, analysis_plan.as_ref());
    let unit_count = schedule.work.len();
    let analysis_contract = analysis_contract_version(&ledger_records);
    store.initialize_analysis_unit_ledger(
        &scan_id,
        analysis_contract,
        analysis_plan.as_ref().map(|plan| plan.plan_id.as_str()),
        analysis_plan
            .as_ref()
            .map(|plan| plan.input_digest.as_str()),
        &ledger_records,
    )?;
    let profiling = scan_profile_enabled();
    let mut performance_phases = Vec::new();
    let mut protocol_event_count = 0_u64;
    let mut ingest_ms = 0_u64;
    let mut global_upserts = BTreeMap::new();
    let mut file_coverage_ledgers = BTreeMap::new();
    let mut analysis_unit_file_paths = BTreeMap::new();
    let mut pending_analysis_unit_completions = BTreeMap::new();
    // Failures are keyed by work unit so a re-split can withdraw the failure
    // of a superseded unit before its replacements run (a replacement that
    // owns the same paths shares the unit ID); they join `failures` once
    // execution has ended.
    let analysis_unit_failures = std::sync::Mutex::new(BTreeMap::<String, String>::new());
    let unit_failures = std::sync::Mutex::new(BTreeMap::<String, ScanFailure>::new());
    let deferred_failures =
        std::sync::Mutex::new(BTreeMap::<String, DeferredAnalysisFailure>::new());
    let defer_resource_prefixes = AtomicBool::new(resplit_context.is_some());
    let mut consume = |store: &mut Store, unit_id: &str, output: WorkerOutput| -> Result<bool> {
        let ingest_started = Instant::now();
        if profiling {
            protocol_event_count += output.events.len() as u64;
            performance_phases.extend(worker_phase_performance(&output));
        }
        let adapter = output.adapter;
        let failure_kind = output.failure_kind;
        let security_violation = output.security_violation;
        let result = if defer_resource_prefixes.load(Ordering::Relaxed)
            && !security_violation
            && matches!(
                failure_kind,
                Some(
                    WorkerFailureKind::MemoryLimit
                        | WorkerFailureKind::Timeout
                        | WorkerFailureKind::OutputLimit
                )
            ) {
            store.save_adapter_log(
                &scan_id,
                adapter.name(),
                &output.stderr,
                output.stderr_truncated,
            )?;
            let detail = output
                .error
                .clone()
                .unwrap_or_else(|| "worker resource limit".to_owned());
            lock_failures(&deferred_failures)
                .insert(unit_id.to_owned(), DeferredAnalysisFailure::stage(output)?);
            Err(anyhow::anyhow!(
                "{} worker failed: {detail}",
                adapter.name()
            ))
        } else {
            bind_worker_output_to_profile_plan(output, &profile_plan).and_then(|output| {
                ingest_worker_output(
                    store,
                    &scan_id,
                    output,
                    Some(&mut global_upserts),
                    Some(&mut file_coverage_ledgers),
                    Some(&mut analysis_unit_file_paths),
                    Some(&mut pending_analysis_unit_completions),
                )
            })
        };
        ingest_ms += elapsed_ms(ingest_started);
        match result {
            Ok(()) => Ok(true),
            Err(error) => {
                lock_failures(&analysis_unit_failures).insert(
                    unit_id.to_owned(),
                    analysis_unit_error_detail(&format!("{error:#}")),
                );
                lock_failures(&unit_failures).insert(
                    unit_id.to_owned(),
                    ScanFailure::with_classification(
                        adapter,
                        format!("{error:#}"),
                        failure_kind.unwrap_or(WorkerFailureKind::Other),
                        security_violation,
                    ),
                );
                Ok(false)
            }
        }
    };
    let validate = |item: &AnalysisWorkItem, validation| {
        validate_work_inputs(
            &execution_context,
            item,
            checkpoint_store_path.as_deref(),
            &profile_plan.plan_id,
            analysis_input_proof.as_deref(),
            validation,
        )
    };
    let mut analysis = execute_analysis_units(
        store,
        &execution_context,
        schedule.work,
        &mut consume,
        &validate,
    )
    .await?;
    // A unit whose worker exceeded its memory, time, or output limit is re-planned at
    // the next finer boundary of the same discovery plan; its replacements
    // run in the same attempt and its failure is withdrawn.  The superseded
    // attempt stays visible in the progress ledger as a failed unit.
    let mut superseded_indices = BTreeSet::new();
    if let (Some(plan), Some(current), Some(resplit)) = (
        analysis_plan.as_ref(),
        split_plan.as_mut(),
        resplit_context.as_ref(),
    ) {
        let mut attempted = BTreeSet::new();
        while !cancellation.is_cancelled() {
            let Some((execution_unit_id, trigger)) =
                analysis
                    .units
                    .iter()
                    .enumerate()
                    .find_map(|(index, progress)| {
                        if superseded_indices.contains(&index)
                            || progress.status != "failed"
                            || lock_failures(&unit_failures)
                                .get(&progress.unit_id)
                                .is_some_and(|failure| failure.security_violation)
                        {
                            return None;
                        }
                        let trigger = match progress.failure_reason.as_deref()? {
                            "memory-limit" => AnalysisResplitTrigger::WorkerMemory,
                            "timeout" => AnalysisResplitTrigger::WorkerTimeout,
                            "output-limit" => AnalysisResplitTrigger::OutputLimit,
                            _ => return None,
                        };
                        let id = execution_unit_ids.get(index)?.clone()?;
                        (!attempted.contains(&id)).then_some((id, trigger))
                    })
            else {
                break;
            };
            attempted.insert(execution_unit_id.clone());
            let resplit_plan = resplit_execution_unit(
                plan,
                current,
                &resplit.split_input,
                &execution_unit_id,
                trigger,
            )?;
            let superseded = execution_unit_ids
                .iter()
                .enumerate()
                .filter(|(_, id)| {
                    id.as_ref()
                        .is_some_and(|id| resplit_plan.superseded_execution_unit_ids.contains(id))
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            // Only a failed attempt is withdrawn: an ingested result is never
            // removed, and retained siblings must keep their chunk numbering
            // because their profiles already carry it.
            let withdrawable = superseded.len() == resplit_plan.superseded_execution_unit_ids.len()
                && superseded.iter().all(|index| {
                    let unit = &analysis.units[*index];
                    unit.status == "failed"
                        && !lock_failures(&unit_failures)
                            .get(&unit.unit_id)
                            .is_some_and(|failure| failure.security_violation)
                })
                && resplit_plan.retained_execution_unit_ids.iter().all(|id| {
                    current
                        .execution_unit(id)
                        .zip(resplit_plan.plan.execution_unit(id))
                        .is_some_and(|(before, after)| {
                            before.batch_index == after.batch_index
                                && before.batch_count == after.batch_count
                        })
                });
            let applied = resplit_plan.outcome == AnalysisResplitOutcome::Split && withdrawable;
            let disposition = match (resplit_plan.outcome, withdrawable) {
                (AnalysisResplitOutcome::Split, true) => "applied",
                (AnalysisResplitOutcome::Split, false) => "deferred",
                (AnalysisResplitOutcome::Unsplittable, _) => "unsplittable",
            };
            let message = format!(
                "analysis re-split {disposition}: execution unit {execution_unit_id} ({}) {} -> {}{}; superseded {}, replacements {}",
                trigger.as_str(),
                resplit_plan.previous_split_plan_id,
                resplit_plan.split_plan_id,
                resplit_plan
                    .unsplittable_reason
                    .map(|reason| format!(" ({})", reason.as_str()))
                    .unwrap_or_default(),
                resplit_plan.superseded_execution_unit_ids.len(),
                resplit_plan.replacement_execution_unit_ids.len(),
            );
            tracing::info!(%message);
            add_core_diagnostic(
                store,
                &scan_id,
                "info",
                "analysis-resplit",
                &message,
                &format!("{}:{}", resplit_plan.split_plan_id, execution_unit_id),
            )?;
            if !applied {
                continue;
            }
            let replacement_ids = resplit_plan
                .replacement_execution_unit_ids
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            let (replacement_execution_ids, replacement_work): (Vec<_>, Vec<_>) = resplit
                .work_items(
                    &execution_context,
                    plan,
                    &resplit_plan.plan,
                    &replacement_ids,
                )
                .into_iter()
                .unzip();
            let replacement_records =
                analysis_ledger_records(&scan_id, &replacement_work, Some(plan));
            let superseded_records = superseded
                .iter()
                .map(|index| ledger_records[*index].clone())
                .collect::<Vec<_>>();
            store.resplit_analysis_unit_ledger(
                &scan_id,
                &superseded_records,
                &replacement_records,
            )?;
            for index in superseded {
                superseded_indices.insert(index);
                let unit_id = &analysis.units[index].unit_id;
                lock_failures(&deferred_failures).remove(unit_id);
                lock_failures(&unit_failures).remove(unit_id);
                lock_failures(&analysis_unit_failures).remove(unit_id);
                let loader = &mut analysis.units[index].loader;
                loader.insert("analysis_resplit".to_owned(), "superseded".to_owned());
                loader.insert(
                    "analysis_resplit_split_plan_id".to_owned(),
                    resplit_plan.split_plan_id.clone(),
                );
            }
            *current = resplit_plan.plan;
            let retained_typed = retained_typed_reference_fingerprints(
                &analysis,
                &execution_unit_ids,
                current,
                &resplit_plan.retained_execution_unit_ids,
            );
            let replacement_progress = execute_analysis_units_with_retained_typed(
                store,
                &execution_context,
                replacement_work,
                &mut consume,
                &validate,
                &retained_typed,
            )
            .await?;
            ledger_records.extend(replacement_records);
            execution_unit_ids.extend(replacement_execution_ids.into_iter().map(Some));
            for mut unit in replacement_progress.units {
                unit.loader
                    .insert("analysis_resplit".to_owned(), "replacement".to_owned());
                unit.loader.insert(
                    "analysis_resplit_split_plan_id".to_owned(),
                    current.split_plan_id.clone(),
                );
                analysis.units.push(unit);
            }
            if replacement_progress.stop_reason.is_some() {
                analysis.stop_reason = replacement_progress.stop_reason;
            }
        }
    }
    // Only prefixes that were not superseded remain useful partial results.
    // Restore in execution order, one file at a time, including on cancellation.
    defer_resource_prefixes.store(false, Ordering::Relaxed);
    for unit in &analysis.units {
        let deferred = lock_failures(&deferred_failures).remove(&unit.unit_id);
        if let Some(deferred) = deferred {
            consume(store, &unit.unit_id, deferred.restore()?)?;
        }
    }
    failures.extend(
        unit_failures
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .into_values(),
    );
    let analysis_unit_failures = analysis_unit_failures
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let ingest_started = Instant::now();
    let allow_semantic_join = failures.is_empty() && !cancellation.is_cancelled();
    if let Err(error) = finalize_analysis_unit_completions(
        store,
        &mut pending_analysis_unit_completions,
        &analysis_unit_file_paths,
        &file_coverage_ledgers,
        allow_semantic_join,
    ) {
        failures.push(ScanFailure::with_classification(
            AdapterKind::Go,
            format!("analysis-unit coverage finalization failed: {error:#}"),
            WorkerFailureKind::Other,
            false,
        ));
    }
    ingest_ms += elapsed_ms(ingest_started);
    // Superseded rows left the Store ledger with their re-split; only the
    // units still part of the attempt are terminalized.
    let mut terminal_ledger = ledger_records
        .into_iter()
        .zip(analysis.units.iter())
        .enumerate()
        .filter(|(index, _)| !superseded_indices.contains(index))
        .map(|(_, pair)| pair)
        .collect::<Vec<_>>();
    for (record, progress) in &mut terminal_ledger {
        record.status = match progress.status.as_str() {
            "completed" => "completed",
            "failed" => "failed",
            "cancelled" => "cancelled",
            _ => "unanalysed",
        }
        .to_owned();
        record.reused = progress.reused;
        // Keep the concrete ingestion/worker error after terminalization.
        // The progress category alone (for example, `ingestion-failed`) does
        // not explain why a checkpoint could not be accepted on retry.
        record.error = analysis_unit_failures
            .get(&progress.unit_id)
            .cloned()
            .or_else(|| progress.failure_reason.clone());
    }
    let terminal_ledger = terminal_ledger
        .into_iter()
        .map(|(record, _)| record)
        .collect::<Vec<_>>();
    let analysis_coverage = store.finalize_analysis_unit_ledger(&scan_id, &terminal_ledger)?;
    if !analysis_coverage.complete {
        let reason = analysis_coverage
            .reasons
            .first()
            .map(String::as_str)
            .unwrap_or("analysis-unit-incomplete");
        if failures.is_empty() {
            failures.push(ScanFailure::with_classification(
                AdapterKind::Go,
                format!("analysis unit coverage is incomplete: {reason}"),
                WorkerFailureKind::Other,
                false,
            ));
        }
        store.mark_coverage_incomplete(&scan_id, reason)?;
    }
    let worker_ms = elapsed_ms(worker_started);
    if cancellation.is_cancelled() {
        let mut outcome = cancel_scan(store, &scan_id)?;
        outcome.analysis = Some(analysis);
        outcome.analysis_coverage = Some(analysis_coverage);
        return Ok(outcome);
    }
    if profiling {
        performance_phases.push(ScanPhasePerformance {
            phase: "core_scan_setup".into(),
            duration_ms: setup_ms,
            items: unit_count as u64,
            bytes: 0,
        });
        performance_phases.push(ScanPhasePerformance {
            phase: "core_worker_execution".into(),
            duration_ms: worker_ms.saturating_sub(ingest_ms),
            items: unit_count as u64,
            bytes: 0,
        });
        let protocol_bytes = performance_phases
            .iter()
            .filter(|phase| phase.phase.ends_with("_protocol_write"))
            .fold(0_u64, |total, phase| total.saturating_add(phase.bytes));
        performance_phases.push(ScanPhasePerformance {
            phase: "core_protocol_ingest".into(),
            duration_ms: ingest_ms,
            items: protocol_event_count,
            bytes: protocol_bytes,
        });
    }
    failures.sort_by_key(|failure| (failure.adapter, failure.kind));
    for failure in &failures {
        let identity = failure.stable_identity();
        let message = failure.diagnostic_message();
        add_core_diagnostic(
            store,
            &scan_id,
            "error",
            if failure.security_violation {
                "security-policy"
            } else {
                "worker-failure"
            },
            &message,
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
        let failure_reasons = failures
            .iter()
            .map(ScanFailure::stable_identity)
            .collect::<BTreeSet<_>>();
        for reason in failure_reasons {
            store.mark_coverage_incomplete(&scan_id, &reason)?;
        }
        let security_violation = failures.iter().any(|failure| failure.security_violation);
        let mut outcome = finish_non_promoted_scan(
            store,
            &scan_id,
            if security_violation {
                "security_failed"
            } else {
                "partial"
            },
            Some(&summary),
            if security_violation { 4 } else { 3 },
            &cancellation,
        )?;
        outcome.analysis = Some(analysis);
        outcome.analysis_coverage = Some(analysis_coverage);
        return Ok(outcome);
    }

    if let Some(proof) = analysis_input_proof.as_ref()
        && !proof.matches_postflight(&root, checkpoint_store_path.as_deref())
    {
        let mut outcome = finish_changed_input_scan(store, &scan_id, &cancellation)?;
        outcome.analysis = Some(analysis);
        outcome.analysis_coverage = Some(analysis_coverage);
        return Ok(outcome);
    }
    if let Some(expected) = analysis_plan.as_ref()
        && !plan_analysis_units(&root, config, checkpoint_store_path.as_deref())
            .is_ok_and(|observed| observed.input_digest == expected.input_digest)
    {
        let mut outcome = finish_changed_input_scan(store, &scan_id, &cancellation)?;
        outcome.analysis = Some(analysis);
        outcome.analysis_coverage = Some(analysis_coverage);
        return Ok(outcome);
    }
    let observed_profile_plan = match plan_repository_profiles(&root, config, None) {
        Ok(preview) if preview.plan.plan_id == profile_plan.plan_id => preview.plan,
        _ => {
            record_cache_rejection(
                store,
                &scan_id,
                "profile-planning-input-changed-during-scan",
            )?;
            add_core_diagnostic(
                store,
                &scan_id,
                "error",
                "profile-planning-input-changed",
                "profile planning input changed while the scan was running",
                "profile-planning-input-changed",
            )?;
            store
                .mark_coverage_incomplete(&scan_id, "profile-planning-input-changed-during-scan")?;
            let mut outcome = finish_non_promoted_scan(
                store,
                &scan_id,
                "partial",
                Some("profile planning input changed during scan"),
                3,
                &cancellation,
            )?;
            outcome.analysis = Some(analysis);
            outcome.analysis_coverage = Some(analysis_coverage);
            return Ok(outcome);
        }
    };
    if let (Some(expected), Some(workers)) = (cache_plan.take(), cache_workers.as_deref()) {
        match prepare_scan_cache(
            &root,
            config,
            workers,
            store.database_path().as_deref(),
            &observed_profile_plan.plan_id,
        ) {
            ScanCachePreparation::Ready(observed)
                if observed.syntax == expected.syntax
                    && observed.semantic == expected.semantic
                    && observed.semantic_reject_reason == expected.semantic_reject_reason =>
            {
                cache_plan = Some(expected);
            }
            _ => {
                record_cache_rejection(store, &scan_id, "input-or-toolchain-changed-during-scan")?;
                let mut outcome = finish_changed_input_scan(store, &scan_id, &cancellation)?;
                outcome.analysis = Some(analysis);
                outcome.analysis_coverage = Some(analysis_coverage);
                return Ok(outcome);
            }
        }
    }

    if cancellation.is_cancelled() {
        let mut outcome = cancel_scan(store, &scan_id)?;
        outcome.analysis = Some(analysis);
        outcome.analysis_coverage = Some(analysis_coverage);
        return Ok(outcome);
    }

    let promotion_started = Instant::now();
    let mut outcome = complete_scan_with_mode(
        store,
        &scan_id,
        strict,
        config,
        cache_plan.as_ref(),
        &cancellation,
        promotion,
    )?;
    outcome.analysis = Some(analysis);
    outcome.analysis_coverage = Some(analysis_coverage);
    if profiling {
        performance_phases.push(ScanPhasePerformance {
            phase: "store_validation_promotion".into(),
            duration_ms: elapsed_ms(promotion_started),
            items: outcome.coverage.dependency_sites,
            bytes: store
                .database_path()
                .and_then(|path| std::fs::metadata(path).ok())
                .map(|metadata| metadata.len())
                .unwrap_or_default(),
        });
        outcome.performance = Some(ScanPerformance {
            phases: performance_phases,
        });
    }
    Ok(outcome)
}

fn finish_changed_input_scan(
    store: &mut Store,
    scan_id: &str,
    cancellation: &CancellationToken,
) -> Result<ScanOutcome> {
    add_core_diagnostic(
        store,
        scan_id,
        "error",
        "analysis-input-changed",
        "analysis input changed while units were running; retry to produce a consistent snapshot",
        "analysis-input-changed-during-scan",
    )?;
    store.mark_coverage_incomplete(scan_id, "analysis-input-changed-during-scan")?;
    finish_non_promoted_scan(
        store,
        scan_id,
        "partial",
        Some("analysis input changed during scan"),
        3,
        cancellation,
    )
}

fn scan_profile_enabled() -> bool {
    std::env::var("DEPGRAPH_SCAN_PROFILE").as_deref() == Ok("1")
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn worker_phase_performance(output: &WorkerOutput) -> Vec<ScanPhasePerformance> {
    output
        .stderr
        .lines()
        .filter_map(|line| {
            let fields = line.strip_prefix("depgraph-progress ")?.split_whitespace();
            let mut phase = None;
            let mut completed = false;
            let mut duration_ms = None;
            let mut items = 0;
            let mut bytes = 0;
            for field in fields {
                let (key, value) = field.split_once('=')?;
                match key {
                    "phase" => phase = Some(value.to_owned()),
                    "status" => completed = value == "completed",
                    "duration_ms" => duration_ms = value.parse().ok(),
                    "items" | "source_files" => items = value.parse().unwrap_or_default(),
                    "bytes" => bytes = value.parse().unwrap_or_default(),
                    _ => {}
                }
            }
            (completed && phase.is_some() && duration_ms.is_some()).then(|| ScanPhasePerformance {
                phase: phase.expect("checked"),
                duration_ms: duration_ms.expect("checked"),
                items,
                bytes,
            })
        })
        .collect()
}

#[cfg(test)]
fn bind_worker_outputs_to_profile_plan(
    outputs: Vec<WorkerOutput>,
    plan: &DefaultProfileSelectionPlan,
    failures: &mut Vec<ScanFailure>,
) -> Vec<WorkerOutput> {
    outputs
        .into_iter()
        .filter_map(|output| {
            let adapter = output.adapter;
            let security_violation = output.security_violation;
            match bind_worker_output_to_profile_plan(output, plan) {
                Ok(output) => Some(output),
                Err(error) => {
                    failures.push(ScanFailure::with_classification(
                        adapter,
                        format!("worker profile-plan binding failed: {error:#}"),
                        WorkerFailureKind::MalformedProtocol,
                        security_violation,
                    ));
                    None
                }
            }
        })
        .collect()
}

fn bind_worker_output_to_profile_plan(
    mut output: WorkerOutput,
    plan: &DefaultProfileSelectionPlan,
) -> Result<WorkerOutput> {
    validate_profile_selection_plan(plan)?;
    let selected_profile_ids = plan
        .selected
        .iter()
        .map(|entry| Value::String(entry.profile_id.clone()))
        .collect::<Vec<_>>();
    let selection_mode = match plan.selection_mode {
        ProfileSelectionMode::Automatic => "automatic",
        ProfileSelectionMode::Explicit => "explicit",
    };
    for event in &mut output.events {
        if event.get("event").and_then(Value::as_str) != Some("profile_declared") {
            continue;
        }
        let profile = event
            .get_mut("profile")
            .and_then(Value::as_object_mut)
            .context("validated worker profile declaration is not an object")?;
        let properties = profile.entry("properties").or_insert(Value::Null);
        if properties.is_null() {
            *properties = json!({});
        }
        let properties = properties
            .as_object_mut()
            .context("validated worker profile properties are not an object")?;
        for (key, value) in [
            (
                "profile_selection_plan_id",
                Value::String(plan.plan_id.clone()),
            ),
            (
                "profile_selection_input_digest",
                Value::String(plan.input_digest.clone()),
            ),
            (
                "profile_selection_mode",
                Value::String(selection_mode.to_owned()),
            ),
            (
                "profile_selection_selected_profile_ids",
                Value::Array(selected_profile_ids.clone()),
            ),
            (
                "profile_selection_complete",
                Value::Bool(plan.summary.selection_complete),
            ),
        ] {
            if properties.insert(key.to_owned(), value).is_some() {
                anyhow::bail!("worker profile collides with reserved profile-selection metadata");
            }
        }
    }
    Ok(output)
}

pub(crate) fn cancel_scan(store: &mut Store, scan_id: &str) -> Result<ScanOutcome> {
    store.finish_scan(scan_id, "cancelled", Some("scan cancelled"), false)?;
    snapshot_outcome(store, scan_id, 3)
}

fn scan_attempt_id(operation_id: &str) -> String {
    let owner_digest = Sha256::digest(operation_id.as_bytes());
    format!("scan-attempt:{owner_digest:x}:{}", Uuid::new_v4().simple())
}

fn promote_validated_scan_cache_hit_if_active(
    store: &mut Store,
    scan_id: &str,
    root: &Path,
    plan: &ScanCachePlan,
    hit: &ValidatedScanCacheHit,
    cancellation: &CancellationToken,
) -> Option<Result<()>> {
    cancellation.run_if_active(|| {
        store.promote_validated_scan_cache_hit_with_precommit(scan_id, hit, || {
            validate_scan_cache_hit_inputs(root, plan).map_err(anyhow::Error::new)
        })
    })
}

pub(crate) fn complete_scan(
    store: &mut Store,
    scan_id: &str,
    strict: bool,
    config: &Config,
    cache_plan: Option<&ScanCachePlan>,
    cancellation: &CancellationToken,
) -> Result<ScanOutcome> {
    let mut pending_promotion = None;
    let mut promotion = ScanPromotionContext {
        mode: ScanPromotionMode::Immediate,
        pending: &mut pending_promotion,
        operation_id: None,
        operation_identity: None,
    };
    let outcome = complete_scan_with_mode(
        store,
        scan_id,
        strict,
        config,
        cache_plan,
        cancellation,
        &mut promotion,
    )?;
    debug_assert!(pending_promotion.is_none());
    Ok(outcome)
}

fn complete_scan_with_mode(
    store: &mut Store,
    scan_id: &str,
    strict: bool,
    config: &Config,
    cache_plan: Option<&ScanCachePlan>,
    cancellation: &CancellationToken,
    promotion: &mut ScanPromotionContext<'_, '_>,
) -> Result<ScanOutcome> {
    if cancellation.is_cancelled() {
        return cancel_scan(store, scan_id);
    }
    let validation = match store.validate_scan_for_completion(scan_id) {
        Ok(validation) => validation,
        Err(error) => {
            add_core_diagnostic(
                store,
                scan_id,
                "error",
                "graph-validation-failed",
                &format!("{error:#}"),
                "graph-validation-failed",
            )?;
            return finish_non_promoted_scan(
                store,
                scan_id,
                "failed",
                Some(&error.to_string()),
                3,
                cancellation,
            );
        }
    };

    let summary = store.load_validated_scan_summary(&validation)?;
    let coverage = &summary.coverage;
    let rust_hir_backend_failure = has_rust_hir_backend_failure(coverage);
    let strict_failure = strict && violates_strict_policy(coverage, config);
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
        return finish_non_promoted_scan(
            store,
            scan_id,
            "policy_failed",
            Some(&message),
            1,
            cancellation,
        );
    }

    let policy = if config.policy.rules.is_empty() {
        None
    } else {
        let snapshot = store.load_snapshot(scan_id)?;
        let snapshot_id = store.prospective_scan_snapshot_id(scan_id)?;
        match evaluate_policy_cancellable(
            snapshot_id,
            &snapshot,
            &config.policy,
            MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
            || cancellation.is_cancelled(),
        ) {
            Ok(result) => Some(result),
            Err(error) if is_policy_evaluation_cancelled(&error) || cancellation.is_cancelled() => {
                return cancel_scan(store, scan_id);
            }
            Err(error) => {
                let message = format!("architecture policy evaluation failed: {error:#}");
                add_core_diagnostic(
                    store,
                    scan_id,
                    "error",
                    "architecture-policy-config",
                    &message,
                    "architecture-policy-config",
                )?;
                let Some(completion) = cancellation
                    .run_if_active(|| store.finish_scan(scan_id, "failed", Some(&message), false))
                else {
                    return cancel_scan(store, scan_id);
                };
                completion?;
                return Err(error.context("architecture policy evaluation failed"));
            }
        }
    };
    if let Some(result) = policy.as_ref().filter(|result| result.exit_code == 1) {
        let message = format!(
            "architecture policy failed: errors={}, warnings={}, suppressed={}",
            result.summary.errors, result.summary.warnings, result.summary.suppressed
        );
        add_core_diagnostic(
            store,
            scan_id,
            "error",
            "architecture-policy",
            &message,
            "architecture-policy",
        )?;
        let mut outcome = finish_non_promoted_scan(
            store,
            scan_id,
            "policy_failed",
            Some(&message),
            1,
            cancellation,
        )?;
        outcome.policy = policy;
        return Ok(outcome);
    }

    // Load everything required for the successful outcome before promotion. Once
    // finish_scan promotes the graph, optional cache maintenance must not turn an
    // already-visible completed snapshot into a retryable daemon failure.
    let mut outcome = ScanOutcome {
        scan_id: scan_id.to_owned(),
        status: "completed".to_owned(),
        exit_code: 0,
        coverage: summary.coverage,
        diagnostics: summary.diagnostics,
        cache_events: store.cache_events_for_scan(scan_id)?,
        policy,
        performance: None,
        analysis: None,
        analysis_coverage: None,
    };

    if promotion.mode == ScanPromotionMode::Deferred {
        *promotion.pending = Some(PendingScanPromotion {
            validation,
            cache_plan: cache_plan.cloned(),
        });
        return Ok(outcome);
    }

    let Some(promotion) =
        cancellation.run_if_active(|| store.finish_validated_scan(validation, true))
    else {
        return cancel_scan(store, scan_id);
    };
    let completed = promotion?;
    if let Some(plan) = cache_plan
        && let Err(error) = store_completed_scan_cache(store, plan, &completed)
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

fn finish_non_promoted_scan(
    store: &mut Store,
    scan_id: &str,
    status: &str,
    error: Option<&str>,
    exit_code: u8,
    cancellation: &CancellationToken,
) -> Result<ScanOutcome> {
    let Some(completion) =
        cancellation.run_if_active(|| store.finish_scan(scan_id, status, error, false))
    else {
        return cancel_scan(store, scan_id);
    };
    completion?;
    snapshot_outcome(store, scan_id, exit_code)
}

fn store_completed_scan_cache(
    store: &mut Store,
    plan: &ScanCachePlan,
    completed: &depgraph_store::CompletedScanSnapshot,
) -> Result<()> {
    let _ = store.store_completed_scan_snapshot_caches(
        &plan.syntax,
        plan.semantic.as_ref(),
        completed,
    )?;
    Ok(())
}

fn record_cache_rejection(store: &Store, scan_id: &str, reason: &str) -> Result<()> {
    for layer in [CacheLayer::Syntax, CacheLayer::Semantic] {
        store.record_cache_event(Some(scan_id), None, layer, None, "reject", reason)?;
    }
    Ok(())
}

fn record_cache_preparation_rejection(
    store: &mut Store,
    scan_id: &str,
    rejection: &CacheRejection,
) -> Result<()> {
    record_cache_rejection(store, scan_id, rejection.reason)?;
    if let Some(path) = rejection.path.as_deref() {
        add_core_diagnostic_at_path(
            store,
            scan_id,
            "warning",
            "cache-input-rejected",
            &format!("scan cache input was rejected: {}", rejection.reason),
            &format!("{}:{path}", rejection.reason),
            path,
        )?;
    }
    Ok(())
}

pub(crate) fn git_source_revision(root: &Path) -> Option<String> {
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

#[cfg(test)]
fn task_adapter(task_adapters: &mut BTreeMap<Id, AdapterKind>, task_id: Id) -> AdapterKind {
    task_adapters
        .remove(&task_id)
        .expect("every spawned worker task must have a registered adapter")
}

#[cfg(test)]
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

#[derive(Clone, Debug)]
struct FileCoverageLedger {
    discovered_sites: u64,
    emitted_sites: u64,
    skipped_sites: u64,
    skipped: bool,
    reason: Option<String>,
}

impl FileCoverageLedger {
    fn from_event(event: &Value) -> Result<(String, Self)> {
        let path = event
            .get("path")
            .and_then(Value::as_str)
            .context("file coverage event is missing path")?
            .to_owned();
        let ledger = Self {
            discovered_sites: event
                .get("discovered_sites")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
            emitted_sites: event
                .get("emitted_sites")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
            skipped_sites: event
                .get("skipped_sites")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
            skipped: event
                .get("skipped")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            reason: event
                .get("reason")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
        };
        Ok((path, ledger))
    }

    fn merge(&self, other: &Self) -> Result<Self> {
        let reason = match (&self.reason, &other.reason) {
            (Some(left), Some(right)) => Some(left.min(right).to_owned()),
            (Some(reason), None) | (None, Some(reason)) => Some(reason.clone()),
            (None, None) => None,
        };
        Ok(Self {
            discovered_sites: self
                .discovered_sites
                .checked_add(other.discovered_sites)
                .context("file coverage discovered-site ledger overflowed")?,
            emitted_sites: self
                .emitted_sites
                .checked_add(other.emitted_sites)
                .context("file coverage emitted-site ledger overflowed")?,
            skipped_sites: self
                .skipped_sites
                .checked_add(other.skipped_sites)
                .context("file coverage skipped-site ledger overflowed")?,
            skipped: self.skipped || other.skipped,
            reason,
        })
    }

    fn write_to_event(&self, event: &mut Value) -> Result<()> {
        let object = event
            .as_object_mut()
            .context("file coverage event is not an object")?;
        object.insert("discovered_sites".into(), json!(self.discovered_sites));
        object.insert("emitted_sites".into(), json!(self.emitted_sites));
        object.insert("skipped_sites".into(), json!(self.skipped_sites));
        object.insert("skipped".into(), json!(self.skipped));
        match &self.reason {
            Some(reason) => {
                object.insert("reason".into(), Value::String(reason.clone()));
            }
            None => {
                object.remove("reason");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
fn merge_file_coverage_events(
    events: &mut [Value],
    adapter: AdapterKind,
    ledgers: &mut BTreeMap<(String, String), FileCoverageLedger>,
) -> Result<()> {
    merge_file_coverage_events_with_unit_paths(events, adapter, ledgers, None)
}

type AnalysisUnitFilePaths = BTreeMap<(AdapterKind, String), BTreeSet<String>>;
type PendingAnalysisUnitCompletions = BTreeMap<(AdapterKind, String, String), Vec<Value>>;
type FileCoverageStageDelta = (
    BTreeMap<(String, String), FileCoverageLedger>,
    AnalysisUnitFilePaths,
);

#[cfg(test)]
fn merge_file_coverage_events_with_unit_paths(
    events: &mut [Value],
    adapter: AdapterKind,
    ledgers: &mut BTreeMap<(String, String), FileCoverageLedger>,
    unit_file_paths: Option<&mut AnalysisUnitFilePaths>,
) -> Result<()> {
    let (ledger_delta, unit_file_path_delta) =
        stage_file_coverage_events(events, adapter, ledgers)?;
    ledgers.extend(ledger_delta);
    if let Some(unit_file_paths) = unit_file_paths {
        for (key, paths) in unit_file_path_delta {
            unit_file_paths.entry(key).or_default().extend(paths);
        }
    }
    Ok(())
}

/// Merge file coverage into a per-output delta.  The caller commits the
/// returned maps only after the corresponding Store transaction succeeds.
/// Keeping this delta bounded by the current worker stream avoids cloning the
/// repository-wide coverage maps while preventing failed ingestion from
/// leaking coverage into later units.
fn stage_file_coverage_events(
    events: &mut [Value],
    adapter: AdapterKind,
    ledgers: &BTreeMap<(String, String), FileCoverageLedger>,
) -> Result<FileCoverageStageDelta> {
    let Some(stage) = analysis_unit_stage(events) else {
        // Legacy whole-adapter workers are allowed to account for manifest and
        // package records that do not map one-to-one to source file rows. Keep
        // their established coverage semantics untouched.
        return Ok((BTreeMap::new(), BTreeMap::new()));
    };
    let adapter_name = adapter.name().to_owned();
    let unit_identity = analysis_unit_identity(events);
    let mut new_files = 0_u64;
    let mut seen_in_stream = BTreeSet::new();
    let mut ledger_delta = BTreeMap::new();
    let mut unit_file_path_delta = AnalysisUnitFilePaths::new();
    for event in events.iter_mut() {
        if event.get("event").and_then(Value::as_str) != Some("file_completed") {
            continue;
        }
        let (path, current) = FileCoverageLedger::from_event(event)?;
        let key = (adapter_name.clone(), path);
        let first_in_scan = !ledgers.contains_key(&key);
        let first_in_stream = seen_in_stream.insert(key.clone());
        if let Some((unit_id, _)) = &unit_identity {
            unit_file_path_delta
                .entry((adapter, unit_id.clone()))
                .or_default()
                .insert(key.1.clone());
        }
        if first_in_scan && first_in_stream {
            new_files = new_files
                .checked_add(1)
                .context("file coverage file count overflowed")?;
        }
        let merged = ledger_delta
            .get(&key)
            .or_else(|| ledgers.get(&key))
            .map(|previous| previous.merge(&current))
            .transpose()?
            .unwrap_or(current);
        merged.write_to_event(event)?;
        ledger_delta.insert(key, merged);
    }

    // Store's coverage event is additive across worker streams, while its
    // per-file table is keyed by (scan_id, adapter, path). Count a path only
    // when it first appears in this scan so syntax/semantic stages do not make
    // the aggregate file count depend on which stage arrived last.
    let (new_skipped, new_analyzed) = if stage == "semantic" {
        let skipped = seen_in_stream
            .iter()
            .filter(|key| {
                ledger_delta
                    .get(*key)
                    .or_else(|| ledgers.get(*key))
                    .is_some_and(|ledger| ledger.skipped)
            })
            .count() as u64;
        let analyzed = (seen_in_stream.len() as u64).saturating_sub(skipped);
        (skipped, analyzed)
    } else {
        // The syntax stage establishes the unique file set. The semantic stage
        // contributes the final analyzed/skipped status after it has had a
        // chance to replace the syntax projection.
        (0, 0)
    };
    for event in events.iter_mut() {
        if event.get("event").and_then(Value::as_str) != Some("scan_completed") {
            continue;
        }
        let coverage = event
            .get_mut("coverage")
            .and_then(Value::as_object_mut)
            .context("scan completion event is missing coverage")?;
        coverage.insert("files_discovered".into(), json!(new_files));
        coverage.insert("files_skipped".into(), json!(new_skipped));
        coverage.insert("files_analyzed".into(), json!(new_analyzed));
    }
    Ok((ledger_delta, unit_file_path_delta))
}

fn analysis_unit_stage(events: &[Value]) -> Option<String> {
    events.iter().find_map(|event| {
        if event.get("event").and_then(Value::as_str) != Some("profile_declared") {
            return None;
        }
        let profile = event.get("profile")?.as_object()?;
        let properties = profile.get("properties")?.as_object()?;
        is_analysis_unit_contract(
            properties
                .get("analysis_unit_contract")
                .and_then(Value::as_str),
        )
        .then(|| {
            properties
                .get("analysis_stage")?
                .as_str()
                .map(ToOwned::to_owned)
        })
        .flatten()
    })
}

fn analysis_unit_identity(events: &[Value]) -> Option<(String, String)> {
    events.iter().find_map(|event| {
        if event.get("event").and_then(Value::as_str) != Some("profile_declared") {
            return None;
        }
        let profile = event.get("profile")?.as_object()?;
        let properties = profile.get("properties")?.as_object()?;
        if !is_analysis_unit_contract(
            properties
                .get("analysis_unit_contract")
                .and_then(Value::as_str),
        ) {
            return None;
        }
        let unit_id = properties
            .get("analysis_unit_id")
            .and_then(Value::as_str)?
            .to_owned();
        let stage = properties
            .get("analysis_stage")
            .and_then(Value::as_str)?
            .to_owned();
        Some((unit_id, stage))
    })
}

fn analysis_unit_ledger_identity(events: &[Value]) -> Option<(String, String, String, String)> {
    events.iter().find_map(|event| {
        if event.get("event").and_then(Value::as_str) != Some("profile_declared") {
            return None;
        }
        let properties = event.get("profile")?.get("properties")?.as_object()?;
        if !is_analysis_unit_contract(
            properties
                .get("analysis_unit_contract")
                .and_then(Value::as_str),
        ) {
            return None;
        }
        Some((
            properties.get("analysis_unit_id")?.as_str()?.to_owned(),
            properties
                .get("analysis_unit_root")
                .and_then(Value::as_str)
                .unwrap_or(".")
                .to_owned(),
            properties.get("analysis_stage")?.as_str()?.to_owned(),
            properties
                .get("analysis_chunk_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        ))
    })
}

fn is_analysis_unit_contract(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        value == ANALYSIS_UNIT_WORKER_CONTRACT_VERSION || value == "depgraph-analysis-unit-v2"
    })
}

fn ingest_worker_output(
    store: &mut Store,
    scan_id: &str,
    output: WorkerOutput,
    global_upserts: Option<&mut BTreeMap<(String, String), [u8; 32]>>,
    file_coverage_ledgers: Option<&mut BTreeMap<(String, String), FileCoverageLedger>>,
    unit_file_paths: Option<&mut AnalysisUnitFilePaths>,
    pending_analysis_unit_completions: Option<&mut PendingAnalysisUnitCompletions>,
) -> Result<()> {
    store.save_adapter_log(
        scan_id,
        output.adapter.name(),
        &output.stderr,
        output.stderr_truncated,
    )?;
    let ledger_identity = analysis_unit_ledger_identity(&output.events);
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
                .filter(|event| event.get("event").and_then(Value::as_str) == Some(*event_type))
                .cloned(),
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
    let mut file_coverage_delta: BTreeMap<(String, String), FileCoverageLedger> = BTreeMap::new();
    let mut unit_file_path_delta = AnalysisUnitFilePaths::new();
    if let Some(existing) = file_coverage_ledgers.as_deref() {
        (file_coverage_delta, unit_file_path_delta) =
            stage_file_coverage_events(&mut ordered, output.adapter, existing)?;
    }
    crate::analysis_canonical::normalize_source_batch_profiles(&mut ordered)?;
    let merge_web_memberships = output.adapter == AdapterKind::Web
        && ordered.iter().any(|event| {
            event["event"] == "profile_declared"
                && event["profile"]["properties"]["analysis_unit_contract"]
                    == "depgraph-analysis-unit-v2"
        });
    let mut merged_profiles = BTreeSet::new();
    let mut merged_nodes = BTreeSet::new();
    for event in &mut ordered {
        if merge_web_memberships
            && event["event"] == "node_upsert"
            && event["node"]["properties"]["profile_ids"].is_array()
            && matches!(
                event["node"]["kind"].as_str(),
                Some("file" | "symbol" | "type" | "external_system")
            )
        {
            let id = event["node"]["id"]
                .as_str()
                .context("semantic node has no ID")?
                .to_owned();
            if let Some(previous) = store.load_scan_node_payload(scan_id, &id)? {
                crate::analysis_canonical::merge_shared_web_node(&previous, &mut event["node"])?;
                merged_nodes.insert(id);
            }
        }
        if event["event"] != "profile_declared"
            || event["profile"]["properties"]["analysis_unit_contract"]
                != "depgraph-analysis-unit-v2"
        {
            continue;
        }
        let id = event["profile"]["id"]
            .as_str()
            .context("source-batch profile is missing its logical ID")?
            .to_owned();
        if let Some(previous) = store.load_scan_profile_declaration(scan_id, &id)? {
            crate::analysis_canonical::merge_logical_profile(&previous, &mut event["profile"])?;
            merged_profiles.insert(id);
        }
    }
    let mut pending_delta = PendingAnalysisUnitCompletions::new();
    if pending_analysis_unit_completions.is_some()
        && let Some((unit_id, stage)) = analysis_unit_identity(&ordered)
    {
        let key = (output.adapter, unit_id, stage);
        let mut retained = Vec::with_capacity(ordered.len());
        for event in ordered {
            if matches!(
                event.get("event").and_then(Value::as_str),
                Some("profile_completed") | Some("scan_completed")
            ) {
                pending_delta.entry(key.clone()).or_default().push(event);
            } else {
                retained.push(event);
            }
        }
        ordered = retained;
    }
    let mut global_upsert_delta = BTreeMap::new();
    if let Some(existing) = global_upserts.as_deref() {
        for event in &ordered {
            if let Some((kind, object)) = upsert_object(event) {
                let id = object
                    .get("id")
                    .and_then(Value::as_str)
                    .context("upsert object is missing id")?;
                let key = (kind.to_owned(), id.to_owned());
                let serialized: [u8; 32] = Sha256::digest(canonical_json(object).as_bytes()).into();
                if let Some(previous) = existing.get(&key).or_else(|| global_upsert_delta.get(&key))
                    && previous != &serialized
                    && !((kind == "profile" && merged_profiles.contains(id))
                        || (kind == "node" && merged_nodes.contains(id)))
                {
                    anyhow::bail!("conflicting cross-worker {kind} upsert for {id}");
                }
                global_upsert_delta.insert(key, serialized);
            }
        }
    }
    let ordered_refs = ordered.iter().collect::<Vec<_>>();
    if let Some((unit_id, unit_root, stage, chunk_id)) = ledger_identity {
        if store.analysis_unit_ledger_contains(scan_id, &unit_id, &unit_root, &stage, &chunk_id)? {
            store.ingest_events_with_analysis_unit(
                scan_id,
                &ordered_refs,
                &unit_id,
                &unit_root,
                &stage,
                &chunk_id,
                if worker_error.is_some() {
                    "failed"
                } else {
                    "completed"
                },
                false,
                worker_error.as_deref(),
            )?;
        } else {
            // Keep the legacy ingestion contract for callers that pass a
            // worker-prefixed stream without initializing a unit ledger.
            // Scheduled attempts always initialize the row above, so this
            // fallback cannot make an unplanned unit complete an attempt.
            store.ingest_events(&ordered_refs)?;
        }
    } else {
        store.ingest_events(&ordered_refs)?;
    }

    // The Store transaction is the commit point for the in-memory indexes as
    // well.  A failed event batch must not leave a global upsert, file
    // coverage entry, or deferred completion visible to a later unit.
    if let Some(global_upserts) = global_upserts {
        global_upserts.extend(global_upsert_delta);
    }
    if let Some(file_coverage_ledgers) = file_coverage_ledgers {
        file_coverage_ledgers.extend(file_coverage_delta);
    }
    if let Some(unit_file_paths) = unit_file_paths {
        for (key, paths) in unit_file_path_delta {
            unit_file_paths.entry(key).or_default().extend(paths);
        }
    }
    if let Some(pending_analysis_unit_completions) = pending_analysis_unit_completions {
        for (key, events) in pending_delta {
            pending_analysis_unit_completions
                .entry(key)
                .or_default()
                .extend(events);
        }
    }
    if let Some(error) = worker_error {
        anyhow::bail!("{} worker failed: {error}", output.adapter.name());
    }
    Ok(())
}

fn finalize_analysis_unit_completions(
    store: &mut Store,
    pending: &mut PendingAnalysisUnitCompletions,
    unit_file_paths: &AnalysisUnitFilePaths,
    ledgers: &BTreeMap<(String, String), FileCoverageLedger>,
    allow_semantic_join: bool,
) -> Result<()> {
    if pending.is_empty() {
        return Ok(());
    }

    for events in pending.values_mut() {
        crate::analysis_canonical::coalesce_stage_completions(events)?;
    }

    let stage_keys = pending.keys().cloned().collect::<Vec<_>>();
    let mut semantic_joins = BTreeSet::new();
    for (adapter, unit_id, stage) in &stage_keys {
        if stage != "syntax" || !allow_semantic_join {
            continue;
        }
        let semantic_key = (*adapter, unit_id.clone(), "semantic".to_owned());
        let Some(semantic_events) = pending.get(&semantic_key) else {
            continue;
        };
        let Some(syntax_events) = pending.get(&(*adapter, unit_id.clone(), stage.clone())) else {
            continue;
        };
        let typed_key = (*adapter, unit_id.clone(), "typed".to_owned());
        let typed_complete = match pending.get(&typed_key) {
            Some(events) => {
                *adapter == AdapterKind::Go
                    && has_completion_pair(events)
                    && reports_completeness(events, "syntax-complete")
                    && typed_profiles_complete(store, events)?
            }
            None => true,
        };
        if has_completion_pair(syntax_events)
            && has_completion_pair(semantic_events)
            && reports_completeness(syntax_events, "syntax-complete")
            && reports_completeness(semantic_events, "semantic-complete")
            && typed_complete
        {
            semantic_joins.insert((*adapter, unit_id.clone()));
        }
    }

    for (adapter, unit_id, stage) in &stage_keys {
        let owner = if pending.contains_key(&(*adapter, unit_id.clone(), "syntax".to_owned())) {
            "syntax"
        } else {
            "semantic"
        };
        let is_owner = stage == owner;
        let Some(events) = pending.get_mut(&(*adapter, unit_id.clone(), stage.clone())) else {
            continue;
        };
        let counts = unit_file_counts(*adapter, unit_id, unit_file_paths, ledgers);
        let joined = semantic_joins.contains(&(*adapter, unit_id.clone()));
        for event in events {
            match event.get("event").and_then(Value::as_str) {
                Some("profile_completed") => {
                    set_coverage_file_counts(event, counts)?;
                    // A profile completion describes one stage's facts. Keep
                    // syntax profiles syntax-only even when their scan-level
                    // projection participates in a successful stage join.
                    set_semantic_completeness(event, stage == "semantic" && joined)?;
                }
                Some("scan_completed") => {
                    set_coverage_file_counts(event, if is_owner { counts } else { (0, 0, 0) })?;
                    set_semantic_completeness(event, joined)?;
                    if stage == "syntax" && joined {
                        remove_coverage_reason(event, "go-packages-parser-fallback")?;
                    }
                }
                _ => {}
            }
        }
    }

    // Profile completion rows are independent upserts, while scan completion
    // rows are merged by the Store. Ingest profiles first so the final scan
    // completeness is the intersection of the joined stage projections.
    let mut ordered = Vec::new();
    for events in pending.values() {
        ordered.extend(events.iter().filter(|event| {
            event.get("event").and_then(Value::as_str) == Some("profile_completed")
        }));
    }
    for events in pending.values() {
        ordered.extend(
            events.iter().filter(|event| {
                event.get("event").and_then(Value::as_str) == Some("scan_completed")
            }),
        );
    }
    let refs = ordered.into_iter().collect::<Vec<_>>();
    store.ingest_events(&refs)?;
    pending.clear();
    Ok(())
}

fn has_completion_pair(events: &[Value]) -> bool {
    let profile_completed = events
        .iter()
        .any(|event| event.get("event").and_then(Value::as_str) == Some("profile_completed"));
    let scan_completed = events
        .iter()
        .any(|event| event.get("event").and_then(Value::as_str) == Some("scan_completed"));
    profile_completed && scan_completed
}

fn typed_profiles_complete(store: &Store, events: &[Value]) -> Result<bool> {
    for event in events
        .iter()
        .filter(|event| event["event"] == "profile_completed")
    {
        let scan_id = event["scan_id"]
            .as_str()
            .context("typed completion has no scan ID")?;
        let profile_id = event["profile_id"]
            .as_str()
            .context("typed completion has no profile ID")?;
        let Some(profile) = store.load_scan_profile_declaration(scan_id, profile_id)? else {
            return Ok(false);
        };
        if profile["language"] != "go"
            || profile["properties"]["analysis_stage"] != "typed"
            || profile["properties"]["go_typed_stage_complete"] != "true"
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn reports_completeness(events: &[Value], level: &str) -> bool {
    !events.is_empty()
        && events.iter().all(|event| {
            event
                .get("coverage")
                .and_then(|coverage| coverage.get("completeness"))
                .and_then(Value::as_array)
                .is_some_and(|levels| levels.iter().any(|value| value.as_str() == Some(level)))
        })
}

fn unit_file_counts(
    adapter: AdapterKind,
    unit_id: &str,
    unit_file_paths: &AnalysisUnitFilePaths,
    ledgers: &BTreeMap<(String, String), FileCoverageLedger>,
) -> (u64, u64, u64) {
    let paths = unit_file_paths
        .get(&(adapter, unit_id.to_owned()))
        .into_iter()
        .flat_map(|paths| paths.iter());
    let mut discovered = 0_u64;
    let mut skipped = 0_u64;
    for path in paths {
        discovered = discovered.saturating_add(1);
        if ledgers
            .get(&(adapter.name().to_owned(), path.clone()))
            .is_some_and(|ledger| ledger.skipped)
        {
            skipped = skipped.saturating_add(1);
        }
    }
    let analyzed = discovered.saturating_sub(skipped);
    (discovered, analyzed, skipped)
}

fn set_coverage_file_counts(event: &mut Value, counts: (u64, u64, u64)) -> Result<()> {
    let coverage = event
        .get_mut("coverage")
        .and_then(Value::as_object_mut)
        .context("analysis-unit completion event is missing coverage")?;
    coverage.insert("files_discovered".into(), json!(counts.0));
    coverage.insert("files_analyzed".into(), json!(counts.1));
    coverage.insert("files_skipped".into(), json!(counts.2));
    Ok(())
}

fn set_semantic_completeness(event: &mut Value, include: bool) -> Result<()> {
    let coverage = event
        .get_mut("coverage")
        .and_then(Value::as_object_mut)
        .context("analysis-unit completion event is missing coverage")?;
    let completeness = coverage
        .entry("completeness")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .context("analysis-unit completion completeness is not an array")?;
    completeness.retain(|level| level.as_str() != Some("semantic-complete"));
    if include {
        completeness.push(Value::String("semantic-complete".to_owned()));
    }
    completeness.sort_by_key(Value::to_string);
    completeness.dedup();
    Ok(())
}

fn remove_coverage_reason(event: &mut Value, reason: &str) -> Result<()> {
    let coverage = event
        .get_mut("coverage")
        .and_then(Value::as_object_mut)
        .context("analysis-unit completion event is missing coverage")?;
    let Some(reasons) = coverage.get_mut("reasons").and_then(Value::as_array_mut) else {
        return Ok(());
    };
    reasons.retain(|value| value.as_str() != Some(reason));
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
    add_core_diagnostic_inner(store, scan_id, severity, code, message, identity, None)
}

fn add_core_diagnostic_at_path(
    store: &mut Store,
    scan_id: &str,
    severity: &str,
    code: &str,
    message: &str,
    identity: &str,
    path: &str,
) -> Result<()> {
    add_core_diagnostic_inner(
        store,
        scan_id,
        severity,
        code,
        message,
        identity,
        Some(path),
    )
}

#[allow(clippy::too_many_arguments)]
fn add_core_diagnostic_inner(
    store: &mut Store,
    scan_id: &str,
    severity: &str,
    code: &str,
    message: &str,
    identity: &str,
    path: Option<&str>,
) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(b"depgraph-core-diagnostic-v1\0");
    hasher.update(code.as_bytes());
    hasher.update(b"\0");
    hasher.update(identity.as_bytes());
    let id = format!("diagnostic:{}", hex::encode(hasher.finalize()));
    let mut diagnostic = json!({
        "id":id,
        "severity":severity,
        "code":code,
        "message":message
    });
    if let Some(path) = path {
        diagnostic["path"] = Value::String(path.to_owned());
    }
    store.ingest_event(&json!({
        "event":"diagnostic",
        "protocol_version":"1.0",
        "scan_id":scan_id,
        "adapter":"core",
        "adapter_version":env!("CARGO_PKG_VERSION"),
        "seq":0,
        "diagnostic":diagnostic
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
    // This helper is used only after cancellation or a non-promoted terminal
    // result. Its summary only needs retained metadata; explicit partial
    // queries can load the graph separately without making summary reporting
    // reconstruct every node, site, edge, evidence, and profile correlation.
    let metadata = store.load_terminal_scan_metadata(scan_id)?;
    Ok(ScanOutcome {
        scan_id: scan_id.to_owned(),
        status: metadata.status,
        exit_code,
        coverage: metadata.coverage,
        diagnostics: metadata.diagnostics,
        cache_events: metadata.cache_events,
        policy: None,
        performance: None,
        analysis: None,
        analysis_coverage: None,
    })
}

/// The per-unit failure maps are shared between the ingestion closure and the
/// re-split pass of one scan future; the lock is never held across an await.
fn lock_failures<T>(failures: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    failures
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Typed units retained across a re-split still own the reference fingerprints
/// a replacement semantic executor must bind. Failed or superseded units are
/// not included; a missing fingerprint is recorded as `None` so the executor
/// refuses the semantic checkpoint rather than hashing an empty set.
fn retained_typed_reference_fingerprints(
    analysis: &AnalysisExecutionProgress,
    execution_unit_ids: &[Option<String>],
    plan: &AnalysisSplitPlan,
    retained_ids: &[String],
) -> Vec<TypedReferenceFingerprint> {
    let retained = retained_ids.iter().cloned().collect::<BTreeSet<_>>();
    analysis
        .units
        .iter()
        .enumerate()
        .filter_map(|(index, unit)| {
            if unit.stage != "typed" || unit.status != "completed" {
                return None;
            }
            let id = execution_unit_ids.get(index)?.as_ref()?;
            if !retained.contains(id) {
                return None;
            }
            let execution = plan.execution_unit(id)?;
            if execution.loader.kind != AnalysisLoaderKind::Package {
                return None;
            }
            Some(TypedReferenceFingerprint {
                unit_id: execution.unit_id.clone(),
                package_roots: execution.loader.package_roots.iter().cloned().collect(),
                fingerprint: unit
                    .loader
                    .get("go_reference_fingerprint")
                    .cloned()
                    .filter(|value| !value.is_empty()),
            })
        })
        .collect()
}

fn analysis_ledger_records(
    scan_id: &str,
    work: &[AnalysisWorkItem],
    plan: Option<&AnalysisPlan>,
) -> Vec<AnalysisUnitLedgerRecord> {
    work.iter()
        .map(|item| {
            let request = item.request.as_ref();
            let logical_unit_id = request
                .and_then(|request| request["unit_id"].as_str())
                .unwrap_or(item.unit_id.as_str());
            let unit = plan.and_then(|plan| plan.unit(logical_unit_id));
            let source_paths = request_paths(request, "source_paths");
            let mut context_paths = request_paths(request, "context_paths");
            if context_paths.is_empty() {
                context_paths = source_paths.clone();
            }
            let auxiliary_paths = request_paths(request, "auxiliary_paths");
            let contract_version = request
                .and_then(|request| request["contract_version"].as_str())
                .unwrap_or("depgraph-analysis-unit-legacy")
                .to_owned();
            let stage = request
                .and_then(|request| request["stage"].as_str())
                .unwrap_or("repository")
                .to_owned();
            let unit_root = request
                .and_then(|request| request["unit_root"].as_str())
                .or_else(|| unit.map(|unit| unit.unit_root.as_str()))
                .unwrap_or(".")
                .to_owned();
            let chunk_id = request
                .and_then(|request| request["chunk_id"].as_str())
                .unwrap_or("")
                .to_owned();
            let chunk_index = request.and_then(|request| request["chunk_index"].as_u64());
            let chunk_count = request.and_then(|request| request["chunk_count"].as_u64());
            let context_fingerprint = request
                .and_then(|request| request["context_fingerprint"].as_str())
                .map(ToOwned::to_owned);
            let input_fingerprint = request
                .and_then(|request| request["input_fingerprint"].as_str())
                .map(ToOwned::to_owned)
                .or_else(|| unit.map(|unit| unit.input_fingerprint.clone()));
            let dependency_ids = unit
                .map(|unit| unit.dependency_ids.clone())
                .unwrap_or_default();
            let unknown_dependencies = request
                .and_then(|request| request["unknown_dependencies"].as_bool())
                .unwrap_or_else(|| unit.is_some_and(|unit| unit.unknown_dependencies));
            AnalysisUnitLedgerRecord {
                scan_id: scan_id.to_owned(),
                contract_version,
                unit_id: logical_unit_id.to_owned(),
                adapter: item.spec.adapter.name().to_owned(),
                unit_root,
                stage,
                chunk_id,
                chunk_index,
                chunk_count,
                status: "queued".to_owned(),
                reused: false,
                source_paths,
                context_paths,
                auxiliary_paths,
                context_fingerprint,
                input_fingerprint,
                dependency_ids,
                unknown_dependencies,
                error: None,
            }
        })
        .collect()
}

fn request_paths(request: Option<&Value>, key: &str) -> Vec<String> {
    let mut paths = request
        .and_then(|request| request[key].as_array())
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    paths
}

fn analysis_contract_version(records: &[AnalysisUnitLedgerRecord]) -> &str {
    let mut contracts = records
        .iter()
        .map(|record| record.contract_version.as_str())
        .collect::<BTreeSet<_>>();
    if contracts.len() == 1 {
        contracts
            .pop_first()
            .unwrap_or("depgraph-analysis-unit-legacy")
    } else if contracts.is_empty() {
        "depgraph-analysis-unit-legacy"
    } else {
        "depgraph-analysis-unit-mixed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use depgraph_store::{CACHE_CONTRACT_VERSION, CacheKey};

    #[test]
    fn analysis_unit_failure_metadata_is_bounded_and_excludes_worker_stderr() {
        assert_eq!(
            analysis_unit_error_detail("worker failed\nexit code 1\t; stderr: raw\nworker output"),
            "worker failed exit code 1 "
        );
        let bounded = analysis_unit_error_detail(&"\u{754c}".repeat(16 * 1024));
        assert!(bounded.len() <= 16 * 1024);
        assert_eq!(bounded.len(), 16 * 1024 - 1);
        assert!(bounded.chars().all(|character| !character.is_control()));
    }

    #[test]
    fn worker_timeout_diagnostic_reports_only_the_last_safe_progress_phase() {
        let failure = ScanFailure::with_kind(
            AdapterKind::Web,
            concat!(
                "web worker failed: timed out; stderr: ",
                "depgraph-progress phase=typescript_definition_graph status=completed duration_ms=10\n",
                "depgraph-progress phase=typescript_dependency_graph status=started source_files=188\n",
                "untrusted trailing detail phase=/private/repository",
            )
            .to_owned(),
            WorkerFailureKind::Timeout,
        );

        assert_eq!(
            failure.diagnostic_message(),
            "worker-failure:web:timeout; last_progress_phase=typescript_dependency_graph"
        );
    }

    #[test]
    fn worker_phase_profile_accepts_only_completed_bounded_metrics() {
        let output = WorkerOutput {
            adapter: AdapterKind::Rust,
            events: Vec::new(),
            stderr: concat!(
                "depgraph-progress phase=rust_hir_vfs status=completed duration_ms=7 items=31 bytes=2048\n",
                "depgraph-progress phase=rust_hir_semantic status=started items=7600\n",
                "untrusted phase=repository_secret duration_ms=999\n",
            )
            .into(),
            stderr_truncated: false,
            error: None,
            failure_kind: None,
            security_violation: false,
            peak_memory_bytes: None,
        };

        assert_eq!(
            worker_phase_performance(&output)
                .into_iter()
                .map(|phase| (phase.phase, phase.duration_ms, phase.items, phase.bytes))
                .collect::<Vec<_>>(),
            vec![("rust_hir_vfs".into(), 7, 31, 2048)]
        );
    }

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
            attested_rust_sysroot: None,
        }
    }

    fn ingest_policy_fixture(store: &mut Store, scan_id: &str) -> Result<()> {
        let common = |event: &str, seq: u64| {
            json!({
                "event":event,
                "protocol_version":"1.0",
                "scan_id":scan_id,
                "adapter":"web",
                "adapter_version":"0.1.0",
                "seq":seq
            })
        };
        let mut profile = common("profile_declared", 1);
        profile["profile"] = json!({
            "id":"profile:production",
            "language":"web",
            "features":[],
            "environment":{"mode":"production"},
            "properties":{}
        });
        let mut source = common("node_upsert", 2);
        source["node"] = json!({
            "id":"file:ui",
            "kind":"file",
            "locator":"file://src/ui/page.ts",
            "display_name":"page.ts",
            "properties":{"path":"src/ui/page.ts","package_locator":"pkg:web"}
        });
        let mut target = common("node_upsert", 3);
        target["node"] = json!({
            "id":"file:data",
            "kind":"file",
            "locator":"file://src/data/internal.ts",
            "display_name":"internal.ts",
            "properties":{"path":"src/data/internal.ts","package_locator":"pkg:web"}
        });
        let evidence = json!([{
            "kind":"source",
            "extractor":"fixture",
            "extractor_version":"1",
            "path":"src/ui/page.ts",
            "start_line":1,
            "start_column":1,
            "end_line":1,
            "end_column":20,
            "properties":{}
        }]);
        let mut site = common("dependency_site", 4);
        site["site"] = json!({
            "id":"site:ui-data",
            "source":"file:ui",
            "kind":"import",
            "specifier":"../data/internal",
            "profile_id":"profile:production",
            "resolution_status":"resolved",
            "precision":"exact",
            "condition":{"op":"eq","key":"mode","value":"production"},
            "target_ids":["file:data"],
            "evidence":evidence
        });
        let mut edge = common("edge_upsert", 5);
        edge["edge"] = json!({
            "id":"edge:ui-data",
            "site_id":"site:ui-data",
            "source":"file:ui",
            "target":"file:data",
            "kind":"imports",
            "phase":"source",
            "environment":"server",
            "profile_id":"profile:production",
            "resolution_status":"resolved",
            "precision":"exact",
            "condition":{"op":"eq","key":"mode","value":"production"},
            "generated":false,
            "evidence":evidence
        });
        let coverage = json!({
            "profiles":1,
            "files_discovered":0,
            "files_analyzed":0,
            "files_skipped":0,
            "dependency_sites":1,
            "resolved":1,
            "candidates":0,
            "external":0,
            "unresolved":0,
            "unsupported_syntax":0,
            "project_code_executed":false,
            "completeness":["syntax-complete"],
            "reasons":[]
        });
        let mut profile_completed = common("profile_completed", 6);
        profile_completed["profile_id"] = json!("profile:production");
        profile_completed["coverage"] = coverage.clone();
        let mut completed = common("scan_completed", 7);
        completed["coverage"] = coverage;
        store.ingest_events(&[
            &profile,
            &source,
            &target,
            &site,
            &edge,
            &profile_completed,
            &completed,
        ])
    }

    fn policy_fixture_config() -> Result<Config> {
        let policy = serde_json::from_value(json!({
            "schema_version":"1.0",
            "rules":[{
                "id":"no-ui-data",
                "kind":"forbidden_dependency",
                "severity":"error",
                "source":{
                    "kind":"file","field":"path","match":"exact",
                    "value":"src/ui/page.ts","cardinality":"one",
                    "exclude":[],"scope":{"paths":[],"packages":[]}
                },
                "target":{
                    "kind":"file","field":"path","match":"exact",
                    "value":"src/data/internal.ts","cardinality":"one",
                    "exclude":[],"scope":{"paths":[],"packages":[]}
                },
                "profiles":{"include":[{"match":"exact","value":"profile:production"}],"exclude":[]},
                "condition":{"op":"eq","key":"mode","value":"production"},
                "precisions":["exact"],
                "resolution_statuses":["resolved"],
                "evidence":{"kinds":["source"],"minimum_spans":1,"primary_only":true}
            }],
            "suppressions":[]
        }))?;
        Ok(Config {
            policy,
            ..Config::default()
        })
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
            go_dependency_witness: crate::go_dependency_witness::compute_go_dependency_witness(
                root.path(),
                &[],
            ),
            symlink_proofs: Vec::new(),
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

    #[test]
    fn architecture_policy_failure_returns_result_and_does_not_promote() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut store = Store::open_in_memory()?;
        let scan_id = "architecture-policy-failure";
        store.start_scan(scan_id, root.path(), false)?;
        ingest_policy_fixture(&mut store, scan_id)?;

        let outcome = complete_scan(
            &mut store,
            scan_id,
            false,
            &policy_fixture_config()?,
            None,
            &CancellationToken::new(),
        )?;

        assert_eq!(
            outcome.status, "policy_failed",
            "diagnostics: {:?}",
            outcome.diagnostics
        );
        assert_eq!(outcome.exit_code, 1);
        let policy = outcome.policy.context("policy result")?;
        assert!(policy.snapshot_id.starts_with("snapshot:sha256:"));
        assert_eq!(policy.summary.errors, 1);
        assert_eq!(policy.violations[0].rule_id, "no-ui-data");
        assert_eq!(
            policy.violations[0].dependency_path[0].edge_id,
            "edge:ui-data"
        );
        assert_eq!(policy.violations[0].evidence[0].path, "src/ui/page.ts");
        assert!(store.snapshot_id_for_source("scan", scan_id)?.is_none());
        Ok(())
    }

    #[test]
    fn architecture_policy_warning_is_reported_and_promoted() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut store = Store::open_in_memory()?;
        let scan_id = "architecture-policy-warning";
        store.start_scan(scan_id, root.path(), false)?;
        ingest_policy_fixture(&mut store, scan_id)?;
        let mut config = policy_fixture_config()?;
        config.policy.rules[0].severity = crate::policy::PolicySeverity::Warning;

        let outcome = complete_scan(
            &mut store,
            scan_id,
            false,
            &config,
            None,
            &CancellationToken::new(),
        )?;

        assert_eq!(outcome.status, "completed");
        assert_eq!(outcome.exit_code, 0);
        let policy = outcome.policy.context("policy result")?;
        assert_eq!(policy.summary.warnings, 1);
        assert_eq!(
            store.snapshot_id_for_source("scan", scan_id)?.as_deref(),
            Some(policy.snapshot_id.as_str())
        );
        Ok(())
    }

    #[test]
    fn ambiguous_policy_selector_is_a_terminal_non_promoted_attempt() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut store = Store::open_in_memory()?;
        let scan_id = "architecture-policy-selector-error";
        store.start_scan(scan_id, root.path(), false)?;
        ingest_policy_fixture(&mut store, scan_id)?;
        let mut config = policy_fixture_config()?;
        config.policy.rules[0].source.value = "src/missing.ts".to_owned();

        let error = format!(
            "{:#}",
            complete_scan(
                &mut store,
                scan_id,
                false,
                &config,
                None,
                &CancellationToken::new(),
            )
            .unwrap_err()
        );

        assert!(error.contains("policy selector"));
        assert_eq!(store.scan(scan_id)?.context("scan")?.status, "failed");
        assert!(store.snapshot_id_for_source("scan", scan_id)?.is_none());
        Ok(())
    }

    #[test]
    fn cancellation_preempts_validation_failure_finalization() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut store = Store::open_in_memory()?;
        let scan_id = "cancelled-invalid-scan";
        store.start_scan(scan_id, root.path(), false)?;
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let outcome = complete_scan(
            &mut store,
            scan_id,
            false,
            &Config::default(),
            None,
            &cancellation,
        )?;

        assert_eq!(outcome.status, "cancelled");
        assert_eq!(outcome.exit_code, 3);
        assert_eq!(store.scan(scan_id)?.unwrap().status, "cancelled");
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
    async fn invalid_policy_identity_does_not_create_a_scan_attempt() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut store = Store::open_in_memory()?;
        let mut config = Config::default();
        config.policy.schema_version = "invalid".to_owned();

        let error = run_scan(&mut store, root.path().to_path_buf(), &config, false)
            .await
            .unwrap_err();

        assert!(
            format!("{error:#}").contains("failed to normalize health policy identity"),
            "unexpected scan error: {error:#}"
        );
        assert!(store.resolve_scan_id(None, true).is_err());
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
    async fn cancellation_preempts_validated_cache_hit_promotion() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let config = Config::default();
        let mut store = Store::open_in_memory()?;
        run_scan(&mut store, root.clone(), &config, false).await?;
        let current = store.current_snapshot_id()?.context("current snapshot")?;
        let profile_plan = plan_repository_profiles(&root, &config, None)?.plan;
        let cache_plan = match prepare_scan_cache(&root, &config, &[], None, &profile_plan.plan_id)
        {
            ScanCachePreparation::Ready(plan) => plan,
            ScanCachePreparation::Rejected(rejection) => {
                anyhow::bail!(
                    "cache preparation unexpectedly rejected: {}",
                    rejection.reason
                )
            }
        };
        let semantic_key = cache_plan.semantic.as_ref().context("semantic cache key")?;

        store.start_scan("cancelled-cache-hit", &root, false)?;
        let hit = store
            .lookup_scan_cache(&cache_plan.syntax, semantic_key, "cancelled-cache-hit")?
            .context("validated semantic cache hit")?;
        assert_eq!(hit.snapshot_id(), current);
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        assert!(
            promote_validated_scan_cache_hit_if_active(
                &mut store,
                "cancelled-cache-hit",
                &root,
                &cache_plan,
                &hit,
                &cancellation,
            )
            .is_none()
        );
        let cancelled = cancel_scan(&mut store, "cancelled-cache-hit")?;
        assert_eq!(cancelled.status, "cancelled");
        assert_eq!(
            store.current_snapshot_id()?.as_deref(),
            Some(current.as_str())
        );
        assert_eq!(
            store.snapshot_id_for_source("scan", "cancelled-cache-hit")?,
            None
        );
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_change_at_cache_hit_precommit_never_promotes() -> Result<()> {
        use std::{fs, os::unix::fs::symlink};

        let root = tempfile::tempdir()?;
        fs::write(root.path().join("CLAUDE.md"), "first\n")?;
        symlink("CLAUDE.md", root.path().join("WARP.md"))?;
        let root = root.path().canonicalize()?;
        let config = Config::default();
        let mut store = Store::open_in_memory()?;
        run_scan(&mut store, root.clone(), &config, false).await?;
        let current = store.current_snapshot_id()?.context("current snapshot")?;
        let profile_plan = plan_repository_profiles(&root, &config, None)?.plan;
        let cache_plan = match prepare_scan_cache(&root, &config, &[], None, &profile_plan.plan_id)
        {
            ScanCachePreparation::Ready(plan) => plan,
            ScanCachePreparation::Rejected(rejection) => {
                anyhow::bail!(
                    "cache preparation unexpectedly rejected: {}",
                    rejection.reason
                )
            }
        };
        let semantic_key = cache_plan.semantic.as_ref().context("semantic cache key")?;
        store.start_scan("changed-cache-hit", &root, false)?;
        let hit = store
            .lookup_scan_cache(&cache_plan.syntax, semantic_key, "changed-cache-hit")?
            .context("validated semantic cache hit")?;
        validate_scan_cache_hit_inputs(&root, &cache_plan).map_err(anyhow::Error::new)?;

        fs::write(root.join("CLAUDE.md"), "other\n")?;
        let promotion = promote_validated_scan_cache_hit_if_active(
            &mut store,
            "changed-cache-hit",
            &root,
            &cache_plan,
            &hit,
            &CancellationToken::new(),
        )
        .context("active promotion")?;
        let error = promotion.unwrap_err();
        assert!(error.downcast_ref::<CacheRejection>().is_some());
        assert_eq!(
            store.current_snapshot_id()?.as_deref(),
            Some(current.as_str())
        );
        assert_eq!(store.scan("changed-cache-hit")?.unwrap().status, "staging");
        assert_eq!(
            store.snapshot_id_for_source("scan", "changed-cache-hit")?,
            None
        );
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn repository_internal_document_symlink_preserves_graph_and_cache_hits() -> Result<()> {
        use std::{fs, os::unix::fs::symlink};

        let baseline_root = tempfile::tempdir()?;
        fs::write(baseline_root.path().join("CLAUDE.md"), "fixture\n")?;
        let linked_root = tempfile::tempdir()?;
        fs::write(linked_root.path().join("CLAUDE.md"), "fixture\n")?;
        symlink("CLAUDE.md", linked_root.path().join("WARP.md"))?;
        let mut store = Store::open_in_memory()?;

        let baseline = run_scan(
            &mut store,
            baseline_root.path().to_path_buf(),
            &Config::default(),
            false,
        )
        .await?;
        let linked_miss = run_scan(
            &mut store,
            linked_root.path().to_path_buf(),
            &Config::default(),
            false,
        )
        .await?;
        let linked_hit = run_scan(
            &mut store,
            linked_root.path().to_path_buf(),
            &Config::default(),
            false,
        )
        .await?;

        assert!(
            linked_miss
                .cache_events
                .iter()
                .any(|event| { event.layer == CacheLayer::Semantic && event.outcome == "stored" })
        );
        assert!(linked_hit.cache_events.iter().any(|event| {
            event.layer == CacheLayer::Semantic
                && event.outcome == "hit"
                && event.reason == "validated"
        }));
        assert!(!linked_hit.coverage.project_code_executed);
        let baseline_graph = store.load_snapshot(&baseline.scan_id)?;
        let linked_graph = store.load_snapshot(&linked_miss.scan_id)?;
        assert_eq!(baseline_graph.profiles, linked_graph.profiles);
        assert_eq!(baseline_graph.nodes, linked_graph.nodes);
        assert_eq!(baseline_graph.sites, linked_graph.sites);
        assert_eq!(baseline_graph.edges, linked_graph.edges);
        assert_eq!(baseline_graph.evidence, linked_graph.evidence);
        assert_eq!(baseline_graph.diagnostics, linked_graph.diagnostics);
        assert_eq!(baseline_graph.file_coverage, linked_graph.file_coverage);
        assert_eq!(baseline_graph.adapter_logs, linked_graph.adapter_logs);
        assert_eq!(baseline_graph.coverage, linked_graph.coverage);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_cache_hit_with_architecture_policy_uses_worker_rescan() -> Result<()> {
        use std::{fs, os::unix::fs::symlink};

        let root = tempfile::tempdir()?;
        fs::write(root.path().join("CLAUDE.md"), "fixture\n")?;
        symlink("CLAUDE.md", root.path().join("WARP.md"))?;
        let policy = serde_json::from_value(json!({
            "schema_version":"1.0",
            "rules":[{
                "id":"empty-forbidden-dependency",
                "kind":"forbidden_dependency",
                "severity":"warning",
                "source":{
                    "kind":"file","field":"path","match":"exact",
                    "value":"missing/source.rs","cardinality":"many",
                    "exclude":[],"scope":{"paths":[],"packages":[]}
                },
                "target":{
                    "kind":"file","field":"path","match":"exact",
                    "value":"missing/target.rs","cardinality":"many",
                    "exclude":[],"scope":{"paths":[],"packages":[]}
                },
                "profiles":{"include":[],"exclude":[]},
                "condition":{"op":"eq","key":"mode","value":"production"},
                "precisions":["exact"],
                "resolution_statuses":["resolved"],
                "evidence":{"kinds":["source"],"minimum_spans":1,"primary_only":true}
            }],
            "suppressions":[]
        }))?;
        let config = Config {
            policy,
            ..Config::default()
        };
        let mut store = Store::open_in_memory()?;

        run_scan(&mut store, root.path().to_path_buf(), &config, false).await?;
        let rescanned = run_scan(&mut store, root.path().to_path_buf(), &config, false).await?;

        assert_eq!(rescanned.status, "completed");
        assert!(rescanned.cache_events.iter().any(|event| {
            event.layer == CacheLayer::Semantic
                && event.outcome == "hit"
                && event.reason == "validated"
        }));
        assert_eq!(
            rescanned
                .cache_events
                .iter()
                .filter(|event| {
                    event.outcome == "reject"
                        && event.reason == "symlink-cache-hit-policy-requires-rescan"
                })
                .count(),
            2
        );
        assert!(!rescanned.coverage.project_code_executed);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn root_out_symlink_rejection_reports_only_its_relative_path() -> Result<()> {
        use std::{fs, os::unix::fs::symlink};

        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let target = outside.path().join("outside.md");
        fs::write(&target, "outside\n")?;
        symlink(&target, root.path().join("WARP.md"))?;
        let mut store = Store::open_in_memory()?;

        let outcome = run_scan(
            &mut store,
            root.path().to_path_buf(),
            &Config::default(),
            false,
        )
        .await?;

        assert_eq!(outcome.status, "completed");
        assert!(!outcome.coverage.project_code_executed);
        assert_eq!(
            outcome
                .cache_events
                .iter()
                .filter(|event| {
                    event.outcome == "reject" && event.reason == "symlink-target-outside-root"
                })
                .count(),
            2
        );
        let diagnostic = outcome
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "cache-input-rejected")
            .context("cache rejection diagnostic")?;
        assert_eq!(diagnostic.path.as_deref(), Some("WARP.md"));
        assert!(!diagnostic.message.contains(&target.display().to_string()));
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
            peak_memory_bytes: None,
        };

        assert!(
            ingest_worker_output(
                &mut store,
                "partial-scan",
                output,
                Some(&mut BTreeMap::new()),
                None,
                None,
                None,
            )
            .is_err()
        );
        let snapshot = store.load_snapshot("partial-scan")?;
        assert!(snapshot.nodes.iter().any(|node| node.id == "file:kept"));
        assert!(snapshot.edges.is_empty());
        Ok(())
    }

    #[test]
    fn failed_analysis_unit_store_transaction_does_not_leak_in_memory_deltas() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut store = Store::open_in_memory()?;
        store.start_scan("atomic-scan", root.path(), false)?;
        let common = |event: &str, seq: u64| {
            json!({
                "event":event,"protocol_version":"1.0","scan_id":"atomic-scan",
                "adapter":"go","adapter_version":"0.1.0","seq":seq
            })
        };
        let mut profile = common("profile_declared", 1);
        profile["profile"] = json!({
            "id":"go:atomic",
            "language":"go",
            "features":[],
            "environment":{},
            "properties":{
                "analysis_unit_contract": ANALYSIS_UNIT_WORKER_CONTRACT_VERSION,
                "analysis_unit_id":"atomic-unit",
                "analysis_stage":"syntax"
            }
        });
        let mut node = common("node_upsert", 2);
        node["node"] = json!({
            "id":"file:atomic",
            "kind":"file",
            "locator":"file://atomic.go",
            "properties":{}
        });
        let mut invalid_edge = common("edge_upsert", 3);
        invalid_edge["edge"] = json!({
            "id":"edge:atomic-orphan",
            "site_id":"site:missing",
            "source":"file:atomic",
            "target":"file:missing",
            "kind":"imports",
            "phase":"source",
            "environment":"host",
            "profile_id":"go:atomic",
            "resolution_status":"resolved",
            "precision":"exact",
            "condition":{"op":"all","conditions":[]},
            "generated":false,
            "evidence":[]
        });
        let mut file = common("file_completed", 4);
        file["path"] = json!("atomic.go");
        file["discovered_sites"] = json!(1);
        file["emitted_sites"] = json!(1);
        file["skipped_sites"] = json!(0);
        file["skipped"] = json!(false);
        let mut profile_completed = common("profile_completed", 5);
        profile_completed["profile_id"] = json!("go:atomic");
        profile_completed["coverage"] = json!({
            "profiles":1,"files_discovered":1,"files_analyzed":1,"files_skipped":0,
            "dependency_sites":0,"resolved":0,"candidates":0,"external":0,
            "unresolved":0,"unsupported_syntax":0,"project_code_executed":false,
            "completeness":["syntax-complete"],"reasons":[]
        });
        let mut scan_completed = common("scan_completed", 6);
        scan_completed["coverage"] = profile_completed["coverage"].clone();

        let output = WorkerOutput {
            adapter: AdapterKind::Go,
            events: vec![
                profile,
                node,
                invalid_edge,
                file,
                profile_completed,
                scan_completed,
            ],
            stderr: String::new(),
            stderr_truncated: false,
            error: None,
            failure_kind: None,
            security_violation: false,
            peak_memory_bytes: None,
        };
        let mut global_upserts = BTreeMap::new();
        let mut file_ledgers = BTreeMap::new();
        let mut unit_file_paths = AnalysisUnitFilePaths::new();
        let mut pending = PendingAnalysisUnitCompletions::new();
        assert!(
            ingest_worker_output(
                &mut store,
                "atomic-scan",
                output,
                Some(&mut global_upserts),
                Some(&mut file_ledgers),
                Some(&mut unit_file_paths),
                Some(&mut pending),
            )
            .is_err()
        );
        assert!(global_upserts.is_empty());
        assert!(file_ledgers.is_empty());
        assert!(unit_file_paths.is_empty());
        assert!(pending.is_empty());
        assert!(store.load_snapshot("atomic-scan")?.nodes.is_empty());
        assert!(store.load_snapshot("atomic-scan")?.file_coverage.is_empty());
        Ok(())
    }

    #[test]
    fn analysis_unit_file_ledgers_merge_by_path_and_keep_legacy_coverage() -> Result<()> {
        let unit_events = |stage: &str, discovered: u64, emitted: u64, skipped: u64| {
            vec![
                json!({
                    "event": "profile_declared",
                    "profile": {"properties": {
                        "analysis_unit_contract": ANALYSIS_UNIT_WORKER_CONTRACT_VERSION,
                        "analysis_stage": stage,
                    }}
                }),
                json!({
                    "event": "file_completed",
                    "path": "main.go",
                    "discovered_sites": discovered,
                    "emitted_sites": emitted,
                    "skipped_sites": skipped,
                    "skipped": skipped > 0,
                }),
                json!({
                    "event": "scan_completed",
                    "coverage": {
                        "files_discovered": 1,
                        "files_analyzed": if skipped == 0 { 1 } else { 0 },
                        "files_skipped": if skipped > 0 { 1 } else { 0 },
                    }
                }),
            ]
        };

        let mut ledgers = BTreeMap::new();
        let mut syntax = unit_events("syntax", 2, 2, 0);
        merge_file_coverage_events(&mut syntax, AdapterKind::Go, &mut ledgers)?;
        assert_eq!(syntax[2]["coverage"]["files_discovered"], 1);
        assert_eq!(syntax[2]["coverage"]["files_analyzed"], 0);

        let mut semantic = unit_events("semantic", 3, 3, 0);
        merge_file_coverage_events(&mut semantic, AdapterKind::Go, &mut ledgers)?;
        assert_eq!(semantic[2]["coverage"]["files_discovered"], 0);
        assert_eq!(semantic[2]["coverage"]["files_analyzed"], 1);
        assert_eq!(semantic[1]["discovered_sites"], 5);
        assert_eq!(semantic[1]["emitted_sites"], 5);

        let mut legacy = vec![
            json!({
                "event": "profile_declared",
                "profile": {"properties": {}}
            }),
            json!({
                "event": "file_completed",
                "path": "main.go",
                "discovered_sites": 2,
                "emitted_sites": 1,
                "skipped_sites": 1,
                "skipped": true,
                "reason": "legacy",
            }),
            json!({
                "event": "scan_completed",
                "coverage": {"files_discovered": 4, "files_analyzed": 2, "files_skipped": 2}
            }),
        ];
        let before = legacy.clone();
        merge_file_coverage_events(&mut legacy, AdapterKind::Go, &mut ledgers)?;
        assert_eq!(legacy, before);
        Ok(())
    }

    #[test]
    fn analysis_unit_stage_join_adds_semantic_completeness_only_after_both_stages() -> Result<()> {
        let root = tempfile::tempdir()?;
        let common = |event: &str, scan_id: &str, seq: u64| {
            json!({
                "event": event,
                "protocol_version": "1.0",
                "scan_id": scan_id,
                "adapter": "go",
                "adapter_version": "0.5.4",
                "seq": seq,
            })
        };
        let completion = |scan_id: &str, profile_id: &str, event: &str, completeness: Value| {
            let mut value = common(
                event,
                scan_id,
                if event == "profile_completed" { 1 } else { 2 },
            );
            if event == "profile_completed" {
                value["profile_id"] = json!(profile_id);
            }
            let reasons = if profile_id == "profile:syntax" {
                json!(["go-packages-parser-fallback"])
            } else {
                json!([])
            };
            value["coverage"] = json!({
                "profiles": 1,
                "files_discovered": 9,
                "files_analyzed": 9,
                "files_skipped": 0,
                "dependency_sites": 0,
                "resolved": 0,
                "candidates": 0,
                "external": 0,
                "unresolved": 0,
                "unsupported_syntax": 0,
                "project_code_executed": false,
                "completeness": completeness,
                "reasons": reasons,
            });
            value
        };

        let mut store = Store::open_in_memory()?;
        store.start_scan("joined", root.path(), false)?;
        let profile_declared = |scan_id: &str, id: &str, stage: &str, seq: u64| {
            let mut value = common("profile_declared", scan_id, seq);
            value["profile"] = json!({
                "id": id,
                "language": "go",
                "features": [],
                "environment": {},
                "properties": {
                    "analysis_unit_contract": ANALYSIS_UNIT_WORKER_CONTRACT_VERSION,
                    "analysis_unit_id": "unit",
                    "analysis_stage": stage,
                },
            });
            value
        };
        let joined_syntax_profile = profile_declared("joined", "profile:syntax", "syntax", 1);
        let joined_semantic_profile = profile_declared("joined", "profile:semantic", "semantic", 2);
        store.ingest_events(&[&joined_syntax_profile, &joined_semantic_profile])?;
        let mut file = common("file_completed", "joined", 3);
        file["path"] = json!("main.go");
        file["discovered_sites"] = json!(0);
        file["emitted_sites"] = json!(0);
        file["skipped_sites"] = json!(0);
        file["skipped"] = json!(false);
        store.ingest_event(&file)?;
        let mut pending = PendingAnalysisUnitCompletions::new();
        pending.insert(
            (AdapterKind::Go, "unit".to_owned(), "syntax".to_owned()),
            vec![
                completion(
                    "joined",
                    "profile:syntax",
                    "profile_completed",
                    json!(["syntax-complete"]),
                ),
                completion(
                    "joined",
                    "profile:syntax",
                    "scan_completed",
                    json!(["syntax-complete"]),
                ),
            ],
        );
        pending.insert(
            (AdapterKind::Go, "unit".to_owned(), "semantic".to_owned()),
            vec![
                completion(
                    "joined",
                    "profile:semantic",
                    "profile_completed",
                    json!(["syntax-complete", "semantic-complete"]),
                ),
                completion(
                    "joined",
                    "profile:semantic",
                    "scan_completed",
                    json!(["syntax-complete", "semantic-complete"]),
                ),
            ],
        );
        let mut unit_file_paths = AnalysisUnitFilePaths::new();
        unit_file_paths
            .entry((AdapterKind::Go, "unit".to_owned()))
            .or_default()
            .insert("main.go".to_owned());
        let mut ledgers = BTreeMap::new();
        ledgers.insert(
            ("go".to_owned(), "main.go".to_owned()),
            FileCoverageLedger {
                discovered_sites: 0,
                emitted_sites: 0,
                skipped_sites: 0,
                skipped: false,
                reason: None,
            },
        );
        assert_eq!(
            unit_file_counts(AdapterKind::Go, "unit", &unit_file_paths, &ledgers),
            (1, 1, 0)
        );
        finalize_analysis_unit_completions(
            &mut store,
            &mut pending,
            &unit_file_paths,
            &ledgers,
            true,
        )?;
        let snapshot = store.load_snapshot("joined")?;
        assert_eq!(snapshot.coverage.files_discovered, 1);
        assert_eq!(snapshot.coverage.files_analyzed, 1);
        assert!(
            snapshot
                .coverage
                .completeness
                .iter()
                .any(|level| level == "semantic-complete")
        );
        let syntax_profile = snapshot
            .profiles
            .iter()
            .find(|profile| profile.id == "profile:syntax")
            .and_then(|profile| profile.coverage.as_ref())
            .context("joined syntax profile coverage was not stored")?;
        assert!(
            !syntax_profile
                .completeness
                .iter()
                .any(|level| level == "semantic-complete")
        );
        assert!(
            syntax_profile
                .reasons
                .iter()
                .any(|reason| reason == "go-packages-parser-fallback")
        );
        assert!(
            !snapshot
                .coverage
                .reasons
                .iter()
                .any(|reason| reason == "go-packages-parser-fallback")
        );

        let mut failed_store = Store::open_in_memory()?;
        failed_store.start_scan("failed", root.path(), false)?;
        let mut failed_file = common("file_completed", "failed", 3);
        failed_file["path"] = json!("main.go");
        failed_file["discovered_sites"] = json!(0);
        failed_file["emitted_sites"] = json!(0);
        failed_file["skipped_sites"] = json!(0);
        failed_file["skipped"] = json!(false);
        failed_store.ingest_event(&failed_file)?;
        let mut failed_pending = PendingAnalysisUnitCompletions::new();
        failed_pending.insert(
            (AdapterKind::Go, "unit".to_owned(), "syntax".to_owned()),
            vec![
                completion(
                    "failed",
                    "profile:syntax",
                    "profile_completed",
                    json!(["syntax-complete"]),
                ),
                completion(
                    "failed",
                    "profile:syntax",
                    "scan_completed",
                    json!(["syntax-complete"]),
                ),
            ],
        );
        failed_pending.insert(
            (AdapterKind::Go, "unit".to_owned(), "semantic".to_owned()),
            vec![
                completion(
                    "failed",
                    "profile:semantic",
                    "profile_completed",
                    json!(["syntax-complete", "semantic-complete"]),
                ),
                completion(
                    "failed",
                    "profile:semantic",
                    "scan_completed",
                    json!(["syntax-complete", "semantic-complete"]),
                ),
            ],
        );
        finalize_analysis_unit_completions(
            &mut failed_store,
            &mut failed_pending,
            &unit_file_paths,
            &ledgers,
            false,
        )?;
        let failed_snapshot = failed_store.load_snapshot("failed")?;
        assert!(
            !failed_snapshot
                .coverage
                .completeness
                .iter()
                .any(|level| level == "semantic-complete")
        );
        Ok(())
    }

    #[test]
    fn worker_profiles_are_bound_to_one_validated_selection_plan() -> Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::write(root.path().join("main.go"), "package main\n")?;
        let plan = plan_repository_profiles(root.path(), &Config::default(), None)?.plan;
        let output = WorkerOutput {
            adapter: AdapterKind::Go,
            events: vec![json!({
                "event":"profile_declared",
                "profile":{
                    "id":"go:test",
                    "language":"go",
                    "features":[],
                    "environment":{},
                    "properties":{}
                }
            })],
            stderr: String::new(),
            stderr_truncated: false,
            error: None,
            failure_kind: None,
            security_violation: false,
            peak_memory_bytes: None,
        };
        let bound = bind_worker_output_to_profile_plan(output, &plan)?;
        let properties = &bound.events[0]["profile"]["properties"];
        assert_eq!(properties["profile_selection_plan_id"], plan.plan_id);
        assert_eq!(
            properties["profile_selection_input_digest"],
            plan.input_digest
        );
        assert_eq!(properties["profile_selection_mode"], "automatic");
        assert_eq!(
            properties["profile_selection_complete"],
            plan.summary.selection_complete
        );
        assert_eq!(
            properties["profile_selection_selected_profile_ids"],
            serde_json::to_value(
                plan.selected
                    .iter()
                    .map(|entry| &entry.profile_id)
                    .collect::<Vec<_>>()
            )?
        );

        let null_properties = WorkerOutput {
            adapter: AdapterKind::Go,
            events: vec![json!({
                "event":"profile_declared",
                "profile":{
                    "id":"go:test",
                    "language":"go",
                    "features":[],
                    "environment":{},
                    "properties":null
                }
            })],
            stderr: String::new(),
            stderr_truncated: false,
            error: None,
            failure_kind: None,
            security_violation: false,
            peak_memory_bytes: None,
        };
        let bound = bind_worker_output_to_profile_plan(null_properties, &plan)?;
        assert_eq!(
            bound.events[0]["profile"]["properties"]["profile_selection_plan_id"],
            plan.plan_id
        );

        let collision = WorkerOutput {
            adapter: AdapterKind::Go,
            events: vec![json!({
                "event":"profile_declared",
                "profile":{
                    "id":"go:test",
                    "language":"go",
                    "features":[],
                    "environment":{},
                    "properties":{"profile_selection_plan_id":"forged"}
                }
            })],
            stderr: String::new(),
            stderr_truncated: false,
            error: None,
            failure_kind: None,
            security_violation: false,
            peak_memory_bytes: None,
        };
        let mut failures = Vec::new();
        assert!(
            bind_worker_outputs_to_profile_plan(vec![collision], &plan, &mut failures).is_empty()
        );
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].kind, WorkerFailureKind::MalformedProtocol);
        assert!(
            failures[0]
                .detail
                .contains("reserved profile-selection metadata")
        );
        Ok(())
    }
}
