use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use depgraph_store::{
    CacheEntryCounts, CacheEventRecord, CacheLayer, CoverageRecord, DiagnosticRecord,
    DiagnosticSummaryRecord, FileCoverageRecord, FileCoverageSummaryRecord, PhaseCoverageRecord,
    ProfileAxisConflictRecord, ProfileMatrixEntryRecord, ProfileMatrixRecord, ProfileRecord,
};
use serde::Serialize;

use crate::{
    CancellationToken, CompilerPackAvailabilityHealth, CompilerPreciseHealth,
    CompilerPreciseProfileHealth, Config, DAEMON_STATUS_SCHEMA_VERSION, DaemonPhase, DaemonStatus,
    DepgraphCapability, DoctorReport, DoctorSummaryReport, ReleaseHealth,
    RepositoryProfilePlanPreview, ScanHealth, ScanHealthSummary, WorkerHealth,
    compiler_pack_availability, doctor_cancellable, doctor_for_root_cancellable,
    doctor_summary_cancellable, doctor_summary_for_root_cancellable,
    parse_explicit_profile_selection_file, plan_explicit_profile_selection,
    plan_repository_profiles, start_repository_daemon,
    validate_explicit_profile_selection_capabilities,
};

use crate::service::{
    DepgraphService, DepgraphServiceError, DepgraphServiceResult, RepositoryFileError,
    RepositoryRelativePath,
};

const MAX_DOCTOR_ITEMS: usize = 1_024;
const MAX_DOCTOR_FILE_COVERAGE_ITEMS: usize = 1_000_000;

/// Bounded profile-plan input. An explicit document and an explicit file are mutually exclusive,
/// and either explicit source is mutually exclusive with an automatic profile budget.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProfilePlanRequest {
    pub profile_budget: Option<u32>,
    pub profiles_document: Option<String>,
    pub profiles_file: Option<RepositoryRelativePath>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DoctorRequest {
    pub details: bool,
    pub use_service_root: bool,
    pub compiler_pack_requirement: Option<PathBuf>,
}

/// Closed doctor projection shared by CLI and MCP frontends.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorResponse {
    report_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail_command: Option<&'static str>,
    diagnostic_root_source: &'static str,
    protocol_version: &'static str,
    graph_schema_version: &'static str,
    store_schema_version: i64,
    cache_contract_version: u32,
    cache_entries: CacheEntryCounts,
    impact_query_cache_contract_version: u32,
    impact_query_cache_entries: u64,
    recent_cache_events: Vec<DoctorCacheEvent>,
    toolchains: Vec<DoctorNamedValue>,
    supported_baselines: Vec<DoctorNamedValue>,
    workers: Vec<DoctorWorker>,
    compiler_pack: DoctorCompilerPack,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_attempt: Option<DoctorAttempt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_successful_scan_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    release: Option<DoctorRelease>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorCacheEvent {
    layer: CacheLayer,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_key: Option<String>,
    outcome: String,
    reason: String,
    created_at: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorWorker {
    adapter: String,
    available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    integrity: String,
    root_launch_allowed: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorNamedValue {
    name: String,
    value: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorNamedCount {
    name: String,
    count: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorCompilerPack {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    archive_asset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    checksum_asset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requirement_asset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    smoke_asset: Option<String>,
    release_page: &'static str,
    fallback_policy: &'static str,
    diagnostic: &'static str,
    remediation: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorAttempt {
    scan_id: String,
    status: String,
    project_code_executed: bool,
    coverage: DoctorCoverage,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profiles_by_language: Option<Vec<DoctorNamedCount>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_instance_count: Option<u64>,
    file_coverage: Vec<DoctorFileCoverage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic_summary: Option<DoctorDiagnosticSummary>,
    profiles: Vec<DoctorProfile>,
    diagnostics: Vec<DoctorDiagnostic>,
    cache_events: Vec<DoctorCacheEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile_matrix: Option<DoctorProfileMatrix>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compiler_precise: Option<DoctorCompilerPrecise>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorFileCoverage {
    adapter: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    files: u64,
    skipped_files: u64,
    discovered_sites: u64,
    emitted_sites: u64,
    skipped_sites: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorProfile {
    id: String,
    language: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    features: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    coverage: Option<DoctorCoverage>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorProfileMatrix {
    schema_version: String,
    entries: Vec<DoctorProfileMatrixEntry>,
    phase_coverage: DoctorPhaseCoverageByPhase,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorProfileMatrixEntry {
    id: String,
    effective_input_id: String,
    language: String,
    profile_ids: Vec<String>,
    parent_profile_ids: Vec<String>,
    phases: Vec<String>,
    phase_coverage: DoctorPhaseCoverageByPhase,
    selection_reasons: Vec<String>,
    axis_conflicts: Vec<DoctorProfileAxisConflict>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorPhaseCoverageByPhase {
    #[serde(rename = "static", skip_serializing_if = "Option::is_none")]
    static_phase: Option<DoctorPhaseCoverage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    build: Option<DoctorPhaseCoverage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime: Option<DoctorPhaseCoverage>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorPhaseCoverage {
    profile_ids: Vec<String>,
    sites: u64,
    edges: u64,
    evidence: u64,
    resolved: u64,
    candidates: u64,
    external: u64,
    unresolved: u64,
    completeness: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorProfileAxisConflict {
    profile_id: String,
    parent_profile_id: String,
    fields: Vec<String>,
    diagnostic_id: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorCoverage {
    profiles: u64,
    files_discovered: u64,
    files_analyzed: u64,
    files_skipped: u64,
    dependency_sites: u64,
    resolved: u64,
    candidates: u64,
    external: u64,
    unresolved: u64,
    unsupported_syntax: u64,
    project_code_executed: bool,
    completeness: Vec<String>,
    reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorDiagnosticSummary {
    total: u64,
    groups: Vec<DoctorDiagnosticGroup>,
    omitted_groups: u64,
    omitted_diagnostics: u64,
    samples: Vec<DoctorDiagnosticSample>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorDiagnosticGroup {
    severity: String,
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    adapter: Option<String>,
    count: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorDiagnosticSample {
    id: String,
    severity: String,
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    adapter: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorDiagnostic {
    id: String,
    severity: String,
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    adapter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_column: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_column: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorCompilerPrecise {
    status: String,
    phase: String,
    precision: String,
    profiles: Vec<DoctorCompilerPreciseProfile>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorCompilerPreciseProfile {
    profile_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compiler_pack_manifest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unit_graph_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    invocation_ledger_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mir_ledger_digest: Option<String>,
    cargo_units: u64,
    typed_mir_bodies: u64,
    compiler_instances: u64,
    compiler_calls: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct DoctorRelease {
    version: String,
    target: String,
    schema_version: String,
    compatibility_integrity: String,
    license_expression: String,
    core_integrity: String,
    schema_integrity: String,
}

impl DepgraphService {
    pub fn profile_plan_cancellable(
        &self,
        request: &ProfilePlanRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<RepositoryProfilePlanPreview> {
        check_cancellation(cancellation)?;
        let explicit_sources = usize::from(request.profiles_document.is_some())
            + usize::from(request.profiles_file.is_some());
        if explicit_sources > 1 || (explicit_sources == 1 && request.profile_budget.is_some()) {
            return Err(DepgraphServiceError::InvalidInput);
        }
        if request.profiles_document.as_ref().is_some_and(|document| {
            document.len() > self.config().limits().max_inline_input_bytes()
        }) {
            return Err(DepgraphServiceError::ResourceExhausted);
        }

        let root = self.config().canonical_root();
        let config = Config::load(root).map_err(DepgraphServiceError::profile_plan)?;
        check_cancellation(cancellation)?;
        // Repository profile planning is static inventory analysis. It never locates or starts a
        // worker, invokes a compiler, or executes project code.
        let mut preview = plan_repository_profiles(root, &config, request.profile_budget)
            .map_err(DepgraphServiceError::profile_plan)?;
        check_cancellation(cancellation)?;

        let explicit = match (&request.profiles_document, &request.profiles_file) {
            (Some(document), None) => Some(
                parse_explicit_profile_selection_file(document)
                    .map_err(DepgraphServiceError::profile_plan)?,
            ),
            (None, Some(path)) => {
                let mut file =
                    self.open_normalized_repository_input(path)
                        .map_err(|error| match error {
                            DepgraphServiceError::RepositoryFile {
                                reason:
                                    RepositoryFileError::BoundaryViolation
                                    | RepositoryFileError::NotRegular,
                            } => DepgraphServiceError::profile_plan_security(anyhow::anyhow!(
                                "unsafe explicit profiles file"
                            )),
                            other => other,
                        })?;
                let bytes =
                    read_bounded(&mut file, self.config().limits().max_inline_input_bytes())?;
                let document = std::str::from_utf8(&bytes).map_err(|_| {
                    DepgraphServiceError::profile_plan_security(anyhow::anyhow!(
                        "unsafe explicit profiles file: input is not UTF-8"
                    ))
                })?;
                Some(
                    parse_explicit_profile_selection_file(document)
                        .map_err(DepgraphServiceError::profile_plan)?,
                )
            }
            (None, None) => None,
            (Some(_), Some(_)) => unreachable!("mutual exclusion was checked"),
        };
        if let Some(explicit) = explicit {
            validate_explicit_profile_selection_capabilities(&preview.plan, &explicit)
                .map_err(DepgraphServiceError::profile_plan)?;
            preview.plan = plan_explicit_profile_selection(preview.plan.input, explicit)
                .map_err(DepgraphServiceError::profile_plan)?;
        }
        check_cancellation(cancellation)?;
        ensure_output_bound(&preview, self.config().limits().max_output_bytes())?;
        Ok(preview)
    }

    /// Reads the published daemon status file. The store and daemon process are
    /// never opened; on Windows only, a missing file is correlated with the
    /// lifecycle lock to bridge the bounded replace visibility gap.
    pub fn daemon_status_cancellable(
        &self,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<DaemonStatus> {
        check_cancellation(cancellation)?;
        let path = status_path(self.config().store_path());
        let mut file =
            open_daemon_status_file_with_platform_gap(self, &path, cancellation, cfg!(windows))?;
        let bytes = read_bounded(&mut file, self.config().limits().max_output_bytes())?;
        let status =
            serde_json::from_slice(&bytes).map_err(|_| DepgraphServiceError::InvalidInput)?;
        check_cancellation(cancellation)?;
        Ok(status)
    }

    /// Run the foreground daemon lifecycle owned by the calling process. The
    /// initial running status is atomically published only after both daemon
    /// locks are held. Cancellation requests graceful shutdown and this method
    /// returns only after stopped publication and control-file cleanup.
    pub async fn daemon_start_foreground_cancellable(
        &self,
        strict: bool,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<DaemonStatus> {
        self.daemon_start_foreground_with_running_cancellable(strict, cancellation, || {})
            .await
    }

    /// Variant used by frontends that must emit a one-time acknowledgement
    /// after running publication but before entering the foreground wait.
    pub async fn daemon_start_foreground_with_running_cancellable(
        &self,
        strict: bool,
        cancellation: &CancellationToken,
        on_running: impl FnOnce(),
    ) -> DepgraphServiceResult<DaemonStatus> {
        self.require_daemon_control()?;
        check_cancellation(cancellation)?;
        self.validate_daemon_root()?;
        match self.daemon_running_cancellable(cancellation) {
            Ok(true) => return Err(DepgraphServiceError::Conflict),
            Ok(false) | Err(DepgraphServiceError::NotFound) => {}
            Err(DepgraphServiceError::Conflict) => {
                let stale = read_daemon_status(
                    self,
                    &status_path(self.config().store_path()),
                    cancellation,
                )?;
                if stale.phase == DaemonPhase::Stopped
                    || daemon_lock_is_held(self.config().store_path())?
                {
                    return Err(DepgraphServiceError::Conflict);
                }
            }
            Err(error) => return Err(error),
        }
        let config = Config::load(self.config().canonical_root())
            .map_err(|_| DepgraphServiceError::InvalidInput)?;
        check_cancellation(cancellation)?;
        let handle = start_repository_daemon(
            self.config().canonical_root().to_path_buf(),
            self.config().store_path().to_path_buf(),
            config,
            strict,
        )
        .map_err(|_| DepgraphServiceError::Conflict)?;
        let stop_path = daemon_stop_path(self.config().store_path());
        let status_path = status_path(self.config().store_path());
        let mut status = handle.subscribe();
        let mut lifecycle_error = remove_daemon_control_file(&stop_path).err();
        if lifecycle_error.is_none() {
            if let Err(error) = write_daemon_status(&status_path, &handle.status()) {
                lifecycle_error = Some(error);
            } else {
                on_running();
                let mut stop_poll = tokio::time::interval(Duration::from_millis(100));
                loop {
                    tokio::select! {
                        () = cancellation.cancelled() => break,
                        changed = status.changed() => {
                            if changed.is_err() {
                                break;
                            }
                            if let Err(error) = write_daemon_status(&status_path, &status.borrow().clone()) {
                                lifecycle_error = Some(error);
                                break;
                            }
                        }
                        _ = stop_poll.tick() => {
                            match daemon_control_file_exists(&stop_path) {
                                Ok(true) => break,
                                Ok(false) => {}
                                Err(error) => {
                                    lifecycle_error = Some(error);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        let stopped = handle
            .stop()
            .await
            .map_err(|_| DepgraphServiceError::Internal);
        if let Ok(stopped) = &stopped {
            if let Err(error) = write_daemon_status(&status_path, stopped) {
                lifecycle_error.get_or_insert(error);
            }
        } else {
            lifecycle_error.get_or_insert(DepgraphServiceError::Internal);
        }
        if let Err(error) = remove_daemon_control_file(&stop_path) {
            lifecycle_error.get_or_insert(error);
        }
        match daemon_lock_is_held(self.config().store_path()) {
            Ok(false) => {}
            Ok(true) => {
                lifecycle_error.get_or_insert(DepgraphServiceError::Integrity);
            }
            Err(error) => {
                lifecycle_error.get_or_insert(error);
            }
        }
        if let Some(error) = lifecycle_error {
            return Err(error);
        }
        stopped
    }

    /// Publish an idempotent stop request and wait for the foreground owner to
    /// finish every cleanup boundary. A stopped result is returned only after
    /// stopped status, stop-control removal, and lifecycle-lock release agree.
    pub async fn daemon_stop_cancellable(
        &self,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<DaemonStatus> {
        self.require_daemon_control()?;
        check_cancellation(cancellation)?;
        self.validate_daemon_root()?;
        let status_path = status_path(self.config().store_path());
        let stop_path = daemon_stop_path(self.config().store_path());
        let initial = read_daemon_status(self, &status_path, cancellation)?;
        if initial.phase == DaemonPhase::Stopped {
            if daemon_lock_is_held(self.config().store_path())? {
                return Err(DepgraphServiceError::Conflict);
            }
            remove_daemon_control_file(&stop_path)?;
            return Ok(initial);
        }
        if !daemon_lock_is_held(self.config().store_path())? {
            return Err(DepgraphServiceError::Conflict);
        }
        write_daemon_stop_request(&stop_path)?;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut poll = tokio::time::interval(Duration::from_millis(100));
        let mut unlocked_active_observations = 0_u8;
        loop {
            tokio::select! {
                () = cancellation.cancelled() => return Err(DepgraphServiceError::Cancelled),
                () = tokio::time::sleep_until(deadline) => {
                    return Err(DepgraphServiceError::ResourceExhausted);
                }
                _ = poll.tick() => {
                    let status = read_daemon_status(self, &status_path, cancellation)?;
                    let lock_held = daemon_lock_is_held(self.config().store_path())?;
                    if status.phase == DaemonPhase::Stopped {
                        if lock_held || daemon_control_file_exists(&stop_path)? {
                            continue;
                        }
                        return Ok(status);
                    }
                    if lock_held {
                        unlocked_active_observations = 0;
                    } else {
                        unlocked_active_observations = unlocked_active_observations.saturating_add(1);
                        if unlocked_active_observations >= 10 {
                            return Err(DepgraphServiceError::Conflict);
                        }
                    }
                }
            }
        }
    }

    /// Validate whether the bound repository has one published running daemon.
    /// An active status without lock ownership, or stopped status with a held
    /// lock, is contradictory durable state and fails closed.
    pub fn daemon_running_cancellable(
        &self,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<bool> {
        self.require_daemon_control()?;
        check_cancellation(cancellation)?;
        self.validate_daemon_root()?;
        let status =
            read_daemon_status(self, &status_path(self.config().store_path()), cancellation)?;
        let lock_held = daemon_lock_is_held(self.config().store_path())?;
        match status.phase {
            DaemonPhase::Stopped if !lock_held => Ok(false),
            DaemonPhase::Stopped => Err(DepgraphServiceError::Conflict),
            _ if lock_held && status.stopped_at.is_none() => Ok(true),
            _ => Err(DepgraphServiceError::Conflict),
        }
    }

    fn require_daemon_control(&self) -> DepgraphServiceResult<()> {
        for required in [
            DepgraphCapability::Read,
            DepgraphCapability::StoreWrite,
            DepgraphCapability::DaemonControl,
        ] {
            if !self.config().capabilities().contains(required) {
                return Err(DepgraphServiceError::CapabilityDenied { required });
            }
        }
        Ok(())
    }

    fn validate_daemon_root(&self) -> DepgraphServiceResult<()> {
        if self.config().repository_root_seal().matches_live_root() {
            Ok(())
        } else {
            Err(DepgraphServiceError::Integrity)
        }
    }

    pub fn doctor_cancellable(
        &self,
        request: &DoctorRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<DoctorResponse> {
        check_cancellation(cancellation)?;
        let response = std::thread::scope(|scope| {
            let worker = scope.spawn(|| -> DepgraphServiceResult<DoctorResponse> {
                let mut read_store = self.read_store_factory().open()?;
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| DepgraphServiceError::Internal)?;
                let compiler_pack =
                    compiler_pack_availability(request.compiler_pack_requirement.as_deref());
                check_cancellation(cancellation)?;
                if request.details {
                    let mut report = runtime
                        .block_on(async {
                            if request.use_service_root {
                                doctor_for_root_cancellable(
                                    read_store.store(),
                                    self.config().canonical_root(),
                                    cancellation,
                                )
                                .await
                            } else {
                                doctor_cancellable(read_store.store(), cancellation).await
                            }
                        })
                        .map_err(|error| map_doctor_error(error, cancellation))?;
                    report.compiler_pack = compiler_pack;
                    Ok(DoctorResponse::from_details(report))
                } else {
                    let mut report = runtime
                        .block_on(async {
                            if request.use_service_root {
                                doctor_summary_for_root_cancellable(
                                    read_store.store(),
                                    self.config().canonical_root(),
                                    cancellation,
                                )
                                .await
                            } else {
                                doctor_summary_cancellable(read_store.store(), cancellation).await
                            }
                        })
                        .map_err(|error| map_doctor_error(error, cancellation))?;
                    report.compiler_pack = compiler_pack;
                    Ok(DoctorResponse::from_summary(report))
                }
            });
            worker.join().map_err(|_| DepgraphServiceError::Internal)?
        })?;
        check_cancellation(cancellation)?;
        ensure_output_bound(&response, self.config().limits().max_output_bytes())?;
        Ok(response)
    }
}

impl DoctorResponse {
    fn from_summary(report: DoctorSummaryReport) -> Self {
        Self {
            report_kind: "summary",
            detail_command: Some(report.detail_command),
            diagnostic_root_source: report.diagnostic_root.source,
            protocol_version: report.protocol_version,
            graph_schema_version: report.graph_schema_version,
            store_schema_version: report.store_schema_version,
            cache_contract_version: report.cache_contract_version,
            cache_entries: report.cache_entries,
            impact_query_cache_contract_version: report.impact_query_cache_contract_version,
            impact_query_cache_entries: report.impact_query_cache_entries,
            recent_cache_events: project_cache_events(report.recent_cache_events),
            toolchains: project_text_map(report.toolchains),
            supported_baselines: project_text_map(report.supported_baselines),
            workers: report
                .workers
                .into_iter()
                .take(3)
                .map(DoctorWorker::from)
                .collect(),
            compiler_pack: DoctorCompilerPack::from(report.compiler_pack),
            latest_attempt: report.latest_attempt.map(DoctorAttempt::from_summary),
            latest_successful_scan_id: report.latest_successful_scan_id.map(safe_text),
            release: report.release.map(DoctorRelease::from),
        }
    }

    fn from_details(report: DoctorReport) -> Self {
        Self {
            report_kind: "details",
            detail_command: None,
            diagnostic_root_source: report.diagnostic_root.source,
            protocol_version: report.protocol_version,
            graph_schema_version: report.graph_schema_version,
            store_schema_version: report.store_schema_version,
            cache_contract_version: report.cache_contract_version,
            cache_entries: report.cache_entries,
            impact_query_cache_contract_version: report.impact_query_cache_contract_version,
            impact_query_cache_entries: report.impact_query_cache_entries,
            recent_cache_events: project_cache_events(report.recent_cache_events),
            toolchains: project_text_map(report.toolchains),
            supported_baselines: project_text_map(report.supported_baselines),
            workers: report
                .workers
                .into_iter()
                .take(3)
                .map(DoctorWorker::from)
                .collect(),
            compiler_pack: DoctorCompilerPack::from(report.compiler_pack),
            latest_attempt: report.latest_attempt.map(DoctorAttempt::from_details),
            latest_successful_scan_id: report.latest_successful_scan_id.map(safe_text),
            release: report.release.map(DoctorRelease::from),
        }
    }
}

impl From<WorkerHealth> for DoctorWorker {
    fn from(worker: WorkerHealth) -> Self {
        Self {
            adapter: safe_text(worker.adapter),
            available: worker.available,
            version: worker.version.map(safe_text),
            protocol: worker.protocol.map(safe_text),
            integrity: if worker.integrity.starts_with("error:") {
                "error".to_owned()
            } else {
                safe_text(worker.integrity)
            },
            root_launch_allowed: worker.root_launch_allowed,
        }
    }
}

impl From<CompilerPackAvailabilityHealth> for DoctorCompilerPack {
    fn from(health: CompilerPackAvailabilityHealth) -> Self {
        let (diagnostic, remediation) = match health.status.as_str() {
            "available" => (
                "the configured compiler pack is verified and available",
                "the compiler pack is ready for compiler-precise analysis",
            ),
            "unconfigured" => (
                "no compiler-pack requirement was supplied to doctor",
                "supply a verified compiler-pack requirement for this host",
            ),
            "unsupported-host" => (
                "no first-party compiler pack is published for this host",
                "use a supported compiler-pack host",
            ),
            _ => (
                "the compiler-pack requirement is unavailable or invalid",
                "supply a verified compiler-pack requirement for this host",
            ),
        };
        Self {
            status: safe_text(health.status),
            host_target: health.host_target.map(safe_text),
            manifest_sha256: health.manifest_sha256.map(safe_text),
            archive_asset: health.archive_asset.map(safe_text),
            checksum_asset: health.checksum_asset.map(safe_text),
            requirement_asset: health.requirement_asset.map(safe_text),
            smoke_asset: health.smoke_asset.map(safe_text),
            release_page: health.release_page,
            fallback_policy: health.fallback_policy,
            diagnostic,
            remediation,
        }
    }
}

impl DoctorAttempt {
    fn from_summary(summary: ScanHealthSummary) -> Self {
        Self {
            scan_id: safe_text(summary.scan_id),
            status: safe_text(summary.status),
            project_code_executed: summary.project_code_executed,
            coverage: DoctorCoverage::from(summary.coverage),
            profile_count: Some(summary.profile_count),
            profiles_by_language: Some(project_count_map(summary.profiles_by_language)),
            package_instance_count: Some(summary.package_instance_count),
            file_coverage: summary
                .file_coverage
                .into_iter()
                .take(MAX_DOCTOR_FILE_COVERAGE_ITEMS)
                .map(DoctorFileCoverage::from_summary)
                .collect(),
            diagnostic_summary: Some(DoctorDiagnosticSummary::from(summary.diagnostics)),
            profiles: Vec::new(),
            diagnostics: Vec::new(),
            cache_events: Vec::new(),
            profile_matrix: None,
            compiler_precise: None,
        }
    }

    fn from_details(details: ScanHealth) -> Self {
        Self {
            scan_id: safe_text(details.scan_id),
            status: safe_text(details.status),
            project_code_executed: details.project_code_executed,
            coverage: DoctorCoverage::from(details.coverage),
            profile_count: None,
            profiles_by_language: None,
            package_instance_count: None,
            file_coverage: details
                .file_coverage
                .into_iter()
                .take(MAX_DOCTOR_FILE_COVERAGE_ITEMS)
                .map(DoctorFileCoverage::from_details)
                .collect(),
            diagnostic_summary: None,
            profiles: details
                .profiles
                .into_iter()
                .take(MAX_DOCTOR_ITEMS)
                .map(DoctorProfile::from)
                .collect(),
            diagnostics: details
                .diagnostics
                .into_iter()
                .take(MAX_DOCTOR_ITEMS)
                .map(DoctorDiagnostic::from)
                .collect(),
            cache_events: project_cache_events(details.cache_events),
            profile_matrix: Some(DoctorProfileMatrix::from(details.profile_matrix)),
            compiler_precise: details.compiler_precise.map(DoctorCompilerPrecise::from),
        }
    }
}

impl DoctorFileCoverage {
    fn from_summary(coverage: FileCoverageSummaryRecord) -> Self {
        Self {
            adapter: safe_text(coverage.adapter),
            path: None,
            files: coverage.files,
            skipped_files: coverage.skipped_files,
            discovered_sites: coverage.discovered_sites,
            emitted_sites: coverage.emitted_sites,
            skipped_sites: coverage.skipped_sites,
        }
    }

    fn from_details(coverage: FileCoverageRecord) -> Self {
        Self {
            adapter: safe_text(coverage.adapter),
            path: safe_repository_path(&coverage.path),
            files: 1,
            skipped_files: u64::from(coverage.skipped),
            discovered_sites: coverage.discovered_sites,
            emitted_sites: coverage.emitted_sites,
            skipped_sites: coverage.skipped_sites,
        }
    }
}

impl From<ProfileRecord> for DoctorProfile {
    fn from(profile: ProfileRecord) -> Self {
        Self {
            id: safe_text(profile.id),
            language: safe_text(profile.language),
            target: profile.target.map(safe_text),
            features: profile
                .features
                .into_iter()
                .take(MAX_DOCTOR_ITEMS)
                .map(safe_text)
                .collect(),
            coverage: profile.coverage.map(DoctorCoverage::from),
        }
    }
}

impl From<ProfileMatrixRecord> for DoctorProfileMatrix {
    fn from(matrix: ProfileMatrixRecord) -> Self {
        Self {
            schema_version: safe_text(matrix.schema_version),
            entries: matrix
                .entries
                .into_iter()
                .take(MAX_DOCTOR_ITEMS)
                .map(DoctorProfileMatrixEntry::from)
                .collect(),
            phase_coverage: DoctorPhaseCoverageByPhase::from(matrix.phase_coverage),
        }
    }
}

impl From<ProfileMatrixEntryRecord> for DoctorProfileMatrixEntry {
    fn from(entry: ProfileMatrixEntryRecord) -> Self {
        Self {
            id: safe_text(entry.id),
            effective_input_id: safe_text(entry.effective_input_id),
            language: safe_text(entry.language),
            profile_ids: bounded_safe_text(entry.profile_ids),
            parent_profile_ids: bounded_safe_text(entry.parent_profile_ids),
            phases: bounded_safe_text(entry.phases),
            phase_coverage: DoctorPhaseCoverageByPhase::from(entry.phase_coverage),
            selection_reasons: bounded_safe_text(entry.selection_reasons),
            axis_conflicts: entry
                .axis_conflicts
                .into_iter()
                .take(MAX_DOCTOR_ITEMS)
                .map(DoctorProfileAxisConflict::from)
                .collect(),
        }
    }
}

impl From<BTreeMap<String, PhaseCoverageRecord>> for DoctorPhaseCoverageByPhase {
    fn from(mut coverage: BTreeMap<String, PhaseCoverageRecord>) -> Self {
        Self {
            static_phase: coverage.remove("static").map(DoctorPhaseCoverage::from),
            build: coverage.remove("build").map(DoctorPhaseCoverage::from),
            runtime: coverage.remove("runtime").map(DoctorPhaseCoverage::from),
        }
    }
}

impl From<PhaseCoverageRecord> for DoctorPhaseCoverage {
    fn from(coverage: PhaseCoverageRecord) -> Self {
        Self {
            profile_ids: bounded_safe_text(coverage.profile_ids),
            sites: coverage.sites,
            edges: coverage.edges,
            evidence: coverage.evidence,
            resolved: coverage.resolved,
            candidates: coverage.candidates,
            external: coverage.external,
            unresolved: coverage.unresolved,
            completeness: bounded_safe_text(coverage.completeness),
        }
    }
}

impl From<ProfileAxisConflictRecord> for DoctorProfileAxisConflict {
    fn from(conflict: ProfileAxisConflictRecord) -> Self {
        Self {
            profile_id: safe_text(conflict.profile_id),
            parent_profile_id: safe_text(conflict.parent_profile_id),
            fields: bounded_safe_text(conflict.fields),
            diagnostic_id: safe_text(conflict.diagnostic_id),
        }
    }
}

impl From<DiagnosticRecord> for DoctorDiagnostic {
    fn from(diagnostic: DiagnosticRecord) -> Self {
        Self {
            id: safe_text(diagnostic.id),
            severity: safe_text(diagnostic.severity),
            code: safe_text(diagnostic.code),
            path: diagnostic.path.as_deref().and_then(safe_repository_path),
            adapter: diagnostic.adapter.map(safe_text),
            start_line: diagnostic.start_line,
            start_column: diagnostic.start_column,
            end_line: diagnostic.end_line,
            end_column: diagnostic.end_column,
        }
    }
}

impl From<CoverageRecord> for DoctorCoverage {
    fn from(coverage: CoverageRecord) -> Self {
        Self {
            profiles: coverage.profiles,
            files_discovered: coverage.files_discovered,
            files_analyzed: coverage.files_analyzed,
            files_skipped: coverage.files_skipped,
            dependency_sites: coverage.dependency_sites,
            resolved: coverage.resolved,
            candidates: coverage.candidates,
            external: coverage.external,
            unresolved: coverage.unresolved,
            unsupported_syntax: coverage.unsupported_syntax,
            project_code_executed: coverage.project_code_executed,
            completeness: coverage
                .completeness
                .into_iter()
                .take(MAX_DOCTOR_ITEMS)
                .map(safe_text)
                .collect(),
            reasons: coverage
                .reasons
                .into_iter()
                .take(MAX_DOCTOR_ITEMS)
                .map(safe_text)
                .collect(),
        }
    }
}

impl From<DiagnosticSummaryRecord> for DoctorDiagnosticSummary {
    fn from(summary: DiagnosticSummaryRecord) -> Self {
        Self {
            total: summary.total,
            groups: summary
                .groups
                .into_iter()
                .take(64)
                .map(|group| DoctorDiagnosticGroup {
                    severity: safe_text(group.severity),
                    code: safe_text(group.code),
                    adapter: group.adapter.map(safe_text),
                    count: group.count,
                })
                .collect(),
            omitted_groups: summary.omitted_groups,
            omitted_diagnostics: summary.omitted_diagnostics,
            samples: summary
                .samples
                .into_iter()
                .take(5)
                .map(|sample| DoctorDiagnosticSample {
                    id: safe_text(sample.id),
                    severity: safe_text(sample.severity),
                    code: safe_text(sample.code),
                    path: sample.path.as_deref().and_then(safe_repository_path),
                    adapter: sample.adapter.map(safe_text),
                })
                .collect(),
        }
    }
}

impl From<CompilerPreciseHealth> for DoctorCompilerPrecise {
    fn from(health: CompilerPreciseHealth) -> Self {
        Self {
            status: safe_text(health.status),
            phase: safe_text(health.phase),
            precision: safe_text(health.precision),
            profiles: health
                .profiles
                .into_iter()
                .take(MAX_DOCTOR_ITEMS)
                .map(DoctorCompilerPreciseProfile::from)
                .collect(),
        }
    }
}

impl From<CompilerPreciseProfileHealth> for DoctorCompilerPreciseProfile {
    fn from(profile: CompilerPreciseProfileHealth) -> Self {
        Self {
            profile_id: safe_text(profile.profile_id),
            target: profile.target.map(safe_text),
            compiler_pack_manifest_sha256: profile.compiler_pack_manifest_sha256.map(safe_text),
            unit_graph_digest: profile.unit_graph_digest.map(safe_text),
            invocation_ledger_digest: profile.invocation_ledger_digest.map(safe_text),
            mir_ledger_digest: profile.mir_ledger_digest.map(safe_text),
            cargo_units: profile.cargo_units,
            typed_mir_bodies: profile.typed_mir_bodies,
            compiler_instances: profile.compiler_instances,
            compiler_calls: profile.compiler_calls,
        }
    }
}

impl From<ReleaseHealth> for DoctorRelease {
    fn from(release: ReleaseHealth) -> Self {
        Self {
            version: safe_text(release.version),
            target: safe_text(release.target),
            schema_version: safe_text(release.schema_version),
            compatibility_integrity: safe_text(release.compatibility_integrity),
            license_expression: safe_text(release.license_expression),
            core_integrity: safe_text(release.core_integrity),
            schema_integrity: safe_text(release.schema_integrity),
        }
    }
}

fn project_cache_events(events: Vec<CacheEventRecord>) -> Vec<DoctorCacheEvent> {
    events
        .into_iter()
        .take(MAX_DOCTOR_ITEMS)
        .map(|event| DoctorCacheEvent {
            layer: event.layer,
            cache_key: event.cache_key.map(safe_text),
            outcome: safe_text(event.outcome),
            reason: safe_text(event.reason),
            created_at: safe_text(event.created_at),
        })
        .collect()
}

fn project_text_map(values: BTreeMap<String, String>) -> Vec<DoctorNamedValue> {
    values
        .into_iter()
        .take(MAX_DOCTOR_ITEMS)
        .map(|(name, value)| DoctorNamedValue {
            name: safe_text(name),
            value: safe_text(value),
        })
        .collect()
}

fn project_count_map(values: BTreeMap<String, u64>) -> Vec<DoctorNamedCount> {
    values
        .into_iter()
        .take(MAX_DOCTOR_ITEMS)
        .map(|(name, count)| DoctorNamedCount {
            name: safe_text(name),
            count,
        })
        .collect()
}

fn bounded_safe_text(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .take(MAX_DOCTOR_ITEMS)
        .map(safe_text)
        .collect()
}

fn safe_repository_path(path: &str) -> Option<String> {
    RepositoryRelativePath::parse(path)
        .ok()
        .map(|path| path.as_str().to_owned())
}

fn safe_text(text: String) -> String {
    const REDACTED: &str = "[redacted]";
    if text.is_empty()
        || text.len() > 256
        || text.bytes().any(|byte| byte.is_ascii_control())
        || contains_absolute_path(&text)
        || contains_credential_shape(&text)
    {
        REDACTED.to_owned()
    } else {
        text
    }
}

fn contains_absolute_path(text: &str) -> bool {
    text.split(|character: char| {
        character.is_whitespace()
            || matches!(
                character,
                '"' | '\'' | '`' | '(' | ')' | '[' | ']' | ',' | ';' | '='
            )
    })
    .map(|part| part.trim_matches([':', '.']))
    .filter(|part| !part.is_empty())
    .any(|part| {
        Path::new(part).is_absolute()
            || part.starts_with("file:")
            || part.starts_with("\\\\")
            || (part.as_bytes().get(1) == Some(&b':')
                && part.as_bytes().first().is_some_and(u8::is_ascii_alphabetic))
    })
}

fn contains_credential_shape(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let trimmed = lower.trim_start();
    let auth_scheme = ["bearer ", "basic "].iter().any(|scheme| {
        trimmed.strip_prefix(scheme).is_some_and(|value| {
            value.len() >= 8
                && !value.chars().any(char::is_whitespace)
                && value.chars().all(|character| {
                    character.is_ascii_alphanumeric()
                        || matches!(character, '-' | '_' | '.' | '~' | '+' | '/' | '=')
                })
        })
    });
    if auth_scheme
        || ["ghp_", "github_pat_", "glpat-", "xoxb-", "xoxp-", "sk-"]
            .iter()
            .any(|prefix| trimmed.starts_with(prefix))
    {
        return true;
    }

    let normalized = lower
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>();
    if [
        "authorization",
        "credential",
        "password",
        "passwd",
        "clientsecret",
        "secretaccesskey",
        "secretkey",
        "privatekey",
        "apikey",
        "accesskeyid",
        "authtoken",
        "accesstoken",
        "refreshtoken",
        "sessiontoken",
        "securitytoken",
    ]
    .iter()
    .any(|shape| normalized.contains(shape))
    {
        return true;
    }

    lower
        .split(|character: char| {
            character.is_whitespace() || matches!(character, ',' | ';' | '?' | '&' | '#')
        })
        .filter_map(|part| part.split_once('=').or_else(|| part.split_once(':')))
        .map(|(key, _)| {
            key.chars()
                .filter(char::is_ascii_alphanumeric)
                .collect::<String>()
        })
        .any(|key| {
            matches!(
                key.as_str(),
                "token" | "secret" | "auth" | "cookie" | "session"
            )
        })
}

fn check_cancellation(cancellation: &CancellationToken) -> DepgraphServiceResult<()> {
    if cancellation.is_cancelled() {
        Err(DepgraphServiceError::Cancelled)
    } else {
        Ok(())
    }
}

fn ensure_output_bound(value: &impl Serialize, maximum: usize) -> DepgraphServiceResult<()> {
    let mut writer = CountingWriter::new(maximum);
    serde_json::to_writer(&mut writer, value).map_err(|_| {
        if writer.exceeded {
            DepgraphServiceError::ResourceExhausted
        } else {
            DepgraphServiceError::Integrity
        }
    })
}

struct CountingWriter {
    maximum: usize,
    written: usize,
    exceeded: bool,
}

impl CountingWriter {
    const fn new(maximum: usize) -> Self {
        Self {
            maximum,
            written: 0,
            exceeded: false,
        }
    }
}

impl Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next = self.written.saturating_add(buffer.len());
        if next > self.maximum {
            self.exceeded = true;
            return Err(io::Error::other("serialized output exceeds limit"));
        }
        self.written = next;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn read_bounded(reader: &mut impl Read, maximum: usize) -> DepgraphServiceResult<Vec<u8>> {
    let limit = u64::try_from(maximum)
        .ok()
        .and_then(|maximum| maximum.checked_add(1))
        .ok_or(DepgraphServiceError::ResourceExhausted)?;
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| DepgraphServiceError::NotFound)?;
    if bytes.len() > maximum {
        return Err(DepgraphServiceError::ResourceExhausted);
    }
    Ok(bytes)
}

fn status_path(store: &Path) -> PathBuf {
    let mut path = store.as_os_str().to_os_string();
    path.push(".daemon-status.json");
    PathBuf::from(path)
}

fn daemon_stop_path(store: &Path) -> PathBuf {
    with_daemon_path_suffix(store, ".daemon-stop")
}

fn daemon_lock_path(store: &Path) -> PathBuf {
    with_daemon_path_suffix(store, ".daemon-lock")
}

fn with_daemon_path_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn read_daemon_status(
    service: &DepgraphService,
    path: &Path,
    cancellation: &CancellationToken,
) -> DepgraphServiceResult<DaemonStatus> {
    let mut file =
        open_daemon_status_file_with_platform_gap(service, path, cancellation, cfg!(windows))?;
    let bytes = read_bounded(&mut file, service.config().limits().max_output_bytes())?;
    let status: DaemonStatus =
        serde_json::from_slice(&bytes).map_err(|_| DepgraphServiceError::Integrity)?;
    if status.schema_version != DAEMON_STATUS_SCHEMA_VERSION
        || status.root != service.config().canonical_root().to_string_lossy()
        || (status.phase == DaemonPhase::Stopped) != status.stopped_at.is_some()
    {
        return Err(DepgraphServiceError::Integrity);
    }
    check_cancellation(cancellation)?;
    Ok(status)
}

fn open_daemon_status_file_with_platform_gap(
    service: &DepgraphService,
    path: &Path,
    cancellation: &CancellationToken,
    platform_has_replace_visibility_gap: bool,
) -> DepgraphServiceResult<File> {
    const RETRY_DEADLINE: Duration = Duration::from_secs(1);
    const RETRY_INTERVAL: Duration = Duration::from_millis(5);

    let deadline = std::time::Instant::now() + RETRY_DEADLINE;
    loop {
        check_cancellation(cancellation)?;
        match open_regular_file_no_follow(path) {
            Ok(file) => return Ok(file),
            Err(DepgraphServiceError::NotFound) if platform_has_replace_visibility_gap => {
                if !daemon_lock_is_held(service.config().store_path())?
                    || std::time::Instant::now() >= deadline
                {
                    return Err(DepgraphServiceError::NotFound);
                }
                std::thread::sleep(RETRY_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
}

fn daemon_lock_is_held(store: &Path) -> DepgraphServiceResult<bool> {
    let path = daemon_lock_path(store);
    let file = match open_regular_file_no_follow(&path) {
        Ok(file) => file,
        Err(DepgraphServiceError::NotFound) => return Ok(false),
        Err(error) => return Err(error),
    };
    match file.try_lock() {
        Ok(()) => Ok(false),
        Err(std::fs::TryLockError::WouldBlock) => Ok(true),
        Err(std::fs::TryLockError::Error(_)) => Err(DepgraphServiceError::Integrity),
    }
}

fn daemon_control_file_exists(path: &Path) -> DepgraphServiceResult<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(DepgraphServiceError::Integrity),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(DepgraphServiceError::Integrity),
    }
}

fn write_daemon_stop_request(path: &Path) -> DepgraphServiceResult<()> {
    if daemon_control_file_exists(path)? {
        return Ok(());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if daemon_control_file_exists(path)? {
                return Ok(());
            }
            return Err(DepgraphServiceError::Integrity);
        }
        Err(_) => return Err(DepgraphServiceError::Internal),
    };
    file.write_all(b"stop\n")
        .and_then(|()| file.sync_all())
        .map_err(|_| DepgraphServiceError::Internal)
}

fn remove_daemon_control_file(path: &Path) -> DepgraphServiceResult<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            std::fs::remove_file(path).map_err(|_| DepgraphServiceError::Internal)
        }
        Ok(_) => Err(DepgraphServiceError::Integrity),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(DepgraphServiceError::Integrity),
    }
}

fn write_daemon_status(path: &Path, status: &DaemonStatus) -> DepgraphServiceResult<()> {
    let parent = path.parent().ok_or(DepgraphServiceError::Integrity)?;
    std::fs::create_dir_all(parent).map_err(|_| DepgraphServiceError::Internal)?;
    let temporary = with_daemon_path_suffix(
        path,
        &format!(".tmp-{}-{}", std::process::id(), uuid::Uuid::new_v4()),
    );
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|_| DepgraphServiceError::Internal)?;
        serde_json::to_writer_pretty(&mut file, status)
            .map_err(|_| DepgraphServiceError::Integrity)?;
        file.write_all(b"\n")
            .and_then(|()| file.sync_all())
            .map_err(|_| DepgraphServiceError::Internal)?;
        drop(file);
        #[cfg(windows)]
        remove_daemon_control_file(path)?;
        std::fs::rename(&temporary, path).map_err(|_| DepgraphServiceError::Internal)?;
        #[cfg(unix)]
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| DepgraphServiceError::Internal)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn open_regular_file_no_follow(path: &Path) -> DepgraphServiceResult<File> {
    #[cfg(windows)]
    use std::os::windows::fs::MetadataExt as _;

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            DepgraphServiceError::NotFound
        } else {
            DepgraphServiceError::InvalidInput
        }
    })?;
    let metadata = file
        .metadata()
        .map_err(|_| DepgraphServiceError::NotFound)?;
    if !metadata.is_file() {
        return Err(DepgraphServiceError::InvalidInput);
    }
    #[cfg(windows)]
    if metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
    {
        return Err(DepgraphServiceError::InvalidInput);
    }
    Ok(file)
}

fn map_doctor_error(
    error: anyhow::Error,
    cancellation: &CancellationToken,
) -> DepgraphServiceError {
    if cancellation.is_cancelled() {
        DepgraphServiceError::Cancelled
    } else {
        DepgraphServiceError::store_operation(error)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write as _;

    use super::*;

    #[test]
    fn doctor_text_projection_rejects_paths_credentials_controls_and_wide_values() {
        for unsafe_value in [
            "/usr/bin/rustc",
            "failed to run /private/tmp/compiler",
            r"C:\\toolchain\\rustc.exe",
            "API_KEY=secret",
            "token=opaque-value",
            "Bearer opaque-value",
            "Basic dXNlcjpwYXNz",
            "AWS_SECRET_ACCESS_KEY=opaque-value",
            "AWS_ACCESS_KEY_ID=opaque-value",
            "github_pat_opaque-value",
            "https://api.example.invalid/v1?token=supersecret",
            "https://api.example.invalid/v1?mode=safe&secret=supersecret",
            "https://api.example.invalid/v1#auth=supersecret",
            "line\nbreak",
            &"x".repeat(4_097),
        ] {
            assert_eq!(safe_text(unsafe_value.to_owned()), "[redacted]");
        }
        for safe_value in [
            "rustc 1.93.1",
            "tokenizer fallback",
            "basic profile",
            "https://api.example.invalid/v1?mode=safe&tokenizer=fallback",
        ] {
            assert_eq!(safe_text(safe_value.to_owned()), safe_value);
        }
    }

    #[test]
    fn output_accounting_is_exact_and_never_returns_a_prefix() {
        assert!(ensure_output_bound(&"abc", 5).is_ok());
        assert!(matches!(
            ensure_output_bound(&"abc", 4),
            Err(DepgraphServiceError::ResourceExhausted)
        ));
    }

    #[test]
    fn issue_315_windows_status_visibility_gap_waits_while_lifecycle_lock_is_held() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        fs::create_dir_all(&root).unwrap();
        let store = temporary.path().join("graph.sqlite");
        let service = DepgraphService::new(
            crate::service::DepgraphServiceConfig::new(
                &root,
                &store,
                crate::service::DepgraphCapabilitySet::read_only(),
                crate::service::DepgraphServiceLimits::default(),
            )
            .unwrap(),
        );
        let lock = File::create(daemon_lock_path(&store)).unwrap();
        lock.lock().unwrap();
        let path = status_path(&store);
        let writer_path = path.clone();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(75));
            fs::write(writer_path, b"visible").unwrap();
        });

        let started = std::time::Instant::now();
        let file = open_daemon_status_file_with_platform_gap(
            &service,
            &path,
            &CancellationToken::new(),
            true,
        )
        .unwrap();

        writer.join().unwrap();
        assert!(file.metadata().unwrap().is_file());
        assert!(started.elapsed() >= Duration::from_millis(50));
    }

    #[test]
    fn issue_315_windows_status_visibility_gap_does_not_retry_without_lock() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repository");
        fs::create_dir_all(&root).unwrap();
        let store = temporary.path().join("graph.sqlite");
        let service = DepgraphService::new(
            crate::service::DepgraphServiceConfig::new(
                &root,
                &store,
                crate::service::DepgraphCapabilitySet::read_only(),
                crate::service::DepgraphServiceLimits::default(),
            )
            .unwrap(),
        );
        let started = std::time::Instant::now();

        let result = open_daemon_status_file_with_platform_gap(
            &service,
            &status_path(&store),
            &CancellationToken::new(),
            true,
        );

        assert!(matches!(result, Err(DepgraphServiceError::NotFound)));
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn daemon_status_reader_rejects_non_files_and_oversized_input() {
        let temporary = tempfile::tempdir().unwrap();
        assert!(open_regular_file_no_follow(temporary.path()).is_err());

        let path = temporary.path().join("status.json");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"12345").unwrap();
        drop(file);
        let mut file = open_regular_file_no_follow(&path).unwrap();
        assert!(matches!(
            read_bounded(&mut file, 4),
            Err(DepgraphServiceError::ResourceExhausted)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn daemon_status_reader_and_repository_input_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target");
        fs::write(&target, b"{}").unwrap();
        let link = temporary.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(open_regular_file_no_follow(&link).is_err());
    }

    #[test]
    fn profile_request_sources_are_closed_and_mutually_exclusive() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("src")).unwrap();
        fs::write(
            root.path().join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        fs::write(root.path().join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
        let store = root.path().join("store.sqlite");
        let service = DepgraphService::new(
            crate::service::DepgraphServiceConfig::new(
                root.path(),
                &store,
                crate::service::DepgraphCapabilitySet::read_only(),
                crate::service::DepgraphServiceLimits::default(),
            )
            .unwrap(),
        );
        let error = service
            .profile_plan_cancellable(
                &ProfilePlanRequest {
                    profile_budget: Some(1),
                    profiles_document: Some("{}".to_owned()),
                    profiles_file: None,
                },
                &CancellationToken::new(),
            )
            .unwrap_err();
        assert!(matches!(error, DepgraphServiceError::InvalidInput));
    }
}
