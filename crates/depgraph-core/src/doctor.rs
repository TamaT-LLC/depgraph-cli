use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use depgraph_store::{
    AdapterLogRecord, AdapterLogSummaryRecord, CACHE_CONTRACT_VERSION, CacheEntryCounts,
    CacheEventRecord, CoverageRecord, DiagnosticRecord, DiagnosticSummaryRecord,
    FileCoverageRecord, FileCoverageSummaryRecord, IMPACT_QUERY_CACHE_CONTRACT_VERSION,
    ProfileMatrixRecord, ProfileRecord, Store,
};
use serde::Serialize;
use serde_json::Value;

use crate::{
    COMPILER_PACK_FALLBACK_POLICY, COMPILER_PRECISE_CONTRACT_VERSION, CancellationToken,
    compiler_pack_host_target, read_compiler_pack_requirement,
    release_health::{ReleaseHealth, release_health, worker_integrity},
    verify_compiler_pack,
    worker::{
        self, AdapterKind, is_security_error, locate_worker,
        probe_toolchain_version_with_cancellation, probe_worker_version_with_cancellation,
        validate_worker_launch_policy,
    },
};

#[derive(Debug, Clone, Serialize)]
pub struct WorkerHealth {
    pub adapter: String,
    pub available: bool,
    pub command: Option<String>,
    pub version: Option<String>,
    pub protocol: Option<String>,
    pub integrity: String,
    pub error: Option<String>,
    pub root_launch_allowed: bool,
    pub root_launch_error: Option<String>,
    /// How the worker was located: the same route a scan in this process
    /// takes (`release-manifest`, `environment-override`, `development-build`),
    /// or `unresolved` when no worker could be located.
    pub resolution: &'static str,
    /// Release-relative artifact path that was verified, for a worker located
    /// through the release manifest.
    pub artifact: Option<String>,
    /// External runtime the worker needs (the Web worker's Node.js range).
    pub runtime_requirement: Option<String>,
    /// Stable code for the check that made `available` false.
    pub unavailable_reason: Option<&'static str>,
    /// Stable code for the check that made `root_launch_allowed` false.
    pub root_launch_blocked_reason: Option<&'static str>,
    /// What a scan of a repository that needs this adapter gets from this
    /// worker: `worker-used`, `adapter-units-fail`, or `scan-security-failed`.
    pub scan_impact: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DoctorDiagnosticRoot {
    pub path: String,
    pub source: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanHealth {
    pub scan_id: String,
    pub status: String,
    pub root: String,
    pub project_code_executed: bool,
    pub coverage: CoverageRecord,
    pub profiles: Vec<ProfileRecord>,
    pub file_coverage: Vec<FileCoverageRecord>,
    pub adapter_logs: Vec<AdapterLogRecord>,
    pub detected_packages: BTreeMap<String, String>,
    pub diagnostics: Vec<DiagnosticRecord>,
    pub profile_matrix: ProfileMatrixRecord,
    pub cache_events: Vec<CacheEventRecord>,
    pub compiler_precise: Option<CompilerPreciseHealth>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanHealthSummary {
    pub scan_id: String,
    pub status: String,
    pub root: String,
    pub project_code_executed: bool,
    pub coverage: CoverageRecord,
    pub profile_count: u64,
    pub profiles_by_language: BTreeMap<String, u64>,
    pub package_instance_count: u64,
    pub file_coverage: Vec<FileCoverageSummaryRecord>,
    pub adapter_logs: Vec<AdapterLogSummaryRecord>,
    pub diagnostics: DiagnosticSummaryRecord,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompilerPreciseHealth {
    pub status: String,
    pub phase: String,
    pub precision: String,
    pub profiles: Vec<CompilerPreciseProfileHealth>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompilerPreciseProfileHealth {
    pub profile_id: String,
    pub target: Option<String>,
    pub compiler_pack_manifest_sha256: Option<String>,
    pub unit_graph_digest: Option<String>,
    pub invocation_ledger_digest: Option<String>,
    pub mir_ledger_digest: Option<String>,
    pub cargo_units: u64,
    pub typed_mir_bodies: u64,
    pub compiler_instances: u64,
    pub compiler_calls: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompilerPackAvailabilityHealth {
    pub status: String,
    pub host_target: Option<String>,
    pub requirement_path: Option<String>,
    pub pack_root: Option<String>,
    pub manifest_sha256: Option<String>,
    pub archive_asset: Option<String>,
    pub checksum_asset: Option<String>,
    pub requirement_asset: Option<String>,
    pub smoke_asset: Option<String>,
    pub release_page: &'static str,
    pub fallback_policy: &'static str,
    pub diagnostic: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub diagnostic_root: DoctorDiagnosticRoot,
    pub protocol_version: &'static str,
    pub graph_schema_version: &'static str,
    pub store_schema_version: i64,
    pub cache_contract_version: u32,
    pub cache_entries: CacheEntryCounts,
    pub impact_query_cache_contract_version: u32,
    pub impact_query_cache_entries: u64,
    pub recent_cache_events: Vec<CacheEventRecord>,
    pub toolchains: BTreeMap<String, String>,
    pub supported_baselines: BTreeMap<String, String>,
    pub toolchain_remediation: BTreeMap<String, String>,
    pub workers: Vec<WorkerHealth>,
    pub compiler_pack: CompilerPackAvailabilityHealth,
    pub latest_attempt: Option<ScanHealth>,
    pub latest_successful_scan_id: Option<String>,
    pub release: Option<ReleaseHealth>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorSummaryReport {
    pub report_kind: &'static str,
    pub detail_command: &'static str,
    pub diagnostic_root: DoctorDiagnosticRoot,
    pub protocol_version: &'static str,
    pub graph_schema_version: &'static str,
    pub store_schema_version: i64,
    pub cache_contract_version: u32,
    pub cache_entries: CacheEntryCounts,
    pub impact_query_cache_contract_version: u32,
    pub impact_query_cache_entries: u64,
    pub recent_cache_events: Vec<CacheEventRecord>,
    pub toolchains: BTreeMap<String, String>,
    pub supported_baselines: BTreeMap<String, String>,
    pub toolchain_remediation: BTreeMap<String, String>,
    pub workers: Vec<WorkerHealth>,
    pub compiler_pack: CompilerPackAvailabilityHealth,
    pub latest_attempt: Option<ScanHealthSummary>,
    pub latest_successful_scan_id: Option<String>,
    pub release: Option<ReleaseHealth>,
}

pub fn compiler_pack_availability(
    requirement_path: Option<&Path>,
) -> CompilerPackAvailabilityHealth {
    const RELEASE_PAGE: &str = "https://github.com/TamaT-LLC/depgraph-cli/releases";
    let Some(host_target) = compiler_pack_host_target() else {
        return CompilerPackAvailabilityHealth {
            status: "unsupported-host".to_owned(),
            host_target: None,
            requirement_path: requirement_path.map(|path| path.to_string_lossy().into_owned()),
            pack_root: None,
            manifest_sha256: None,
            archive_asset: None,
            checksum_asset: None,
            requirement_asset: None,
            smoke_asset: None,
            release_page: RELEASE_PAGE,
            fallback_policy: COMPILER_PACK_FALLBACK_POLICY,
            diagnostic: format!(
                "no first-party compiler pack is published for {}-{}",
                std::env::consts::ARCH,
                std::env::consts::OS
            ),
            remediation:
                "use one of the five supported hosts; depgraph will not fall back to rustup, PATH, system, or project compilers"
                    .to_owned(),
        };
    };
    let version = env!("CARGO_PKG_VERSION");
    let name = format!("depgraph-compiler-pack-{version}-{host_target}");
    let archive_asset = format!(
        "{name}.{}",
        if host_target.ends_with("windows-msvc") {
            "zip"
        } else {
            "tar.gz"
        }
    );
    let checksum_asset = format!("{archive_asset}.sha256");
    let requirement_asset = format!("{name}.requirement.json");
    let smoke_asset = format!("{name}.smoke.json");
    let install = format!(
        "download {archive_asset}, {checksum_asset}, {requirement_asset}, and {smoke_asset} from a depgraph {version} release at {RELEASE_PAGE}; verify the checksum, extract the archive next to the requirement, then run `depgraph doctor --compiler-pack-requirement {requirement_asset}`"
    );
    let Some(requirement_path) = requirement_path else {
        return CompilerPackAvailabilityHealth {
            status: "unconfigured".to_owned(),
            host_target: Some(host_target.to_owned()),
            requirement_path: None,
            pack_root: None,
            manifest_sha256: None,
            archive_asset: Some(archive_asset),
            checksum_asset: Some(checksum_asset),
            requirement_asset: Some(requirement_asset),
            smoke_asset: Some(smoke_asset),
            release_page: RELEASE_PAGE,
            fallback_policy: COMPILER_PACK_FALLBACK_POLICY,
            diagnostic: "no compiler-pack requirement was supplied to doctor".to_owned(),
            remediation: install,
        };
    };
    let requirement_display = requirement_path.to_string_lossy().into_owned();
    let inspected = read_compiler_pack_requirement(requirement_path).and_then(|requirement| {
        if requirement.host != host_target || requirement.target != host_target {
            anyhow::bail!(
                "compiler pack requirement targets {}/{} instead of current host {host_target}",
                requirement.host,
                requirement.target
            );
        }
        verify_compiler_pack(&requirement)
    });
    match inspected {
        Ok(pack) => CompilerPackAvailabilityHealth {
            status: "available".to_owned(),
            host_target: Some(host_target.to_owned()),
            requirement_path: Some(requirement_display.clone()),
            pack_root: Some(pack.root.to_string_lossy().into_owned()),
            manifest_sha256: Some(pack.attestation.manifest_sha256),
            archive_asset: Some(archive_asset),
            checksum_asset: Some(checksum_asset),
            requirement_asset: Some(requirement_asset),
            smoke_asset: Some(smoke_asset),
            release_page: RELEASE_PAGE,
            fallback_policy: COMPILER_PACK_FALLBACK_POLICY,
            diagnostic: "the exact current-host compiler pack is verified and available".to_owned(),
            remediation: format!(
                "run compiler-precise resolve with `--compiler-pack-requirement {requirement_display}`"
            ),
        },
        Err(error) => CompilerPackAvailabilityHealth {
            status: "unavailable".to_owned(),
            host_target: Some(host_target.to_owned()),
            requirement_path: Some(requirement_display),
            pack_root: None,
            manifest_sha256: None,
            archive_asset: Some(archive_asset),
            checksum_asset: Some(checksum_asset),
            requirement_asset: Some(requirement_asset),
            smoke_asset: Some(smoke_asset),
            release_page: RELEASE_PAGE,
            fallback_policy: COMPILER_PACK_FALLBACK_POLICY,
            diagnostic: format!("compiler pack verification failed: {error:#}"),
            remediation: install,
        },
    }
}

#[derive(Debug)]
enum DoctorWorkerLocation {
    Ready(worker::WorkerSpec),
    Unavailable(String),
}

#[derive(Debug)]
struct DoctorWorkerPreflight {
    locations: Vec<(AdapterKind, DoctorWorkerLocation)>,
    suppress_probes: bool,
}

fn preflight_doctor_workers(
    adapters: impl IntoIterator<Item = AdapterKind>,
    mut locate: impl FnMut(AdapterKind) -> Result<worker::WorkerSpec>,
) -> DoctorWorkerPreflight {
    let mut locations = Vec::new();
    let mut suppress_probes = false;

    for adapter in adapters {
        let location = match locate(adapter) {
            Ok(spec) => DoctorWorkerLocation::Ready(spec),
            Err(error) => {
                let error = format!("{error:#}");
                suppress_probes |= is_security_error(&error);
                DoctorWorkerLocation::Unavailable(error)
            }
        };
        locations.push((adapter, location));
    }

    DoctorWorkerPreflight {
        locations,
        suppress_probes,
    }
}

fn worker_root_launch_policy(spec: &worker::WorkerSpec, root: &Path) -> (bool, Option<String>) {
    match validate_worker_launch_policy(spec, root) {
        Ok(()) => (true, None),
        Err(error) => (false, Some(format!("{error:#}"))),
    }
}

/// The route `locate_worker` took for `spec`. Only the release-manifest
/// branch records an expected version, and the environment override is the
/// only route consulted before the development build candidates.
fn worker_resolution(spec: &worker::WorkerSpec) -> &'static str {
    if spec.expected_version.is_some() {
        "release-manifest"
    } else if std::env::var_os(spec.adapter.env_override()).is_some() {
        "environment-override"
    } else {
        "development-build"
    }
}

/// The verified artifact relative to the release root (`libexec/<worker>`).
/// Development and override paths are absolute and stay out of the report.
fn worker_release_artifact(spec: &worker::WorkerSpec) -> Option<String> {
    spec.expected_version.as_ref()?;
    let file = spec.artifact_path.file_name()?.to_str()?;
    let directory = spec.artifact_path.parent()?.file_name()?.to_str()?;
    Some(format!("{directory}/{file}"))
}

fn worker_location_failure_reason(error: &str) -> &'static str {
    if is_security_error(error) {
        "release-verification-failed"
    } else if error.contains("does not name a readable worker") {
        "override-unreadable"
    } else {
        "not-found"
    }
}

fn worker_probe_failure_reason(error: &str) -> &'static str {
    if error.contains("node is unavailable on the sanitized PATH") {
        "runtime-unavailable"
    } else if error.contains("Node.js runtime") {
        "runtime-requirement-unmet"
    } else if is_security_error(error) {
        "release-verification-failed"
    } else {
        "handshake-failed"
    }
}

fn worker_root_launch_blocked_reason(error: &str) -> &'static str {
    if error.contains("is inside the scan root") {
        "artifact-inside-root"
    } else if error.contains("node is unavailable on the sanitized PATH") {
        "runtime-unavailable"
    } else if error.contains("worker artifact") && error.contains("is unavailable") {
        "artifact-missing"
    } else {
        "launch-policy-violation"
    }
}

fn worker_scan_impact(
    available: bool,
    root_launch_allowed: bool,
    unavailable_reason: Option<&str>,
) -> &'static str {
    if available && root_launch_allowed {
        "worker-used"
    } else if matches!(
        unavailable_reason,
        Some("release-verification-failed" | "probe-suppressed")
    ) {
        "scan-security-failed"
    } else {
        "adapter-units-fail"
    }
}

fn evaluated_worker_health(
    adapter: AdapterKind,
    spec: worker::WorkerSpec,
    root: &Path,
    version: Result<String>,
) -> WorkerHealth {
    let (root_launch_allowed, root_launch_error) = worker_root_launch_policy(&spec, root);
    let reported_version = version.as_deref().ok();
    let protocol = reported_version
        .and_then(parse_worker_handshake)
        .map(|(_, _, protocol)| protocol.to_owned());
    let integrity = worker_integrity(adapter, &spec.artifact_path, reported_version);
    let unavailable_reason = match &version {
        Err(error) => Some(worker_probe_failure_reason(&format!("{error:#}"))),
        Ok(_) if integrity.starts_with("error: ") => Some("integrity-mismatch"),
        Ok(_) => None,
    };
    let error = version
        .as_ref()
        .err()
        .map(ToString::to_string)
        .or_else(|| integrity.strip_prefix("error: ").map(ToOwned::to_owned));
    let available = error.is_none();
    WorkerHealth {
        adapter: adapter.name().to_owned(),
        available,
        resolution: worker_resolution(&spec),
        artifact: worker_release_artifact(&spec),
        runtime_requirement: spec.runtime_requirement.clone(),
        command: Some(spec.display),
        version: version.ok(),
        protocol,
        integrity,
        error,
        root_launch_blocked_reason: root_launch_error
            .as_deref()
            .map(worker_root_launch_blocked_reason),
        scan_impact: worker_scan_impact(available, root_launch_allowed, unavailable_reason),
        unavailable_reason,
        root_launch_allowed,
        root_launch_error,
    }
}

fn suppressed_worker_health(
    adapter: AdapterKind,
    spec: worker::WorkerSpec,
    root: &Path,
) -> WorkerHealth {
    let (root_launch_allowed, root_launch_error) = worker_root_launch_policy(&spec, root);
    let unavailable_reason = Some("probe-suppressed");
    WorkerHealth {
        adapter: adapter.name().to_owned(),
        available: false,
        resolution: worker_resolution(&spec),
        artifact: worker_release_artifact(&spec),
        runtime_requirement: spec.runtime_requirement.clone(),
        command: Some(spec.display),
        version: None,
        protocol: None,
        integrity: worker_integrity(adapter, &spec.artifact_path, None),
        error: Some(
            "worker probe suppressed because another adapter failed release security verification"
                .to_owned(),
        ),
        unavailable_reason,
        root_launch_blocked_reason: root_launch_error
            .as_deref()
            .map(worker_root_launch_blocked_reason),
        // A scan stops every worker once one adapter fails release security
        // verification, so this worker would not run either.
        scan_impact: worker_scan_impact(false, root_launch_allowed, unavailable_reason),
        root_launch_allowed,
        root_launch_error,
    }
}

fn unresolved_worker_health(adapter: AdapterKind, error: String) -> WorkerHealth {
    let unavailable_reason = Some(worker_location_failure_reason(&error));
    WorkerHealth {
        adapter: adapter.name().to_owned(),
        available: false,
        resolution: "unresolved",
        artifact: None,
        runtime_requirement: None,
        command: None,
        version: None,
        protocol: None,
        integrity: "unavailable".to_owned(),
        root_launch_error: Some(format!(
            "root launch policy was not evaluated because the worker is unavailable: {error}"
        )),
        error: Some(error),
        unavailable_reason,
        root_launch_blocked_reason: Some("worker-unavailable"),
        scan_impact: worker_scan_impact(false, false, unavailable_reason),
        root_launch_allowed: false,
    }
}

async fn doctor_workers(root: &Path, cancellation: &CancellationToken) -> Vec<WorkerHealth> {
    let preflight = preflight_doctor_workers(
        [AdapterKind::Rust, AdapterKind::Go, AdapterKind::Web],
        locate_worker,
    );
    let mut workers = Vec::new();
    for (adapter, location) in preflight.locations {
        workers.push(match location {
            DoctorWorkerLocation::Ready(spec) if preflight.suppress_probes => {
                suppressed_worker_health(adapter, spec, root)
            }
            DoctorWorkerLocation::Ready(spec) => {
                let version = worker_artifact_version(&spec, cancellation).await;
                evaluated_worker_health(adapter, spec, root, version)
            }
            DoctorWorkerLocation::Unavailable(error) => unresolved_worker_health(adapter, error),
        });
    }
    workers
}

async fn worker_artifact_version(
    spec: &worker::WorkerSpec,
    cancellation: &CancellationToken,
) -> Result<String> {
    let probe_root = tempfile::Builder::new()
        .prefix("depgraph-doctor-worker-probe-")
        .tempdir()
        .context("failed to create a neutral worker health probe root")?;
    worker_version_cancellable(spec, probe_root.path(), cancellation).await
}

fn default_doctor_diagnostic_root(store: &Store) -> Result<(PathBuf, &'static str)> {
    if let Some(scan_id) = store.latest_attempt_id()?
        && let Some(scan) = store.scan(&scan_id)?
    {
        let root = PathBuf::from(scan.root);
        if !root.is_absolute() {
            anyhow::bail!("stored diagnostic root is not absolute");
        }
        return Ok((root, "latest-attempt"));
    }
    Ok((
        std::env::current_dir()?.canonicalize()?,
        "current-working-directory",
    ))
}

fn normalize_doctor_diagnostic_root(
    root: &Path,
    source: &'static str,
) -> (PathBuf, DoctorDiagnosticRoot) {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let diagnostic_root = DoctorDiagnosticRoot {
        path: root.to_string_lossy().into_owned(),
        source,
    };
    (root, diagnostic_root)
}

pub async fn doctor(store: &Store) -> Result<DoctorReport> {
    doctor_cancellable(store, &CancellationToken::new()).await
}

pub async fn doctor_cancellable(
    store: &Store,
    cancellation: &CancellationToken,
) -> Result<DoctorReport> {
    let (root, source) = default_doctor_diagnostic_root(store)?;
    doctor_with_diagnostic_root(store, &root, source, cancellation).await
}

pub async fn doctor_for_root(store: &Store, root: &Path) -> Result<DoctorReport> {
    doctor_for_root_cancellable(store, root, &CancellationToken::new()).await
}

pub async fn doctor_for_root_cancellable(
    store: &Store,
    root: &Path,
    cancellation: &CancellationToken,
) -> Result<DoctorReport> {
    doctor_with_diagnostic_root(store, root, "explicit", cancellation).await
}

async fn doctor_with_diagnostic_root(
    store: &Store,
    root: &Path,
    source: &'static str,
    cancellation: &CancellationToken,
) -> Result<DoctorReport> {
    if cancellation.is_cancelled() {
        anyhow::bail!("doctor cancelled");
    }
    let (root, diagnostic_root) = normalize_doctor_diagnostic_root(root, source);
    let workers = doctor_workers(&root, cancellation).await;
    let latest_attempt = store
        .latest_attempt_id()?
        .map(|scan_id| {
            let snapshot = store.load_snapshot(&scan_id)?;
            let compiler_profiles = snapshot
                .profiles
                .iter()
                .filter(|profile| {
                    profile
                        .properties
                        .get("compiler_precise_contract")
                        .and_then(Value::as_str)
                        == Some(COMPILER_PRECISE_CONTRACT_VERSION)
                        && profile
                            .properties
                            .get("profile_phase")
                            .and_then(Value::as_str)
                            == Some("build")
                })
                .map(|profile| {
                    let string_property = |name: &str| {
                        profile
                            .properties
                            .get(name)
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                    };
                    let count_property = |name: &str| {
                        profile
                            .properties
                            .get(name)
                            .and_then(Value::as_u64)
                            .unwrap_or(0)
                    };
                    CompilerPreciseProfileHealth {
                        profile_id: profile.id.clone(),
                        target: profile.target.clone(),
                        compiler_pack_manifest_sha256: string_property(
                            "compiler_pack_manifest_sha256",
                        ),
                        unit_graph_digest: string_property("unit_graph_digest"),
                        invocation_ledger_digest: string_property("invocation_ledger_digest"),
                        mir_ledger_digest: string_property("mir_ledger_digest"),
                        cargo_units: count_property("cargo_unit_count"),
                        typed_mir_bodies: count_property("typed_mir_body_count"),
                        compiler_instances: count_property("compiler_instance_count"),
                        compiler_calls: count_property("compiler_call_count"),
                    }
                })
                .collect::<Vec<_>>();
            let compiler_precise =
                (!compiler_profiles.is_empty()).then_some(CompilerPreciseHealth {
                    status: "promoted".to_owned(),
                    phase: "build".to_owned(),
                    precision: "observed".to_owned(),
                    profiles: compiler_profiles,
                });
            let detected_packages = snapshot
                .nodes
                .iter()
                .filter(|node| node.kind == "package_instance")
                .filter_map(|node| {
                    let name = node.properties.get("name")?.as_str()?;
                    let version = node.properties.get("version")?.as_str()?;
                    Some((name.to_owned(), version.to_owned()))
                })
                .collect();
            Ok::<_, anyhow::Error>(ScanHealth {
                scan_id: scan_id.clone(),
                status: snapshot.scan.status,
                root: snapshot.scan.root,
                project_code_executed: snapshot.scan.project_code_executed,
                coverage: snapshot.coverage,
                profiles: snapshot.profiles,
                file_coverage: snapshot.file_coverage,
                adapter_logs: snapshot.adapter_logs,
                detected_packages,
                diagnostics: snapshot.diagnostics,
                profile_matrix: snapshot.profile_matrix,
                cache_events: store.cache_events_for_scan(&scan_id)?,
                compiler_precise,
            })
        })
        .transpose()?;
    if cancellation.is_cancelled() {
        anyhow::bail!("doctor cancelled");
    }
    let toolchains = toolchain_versions(&root, cancellation).await;
    let toolchain_remediation = doctor_toolchain_remediation(&toolchains);
    Ok(DoctorReport {
        diagnostic_root,
        protocol_version: "1.0",
        graph_schema_version: "1.0",
        store_schema_version: store.schema_version()?,
        cache_contract_version: CACHE_CONTRACT_VERSION,
        cache_entries: store.cache_entry_counts()?,
        impact_query_cache_contract_version: IMPACT_QUERY_CACHE_CONTRACT_VERSION,
        impact_query_cache_entries: store.impact_query_cache_entry_count()?,
        recent_cache_events: store.recent_cache_events(20)?,
        toolchains,
        supported_baselines: doctor_supported_baselines(),
        toolchain_remediation,
        workers,
        compiler_pack: compiler_pack_availability(None),
        latest_attempt,
        latest_successful_scan_id: store.latest_successful_id()?,
        release: release_health()?,
    })
}

pub async fn doctor_summary(store: &Store) -> Result<DoctorSummaryReport> {
    doctor_summary_cancellable(store, &CancellationToken::new()).await
}

pub async fn doctor_summary_cancellable(
    store: &Store,
    cancellation: &CancellationToken,
) -> Result<DoctorSummaryReport> {
    let (root, source) = default_doctor_diagnostic_root(store)?;
    doctor_summary_with_diagnostic_root(store, &root, source, cancellation).await
}

pub async fn doctor_summary_for_root(store: &Store, root: &Path) -> Result<DoctorSummaryReport> {
    doctor_summary_for_root_cancellable(store, root, &CancellationToken::new()).await
}

pub async fn doctor_summary_for_root_cancellable(
    store: &Store,
    root: &Path,
    cancellation: &CancellationToken,
) -> Result<DoctorSummaryReport> {
    doctor_summary_with_diagnostic_root(store, root, "explicit", cancellation).await
}

async fn doctor_summary_with_diagnostic_root(
    store: &Store,
    root: &Path,
    source: &'static str,
    cancellation: &CancellationToken,
) -> Result<DoctorSummaryReport> {
    if cancellation.is_cancelled() {
        anyhow::bail!("doctor cancelled");
    }
    let (root, diagnostic_root) = normalize_doctor_diagnostic_root(root, source);
    let workers = doctor_workers(&root, cancellation).await;
    let latest_attempt = store
        .latest_attempt_id()?
        .map(|scan_id| {
            let summary = store.scan_attempt_summary(&scan_id)?;
            Ok::<_, anyhow::Error>(ScanHealthSummary {
                scan_id,
                status: summary.scan.status,
                root: summary.scan.root,
                project_code_executed: summary.scan.project_code_executed,
                coverage: summary.coverage,
                profile_count: summary.profile_count,
                profiles_by_language: summary.profiles_by_language,
                package_instance_count: summary.package_instance_count,
                file_coverage: summary.file_coverage,
                adapter_logs: summary.adapter_logs,
                diagnostics: summary.diagnostics,
            })
        })
        .transpose()?;
    if cancellation.is_cancelled() {
        anyhow::bail!("doctor cancelled");
    }
    let toolchains = toolchain_versions(&root, cancellation).await;
    let toolchain_remediation = doctor_toolchain_remediation(&toolchains);
    Ok(DoctorSummaryReport {
        report_kind: "summary",
        detail_command: "depgraph doctor --details",
        diagnostic_root,
        protocol_version: "1.0",
        graph_schema_version: "1.0",
        store_schema_version: store.schema_version()?,
        cache_contract_version: CACHE_CONTRACT_VERSION,
        cache_entries: store.cache_entry_counts()?,
        impact_query_cache_contract_version: IMPACT_QUERY_CACHE_CONTRACT_VERSION,
        impact_query_cache_entries: store.impact_query_cache_entry_count()?,
        recent_cache_events: store.recent_cache_events(20)?,
        toolchains,
        supported_baselines: doctor_supported_baselines(),
        toolchain_remediation,
        workers,
        compiler_pack: compiler_pack_availability(None),
        latest_attempt,
        latest_successful_scan_id: store.latest_successful_id()?,
        release: release_health()?,
    })
}

fn doctor_supported_baselines() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("rust".to_owned(), "1.93.1".to_owned()),
        ("go".to_owned(), "1.26.1".to_owned()),
        ("node".to_owned(), "24.18.0".to_owned()),
        ("pnpm".to_owned(), "10.33.0".to_owned()),
        ("typescript".to_owned(), "7.0.2".to_owned()),
    ])
}

async fn worker_version_cancellable(
    spec: &worker::WorkerSpec,
    root: &Path,
    cancellation: &CancellationToken,
) -> Result<String> {
    let version = probe_worker_version_with_cancellation(spec, root, cancellation).await?;
    let expected_name = format!("depgraph-{}-worker", spec.adapter.name());
    let Some((name, _, protocol)) = parse_worker_handshake(&version) else {
        anyhow::bail!("worker reports a malformed version handshake: {version}");
    };
    if name != expected_name || protocol != "1.0" {
        anyhow::bail!("worker reports an incompatible protocol: {version}");
    }
    Ok(version)
}

pub(crate) fn parse_worker_handshake(handshake: &str) -> Option<(&str, &str, &str)> {
    let (identity, details) = handshake.split_once(" (protocol ")?;
    let details = details.strip_suffix(')')?;
    let protocol = details.split_once(';').map_or(details, |(value, _)| value);
    let mut identity = identity.split_whitespace();
    let name = identity.next()?;
    let version = identity.next()?;
    if identity.next().is_some() || name.is_empty() || version.is_empty() || protocol.is_empty() {
        return None;
    }
    Some((name, version, protocol))
}

async fn toolchain_versions(
    root: &Path,
    cancellation: &CancellationToken,
) -> BTreeMap<String, String> {
    let mut versions = BTreeMap::new();
    for (name, command, argument) in [
        ("rust", "rustc", "--version"),
        ("go", "go", "version"),
        ("node", "node", "--version"),
    ] {
        if cancellation.is_cancelled() {
            break;
        }
        let version =
            probe_toolchain_version_with_cancellation(command, argument, root, cancellation)
                .await
                .ok()
                .unwrap_or_else(|| "unavailable".to_owned());
        versions.insert(name.to_owned(), version);
    }
    versions
}

fn doctor_toolchain_remediation(toolchains: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut remediation = BTreeMap::new();
    if toolchains
        .get("rust")
        .is_none_or(|version| !version.starts_with("rustc 1.93.1 "))
    {
        remediation.insert(
            "rust".to_owned(),
            "safe HIR automatically selects an already-installed verified Rust 1.93.1 pair; if it is unavailable, run `rustup toolchain install 1.93.1 --profile minimal --component rust-src`; depgraph never installs or switches toolchains automatically"
                .to_owned(),
        );
    }
    remediation
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        ffi::OsString,
        path::{Path, PathBuf},
    };

    use super::{
        AdapterKind, DoctorWorkerLocation, default_doctor_diagnostic_root,
        doctor_toolchain_remediation, evaluated_worker_health, parse_worker_handshake,
        preflight_doctor_workers, suppressed_worker_health, worker,
    };

    fn test_worker_spec(adapter: AdapterKind) -> worker::WorkerSpec {
        let path = PathBuf::from(format!("/tmp/depgraph-{}-worker", adapter.name()));
        worker::WorkerSpec {
            adapter,
            program: OsString::from(&path),
            leading_args: Vec::new(),
            display: path.display().to_string(),
            artifact_path: path,
            runtime_requirement: None,
            expected_version: None,
            release_attested: false,
            attested_rust_sysroot: None,
        }
    }

    #[test]
    fn doctor_explains_the_installed_baseline_path_for_a_newer_host() {
        let newer = BTreeMap::from([(
            "rust".to_owned(),
            "rustc 1.97.1 (8bab26f4f 2026-07-14)".to_owned(),
        )]);
        let remediation = doctor_toolchain_remediation(&newer);
        let rust = remediation.get("rust").expect("Rust remediation");
        assert!(rust.contains("automatically selects"));
        assert!(
            rust.contains("rustup toolchain install 1.93.1 --profile minimal --component rust-src")
        );
        assert!(rust.contains("never installs or switches"));

        let baseline = BTreeMap::from([(
            "rust".to_owned(),
            "rustc 1.93.1 (01f6ddf75 2026-02-11)".to_owned(),
        )]);
        assert!(doctor_toolchain_remediation(&baseline).is_empty());
    }

    #[test]
    fn worker_handshake_requires_an_exact_protocol_token() {
        assert_eq!(
            parse_worker_handshake("depgraph-web-worker 0.1.0 (protocol 1.0; typescript 7.0.2)"),
            Some(("depgraph-web-worker", "0.1.0", "1.0"))
        );
        assert_eq!(
            parse_worker_handshake("depgraph-go-worker 0.1.0 (protocol 1.00)"),
            Some(("depgraph-go-worker", "0.1.0", "1.00"))
        );
        assert_eq!(parse_worker_handshake("depgraph-go-worker 0.1.0"), None);
    }

    #[test]
    fn late_security_failure_suppresses_every_successful_doctor_probe() {
        let mut visited = Vec::new();
        let preflight = preflight_doctor_workers(
            [AdapterKind::Rust, AdapterKind::Go, AdapterKind::Web],
            |adapter| {
                visited.push(adapter);
                if adapter == AdapterKind::Web {
                    anyhow::bail!("security policy violation: late Web release manifest mismatch");
                }
                Ok(test_worker_spec(adapter))
            },
        );

        assert_eq!(
            visited,
            vec![AdapterKind::Rust, AdapterKind::Go, AdapterKind::Web]
        );
        assert!(preflight.suppress_probes);
        assert_eq!(
            preflight
                .locations
                .iter()
                .filter(|(_, location)| matches!(location, DoctorWorkerLocation::Ready(_)))
                .count(),
            2
        );

        for (adapter, location) in preflight.locations {
            if let DoctorWorkerLocation::Ready(spec) = location {
                let health = suppressed_worker_health(adapter, spec, Path::new("/tmp"));
                assert!(!health.available);
                assert!(health.command.is_some());
                assert!(health.version.is_none());
                assert!(health.protocol.is_none());
                assert!(
                    health.integrity == "development-unverified"
                        || health.integrity.starts_with("error: ")
                );
                assert!(
                    health
                        .error
                        .as_deref()
                        .is_some_and(|error| error.contains("probe suppressed"))
                );
            }
        }
    }

    #[test]
    fn worker_artifact_health_is_independent_from_root_confinement_for_every_adapter() {
        let source_root = tempfile::tempdir().expect("source root");
        let unrelated_root = tempfile::tempdir().expect("unrelated root");
        for adapter in [AdapterKind::Rust, AdapterKind::Go, AdapterKind::Web] {
            let artifact = source_root
                .path()
                .join(format!("depgraph-{}-worker", adapter.name()));
            std::fs::write(&artifact, b"fixture").expect("worker artifact");
            let spec = worker::WorkerSpec {
                adapter,
                program: OsString::from(&artifact),
                leading_args: Vec::new(),
                display: artifact.display().to_string(),
                artifact_path: artifact,
                runtime_requirement: None,
                expected_version: None,
                release_attested: false,
                attested_rust_sysroot: None,
            };
            let version = format!(
                "depgraph-{}-worker {} (protocol 1.0)",
                adapter.name(),
                env!("CARGO_PKG_VERSION")
            );
            let blocked = evaluated_worker_health(
                adapter,
                spec.clone(),
                source_root.path(),
                Ok(version.clone()),
            );
            let allowed =
                evaluated_worker_health(adapter, spec, unrelated_root.path(), Ok(version));

            assert!(blocked.available);
            assert_eq!(blocked.protocol.as_deref(), Some("1.0"));
            assert!(blocked.error.is_none());
            assert!(!blocked.root_launch_allowed);
            assert!(
                blocked
                    .root_launch_error
                    .as_deref()
                    .is_some_and(|error| error.contains("inside the scan root"))
            );
            assert!(allowed.available);
            assert_eq!(allowed.protocol.as_deref(), Some("1.0"));
            assert!(allowed.root_launch_allowed);
            assert!(allowed.root_launch_error.is_none());
            assert_eq!(blocked.version, allowed.version);
            assert_eq!(blocked.integrity, allowed.integrity);
        }
    }

    #[test]
    fn doctor_diagnostic_root_prefers_the_latest_attempt_and_has_a_cwd_fallback()
    -> anyhow::Result<()> {
        let mut store = depgraph_store::Store::open_in_memory()?;
        let (fallback, fallback_source) = default_doctor_diagnostic_root(&store)?;
        assert_eq!(fallback_source, "current-working-directory");
        assert_eq!(fallback, std::env::current_dir()?.canonicalize()?);

        let root = tempfile::tempdir()?;
        store.start_scan("diagnostic-root", root.path(), false)?;
        let (selected, selected_source) = default_doctor_diagnostic_root(&store)?;
        assert_eq!(selected_source, "latest-attempt");
        assert_eq!(selected, root.path());
        Ok(())
    }

    #[test]
    fn non_security_unavailability_keeps_successful_doctor_probes_enabled() {
        let preflight = preflight_doctor_workers(
            [AdapterKind::Rust, AdapterKind::Go, AdapterKind::Web],
            |adapter| {
                if adapter == AdapterKind::Go {
                    anyhow::bail!("Go worker is unavailable");
                }
                Ok(test_worker_spec(adapter))
            },
        );

        assert!(!preflight.suppress_probes);
        assert_eq!(
            preflight
                .locations
                .iter()
                .filter(|(_, location)| matches!(location, DoctorWorkerLocation::Ready(_)))
                .count(),
            2
        );
        assert!(matches!(
            &preflight.locations[1],
            (AdapterKind::Go, DoctorWorkerLocation::Unavailable(error))
                if error == "Go worker is unavailable"
        ));
    }

    /// #569: an unavailable worker names the check that failed and what a
    /// scan gets instead, so `available: false` is no longer ambiguous.
    #[test]
    fn doctor_worker_health_names_the_failed_check_and_scan_impact() {
        let unresolved = super::unresolved_worker_health(
            AdapterKind::Rust,
            "security policy violation: bundled release verification failed".to_owned(),
        );
        assert!(!unresolved.available);
        assert_eq!(unresolved.resolution, "unresolved");
        assert_eq!(
            unresolved.unavailable_reason,
            Some("release-verification-failed")
        );
        assert_eq!(
            unresolved.root_launch_blocked_reason,
            Some("worker-unavailable")
        );
        assert_eq!(unresolved.scan_impact, "scan-security-failed");

        let missing = super::unresolved_worker_health(
            AdapterKind::Go,
            "go worker is unavailable; set DEPGRAPH_GO_WORKER or build the bundled worker"
                .to_owned(),
        );
        assert_eq!(missing.unavailable_reason, Some("not-found"));
        assert_eq!(missing.scan_impact, "adapter-units-fail");

        let unrelated_root = tempfile::tempdir().expect("unrelated root");
        let mut web = test_worker_spec(AdapterKind::Web);
        web.runtime_requirement = Some("Node.js >=24.0.0".to_owned());
        let old_node = evaluated_worker_health(
            AdapterKind::Web,
            web,
            unrelated_root.path(),
            Err(anyhow::anyhow!(
                "Node.js runtime 22.23.2 does not satisfy Node.js >=24.0.0"
            )),
        );
        assert!(!old_node.available);
        assert_eq!(old_node.resolution, "development-build");
        assert_eq!(
            old_node.unavailable_reason,
            Some("runtime-requirement-unmet")
        );
        assert_eq!(
            old_node.runtime_requirement.as_deref(),
            Some("Node.js >=24.0.0")
        );
        assert_eq!(old_node.scan_impact, "adapter-units-fail");
        assert!(old_node.artifact.is_none());

        let source_root = tempfile::tempdir().expect("source root");
        let artifact = source_root.path().join("depgraph-go-worker");
        std::fs::write(&artifact, b"fixture").expect("worker artifact");
        let mut go = test_worker_spec(AdapterKind::Go);
        go.artifact_path = artifact;
        let version = format!(
            "depgraph-go-worker {} (protocol 1.0)",
            env!("CARGO_PKG_VERSION")
        );
        let used = evaluated_worker_health(
            AdapterKind::Go,
            go.clone(),
            unrelated_root.path(),
            Ok(version.clone()),
        );
        assert!(used.available && used.root_launch_allowed);
        assert_eq!(used.unavailable_reason, None);
        assert_eq!(used.root_launch_blocked_reason, None);
        assert_eq!(used.scan_impact, "worker-used");

        let blocked = evaluated_worker_health(AdapterKind::Go, go, source_root.path(), Ok(version));
        assert!(blocked.available && !blocked.root_launch_allowed);
        assert_eq!(
            blocked.root_launch_blocked_reason,
            Some("artifact-inside-root")
        );
        assert_eq!(blocked.scan_impact, "adapter-units-fail");

        let mut released = test_worker_spec(AdapterKind::Rust);
        released.artifact_path = PathBuf::from("/opt/depgraph/libexec/depgraph-rust-worker");
        released.expected_version = Some(env!("CARGO_PKG_VERSION").to_owned());
        assert_eq!(super::worker_resolution(&released), "release-manifest");
        assert_eq!(
            super::worker_release_artifact(&released).as_deref(),
            Some("libexec/depgraph-rust-worker")
        );

        let suppressed = suppressed_worker_health(
            AdapterKind::Go,
            test_worker_spec(AdapterKind::Go),
            Path::new("/tmp"),
        );
        assert_eq!(suppressed.unavailable_reason, Some("probe-suppressed"));
        assert_eq!(suppressed.scan_impact, "scan-security-failed");
    }
}
