pub mod build;
pub mod build_evidence;
pub mod cache;
pub mod cancellation;
pub mod config;
pub mod daemon;
pub mod export;
pub mod impact;
pub mod incremental;
pub mod query;
pub mod rust_build_observer;
pub mod scan;
pub mod worker;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::Result;
use depgraph_store::{
    AdapterLogRecord, CACHE_CONTRACT_VERSION, CacheEntryCounts, CacheEventRecord, CoverageRecord,
    DiagnosticRecord, FileCoverageRecord, ProfileMatrixRecord, ProfileRecord, Store,
};
use serde::{Deserialize, Serialize};

pub use build::{
    ASTRO_BUILD_OBSERVER, BUILD_SUPERVISOR_VERSION, BuildAudit, BuildExecutionOutcome,
    BuildExecutionPlan, BuildExecutionRequest, BuildOutcomeKind, NEXT_BUILD_OBSERVER,
    NetworkIsolation, TANSTACK_START_BUILD_OBSERVER, WEB_BUILD_OBSERVER_VERSION, WebBuildAdapter,
    WebBuildObservation, create_build_execution_request, execute_build_request,
    execute_build_request_with_cancellation, supervise_build, supervise_build_with_cancellation,
};
pub use build_evidence::{
    stage_build_evidence, validate_build_evidence, web_build_protocol_ndjson,
};
pub use cache::build_cache_key;
pub use cancellation::CancellationToken;
pub use config::{Config, DaemonConfig, default_store_path, init_config};
pub use daemon::{
    DAEMON_STATUS_SCHEMA_VERSION, DaemonAttempt, DaemonHandle, DaemonPhase, DaemonScanFuture,
    DaemonScanOutcome, DaemonScanRequest, DaemonScanRunner, DaemonStatus, EventCoalescer,
    RepositoryScanRunner, WatchIgnoreRules, WatchPathKind, WatchedPath,
    coalesce_incremental_changes, start_daemon_with_runner, start_repository_daemon,
};
pub use depgraph_store::GraphSnapshot;
pub use export::{ExportFormat, export};
pub use impact::{
    ChangedNodeMapping, GitChange, GitChangedSet, ImpactDiagnostic, ImpactFilters, ImpactNode,
    ImpactResult, impact, map_changed_set, read_git_changed_set,
};
pub use incremental::{
    INCREMENTAL_PLAN_SCHEMA_VERSION, IncrementalChangeKind, IncrementalFileChange,
    IncrementalInvalidationMode, IncrementalInvalidationPlan, IncrementalInvalidationReason,
    plan_incremental_invalidation,
};
pub use query::{
    CycleLevel, CycleResult, TraversalResult, UnresolvedResult, WhyResult, cycles,
    render_condition, resolve_selector, traverse, unresolved, why,
};
pub use rust_build_observer::{
    RUST_BUILD_CAPABILITY, RUST_BUILD_OBSERVATION_SCHEMA, RUST_BUILD_OBSERVER,
    RUST_BUILD_OBSERVER_VERSION, RustBuildObservation, rust_build_protocol_events,
    rust_build_protocol_ndjson,
};
pub use scan::{
    ScanCacheMode, ScanOutcome, run_scan, run_scan_with_cache_mode,
    run_scan_with_cache_mode_and_cancellation,
};

use worker::{
    AdapterKind, RUST_BACKEND_KIND, RUST_BACKEND_REVISION, RUST_BACKEND_SALSA_VERSION,
    RUST_BACKEND_VERSION, is_security_error, locate_worker, probe_toolchain_version,
    probe_worker_version, verify_release_artifact, verify_release_runtime_component,
    verify_rust_release_handshake, verify_web_release_handshake, verify_web_semantic_compatibility,
};

#[derive(Debug, Clone, Serialize)]
pub struct WorkerHealth {
    pub adapter: String,
    pub available: bool,
    pub command: Option<String>,
    pub version: Option<String>,
    pub integrity: String,
    pub error: Option<String>,
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
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub protocol_version: &'static str,
    pub graph_schema_version: &'static str,
    pub store_schema_version: i64,
    pub cache_contract_version: u32,
    pub cache_entries: CacheEntryCounts,
    pub recent_cache_events: Vec<CacheEventRecord>,
    pub toolchains: BTreeMap<String, String>,
    pub supported_baselines: BTreeMap<String, String>,
    pub workers: Vec<WorkerHealth>,
    pub latest_attempt: Option<ScanHealth>,
    pub latest_successful_scan_id: Option<String>,
    pub release: Option<ReleaseHealth>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReleaseHealth {
    pub version: String,
    pub target: String,
    pub schema_version: String,
    pub license_expression: String,
    pub core_integrity: String,
    pub schema_integrity: String,
    pub runtime_integrity: BTreeMap<String, String>,
    pub runtime_requirements: BTreeMap<String, String>,
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

fn suppressed_worker_health(adapter: AdapterKind, spec: worker::WorkerSpec) -> WorkerHealth {
    WorkerHealth {
        adapter: adapter.name().to_owned(),
        available: false,
        command: Some(spec.display),
        version: None,
        integrity: worker_integrity(adapter, &spec.artifact_path, None),
        error: Some(
            "worker probe suppressed because another adapter failed release security verification"
                .to_owned(),
        ),
    }
}

pub async fn doctor(store: &Store) -> Result<DoctorReport> {
    let root = std::env::current_dir()?.canonicalize()?;
    let preflight = preflight_doctor_workers(
        [AdapterKind::Rust, AdapterKind::Go, AdapterKind::Web],
        locate_worker,
    );
    let mut workers = Vec::new();
    for (adapter, location) in preflight.locations {
        workers.push(match location {
            DoctorWorkerLocation::Ready(spec) if preflight.suppress_probes => {
                suppressed_worker_health(adapter, spec)
            }
            DoctorWorkerLocation::Ready(spec) => {
                let version = worker_version(&spec, &root).await;
                let integrity =
                    worker_integrity(adapter, &spec.artifact_path, version.as_deref().ok());
                let error = version
                    .as_ref()
                    .err()
                    .map(ToString::to_string)
                    .or_else(|| integrity.strip_prefix("error: ").map(ToOwned::to_owned));
                WorkerHealth {
                    adapter: adapter.name().to_owned(),
                    available: error.is_none(),
                    command: Some(spec.display),
                    version: version.ok(),
                    integrity,
                    error,
                }
            }
            DoctorWorkerLocation::Unavailable(error) => WorkerHealth {
                adapter: adapter.name().to_owned(),
                available: false,
                command: None,
                version: None,
                integrity: "unavailable".to_owned(),
                error: Some(error),
            },
        });
    }
    let latest_attempt = store
        .latest_attempt_id()?
        .map(|scan_id| {
            let snapshot = store.load_snapshot(&scan_id)?;
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
            })
        })
        .transpose()?;
    Ok(DoctorReport {
        protocol_version: "1.0",
        graph_schema_version: "1.0",
        store_schema_version: store.schema_version()?,
        cache_contract_version: CACHE_CONTRACT_VERSION,
        cache_entries: store.cache_entry_counts()?,
        recent_cache_events: store.recent_cache_events(20)?,
        toolchains: toolchain_versions(&root).await,
        supported_baselines: BTreeMap::from([
            ("rust".to_owned(), "1.93.1".to_owned()),
            ("go".to_owned(), "1.26.1".to_owned()),
            ("node".to_owned(), "24.18.0".to_owned()),
            ("pnpm".to_owned(), "10.33.0".to_owned()),
            ("typescript".to_owned(), "7.0.2".to_owned()),
        ]),
        workers,
        latest_attempt,
        latest_successful_scan_id: store.latest_successful_id()?,
        release: release_health(),
    })
}

async fn worker_version(spec: &worker::WorkerSpec, root: &Path) -> Result<String> {
    let version = probe_worker_version(spec, root).await?;
    let expected_name = format!("depgraph-{}-worker", spec.adapter.name());
    let Some((name, _, protocol)) = parse_worker_handshake(&version) else {
        anyhow::bail!("worker reports a malformed version handshake: {version}");
    };
    if name != expected_name || protocol != "1.0" {
        anyhow::bail!("worker reports an incompatible protocol: {version}");
    }
    Ok(version)
}

fn parse_worker_handshake(handshake: &str) -> Option<(&str, &str, &str)> {
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

#[derive(Deserialize)]
struct ReleaseManifest {
    release_version: String,
    protocol_version: String,
    schema_version: String,
    target: String,
    license_expression: String,
    project_licenses: Vec<ReleaseArtifact>,
    core: ReleaseArtifact,
    schema: ReleaseArtifact,
    #[serde(default)]
    runtime_artifacts: Vec<ReleaseArtifact>,
    #[serde(default)]
    runtime_components: Vec<ReleaseRuntimeComponent>,
    #[serde(default)]
    runtime_requirements: BTreeMap<String, String>,
    workers: Vec<ReleaseWorker>,
}

#[derive(Deserialize)]
struct ReleaseArtifact {
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
struct ReleaseRuntimeComponent {
    name: String,
    version: String,
    kind: String,
    root: String,
    entrypoint: Option<String>,
    sha256: String,
}

#[derive(Deserialize)]
struct ReleaseWorker {
    adapter: String,
    version: String,
    #[serde(default)]
    backend: Option<ReleaseWorkerBackend>,
    #[serde(default)]
    semantic: Option<ReleaseWebSemanticAttestation>,
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
struct ReleaseWorkerBackend {
    kind: String,
    version: String,
    revision: String,
    salsa_version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseWebSemanticAttestation {
    typescript_version: String,
    capabilities: Vec<String>,
    runtime_components: Vec<String>,
    runtime_artifacts: Vec<String>,
}

fn worker_integrity(
    adapter: AdapterKind,
    artifact: &Path,
    reported_version: Option<&str>,
) -> String {
    let Some((manifest_path, manifest)) = load_release_manifest() else {
        return "development-unverified".to_owned();
    };
    if manifest.protocol_version != "1.0" {
        return format!(
            "error: release manifest protocol {} is incompatible",
            manifest.protocol_version
        );
    }
    if manifest.release_version != env!("CARGO_PKG_VERSION") {
        return format!(
            "error: release manifest version {} does not match core {}",
            manifest.release_version,
            env!("CARGO_PKG_VERSION")
        );
    }
    let Some(entry) = manifest
        .workers
        .iter()
        .find(|entry| entry.adapter == adapter.name())
    else {
        return format!("error: {} is absent from release manifest", adapter.name());
    };
    if adapter == AdapterKind::Rust {
        let Some(backend) = &entry.backend else {
            return "error: Rust worker backend attestation is missing".to_owned();
        };
        if backend.kind != RUST_BACKEND_KIND
            || backend.version != RUST_BACKEND_VERSION
            || backend.revision != RUST_BACKEND_REVISION
            || backend.salsa_version != RUST_BACKEND_SALSA_VERSION
        {
            return "error: Rust worker backend attestation does not match core".to_owned();
        }
        if let Some(reported) = reported_version
            && let Err(error) = verify_rust_release_handshake(
                reported,
                &entry.version,
                &backend.kind,
                &backend.version,
                &backend.revision,
                &backend.salsa_version,
            )
        {
            return format!("error: {error:#}");
        }
    } else if entry.backend.is_some() {
        return format!(
            "error: {} worker unexpectedly declares a Rust backend attestation",
            adapter.name()
        );
    }
    if adapter == AdapterKind::Web {
        let Some(semantic) = &entry.semantic else {
            return "error: Web worker semantic attestation is missing".to_owned();
        };
        if let Err(error) = verify_web_semantic_compatibility(
            &semantic.typescript_version,
            &semantic.capabilities,
            &semantic.runtime_components,
            &semantic.runtime_artifacts,
        ) {
            return format!("error: {error:#}");
        }
        if let Some(reported) = reported_version
            && let Err(error) = verify_web_release_handshake(
                reported,
                &entry.version,
                &semantic.typescript_version,
                &semantic.capabilities,
            )
        {
            return format!("error: {error:#}");
        }
    } else if entry.semantic.is_some() {
        return format!(
            "error: {} worker unexpectedly declares a Web semantic attestation",
            adapter.name()
        );
    }
    if let Some(reported) = reported_version {
        let actual = parse_worker_handshake(reported)
            .map(|(_, version, _)| version)
            .unwrap_or_default();
        if actual != entry.version {
            return format!(
                "error: worker version {actual} does not match release manifest {}",
                entry.version
            );
        }
    }
    let root = manifest_path.parent().unwrap_or(Path::new("."));
    let expected_path = match verify_release_artifact(
        root,
        &entry.path,
        &entry.sha256,
        &format!("{} worker", adapter.name()),
    ) {
        Ok(path) => path,
        Err(error) => return format!("error: {error:#}"),
    };
    let actual_path = artifact
        .canonicalize()
        .unwrap_or_else(|_| artifact.to_path_buf());
    if expected_path != actual_path {
        return format!(
            "error: manifest path {} does not match {}",
            expected_path.display(),
            actual_path.display()
        );
    }
    "verified".to_owned()
}

fn load_release_manifest() -> Option<(PathBuf, ReleaseManifest)> {
    let executable = std::env::current_exe().ok()?;
    let parent = executable.parent()?;
    for candidate in [
        parent.join("release-manifest.json"),
        parent.join("../release-manifest.json"),
    ] {
        if let Ok(raw) = std::fs::read_to_string(&candidate)
            && let Ok(manifest) = serde_json::from_str(&raw)
        {
            return Some((candidate, manifest));
        }
    }
    None
}

fn release_health() -> Option<ReleaseHealth> {
    let (manifest_path, manifest) = load_release_manifest()?;
    let root = manifest_path.parent().unwrap_or(Path::new("."));
    let executable = std::env::current_exe().ok()?;
    let mut runtime_integrity: BTreeMap<String, String> = manifest
        .project_licenses
        .iter()
        .map(|artifact| {
            (
                format!("project-license:{}", artifact.path),
                artifact_integrity(root, artifact, None),
            )
        })
        .chain(manifest.runtime_artifacts.iter().map(|artifact| {
            (
                artifact.path.clone(),
                artifact_integrity(root, artifact, None),
            )
        }))
        .collect();
    for component in &manifest.runtime_components {
        let key = format!("component:{}@{}", component.name, component.version);
        let integrity = match verify_release_runtime_component(
            root,
            &component.name,
            &component.version,
            &component.kind,
            &component.root,
            component.entrypoint.as_deref(),
            &component.sha256,
        ) {
            Ok(()) => "verified".to_owned(),
            Err(error) => format!("error: {error:#}"),
        };
        runtime_integrity.insert(key, integrity);
    }
    Some(ReleaseHealth {
        version: manifest.release_version,
        target: manifest.target,
        schema_version: manifest.schema_version,
        license_expression: manifest.license_expression,
        core_integrity: artifact_integrity(root, &manifest.core, Some(&executable)),
        schema_integrity: artifact_integrity(root, &manifest.schema, None),
        runtime_integrity,
        runtime_requirements: manifest.runtime_requirements,
    })
}

fn artifact_integrity(root: &Path, artifact: &ReleaseArtifact, expected: Option<&Path>) -> String {
    let path = match verify_release_artifact(root, &artifact.path, &artifact.sha256, "artifact") {
        Ok(path) => path,
        Err(error) => return format!("error: {error:#}"),
    };
    if let Some(expected) = expected {
        let expected = expected
            .canonicalize()
            .unwrap_or_else(|_| expected.to_path_buf());
        if path != expected {
            return format!(
                "error: manifest path {} does not match {}",
                path.display(),
                expected.display()
            );
        }
    }
    "verified".to_owned()
}

async fn toolchain_versions(root: &Path) -> BTreeMap<String, String> {
    let mut versions = BTreeMap::new();
    for (name, command, argument) in [
        ("rust", "rustc", "--version"),
        ("go", "go", "version"),
        ("node", "node", "--version"),
    ] {
        let version = probe_toolchain_version(command, argument, root)
            .await
            .ok()
            .unwrap_or_else(|| "unavailable".to_owned());
        versions.insert(name.to_owned(), version);
    }
    versions
}

pub fn open_store(path: &Path) -> Result<Store> {
    Store::open(path)
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, path::PathBuf};

    use super::{
        AdapterKind, DoctorWorkerLocation, parse_worker_handshake, preflight_doctor_workers,
        suppressed_worker_health, worker,
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
        }
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
                let health = suppressed_worker_health(adapter, spec);
                assert!(!health.available);
                assert!(health.command.is_some());
                assert!(health.version.is_none());
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
}
