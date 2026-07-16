pub mod config;
pub mod export;
pub mod query;
pub mod scan;
pub mod worker;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::Result;
use depgraph_store::{
    AdapterLogRecord, CoverageRecord, DiagnosticRecord, FileCoverageRecord, ProfileRecord, Store,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use config::{Config, default_store_path, init_config};
pub use depgraph_store::GraphSnapshot;
pub use export::{ExportFormat, export};
pub use query::{
    CycleLevel, CycleResult, TraversalResult, UnresolvedResult, WhyResult, cycles,
    render_condition, resolve_selector, traverse, unresolved, why,
};
pub use scan::{ScanOutcome, run_scan};

use worker::{
    AdapterKind, locate_worker, probe_toolchain_version, probe_worker_version,
    verify_release_runtime_component,
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
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub protocol_version: &'static str,
    pub graph_schema_version: &'static str,
    pub store_schema_version: i64,
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
    pub core_integrity: String,
    pub schema_integrity: String,
    pub runtime_integrity: BTreeMap<String, String>,
    pub runtime_requirements: BTreeMap<String, String>,
}

pub async fn doctor(store: &Store) -> Result<DoctorReport> {
    let root = std::env::current_dir()?.canonicalize()?;
    let mut workers = Vec::new();
    for adapter in [AdapterKind::Rust, AdapterKind::Go, AdapterKind::Web] {
        workers.push(match locate_worker(adapter) {
            Ok(spec) => {
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
            Err(error) => WorkerHealth {
                adapter: adapter.name().to_owned(),
                available: false,
                command: None,
                version: None,
                integrity: "unavailable".to_owned(),
                error: Some(error.to_string()),
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
                scan_id,
                status: snapshot.scan.status,
                root: snapshot.scan.root,
                project_code_executed: snapshot.scan.project_code_executed,
                coverage: snapshot.coverage,
                profiles: snapshot.profiles,
                file_coverage: snapshot.file_coverage,
                adapter_logs: snapshot.adapter_logs,
                detected_packages,
                diagnostics: snapshot.diagnostics,
            })
        })
        .transpose()?;
    Ok(DoctorReport {
        protocol_version: "1.0",
        graph_schema_version: "1.0",
        store_schema_version: store.schema_version()?,
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
    root: String,
    entrypoint: String,
    sha256: String,
}

#[derive(Deserialize)]
struct ReleaseWorker {
    adapter: String,
    version: String,
    path: String,
    sha256: String,
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
    let Some(entry) = manifest
        .workers
        .iter()
        .find(|entry| entry.adapter == adapter.name())
    else {
        return format!("error: {} is absent from release manifest", adapter.name());
    };
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
    let expected_path = manifest_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(&entry.path)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(&entry.path));
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
    match std::fs::read(&actual_path) {
        Ok(bytes) => {
            let digest = hex::encode(Sha256::digest(bytes));
            if digest == entry.sha256 {
                "verified".to_owned()
            } else {
                "error: worker checksum mismatch".to_owned()
            }
        }
        Err(error) => format!("error: could not read worker for checksum: {error}"),
    }
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
        .runtime_artifacts
        .iter()
        .map(|artifact| {
            (
                artifact.path.clone(),
                artifact_integrity(root, artifact, None),
            )
        })
        .collect();
    for component in &manifest.runtime_components {
        let key = format!("component:{}@{}", component.name, component.version);
        let integrity = match verify_release_runtime_component(
            root,
            &component.name,
            &component.root,
            &component.entrypoint,
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
        core_integrity: artifact_integrity(root, &manifest.core, Some(&executable)),
        schema_integrity: artifact_integrity(root, &manifest.schema, None),
        runtime_integrity,
        runtime_requirements: manifest.runtime_requirements,
    })
}

fn artifact_integrity(root: &Path, artifact: &ReleaseArtifact, expected: Option<&Path>) -> String {
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let path = canonical_root
        .join(&artifact.path)
        .canonicalize()
        .unwrap_or_else(|_| canonical_root.join(&artifact.path));
    if !path.starts_with(&canonical_root) {
        return "error: artifact path escapes release root".to_owned();
    }
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
    match std::fs::read(path) {
        Ok(bytes) if hex::encode(Sha256::digest(&bytes)) == artifact.sha256 => {
            "verified".to_owned()
        }
        Ok(_) => "error: checksum mismatch".to_owned(),
        Err(error) => format!("error: could not read artifact: {error}"),
    }
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
    use super::parse_worker_handshake;

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
}
