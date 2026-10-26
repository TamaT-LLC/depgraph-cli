use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH, canonicalize_executable,
    doctor::parse_worker_handshake,
    release_compatibility::{
        ReleaseCompatibilityHealth, cross_language_release_compatibility_contract,
        release_compatibility_contract,
    },
    worker::{
        self, AdapterKind, RUST_BACKEND_KIND, RUST_BACKEND_REVISION, RUST_BACKEND_SALSA_VERSION,
        RUST_BACKEND_VERSION, verify_release_artifact, verify_release_runtime_component,
        verify_rust_release_handshake, verify_web_release_handshake,
        verify_web_semantic_compatibility,
    },
};

#[derive(Debug, Clone, Serialize)]
pub struct ReleaseHealth {
    pub version: String,
    pub target: String,
    pub schema_version: String,
    pub compatibility: ReleaseCompatibilityHealth,
    pub compatibility_integrity: String,
    pub license_expression: String,
    pub core_integrity: String,
    pub schema_integrity: String,
    pub runtime_integrity: BTreeMap<String, String>,
    pub runtime_requirements: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct ReleaseManifest {
    release_version: String,
    protocol_version: String,
    schema_version: String,
    compatibility: ReleaseCompatibilityHealth,
    target: String,
    license_expression: String,
    project_licenses: Vec<ReleaseArtifact>,
    core: ReleaseArtifact,
    schema: ReleaseArtifact,
    query_fixture: ReleaseArtifact,
    cross_language_fixture: ReleaseArtifact,
    cross_language_schemas: Vec<ReleaseArtifact>,
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
    license: String,
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

pub(crate) fn worker_integrity(
    adapter: AdapterKind,
    artifact: &Path,
    reported_version: Option<&str>,
) -> String {
    let (manifest_path, manifest) = match load_release_manifest() {
        Ok(Some(release)) => release,
        Ok(None) => return "development-unverified".to_owned(),
        Err(error) => return format!("error: {error:#}"),
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
    if let Err(error) = verify_release_compatibility(&manifest.compatibility) {
        return format!("error: {error:#}");
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

fn parse_release_manifest(path: &Path) -> Result<ReleaseManifest> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read release manifest {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("invalid release manifest {}", path.display()))
}

fn canonical_current_executable() -> Result<PathBuf> {
    let executable =
        std::env::current_exe().context("failed to locate the running depgraph executable")?;
    canonicalize_executable(&executable, "the running depgraph executable")
}

fn load_release_manifest() -> Result<Option<(PathBuf, ReleaseManifest)>> {
    let executable = canonical_current_executable()?;
    load_release_manifest_for_executable(&executable)
}

fn load_release_manifest_for_executable(
    executable: &Path,
) -> Result<Option<(PathBuf, ReleaseManifest)>> {
    let parent = executable
        .parent()
        .context("running depgraph executable has no parent directory")?;
    let mut candidates = vec![parent.join("release-manifest.json")];
    if let Some(release_root) = parent.parent() {
        candidates.push(release_root.join("release-manifest.json"));
    }
    for candidate in candidates {
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => {
                return Ok(Some((
                    candidate.clone(),
                    parse_release_manifest(&candidate)?,
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect release manifest candidate {}",
                        candidate.display()
                    )
                });
            }
        }
    }
    Ok(None)
}

pub(crate) fn release_health() -> Result<Option<ReleaseHealth>> {
    let executable = canonical_current_executable()?;
    let Some((manifest_path, manifest)) = load_release_manifest_for_executable(&executable)? else {
        return Ok(None);
    };
    let root = manifest_path.parent().unwrap_or(Path::new("."));
    let query_fixture_integrity = if manifest.query_fixture.path
        != BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH
        || format!("sha256:{}", manifest.query_fixture.sha256)
            != manifest.compatibility.bounded_query.fixture_sha256
    {
        "error: bounded query fixture identity does not match the compatibility contract".to_owned()
    } else {
        artifact_integrity(root, &manifest.query_fixture, None)
    };
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
    runtime_integrity.insert("bounded-query-contract".to_owned(), query_fixture_integrity);
    let cross_language_contract = cross_language_release_compatibility_contract();
    let cross_language_fixture_integrity = if manifest.cross_language_fixture.path
        != cross_language_contract.fixture_path
        || format!("sha256:{}", manifest.cross_language_fixture.sha256)
            != cross_language_contract.fixture_sha256
    {
        "error: cross-language fixture identity does not match the compatibility contract"
            .to_owned()
    } else {
        artifact_integrity(root, &manifest.cross_language_fixture, None)
    };
    runtime_integrity.insert(
        "cross-language-contract-fixture".to_owned(),
        cross_language_fixture_integrity,
    );
    let declared_cross_language_schemas = manifest
        .cross_language_schemas
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    for expected in cross_language_contract.schemas {
        let integrity = declared_cross_language_schemas
            .get(expected.path.as_str())
            .filter(|artifact| format!("sha256:{}", artifact.sha256) == expected.sha256)
            .map_or_else(
                || "error: missing or incompatible cross-language schema".to_owned(),
                |artifact| artifact_integrity(root, artifact, None),
            );
        runtime_integrity.insert(
            format!("cross-language-schema:{}", expected.path),
            integrity,
        );
    }
    for component in &manifest.runtime_components {
        let key = format!("component:{}@{}", component.name, component.version);
        let integrity = match verify_release_runtime_component(
            root,
            &worker::ReleaseRuntimeComponentAttestation {
                name: &component.name,
                version: &component.version,
                kind: &component.kind,
                root: &component.root,
                entrypoint: component.entrypoint.as_deref(),
                license: &component.license,
                sha256: &component.sha256,
            },
        ) {
            Ok(()) => "verified".to_owned(),
            Err(error) => format!("error: {error:#}"),
        };
        runtime_integrity.insert(key, integrity);
    }
    let compatibility_integrity = verify_release_compatibility(&manifest.compatibility)
        .map(|()| "verified".to_owned())
        .unwrap_or_else(|error| format!("error: {error:#}"));
    Ok(Some(ReleaseHealth {
        version: manifest.release_version,
        target: manifest.target,
        schema_version: manifest.schema_version,
        compatibility: manifest.compatibility,
        compatibility_integrity,
        license_expression: manifest.license_expression,
        // The MCP server and the operation runner read the same manifest from
        // their own process; the core identity check only applies to the core.
        core_integrity: artifact_integrity(
            root,
            &manifest.core,
            Path::new(&manifest.core.path)
                .file_name()
                .is_some_and(|name| Some(name) == executable.file_name())
                .then_some(executable.as_path()),
        ),
        schema_integrity: artifact_integrity(root, &manifest.schema, None),
        runtime_integrity,
        runtime_requirements: manifest.runtime_requirements,
    }))
}

pub(crate) fn verify_release_compatibility(
    compatibility: &ReleaseCompatibilityHealth,
) -> Result<()> {
    let expected = release_compatibility_contract();
    if compatibility != &expected {
        anyhow::bail!(
            "release compatibility metadata does not match the core contract: expected {expected:?}, found {compatibility:?}"
        );
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use depgraph_store::STORE_SCHEMA_VERSION;

    use super::{
        parse_release_manifest, release_compatibility_contract, verify_release_compatibility,
    };

    #[test]
    fn release_compatibility_contract_rejects_drift() {
        let compatible = release_compatibility_contract();
        verify_release_compatibility(&compatible).unwrap();
        assert_eq!(compatible.worker_protocol_version, "1.0");
        assert_eq!(compatible.store_schema_version, STORE_SCHEMA_VERSION);
        assert_eq!(compatible.operation_journal_schema_version, 6);
        assert_eq!(
            compatible.mcp_tool_contract_version,
            "depgraph-mcp-tools-v1"
        );
        assert_eq!(
            compatible.mcp_operation_contract_version,
            "depgraph-operation-v2"
        );
        assert_eq!(compatible.stable_release_version, "0.7.3");
        assert_eq!(compatible.previous_release_version, "0.5.4");
        assert_eq!(compatible.previous_release_store_schema_version, 17);
        assert_eq!(compatible.stable_upgrade_source_version, "0.4.0-rc.6");
        assert_eq!(compatible.stable_upgrade_source_store_schema_version, 13);

        let mut drifted = compatible.clone();
        drifted.store_schema_version += 1;
        assert!(
            verify_release_compatibility(&drifted)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );

        let mut journal_drifted = compatible.clone();
        journal_drifted.operation_journal_schema_version += 1;
        assert!(verify_release_compatibility(&journal_drifted).is_err());

        let mut mcp_drifted = compatible.clone();
        mcp_drifted.mcp_tool_contract_version = "depgraph-mcp-tools-v2".to_owned();
        assert!(verify_release_compatibility(&mcp_drifted).is_err());

        let mut collector_drifted = compatible.clone();
        collector_drifted.runtime_collector_contract_version = "runtime-collector-v2".to_owned();
        assert!(
            verify_release_compatibility(&collector_drifted)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );

        let mut profile_selection_drifted = compatible.clone();
        profile_selection_drifted
            .profile_selection
            .selection_contract_version = "default-profile-selection-v2".to_owned();
        assert!(
            verify_release_compatibility(&profile_selection_drifted)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );

        let mut framework_build_drifted = compatible;
        framework_build_drifted.framework_build_graph_contract_version =
            "framework-build-graph-v2".to_owned();
        assert!(
            verify_release_compatibility(&framework_build_drifted)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );

        let mut framework_capability_drifted = release_compatibility_contract();
        framework_capability_drifted.framework_build_capabilities[0].observer_version =
            "9.9.9".to_owned();
        assert!(
            verify_release_compatibility(&framework_capability_drifted)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );

        let mut rust_sysroot_drifted = release_compatibility_contract();
        rust_sysroot_drifted.rust_sysroot.toolchain_commit =
            "0000000000000000000000000000000000000000".to_owned();
        assert!(
            verify_release_compatibility(&rust_sysroot_drifted)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );

        let mut query_drifted = release_compatibility_contract();
        query_drifted.bounded_query.result_schema_version = "bounded-query-result-v2".to_owned();
        assert!(
            verify_release_compatibility(&query_drifted)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );

        let mut cross_language_drifted = release_compatibility_contract();
        cross_language_drifted.cross_language.capabilities.pop();
        assert!(
            verify_release_compatibility(&cross_language_drifted)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );
    }

    #[test]
    fn stale_release_manifest_is_an_explicit_parse_error() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let manifest_path = temp.path().join("release-manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "release_version": "0.2.0-rc.1",
                "protocol_version": "1.0",
                "schema_version": "1.0",
                "target": "legacy-target",
                "license_expression": "MIT OR Apache-2.0",
                "project_licenses": [],
                "core": {"path": "bin/depgraph", "sha256": "legacy"},
                "schema": {"path": "schemas/depgraph-protocol-v1.schema.json", "sha256": "legacy"},
                "workers": [],
            }))?,
        )?;

        let error = match parse_release_manifest(&manifest_path) {
            Ok(_) => panic!("stale manifest unexpectedly parsed"),
            Err(error) => error,
        };
        let message = format!("{error:#}");
        assert!(message.contains("invalid release manifest"));
        assert!(message.contains("missing field `compatibility`"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn release_manifest_lookup_resolves_external_executable_symlink() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        use anyhow::Context as _;

        use super::{canonicalize_executable, load_release_manifest_for_executable};

        let temp = tempfile::tempdir()?;
        let release = temp.path().join("release");
        let executable = release.join("bin/depgraph");
        std::fs::create_dir_all(
            executable
                .parent()
                .context("test executable has no parent")?,
        )?;
        std::fs::write(&executable, b"test executable")?;
        let manifest = release.join("release-manifest.json");
        std::fs::write(
            &manifest,
            serde_json::to_vec(&serde_json::json!({
                "release_version": env!("CARGO_PKG_VERSION"),
                "protocol_version": "1.0",
                "schema_version": "1.0",
                "compatibility": release_compatibility_contract(),
                "target": "test-target",
                "license_expression": "MIT OR Apache-2.0",
                "project_licenses": [],
                "core": {"path": "bin/depgraph", "sha256": "0"},
                "schema": {"path": "schemas/depgraph-protocol-v1.schema.json", "sha256": "0"},
                "query_fixture": {"path": "queries/bounded.query", "sha256": "0"},
                "cross_language_fixture": {"path": "fixtures/cross-language.json", "sha256": "0"},
                "cross_language_schemas": [],
                "workers": []
            }))?,
        )?;
        let alias = temp.path().join("depgraph-alias");
        symlink(&executable, &alias)?;

        let canonical = canonicalize_executable(&alias, "test depgraph executable")?;
        let (found_manifest, _) = load_release_manifest_for_executable(&canonical)?
            .context("release manifest was not found through the canonical executable")?;
        assert_eq!(found_manifest.canonicalize()?, manifest.canonicalize()?);
        Ok(())
    }
}
