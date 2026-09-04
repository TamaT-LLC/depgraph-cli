use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    future::Future,
    io::{Cursor, Write},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use depgraph_protocol::{
    CompletenessLevel, EvidenceKind, MAX_EVENT_LINE_BYTES, Phase, Precision, ProtocolError,
    ProtocolEvent, ProtocolValidator, ResolutionStatus, ValidatedDelta, WorkerDeltaRequest,
    validate_delta_ndjson, validate_semantic_contract,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    time::timeout,
};
use walkdir::WalkDir;

use crate::{
    BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH, BOUNDED_QUERY_RELEASE_SMOKE_QUERY,
    RUST_SYSROOT_COMPONENT_NAME, RUST_SYSROOT_COMPONENT_ROOT, RUST_SYSROOT_COMPONENT_VERSION,
    RUST_SYSROOT_LICENSE_EXPRESSION, ReleaseCompatibilityHealth,
    cancellation::CancellationToken,
    config::{ProfileConfig, ScanConfig},
    repository_inventory::{build_repository_file_inventory, write_repository_inventory_file},
    validate_cross_language_worker_protocol, verify_release_compatibility,
};

// Entry points called from this file's own runtime code (delta parsing / validation dispatch).
use crate::worker_web_semantic::{
    WebFrameworkCompletenessState, WebFrameworkSemanticState, WebSemanticCapability,
    discard_web_definition_delta, discard_web_framework_delta, is_web_definition_relation_kind,
    is_web_framework_semantic_delta_event, is_web_framework_semantic_node,
    is_web_framework_semantic_site_kind, is_web_semantic_delta_event,
    is_web_semantic_dependency_edge_kind, is_web_semantic_dependency_site_kind,
    record_web_rejected_site_closure, semantic_contract_failure_is_framework,
    validate_web_definition_graph, validate_web_framework_semantic_graph,
    web_definition_profile_ready, web_framework_completeness_state, web_framework_semantic_state,
    web_semantic_capability,
};
// Contract-string constants referenced only by worker::tests (kept visible to `super::*` there
// without editing every call site in worker/tests.rs; unused outside cfg(test) builds).
#[cfg(test)]
use crate::worker_web_semantic::{
    TYPESCRIPT_ANALYSIS_MODE_DEFINITION_GRAPH, TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_CALL_GRAPH,
    TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_GRAPH, TYPESCRIPT_ANALYSIS_MODE_PROPERTY,
    TYPESCRIPT_CLOSED_LOCAL_CALL_FLOW_ALGORITHM,
    TYPESCRIPT_CLOSED_LOCAL_FRESH_INSTANCE_FLOW_ALGORITHM, TYPESCRIPT_DEFINITION_STATUS_PROPERTY,
    TYPESCRIPT_MAX_TYPE_DESCRIPTOR_CHARS, TYPESCRIPT_PROJECT_STATUS_PROPERTY,
    TYPESCRIPT_SEMANTIC_BACKEND, TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY,
    TYPESCRIPT_SEMANTIC_EMISSION_DEFINITION_GRAPH_V1,
    TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V1,
    TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2,
    TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_GRAPH_V1, TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY,
    TYPESCRIPT_SEMANTIC_EXTRACTOR, TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY,
    TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY, WEB_FRAMEWORK_COMPLETENESS_CAPABILITY_PROPERTY,
    WEB_FRAMEWORK_COMPLETENESS_CAPABILITY_V1, WEB_FRAMEWORK_COMPLETENESS_ISSUE_COUNT_PROPERTY,
    WEB_FRAMEWORK_COMPLETENESS_LEDGER_PROPERTY, WEB_FRAMEWORK_COMPLETENESS_STATUS_PROPERTY,
    WEB_FRAMEWORK_SEMANTIC_CAPABILITY_PROPERTY, WEB_FRAMEWORK_SEMANTIC_CAPABILITY_V1,
    WEB_FRAMEWORK_SEMANTIC_EDGE_COUNT_PROPERTY, WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION,
    WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION_PROPERTY, WEB_FRAMEWORK_SEMANTIC_NODE_COUNT_PROPERTY,
    WEB_FRAMEWORK_SEMANTIC_SITE_COUNT_PROPERTY, WEB_FRAMEWORK_SEMANTIC_STATUS_PROPERTY,
};

pub(crate) const RUST_BACKEND_KIND: &str = "rust-analyzer-library";
pub(crate) const RUST_BACKEND_VERSION: &str = "0.0.330";
pub(crate) const RUST_BACKEND_REVISION: &str = "8954b66d43225e62c92e8bbcc8500191b5cceb1e";
pub(crate) const RUST_BACKEND_SALSA_VERSION: &str = "0.26.1";
const RUST_RELEASE_GATE_ENV: &str = "DEPGRAPH_RUST_RELEASE_GATE";
const RUST_SYSROOT_ROOT_ENV: &str = "DEPGRAPH_RUST_SYSROOT_ROOT";
const RUST_RELEASE_GATE_PENDING: &str = "release-gate-pending";
const RUST_RELEASE_GATE_VERIFIED: &str = "release-gate-verified";
const TYPESCRIPT_RELEASE_GATE_ENV: &str = "DEPGRAPH_TYPESCRIPT_RELEASE_GATE";
const TYPESCRIPT_RELEASE_GATE_PROPERTY: &str = "typescript_release_gate";
const TYPESCRIPT_RELEASE_GATE_PENDING: &str = "release-gate-pending";
const TYPESCRIPT_RELEASE_GATE_VERIFIED: &str = "release-gate-verified";
pub(crate) const TYPESCRIPT_COMPILER_VERSION: &str = "7.0.2";
const WEB_RUNTIME_REQUIREMENT: &str = "Node.js >=24.0.0";
const PROTOCOL_SCHEMA_PATH: &str = "schemas/depgraph-protocol-v1.schema.json";
const PROJECT_LICENSE_EXPRESSION: &str = "MIT OR Apache-2.0";
const PROJECT_LICENSE_PATHS: [&str; 2] = ["LICENSE-APACHE", "LICENSE-MIT"];
const WEB_SEMANTIC_CAPABILITIES: &[&str] = &[
    "astro-component-render-hydration-v1",
    "framework-semantic-completeness-v1",
    "framework-semantic-graph-v1",
    "next-route-component-boundary-v1",
    "tanstack-router-typed-route-v1",
    "tanstack-start-rpc-middleware-v1",
    "typescript-definition-import-type-call-graph-v2",
    "worker-delta-v1",
];
const WEB_SEMANTIC_RUNTIME_COMPONENTS: &[&str] = &[
    "astro-parser-wasm@4.0.0",
    "typescript-native-compiler@7.0.2",
];
const WEB_SEMANTIC_RUNTIME_ARTIFACTS: &[&str] = &[];
const WEB_RUNTIME_ARTIFACT_PATHS: &[&str] = &[
    "libexec/next-build-adapter.mjs",
    "libexec/astro-build-integration.mjs",
    "libexec/tanstack-router-build-observer.mjs",
    "libexec/tanstack-start-build-observer.mjs",
    "libexec/depgraph-web-build-evidence.mjs",
    "libexec/depgraph-runtime-collector.mjs",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdapterKind {
    Rust,
    Go,
    Web,
}

impl AdapterKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::Go => "go",
            Self::Web => "web",
        }
    }

    pub(crate) fn from_name(value: &str) -> Option<Self> {
        match value {
            "rust" => Some(Self::Rust),
            "go" => Some(Self::Go),
            "web" => Some(Self::Web),
            _ => None,
        }
    }

    fn env_override(self) -> &'static str {
        match self {
            Self::Rust => "DEPGRAPH_RUST_WORKER",
            Self::Go => "DEPGRAPH_GO_WORKER",
            Self::Web => "DEPGRAPH_WEB_WORKER",
        }
    }
}

pub(crate) fn worker_capabilities(handshake: &str) -> Vec<String> {
    let Some((_, details)) = handshake.split_once(" (protocol ") else {
        return Vec::new();
    };
    let Some(details) = details.strip_suffix(')') else {
        return Vec::new();
    };
    let mut fields = details
        .split(';')
        .filter_map(|field| field.trim().strip_prefix("capabilities "));
    let Some(value) = fields.next() else {
        return Vec::new();
    };
    if fields.next().is_some() {
        return Vec::new();
    }
    let capabilities = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if capabilities.is_empty()
        || capabilities.windows(2).any(|pair| pair[0] >= pair[1])
        || value.split(',').count() != capabilities.len()
    {
        return Vec::new();
    }
    capabilities
}

#[derive(Debug, Clone)]
pub struct WorkerSpec {
    pub adapter: AdapterKind,
    pub program: OsString,
    pub leading_args: Vec<OsString>,
    pub display: String,
    pub artifact_path: PathBuf,
    pub runtime_requirement: Option<String>,
    pub expected_version: Option<String>,
    pub(crate) release_attested: bool,
    pub(crate) attested_rust_sysroot: Option<PathBuf>,
}

#[derive(Debug)]
pub struct WorkerOutput {
    pub adapter: AdapterKind,
    pub events: Vec<Value>,
    pub stderr: String,
    pub stderr_truncated: bool,
    pub error: Option<String>,
    pub(crate) failure_kind: Option<WorkerFailureKind>,
    pub security_violation: bool,
}

#[derive(Debug)]
pub(crate) struct WorkerDeltaOutput {
    pub adapter: AdapterKind,
    pub delta: Option<ValidatedDelta>,
    pub stderr: String,
    pub stderr_truncated: bool,
    pub error: Option<String>,
    pub(crate) failure_kind: Option<WorkerFailureKind>,
    pub security_violation: bool,
}

#[derive(Debug)]
struct WorkerExecution {
    events: Vec<Value>,
    delta: Option<ValidatedDelta>,
    stderr: String,
    stderr_truncated: bool,
    error: Option<String>,
    failure_kind: Option<WorkerFailureKind>,
    security_violation: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum WorkerFailureKind {
    Timeout,
    Cancelled,
    MalformedProtocol,
    OutputLimit,
    NonzeroExit,
    IncompleteProtocol,
    TaskPanic,
    Other,
}

impl WorkerFailureKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::MalformedProtocol => "malformed-protocol",
            Self::OutputLimit => "output-limit",
            Self::NonzeroExit => "nonzero-exit",
            Self::IncompleteProtocol => "incomplete-protocol",
            Self::TaskPanic => "task-panic",
            Self::Other => "other",
        }
    }
}

fn select_worker_failure_kind(kinds: &[WorkerFailureKind]) -> Option<WorkerFailureKind> {
    const PRECEDENCE: &[WorkerFailureKind] = &[
        WorkerFailureKind::Timeout,
        WorkerFailureKind::Cancelled,
        WorkerFailureKind::NonzeroExit,
        WorkerFailureKind::OutputLimit,
        WorkerFailureKind::MalformedProtocol,
        WorkerFailureKind::IncompleteProtocol,
        WorkerFailureKind::TaskPanic,
        WorkerFailureKind::Other,
    ];
    PRECEDENCE
        .iter()
        .copied()
        .find(|candidate| kinds.contains(candidate))
}

pub fn detect_adapters(root: &Path, _follow_symlinks: bool) -> Result<Vec<AdapterKind>> {
    let mut detected = BTreeSet::new();
    for relative in build_repository_file_inventory(root)?.paths {
        match Path::new(&relative)
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
        {
            "Cargo.toml" => {
                detected.insert(AdapterKind::Rust);
            }
            "go.mod" | "go.work" => {
                detected.insert(AdapterKind::Go);
            }
            "package.json" => {
                detected.insert(AdapterKind::Web);
            }
            _ => {}
        }
    }
    Ok(detected.into_iter().collect())
}

pub fn locate_worker(adapter: AdapterKind) -> Result<WorkerSpec> {
    let executable = canonical_current_executable()?;
    locate_worker_for_executable(adapter, &executable)
}

fn locate_worker_for_executable(adapter: AdapterKind, executable: &Path) -> Result<WorkerSpec> {
    let executable_dir = executable.parent().unwrap_or(Path::new("."));
    if let Some(manifest_path) = release_manifest_path(executable_dir) {
        return locate_verified_bundled_worker_for_executable(
            adapter,
            &manifest_path,
            Some(executable),
        )
        .context("security policy violation: bundled release verification failed");
    }
    if cfg!(feature = "packaged") || looks_like_packaged_layout(executable_dir) {
        bail!("security policy violation: packaged installation is missing release-manifest.json");
    }

    // Overrides are a development/test affordance. Packaged installations
    // always have a release manifest and therefore take the verified branch
    // above before consulting process environment.
    if let Some(override_path) = std::env::var_os(adapter.env_override()) {
        let override_path = PathBuf::from(override_path)
            .canonicalize()
            .with_context(|| {
                format!("{} does not name a readable worker", adapter.env_override())
            })?;
        return Ok(worker_spec_from_path(adapter, override_path, None));
    }

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let binary_name = match adapter {
        AdapterKind::Rust => executable_name("depgraph-rust-worker"),
        AdapterKind::Go => executable_name("depgraph-go-worker"),
        AdapterKind::Web => "depgraph-web-worker.mjs".to_owned(),
    };
    let mut candidates = vec![
        executable_dir.join(&binary_name),
        executable_dir.join("../libexec").join(&binary_name),
    ];
    match adapter {
        AdapterKind::Rust => candidates.push(repo_root.join("target/debug").join(&binary_name)),
        AdapterKind::Go => candidates.push(repo_root.join("workers/go/bin").join(&binary_name)),
        AdapterKind::Web => {
            candidates.push(repo_root.join("workers/web/dist/worker.mjs"));
            candidates.push(repo_root.join("workers/web/dist/index.mjs"));
        }
    }
    if let Some(path) = candidates.into_iter().find(|path| path.is_file()) {
        let requirement = (adapter == AdapterKind::Web).then(|| WEB_RUNTIME_REQUIREMENT.to_owned());
        return Ok(worker_spec_from_path(adapter, path, requirement));
    }
    bail!(
        "{} worker is unavailable; set {} or build the bundled worker",
        adapter.name(),
        adapter.env_override()
    )
}

pub(crate) fn locate_web_build_runtime(file_name: &str, root: &Path) -> Result<PathBuf> {
    let executable = canonical_current_executable()?;
    locate_web_build_runtime_for_executable(file_name, root, &executable)
}

fn locate_web_build_runtime_for_executable(
    file_name: &str,
    root: &Path,
    executable: &Path,
) -> Result<PathBuf> {
    if file_name.contains('/') || file_name.contains('\\') || !file_name.ends_with(".mjs") {
        bail!("security policy violation: invalid Web build runtime artifact name");
    }
    let executable_dir = executable.parent().unwrap_or(Path::new("."));
    if let Some(manifest_path) = release_manifest_path(executable_dir) {
        // Verify the complete compatibility unit and the running core before
        // selecting a build-only runtime artifact from the same manifest.
        locate_verified_bundled_worker_for_executable(
            AdapterKind::Web,
            &manifest_path,
            Some(executable),
        )
        .context("security policy violation: bundled release verification failed")?;
        let release_root = verified_release_root(&manifest_path)?;
        let manifest: BundledManifest = serde_json::from_slice(&std::fs::read(&manifest_path)?)
            .context("security policy violation: invalid release manifest")?;
        let expected_runtime_paths = WEB_RUNTIME_ARTIFACT_PATHS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let declared_runtime_paths = manifest
            .runtime_artifacts
            .iter()
            .map(|artifact| artifact.path.as_str())
            .collect::<BTreeSet<_>>();
        if declared_runtime_paths != expected_runtime_paths
            || manifest.runtime_artifacts.len() != expected_runtime_paths.len()
        {
            bail!(
                "security policy violation: Web build runtime attestation is incomplete or unknown"
            );
        }
        let expected_path = format!("libexec/{file_name}");
        let artifact = manifest
            .runtime_artifacts
            .iter()
            .find(|artifact| artifact.path == expected_path)
            .with_context(|| {
                format!(
                    "security policy violation: release manifest has no required Web build runtime {expected_path}"
                )
            })?;
        return verify_bundled_artifact(&release_root, artifact, "Web build runtime artifact");
    }
    if cfg!(feature = "packaged") || looks_like_packaged_layout(executable_dir) {
        bail!("security policy violation: packaged installation is missing release-manifest.json");
    }
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let candidate = repo_root.join("workers/web/dist").join(file_name);
    let candidate = candidate.canonicalize().with_context(|| {
        format!("Web build runtime {file_name} is unavailable; build the Web worker")
    })?;
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    if candidate.starts_with(canonical_root) || !candidate.is_file() {
        bail!("security policy violation: Web build runtime is inside the project root");
    }
    Ok(candidate)
}

fn canonical_current_executable() -> Result<PathBuf> {
    let executable = std::env::current_exe().context("failed to locate depgraph executable")?;
    crate::canonicalize_executable(&executable, "depgraph executable")
}

#[derive(Debug, Deserialize)]
struct BundledManifest {
    release_version: String,
    protocol_version: String,
    schema_version: String,
    compatibility: ReleaseCompatibilityHealth,
    target: String,
    license_expression: String,
    project_licenses: Vec<BundledArtifact>,
    core: BundledArtifact,
    schema: BundledArtifact,
    query_fixture: BundledArtifact,
    cross_language_fixture: BundledArtifact,
    cross_language_schemas: Vec<BundledArtifact>,
    #[serde(default)]
    runtime_artifacts: Vec<BundledArtifact>,
    #[serde(default)]
    runtime_components: Vec<BundledRuntimeComponent>,
    #[serde(default)]
    runtime_requirements: std::collections::BTreeMap<String, String>,
    workers: Vec<BundledWorker>,
}

#[derive(Debug, Deserialize)]
struct BundledArtifact {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct BundledRuntimeComponent {
    name: String,
    version: String,
    kind: BundledRuntimeComponentKind,
    root: String,
    entrypoint: Option<String>,
    license: String,
    sha256: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum BundledRuntimeComponentKind {
    ExecutableTree,
    DataTree,
}

impl BundledRuntimeComponentKind {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "executable-tree" => Ok(Self::ExecutableTree),
            "data-tree" => Ok(Self::DataTree),
            _ => bail!("security policy violation: unsupported runtime component kind {value}"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct BundledWorker {
    adapter: String,
    version: String,
    #[serde(default)]
    backend: Option<BundledWorkerBackend>,
    #[serde(default)]
    semantic: Option<BundledWebSemanticAttestation>,
    #[serde(flatten)]
    artifact: BundledArtifact,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundledWorkerBackend {
    kind: String,
    version: String,
    revision: String,
    salsa_version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundledWebSemanticAttestation {
    typescript_version: String,
    capabilities: Vec<String>,
    runtime_components: Vec<String>,
    runtime_artifacts: Vec<String>,
}

fn release_manifest_path(executable_dir: &Path) -> Option<PathBuf> {
    let mut candidates = vec![executable_dir.join("release-manifest.json")];
    if let Some(release_root) = executable_dir.parent() {
        candidates.push(release_root.join("release-manifest.json"));
    }
    candidates.into_iter().find(|path| path.is_file())
}

fn looks_like_packaged_layout(executable_dir: &Path) -> bool {
    executable_dir.file_name().is_some_and(|name| name == "bin")
        && executable_dir.join("../libexec").is_dir()
}

#[cfg(test)]
fn locate_verified_bundled_worker(
    adapter: AdapterKind,
    manifest_path: &Path,
) -> Result<WorkerSpec> {
    locate_verified_bundled_worker_for_executable(adapter, manifest_path, None)
}

fn locate_verified_bundled_worker_for_executable(
    adapter: AdapterKind,
    manifest_path: &Path,
    expected_executable: Option<&Path>,
) -> Result<WorkerSpec> {
    let release_root = verified_release_root(manifest_path)?;
    let raw = std::fs::read_to_string(manifest_path).with_context(|| {
        format!(
            "security policy violation: failed to read {}",
            manifest_path.display()
        )
    })?;
    let manifest: BundledManifest = serde_json::from_str(&raw).with_context(|| {
        format!(
            "security policy violation: invalid release manifest {}",
            manifest_path.display()
        )
    })?;
    if manifest.release_version != env!("CARGO_PKG_VERSION") {
        bail!(
            "security policy violation: release manifest version {} does not match core version {}",
            manifest.release_version,
            env!("CARGO_PKG_VERSION")
        );
    }
    if manifest.protocol_version != "1.0" {
        bail!(
            "security policy violation: release manifest protocol {} is incompatible with core protocol 1.0",
            manifest.protocol_version
        );
    }
    verify_release_compatibility(&manifest.compatibility)
        .context("security policy violation: release manifest compatibility is incompatible")?;
    if manifest.schema_version != "1.0" || manifest.target.trim().is_empty() {
        bail!(
            "security policy violation: release manifest has an incompatible schema or empty target"
        );
    }
    if manifest.license_expression != PROJECT_LICENSE_EXPRESSION {
        bail!(
            "security policy violation: release manifest project license expression must be {PROJECT_LICENSE_EXPRESSION}"
        );
    }
    if manifest.project_licenses.len() != PROJECT_LICENSE_PATHS.len() {
        bail!(
            "security policy violation: release manifest must contain exactly the project license files"
        );
    }
    let project_licenses = manifest
        .project_licenses
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact))
        .collect::<std::collections::BTreeMap<_, _>>();
    if project_licenses.len() != PROJECT_LICENSE_PATHS.len() {
        bail!(
            "security policy violation: release manifest contains a duplicate project license path"
        );
    }
    for path in PROJECT_LICENSE_PATHS {
        let artifact = project_licenses.get(path).with_context(|| {
            format!("security policy violation: release manifest is missing project license {path}")
        })?;
        verify_bundled_artifact(&release_root, artifact, "project license")?;
    }

    let expected_core_path = format!("bin/{}", executable_name("depgraph"));
    if manifest.core.path != expected_core_path {
        bail!(
            "security policy violation: release manifest core path does not match {expected_core_path}"
        );
    }
    if manifest.schema.path != PROTOCOL_SCHEMA_PATH {
        bail!(
            "security policy violation: release manifest schema path does not match {PROTOCOL_SCHEMA_PATH}"
        );
    }
    let core = verify_bundled_artifact(&release_root, &manifest.core, "core executable")?;
    if let Some(expected) = expected_executable {
        let expected = expected
            .canonicalize()
            .context("security policy violation: failed to canonicalize the running core")?;
        if core != expected {
            bail!(
                "security policy violation: release manifest core path does not match the running executable"
            );
        }
    }
    verify_bundled_artifact(&release_root, &manifest.schema, "protocol schema")?;
    if manifest.query_fixture.path != BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH
        || format!("sha256:{}", manifest.query_fixture.sha256)
            != manifest.compatibility.bounded_query.fixture_sha256
    {
        bail!(
            "security policy violation: release manifest bounded query fixture identity is incompatible"
        );
    }
    let query_fixture = verify_bundled_artifact(
        &release_root,
        &manifest.query_fixture,
        "bounded query fixture",
    )?;
    if std::fs::read_to_string(query_fixture)? != BOUNDED_QUERY_RELEASE_SMOKE_QUERY {
        bail!(
            "security policy violation: bounded query fixture differs from the compiled contract"
        );
    }
    let cross_language_contract = crate::cross_language_release_compatibility_contract();
    if manifest.cross_language_fixture.path != cross_language_contract.fixture_path
        || format!("sha256:{}", manifest.cross_language_fixture.sha256)
            != cross_language_contract.fixture_sha256
    {
        bail!(
            "security policy violation: release manifest cross-language fixture identity is incompatible"
        );
    }
    let cross_language_fixture = verify_bundled_artifact(
        &release_root,
        &manifest.cross_language_fixture,
        "cross-language fixture",
    )?;
    if std::fs::read_to_string(cross_language_fixture)?
        != crate::CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE
    {
        bail!(
            "security policy violation: cross-language fixture differs from the compiled contract"
        );
    }
    let declared_cross_language_schemas = manifest
        .cross_language_schemas
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact))
        .collect::<std::collections::BTreeMap<_, _>>();
    if declared_cross_language_schemas.len() != cross_language_contract.schemas.len()
        || manifest.cross_language_schemas.len() != cross_language_contract.schemas.len()
    {
        bail!(
            "security policy violation: release manifest cross-language schema closure is incomplete"
        );
    }
    for schema in cross_language_contract.schemas {
        let artifact = declared_cross_language_schemas
            .get(schema.path.as_str())
            .with_context(|| {
                format!(
                    "security policy violation: release manifest is missing cross-language schema {}",
                    schema.path
                )
            })?;
        if format!("sha256:{}", artifact.sha256) != schema.sha256 {
            bail!(
                "security policy violation: release manifest cross-language schema {} has an incompatible digest",
                schema.path
            );
        }
        verify_bundled_artifact(&release_root, artifact, "cross-language schema")?;
    }

    let expected_runtime_paths = WEB_RUNTIME_ARTIFACT_PATHS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let declared_runtime_paths = manifest
        .runtime_artifacts
        .iter()
        .map(|runtime| runtime.path.as_str())
        .collect::<BTreeSet<_>>();
    if declared_runtime_paths != expected_runtime_paths
        || manifest.runtime_artifacts.len() != WEB_RUNTIME_ARTIFACT_PATHS.len()
    {
        bail!(
            "security policy violation: release manifest Web runtime artifact closure is incomplete or unknown"
        );
    }
    let mut runtime_paths = BTreeSet::new();
    for runtime in &manifest.runtime_artifacts {
        if !runtime_paths.insert(runtime.path.as_str()) {
            bail!(
                "security policy violation: release manifest contains duplicate runtime artifact {}",
                runtime.path
            );
        }
        verify_bundled_artifact(&release_root, runtime, "runtime artifact")?;
    }
    let mut runtime_components = std::collections::BTreeMap::new();
    for component in &manifest.runtime_components {
        if runtime_components
            .insert(component.name.as_str(), component)
            .is_some()
        {
            bail!(
                "security policy violation: release manifest contains duplicate runtime component {}",
                component.name
            );
        }
        verify_bundled_runtime_component(&release_root, component)?;
    }

    let astro = runtime_components.get("astro-parser-wasm").context(
        "security policy violation: release manifest has no required Web runtime component astro-parser-wasm",
    )?;
    if astro.version != "4.0.0"
        || astro.kind != BundledRuntimeComponentKind::DataTree
        || astro.root != "libexec/astro"
        || astro.entrypoint.as_deref() != Some("libexec/astro/astro.wasm")
        || astro.license != "MIT"
    {
        bail!(
            "security policy violation: Astro parser runtime component does not match 4.0.0 at libexec/astro/astro.wasm"
        );
    }
    let typescript = runtime_components
        .get("typescript-native-compiler")
        .context(
            "security policy violation: release manifest has no required Web runtime component typescript-native-compiler",
        )?;
    let expected_typescript_entrypoint =
        format!("libexec/typescript/lib/{}", executable_name("tsc"));
    if typescript.version != "7.0.2"
        || typescript.kind != BundledRuntimeComponentKind::ExecutableTree
        || typescript.root != "libexec/typescript/lib"
        || typescript.entrypoint.as_deref() != Some(expected_typescript_entrypoint.as_str())
        || typescript.license != "Apache-2.0"
    {
        bail!(
            "security policy violation: TypeScript runtime component does not match 7.0.2 at {expected_typescript_entrypoint}"
        );
    }
    let rust_sysroot = runtime_components.get(RUST_SYSROOT_COMPONENT_NAME).context(
        "security policy violation: release manifest has no required Rust sysroot source component",
    )?;
    if rust_sysroot.version != RUST_SYSROOT_COMPONENT_VERSION
        || rust_sysroot.kind != BundledRuntimeComponentKind::DataTree
        || rust_sysroot.root != RUST_SYSROOT_COMPONENT_ROOT
        || rust_sysroot.entrypoint.is_some()
        || rust_sysroot.license != RUST_SYSROOT_LICENSE_EXPRESSION
    {
        bail!(
            "security policy violation: Rust sysroot source component does not match the pinned release compatibility unit"
        );
    }
    if manifest.runtime_requirements.get("web").map(String::as_str) != Some(WEB_RUNTIME_REQUIREMENT)
    {
        bail!(
            "security policy violation: release manifest Web runtime requirement must be {WEB_RUNTIME_REQUIREMENT}"
        );
    }

    let mut workers = std::collections::BTreeMap::new();
    for worker in &manifest.workers {
        if !matches!(worker.adapter.as_str(), "rust" | "go" | "web") {
            bail!(
                "security policy violation: release manifest contains unknown worker adapter {}",
                worker.adapter
            );
        }
        if workers.contains_key(worker.adapter.as_str()) {
            bail!(
                "security policy violation: release manifest contains duplicate {} workers",
                worker.adapter
            );
        }
        if worker.adapter != "rust" && worker.backend.is_some() {
            bail!(
                "security policy violation: {} worker cannot declare a Rust backend attestation",
                worker.adapter
            );
        }
        if worker.adapter == "web" {
            verify_web_worker_manifest(worker)?;
        } else if worker.semantic.is_some() {
            bail!(
                "security policy violation: {} worker cannot declare a Web semantic attestation",
                worker.adapter
            );
        }
        let expected_worker_path = if worker.adapter == "web" {
            "libexec/depgraph-web-worker.mjs".to_owned()
        } else {
            format!(
                "libexec/{}",
                executable_name(&format!("depgraph-{}-worker", worker.adapter))
            )
        };
        if worker.artifact.path != expected_worker_path {
            bail!(
                "security policy violation: {} worker path does not match {expected_worker_path}",
                worker.adapter
            );
        }
        if worker.version != env!("CARGO_PKG_VERSION") {
            bail!(
                "security policy violation: {} worker version {} does not match core version {}",
                worker.adapter,
                worker.version,
                env!("CARGO_PKG_VERSION")
            );
        }
        let artifact = verify_bundled_artifact(
            &release_root,
            &worker.artifact,
            &format!("{} worker", worker.adapter),
        )?;
        if worker.adapter != "web" && !is_executable_file(&artifact) {
            bail!(
                "security policy violation: bundled {} worker is not executable",
                worker.adapter
            );
        }
        workers.insert(worker.adapter.as_str(), (worker, artifact));
    }

    for required in ["rust", "go", "web"] {
        if !workers.contains_key(required) {
            bail!("security policy violation: release manifest has no {required} worker");
        }
    }
    verify_rust_worker_manifest(workers["rust"].0)?;

    let (entry, artifact) = workers.get(adapter.name()).with_context(|| {
        format!(
            "security policy violation: release manifest has no {} worker",
            adapter.name()
        )
    })?;
    let runtime_requirement =
        (adapter == AdapterKind::Web).then(|| WEB_RUNTIME_REQUIREMENT.to_owned());
    let mut spec = worker_spec_from_path(adapter, artifact.clone(), runtime_requirement);
    spec.expected_version = Some(entry.version.clone());
    spec.release_attested = matches!(adapter, AdapterKind::Rust | AdapterKind::Web);
    if adapter == AdapterKind::Rust {
        spec.attested_rust_sysroot = Some(
            release_root
                .join(&rust_sysroot.root)
                .canonicalize()
                .context("security policy violation: Rust sysroot component disappeared")?,
        );
    }
    Ok(spec)
}

fn verified_release_root(manifest_path: &Path) -> Result<PathBuf> {
    let manifest_metadata = std::fs::symlink_metadata(manifest_path).with_context(|| {
        format!(
            "security policy violation: release manifest {} is missing",
            manifest_path.display()
        )
    })?;
    if manifest_metadata.file_type().is_symlink() || !manifest_metadata.is_file() {
        bail!(
            "security policy violation: release manifest {} must be a non-symlink regular file",
            manifest_path.display()
        );
    }
    let declared_root = manifest_path.parent().unwrap_or(Path::new("."));
    let root_metadata = std::fs::symlink_metadata(declared_root)
        .context("security policy violation: release root is missing")?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        bail!("security policy violation: release root must be a non-symlink directory");
    }
    declared_root
        .canonicalize()
        .context("security policy violation: failed to canonicalize release root")
}

fn verify_rust_worker_manifest(worker: &BundledWorker) -> Result<()> {
    if worker.version != env!("CARGO_PKG_VERSION") {
        bail!(
            "security policy violation: Rust worker version {} does not match core version {}",
            worker.version,
            env!("CARGO_PKG_VERSION")
        );
    }
    let backend = worker
        .backend
        .as_ref()
        .context("security policy violation: Rust worker has no backend attestation")?;
    if backend.kind != RUST_BACKEND_KIND
        || backend.version != RUST_BACKEND_VERSION
        || backend.revision != RUST_BACKEND_REVISION
        || backend.salsa_version != RUST_BACKEND_SALSA_VERSION
    {
        bail!(
            "security policy violation: Rust worker backend attestation does not match the core compatibility unit"
        );
    }
    Ok(())
}

fn verify_web_worker_manifest(worker: &BundledWorker) -> Result<()> {
    let semantic = worker
        .semantic
        .as_ref()
        .context("security policy violation: Web worker has no semantic compatibility unit")?;
    verify_web_semantic_compatibility(
        &semantic.typescript_version,
        &semantic.capabilities,
        &semantic.runtime_components,
        &semantic.runtime_artifacts,
    )
}

pub(crate) fn verify_web_semantic_compatibility(
    typescript_version: &str,
    capabilities: &[String],
    runtime_components: &[String],
    runtime_artifacts: &[String],
) -> Result<()> {
    let expected_capabilities = WEB_SEMANTIC_CAPABILITIES
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let expected_components = WEB_SEMANTIC_RUNTIME_COMPONENTS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let expected_artifacts = WEB_SEMANTIC_RUNTIME_ARTIFACTS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    if typescript_version != TYPESCRIPT_COMPILER_VERSION
        || capabilities != expected_capabilities
        || runtime_components != expected_components
        || runtime_artifacts != expected_artifacts
    {
        bail!(
            "security policy violation: Web worker semantic attestation does not match the core compatibility unit"
        );
    }
    Ok(())
}

fn verify_node_version(requirement: &str, version: &str) -> Result<()> {
    let minimum = requirement
        .strip_prefix("Node.js >=")
        .with_context(|| format!("unsupported web runtime requirement {requirement:?}"))?;
    let minimum = parse_version_triplet(minimum)
        .with_context(|| format!("invalid web runtime requirement {requirement:?}"))?;
    let actual = parse_version_triplet(version.trim().trim_start_matches('v'))
        .with_context(|| format!("unrecognized Node.js version {version:?}"))?;
    if actual < minimum {
        bail!(
            "Node.js runtime {}.{}.{} does not satisfy {requirement}",
            actual.0,
            actual.1,
            actual.2
        );
    }
    Ok(())
}

fn parse_version_triplet(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.split('-').next()?.parse().ok()?;
    Some((major, minor, patch))
}

pub(crate) fn verify_rust_release_handshake(
    handshake: &str,
    expected_adapter_version: &str,
    expected_backend_kind: &str,
    expected_backend_version: &str,
    expected_backend_revision: &str,
    expected_salsa_version: &str,
) -> Result<()> {
    let (identity, details) = handshake
        .split_once(" (protocol ")
        .context("security policy violation: malformed Rust worker handshake")?;
    let details = details
        .strip_suffix(')')
        .context("security policy violation: malformed Rust worker handshake")?;
    let mut identity = identity.split_whitespace();
    let name = identity.next().unwrap_or_default();
    let adapter_version = identity.next().unwrap_or_default();
    if identity.next().is_some()
        || name != "depgraph-rust-worker"
        || adapter_version != expected_adapter_version
    {
        bail!("security policy violation: Rust worker adapter handshake mismatch");
    }

    let mut fields = details.split("; ");
    let protocol = fields.next().unwrap_or_default();
    let backend_version = fields
        .next()
        .and_then(|field| field.strip_prefix("rust-analyzer "))
        .unwrap_or_default();
    let backend_revision = fields
        .next()
        .and_then(|field| field.strip_prefix("rust-analyzer-revision "))
        .unwrap_or_default();
    let salsa_version = fields
        .next()
        .and_then(|field| field.strip_prefix("salsa "))
        .unwrap_or_default();
    if fields.next().is_some()
        || protocol != "1.0"
        || expected_backend_kind != RUST_BACKEND_KIND
        || backend_version != expected_backend_version
        || backend_revision != expected_backend_revision
        || salsa_version != expected_salsa_version
    {
        bail!("security policy violation: Rust worker backend handshake mismatch");
    }
    Ok(())
}

pub(crate) fn verify_web_release_handshake(
    handshake: &str,
    expected_adapter_version: &str,
    expected_typescript_version: &str,
    expected_capabilities: &[String],
) -> Result<()> {
    let (identity, details) = handshake
        .split_once(" (protocol ")
        .context("security policy violation: malformed Web worker handshake")?;
    let details = details
        .strip_suffix(')')
        .context("security policy violation: malformed Web worker handshake")?;
    let mut identity = identity.split_whitespace();
    let name = identity.next().unwrap_or_default();
    let adapter_version = identity.next().unwrap_or_default();
    if identity.next().is_some()
        || name != "depgraph-web-worker"
        || adapter_version != expected_adapter_version
    {
        bail!("security policy violation: Web worker adapter handshake mismatch");
    }

    let mut fields = details.split("; ");
    let protocol = fields.next().unwrap_or_default();
    let typescript_version = fields
        .next()
        .and_then(|field| field.strip_prefix("typescript "))
        .unwrap_or_default();
    let capabilities = fields
        .next()
        .and_then(|field| field.strip_prefix("capabilities "))
        .map(|value| value.split(',').map(str::to_owned).collect::<Vec<_>>())
        .unwrap_or_default();
    if fields.next().is_some()
        || protocol != "1.0"
        || typescript_version != expected_typescript_version
        || capabilities != expected_capabilities
    {
        bail!("security policy violation: Web worker semantic handshake mismatch");
    }
    Ok(())
}

fn verify_bundled_artifact(
    release_root: &Path,
    entry: &BundledArtifact,
    description: &str,
) -> Result<PathBuf> {
    reject_symlinked_component_path(release_root, &entry.path)?;
    let artifact = release_root
        .join(&entry.path)
        .canonicalize()
        .with_context(|| {
            format!(
                "security policy violation: bundled {description} {} is missing",
                entry.path
            )
        })?;
    if !artifact.starts_with(release_root) {
        bail!("security policy violation: bundled {description} path escapes the release root");
    }
    if !artifact.is_file() {
        bail!("security policy violation: bundled {description} is not a regular file");
    }
    let actual = hex::encode(Sha256::digest(std::fs::read(&artifact).with_context(
        || format!("security policy violation: failed to read bundled {description}"),
    )?));
    if actual != entry.sha256 {
        bail!("security policy violation: bundled {description} checksum mismatch");
    }
    Ok(artifact)
}

pub(crate) fn verify_release_artifact(
    release_root: &Path,
    path: &str,
    sha256: &str,
    description: &str,
) -> Result<PathBuf> {
    let release_root = release_root
        .canonicalize()
        .context("security policy violation: failed to canonicalize release root")?;
    verify_bundled_artifact(
        &release_root,
        &BundledArtifact {
            path: path.to_owned(),
            sha256: sha256.to_owned(),
        },
        description,
    )
}

fn runtime_tree_digest(root: &Path) -> Result<String> {
    let mut entries = Vec::new();
    for entry in WalkDir::new(root).follow_links(false).min_depth(1) {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!(
                "security policy violation: symlink in bundled runtime component {}",
                entry.path().display()
            );
        }
        if entry.file_type().is_file() {
            let relative = entry
                .path()
                .strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/");
            entries.push((relative, true, entry.path().to_path_buf()));
        } else if entry.file_type().is_dir() {
            let relative = entry
                .path()
                .strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/");
            entries.push((relative, false, entry.path().to_path_buf()));
        } else {
            bail!(
                "security policy violation: unsupported entry in bundled runtime component {}",
                entry.path().display()
            );
        }
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    if !entries.iter().any(|(_, is_file, _)| *is_file) {
        bail!("security policy violation: bundled runtime component is empty");
    }
    let mut digest = Sha256::new();
    digest.update(b"depgraph-runtime-tree-v2\0");
    for (relative, is_file, path) in entries {
        digest.update([if is_file { b'f' } else { b'd' }]);
        let relative = relative.as_bytes();
        digest.update((relative.len() as u64).to_be_bytes());
        digest.update(relative);
        if is_file {
            let content = std::fs::read(&path)?;
            digest.update((content.len() as u64).to_be_bytes());
            digest.update(content);
        } else {
            digest.update(0_u64.to_be_bytes());
        }
    }
    Ok(hex::encode(digest.finalize()))
}

fn verify_bundled_runtime_component(
    release_root: &Path,
    component: &BundledRuntimeComponent,
) -> Result<PathBuf> {
    if component.name.trim().is_empty()
        || component.version.trim().is_empty()
        || component.license.trim().is_empty()
    {
        bail!(
            "security policy violation: bundled runtime component name, version, and license must be non-empty"
        );
    }
    if component.root.trim().is_empty() {
        bail!("security policy violation: bundled runtime component root must be non-empty");
    }
    if component
        .entrypoint
        .as_deref()
        .is_some_and(|entrypoint| entrypoint.trim().is_empty())
    {
        bail!(
            "security policy violation: bundled runtime component entrypoint must be non-empty when present"
        );
    }
    let release_root = release_root
        .canonicalize()
        .context("failed to canonicalize release root for runtime component")?;
    reject_symlinked_component_path(&release_root, &component.root)?;
    if let Some(entrypoint) = &component.entrypoint {
        reject_symlinked_component_path(&release_root, entrypoint)?;
    }
    let declared_root = release_root.join(&component.root);
    if std::fs::symlink_metadata(&declared_root)
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!(
            "security policy violation: bundled runtime component root {} is a symlink",
            component.root
        );
    }
    let root = declared_root.canonicalize().with_context(|| {
        format!(
            "security policy violation: bundled runtime component {} is missing",
            component.name
        )
    })?;
    if !root.starts_with(&release_root) || !root.is_dir() {
        bail!(
            "security policy violation: bundled runtime component {} escapes the release root",
            component.name
        );
    }
    let entrypoint = component
        .entrypoint
        .as_deref()
        .map(|declared| {
            let entrypoint = release_root.join(declared).canonicalize().with_context(|| {
                format!(
                    "security policy violation: bundled runtime component entrypoint {declared} is missing"
                )
            })?;
            if !entrypoint.starts_with(&root) || !entrypoint.is_file() {
                bail!(
                    "security policy violation: bundled runtime component entrypoint {declared} escapes its root"
                );
            }
            Ok(entrypoint)
        })
        .transpose()?;
    match component.kind {
        BundledRuntimeComponentKind::ExecutableTree => {
            let entrypoint = entrypoint.as_deref().context(
                "security policy violation: executable-tree runtime component has no entrypoint",
            )?;
            if !is_executable_file(entrypoint) {
                bail!(
                    "security policy violation: executable-tree runtime component entrypoint is not executable"
                );
            }
        }
        BundledRuntimeComponentKind::DataTree => {}
    }
    if runtime_tree_digest(&root)? != component.sha256 {
        bail!(
            "security policy violation: bundled runtime component {} checksum mismatch",
            component.name
        );
    }
    Ok(entrypoint.unwrap_or(root))
}

fn reject_symlinked_component_path(release_root: &Path, declared: &str) -> Result<()> {
    let declared = Path::new(declared);
    if declared.is_absolute()
        || declared
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!(
            "security policy violation: invalid bundled runtime component path {}",
            declared.display()
        );
    }
    let mut current = release_root.to_path_buf();
    for component in declared.components() {
        let std::path::Component::Normal(component) = component else {
            unreachable!();
        };
        current.push(component);
        if std::fs::symlink_metadata(&current)
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            bail!(
                "security policy violation: symlink in bundled runtime component path {}",
                current.display()
            );
        }
    }
    Ok(())
}

pub(crate) struct ReleaseRuntimeComponentAttestation<'a> {
    pub(crate) name: &'a str,
    pub(crate) version: &'a str,
    pub(crate) kind: &'a str,
    pub(crate) root: &'a str,
    pub(crate) entrypoint: Option<&'a str>,
    pub(crate) license: &'a str,
    pub(crate) sha256: &'a str,
}

pub(crate) fn verify_release_runtime_component(
    release_root: &Path,
    component: &ReleaseRuntimeComponentAttestation<'_>,
) -> Result<()> {
    verify_bundled_runtime_component(
        release_root,
        &BundledRuntimeComponent {
            name: component.name.to_owned(),
            version: component.version.to_owned(),
            kind: BundledRuntimeComponentKind::parse(component.kind)?,
            root: component.root.to_owned(),
            entrypoint: component.entrypoint.map(ToOwned::to_owned),
            license: component.license.to_owned(),
            sha256: component.sha256.to_owned(),
        },
    )?;
    Ok(())
}

fn worker_spec_from_path(
    adapter: AdapterKind,
    path: PathBuf,
    runtime_requirement: Option<String>,
) -> WorkerSpec {
    if adapter == AdapterKind::Web {
        let entrypoint = process_argument_path(&path);
        WorkerSpec {
            adapter,
            program: OsString::from("node"),
            leading_args: vec![entrypoint.clone()],
            display: format!("node {}", Path::new(&entrypoint).display()),
            artifact_path: path,
            runtime_requirement,
            expected_version: None,
            release_attested: false,
            attested_rust_sysroot: None,
        }
    } else {
        WorkerSpec {
            adapter,
            program: path.clone().into_os_string(),
            leading_args: Vec::new(),
            display: path.display().to_string(),
            artifact_path: path,
            runtime_requirement,
            expected_version: None,
            release_attested: false,
            attested_rust_sysroot: None,
        }
    }
}

// Windows canonicalization deliberately returns a verbatim path (`\\?\...`).
// That form is useful for integrity and confinement checks, but Node.js treats
// a verbatim drive path passed as its entry script as `C:` and fails with
// EISDIR. Preserve the canonical artifact path on WorkerSpec and normalize
// only the argument handed to the external runtime.
#[cfg(windows)]
pub(crate) fn process_argument_path(path: &Path) -> OsString {
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};

    let wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    OsString::from_wide(&without_windows_verbatim_prefix(&wide))
}

#[cfg(not(windows))]
pub(crate) fn process_argument_path(path: &Path) -> OsString {
    path.as_os_str().to_owned()
}

#[cfg(any(windows, test))]
fn without_windows_verbatim_prefix(path: &[u16]) -> Vec<u16> {
    const VERBATIM: &[u16] = &[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    const VERBATIM_UNC: &[u16] = &[
        b'\\' as u16,
        b'\\' as u16,
        b'?' as u16,
        b'\\' as u16,
        b'U' as u16,
        b'N' as u16,
        b'C' as u16,
        b'\\' as u16,
    ];

    if let Some(rest) = path.strip_prefix(VERBATIM_UNC) {
        [b'\\' as u16, b'\\' as u16]
            .into_iter()
            .chain(rest.iter().copied())
            .collect()
    } else if let Some(rest) = path.strip_prefix(VERBATIM) {
        rest.to_vec()
    } else {
        path.to_vec()
    }
}

#[cfg(windows)]
fn executable_name(name: &str) -> String {
    format!("{name}.exe")
}

#[cfg(not(windows))]
fn executable_name(name: &str) -> String {
    name.to_owned()
}

pub async fn execute_worker(
    spec: WorkerSpec,
    root: PathBuf,
    scan_id: String,
    config: ScanConfig,
    profiles: ProfileConfig,
) -> WorkerOutput {
    let adapter = spec.adapter;
    match execute_worker_inner(&spec, &root, &scan_id, &config, &profiles).await {
        Ok(execution) => WorkerOutput {
            adapter,
            events: execution.events,
            stderr: execution.stderr,
            stderr_truncated: execution.stderr_truncated,
            error: execution.error,
            failure_kind: execution.failure_kind,
            security_violation: execution.security_violation,
        },
        Err(error) => {
            let error = format!("{error:#}");
            WorkerOutput {
                adapter,
                events: Vec::new(),
                stderr: String::new(),
                stderr_truncated: false,
                failure_kind: Some(WorkerFailureKind::Other),
                security_violation: is_security_error(&error),
                error: Some(error),
            }
        }
    }
}

pub(crate) async fn execute_worker_with_cancellation(
    spec: WorkerSpec,
    root: PathBuf,
    scan_id: String,
    config: ScanConfig,
    profiles: ProfileConfig,
    cancellation: CancellationToken,
) -> WorkerOutput {
    let adapter = spec.adapter;
    match execute_worker_inner_with_cancellation(
        &spec,
        &root,
        &scan_id,
        &config,
        &profiles,
        None,
        async move {
            cancellation.cancelled().await;
            Ok(())
        },
    )
    .await
    {
        Ok(execution) => WorkerOutput {
            adapter,
            events: execution.events,
            stderr: execution.stderr,
            stderr_truncated: execution.stderr_truncated,
            error: execution.error,
            failure_kind: execution.failure_kind,
            security_violation: execution.security_violation,
        },
        Err(error) => {
            let error = format!("{error:#}");
            WorkerOutput {
                adapter,
                events: Vec::new(),
                stderr: String::new(),
                stderr_truncated: false,
                failure_kind: Some(WorkerFailureKind::Other),
                security_violation: is_security_error(&error),
                error: Some(error),
            }
        }
    }
}

pub(crate) async fn execute_worker_delta_with_cancellation(
    spec: WorkerSpec,
    root: PathBuf,
    config: ScanConfig,
    profiles: ProfileConfig,
    request: WorkerDeltaRequest,
    cancellation: CancellationToken,
) -> WorkerDeltaOutput {
    let adapter = spec.adapter;
    let scan_id = request.scan_id.clone();
    match execute_worker_inner_with_cancellation(
        &spec,
        &root,
        &scan_id,
        &config,
        &profiles,
        Some(&request),
        async move {
            cancellation.cancelled().await;
            Ok(())
        },
    )
    .await
    {
        Ok(execution) => WorkerDeltaOutput {
            adapter,
            delta: execution.delta,
            stderr: execution.stderr,
            stderr_truncated: execution.stderr_truncated,
            error: execution.error,
            failure_kind: execution.failure_kind,
            security_violation: execution.security_violation,
        },
        Err(error) => {
            let error = format!("{error:#}");
            WorkerDeltaOutput {
                adapter,
                delta: None,
                stderr: String::new(),
                stderr_truncated: false,
                failure_kind: Some(WorkerFailureKind::Other),
                security_violation: is_security_error(&error),
                error: Some(error),
            }
        }
    }
}

pub(crate) fn is_security_error(error: &str) -> bool {
    error.starts_with("security policy violation:")
        || error.starts_with("security policy violation at line ")
        || error.starts_with("safe-mode scan reports project_code_executed=true")
        || (error.starts_with("protocol path ") && error.contains(" escapes scan root "))
        || (error.starts_with("bundled ") && error.contains(" checksum mismatch"))
}

async fn execute_worker_inner(
    spec: &WorkerSpec,
    root: &Path,
    scan_id: &str,
    config: &ScanConfig,
    profiles: &ProfileConfig,
) -> Result<WorkerExecution> {
    execute_worker_inner_with_cancellation(
        spec,
        root,
        scan_id,
        config,
        profiles,
        None,
        tokio::signal::ctrl_c(),
    )
    .await
}

async fn execute_worker_inner_with_cancellation<F>(
    spec: &WorkerSpec,
    root: &Path,
    scan_id: &str,
    config: &ScanConfig,
    profiles: &ProfileConfig,
    delta_request: Option<&WorkerDeltaRequest>,
    cancellation: F,
) -> Result<WorkerExecution>
where
    F: Future<Output = std::io::Result<()>>,
{
    let program = resolve_worker_program(spec, root)?;
    tokio::pin!(cancellation);
    if let Some(requirement) = &spec.runtime_requirement {
        let output = run_probe_with_signal(
            &program,
            &[OsString::from("--version")],
            root,
            cancellation.as_mut(),
        )
        .await?;
        if !output.status.success() {
            bail!("Node.js runtime version check failed");
        }
        let version = String::from_utf8(output.stdout)
            .context("Node.js runtime returned a non-UTF-8 version")?;
        verify_node_version(requirement, &version)?;
    }

    let neutral_cwd = neutral_working_directory(root)?;
    let repository_inventory_file = write_repository_inventory_file(root)?;
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let inventory_parent = repository_inventory_file
        .path()
        .parent()
        .context("repository inventory file has no parent")?
        .canonicalize()
        .context("failed to canonicalize repository inventory directory")?;
    if inventory_parent.starts_with(&canonical_root) {
        bail!("security policy violation: repository inventory file is inside the scan root");
    }
    let mut delta_request_file = None;
    if let Some(request) = delta_request {
        request.validate().context("invalid worker delta request")?;
        let mut file = tempfile::Builder::new()
            .prefix("depgraph-worker-delta-")
            .tempfile()
            .context("failed to create worker delta request file")?;
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let request_parent = file
            .path()
            .parent()
            .context("worker delta request file has no parent")?
            .canonicalize()
            .context("failed to canonicalize worker delta request directory")?;
        if request_parent.starts_with(&canonical_root) {
            bail!("security policy violation: worker delta request file is inside the scan root");
        }
        serde_json::to_writer(file.as_file_mut(), request)
            .context("failed to serialize worker delta request")?;
        file.as_file_mut()
            .flush()
            .context("failed to flush worker delta request")?;
        delta_request_file = Some(file);
    }
    let mut command = Command::new(&program);
    command
        .args(&spec.leading_args)
        .arg("--root")
        .arg(root)
        .arg("--scan-id")
        .arg(scan_id)
        .arg("--inventory-file")
        .arg(repository_inventory_file.path())
        .current_dir(&neutral_cwd.path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_clear();
    if let Some(file) = delta_request_file.as_ref() {
        command.arg("--delta-request").arg(file.path());
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.as_std_mut().process_group(0);
    }
    copy_safe_environment(&mut command, root)?;
    command
        .env("DEPGRAPH_SAFE_MODE", "1")
        .env(
            "DEPGRAPH_PROFILE_CONFIG",
            serde_json::to_string(profiles).context("serialize worker profile configuration")?,
        )
        .env("GOPROXY", "off")
        .env("GOSUMDB", "off")
        .env("GOTOOLCHAIN", "local")
        .env("GOPACKAGESDRIVER", "off")
        .env("GOFLAGS", "-mod=readonly")
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_REGISTRY_GLOBAL_CREDENTIAL_PROVIDERS", "cargo:token");
    if spec.adapter == AdapterKind::Rust
        && std::env::var("DEPGRAPH_SCAN_PROFILE").as_deref() == Ok("1")
    {
        command.env("DEPGRAPH_SCAN_PROFILE", "1");
    }
    if spec.adapter == AdapterKind::Rust && spec.release_attested {
        let sysroot = spec.attested_rust_sysroot.as_ref().context(
            "security policy violation: verified Rust worker has no attested sysroot component",
        )?;
        command
            .env(RUST_RELEASE_GATE_ENV, RUST_RELEASE_GATE_VERIFIED)
            .env(RUST_SYSROOT_ROOT_ENV, sysroot);
    }
    if spec.adapter == AdapterKind::Web && spec.release_attested {
        command.env(
            TYPESCRIPT_RELEASE_GATE_ENV,
            TYPESCRIPT_RELEASE_GATE_VERIFIED,
        );
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("failed to start {}", spec.display))?;
    let process_guard = ProcessTreeGuard::attach(&child)
        .with_context(|| format!("failed to isolate {} process tree", spec.display))?;
    let stdout = child
        .stdout
        .take()
        .context("worker stdout pipe is unavailable")?;
    let stderr = child
        .stderr
        .take()
        .context("worker stderr pipe is unavailable")?;
    let stdout_task = tokio::spawn(read_capped(stdout, config.max_protocol_bytes));
    let stderr_task = tokio::spawn(read_capped(stderr, config.max_stderr_bytes));

    let mut errors = Vec::new();
    let mut failure_kinds = Vec::new();
    enum WaitResult {
        Process(
            std::result::Result<
                std::io::Result<std::process::ExitStatus>,
                tokio::time::error::Elapsed,
            >,
        ),
        Cancelled(std::io::Result<()>),
    }
    let wait_result = tokio::select! {
        result = timeout(Duration::from_secs(config.worker_timeout_seconds), child.wait()) => {
            WaitResult::Process(result)
        }
        signal = cancellation.as_mut() => WaitResult::Cancelled(signal),
    };
    match wait_result {
        WaitResult::Process(Ok(Ok(status))) if !status.success() => {
            errors.push(format!("{} exited with {status}", spec.display));
            failure_kinds.push(WorkerFailureKind::NonzeroExit);
        }
        WaitResult::Process(Ok(Ok(_))) => {}
        WaitResult::Process(Ok(Err(error))) => {
            errors.push(format!("failed to wait for {}: {error}", spec.display));
            failure_kinds.push(WorkerFailureKind::Other);
        }
        WaitResult::Process(Err(_)) => {
            errors.push(format!(
                "{} timed out after {} seconds",
                spec.display, config.worker_timeout_seconds
            ));
            failure_kinds.push(WorkerFailureKind::Timeout);
            terminate_worker(&mut child, &process_guard).await;
        }
        WaitResult::Cancelled(signal) => {
            if let Err(error) = signal {
                errors.push(format!("failed to listen for cancellation: {error}"));
                failure_kinds.push(WorkerFailureKind::Other);
            } else {
                errors.push(format!("{} cancelled by user", spec.display));
                failure_kinds.push(WorkerFailureKind::Cancelled);
            }
            terminate_worker(&mut child, &process_guard).await;
        }
    }
    // A well-behaved worker has no live descendants after its direct process
    // exits. Closing the tree here also guarantees inherited pipes reach EOF.
    process_guard.terminate();

    let previous_error_count = errors.len();
    let (stdout_bytes, stdout_truncated) =
        finish_reader(stdout_task, "stdout", &mut errors).await?;
    failure_kinds.extend(std::iter::repeat_n(
        WorkerFailureKind::Other,
        errors.len() - previous_error_count,
    ));
    let previous_error_count = errors.len();
    let (stderr_bytes, stderr_truncated) =
        finish_reader(stderr_task, "stderr", &mut errors).await?;
    failure_kinds.extend(std::iter::repeat_n(
        WorkerFailureKind::Other,
        errors.len() - previous_error_count,
    ));
    let stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();
    let (events, delta, parsed_error, parsed_failure_kind, parsed_security_violation) =
        if let Some(request) = delta_request {
            let parsed = parse_delta_events(
                &stdout_bytes,
                request,
                config.max_protocol_line_bytes,
                spec.expected_version.as_deref(),
            );
            (
                Vec::new(),
                parsed.delta,
                parsed.error,
                parsed.failure_kind,
                parsed.security_violation,
            )
        } else {
            let parsed = parse_events_preserving_prefix(
                &stdout_bytes,
                scan_id,
                spec.adapter.name(),
                root,
                config.max_protocol_line_bytes,
                spec.expected_version.as_deref(),
                Some(spec.release_attested),
            );
            (
                parsed.events,
                None,
                parsed.error,
                parsed.failure_kind,
                parsed.security_violation,
            )
        };
    if stdout_truncated {
        errors.push(format!(
            "{} protocol output exceeded {} bytes",
            spec.display, config.max_protocol_bytes
        ));
        failure_kinds.push(WorkerFailureKind::OutputLimit);
    }
    if let Some(error) = parsed_error {
        errors.push(error);
        failure_kinds
            .push(parsed_failure_kind.expect("a protocol error always has a typed failure kind"));
    }
    // Classify only supervisor/protocol errors. Worker stderr is retained for
    // diagnosis but must never be able to spoof timeout/security categories.
    let control_error = (!errors.is_empty()).then(|| errors.join("; "));
    let failure_kind = select_worker_failure_kind(&failure_kinds);
    let security_violation = parsed_security_violation;
    let error = match (control_error, stderr.is_empty()) {
        (Some(error), false) => Some(format!("{error}; stderr: {stderr}")),
        (error, _) => error,
    };
    Ok(WorkerExecution {
        events,
        delta,
        stderr,
        stderr_truncated,
        error,
        failure_kind,
        security_violation,
    })
}

pub(crate) async fn read_capped(
    mut reader: impl AsyncRead + Unpin,
    limit: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut stored = Vec::with_capacity(limit.min(64 * 1024));
    let mut truncated = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(stored.len());
        let keep = remaining.min(read);
        stored.extend_from_slice(&buffer[..keep]);
        truncated |= keep < read;
    }
    Ok((stored, truncated))
}

pub(crate) async fn finish_reader(
    mut task: tokio::task::JoinHandle<std::io::Result<(Vec<u8>, bool)>>,
    stream: &str,
    errors: &mut Vec<String>,
) -> Result<(Vec<u8>, bool)> {
    match timeout(Duration::from_secs(2), &mut task).await {
        Ok(result) => result
            .context("worker output reader task failed")?
            .context("worker output read failed"),
        Err(_) => {
            task.abort();
            let _ = task.await;
            errors.push(format!(
                "worker {stream} remained open after process termination"
            ));
            Ok((Vec::new(), true))
        }
    }
}

pub(crate) async fn terminate_worker(child: &mut tokio::process::Child, guard: &ProcessTreeGuard) {
    guard.terminate();
    let _ = child.kill().await;
    let _ = child.wait().await;
}

pub(crate) fn copy_safe_environment(command: &mut Command, root: &Path) -> Result<()> {
    command.env("PATH", sanitized_path(root)?);
    const PATH_KEYS: &[&str] = &[
        "HOME",
        "USERPROFILE",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SystemRoot",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "GOROOT",
        "GOPATH",
        "GOMODCACHE",
    ];
    for key in PATH_KEYS {
        if let Some(value) = std::env::var_os(key) {
            let path = PathBuf::from(&value);
            let safe = path.is_absolute()
                && path
                    .canonicalize()
                    .is_ok_and(|canonical| !canonical.starts_with(root));
            if safe {
                command.env(key, value);
            }
        }
    }
    for key in ["LANG", "LC_ALL"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    Ok(())
}

pub(crate) fn sanitized_path(root: &Path) -> Result<OsString> {
    let raw = std::env::var_os("PATH")
        .context("security policy violation: PATH is unavailable for safe worker execution")?;
    sanitize_path_value(&raw, root)
}

pub(crate) fn sanitize_path_value(raw: &OsStr, root: &Path) -> Result<OsString> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let mut paths = Vec::new();
    for path in std::env::split_paths(raw) {
        if !path.is_absolute() {
            continue;
        }
        let Ok(path) = path.canonicalize() else {
            continue;
        };
        if !path.is_dir() || path.starts_with(&root) || paths.contains(&path) {
            continue;
        }
        paths.push(path);
    }
    if paths.is_empty() {
        bail!(
            "security policy violation: PATH contains no safe absolute directories outside the scan root"
        );
    }
    std::env::join_paths(paths)
        .context("security policy violation: could not construct a safe PATH")
}

fn resolve_worker_program(spec: &WorkerSpec, root: &Path) -> Result<OsString> {
    validate_worker_root_confinement(spec, root)?;
    if spec.adapter == AdapterKind::Web {
        resolve_safe_executable("node", root).map(PathBuf::into_os_string)
    } else {
        Ok(spec.program.clone())
    }
}

pub(crate) fn validate_worker_root_confinement(spec: &WorkerSpec, root: &Path) -> Result<()> {
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let artifact = spec.artifact_path.canonicalize().with_context(|| {
        format!(
            "worker artifact {} is unavailable",
            spec.artifact_path.display()
        )
    })?;
    if spec.expected_version.is_none() && artifact.starts_with(&canonical_root) {
        bail!(
            "security policy violation: development worker artifact {} is inside the scan root",
            artifact.display()
        );
    }
    Ok(())
}

pub(crate) fn validate_worker_launch_policy(spec: &WorkerSpec, root: &Path) -> Result<()> {
    resolve_worker_program(spec, root).map(|_| ())
}

pub(crate) fn resolve_safe_executable(name: &str, root: &Path) -> Result<PathBuf> {
    let path = sanitized_path(root)?;
    for directory in std::env::split_paths(&path) {
        for file_name in executable_file_names(name) {
            let candidate = directory.join(file_name);
            let Ok(target) = candidate.canonicalize() else {
                continue;
            };
            if target.starts_with(root) || !is_executable_file(&target) {
                continue;
            }
            // Preserve the invoked name: shims such as rustup dispatch cargo
            // and rustc from argv[0], even though both canonicalize to rustup.
            return Ok(candidate);
        }
    }
    bail!("{name} is unavailable on the sanitized PATH")
}

#[cfg(windows)]
fn executable_file_names(name: &str) -> Vec<OsString> {
    vec![OsString::from(format!("{name}.exe"))]
}

#[cfg(not(windows))]
fn executable_file_names(name: &str) -> Vec<OsString> {
    vec![OsString::from(name)]
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;

    path.is_file()
        && std::fs::metadata(path).is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(windows)]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
        && path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
}

pub(crate) struct ProcessTreeGuard {
    #[cfg(unix)]
    process_group: i32,
    #[cfg(windows)]
    job: usize,
}

impl ProcessTreeGuard {
    pub(crate) fn attach(child: &tokio::process::Child) -> Result<Self> {
        #[cfg(unix)]
        {
            let process_group = child.id().context("worker has no process id")? as i32;
            Ok(Self { process_group })
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::{
                Foundation::CloseHandle,
                System::JobObjects::{
                    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                    SetInformationJobObject,
                },
            };

            let process_handle = child.raw_handle().context("worker has no process handle")?;
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if job.is_null() {
                return Err(std::io::Error::last_os_error()).context("create Windows Job Object");
            }
            let configured = unsafe {
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    (&raw const limits).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )
            };
            let assigned =
                configured != 0 && unsafe { AssignProcessToJobObject(job, process_handle) } != 0;
            if !assigned {
                let error = std::io::Error::last_os_error();
                unsafe {
                    CloseHandle(job);
                }
                return Err(error).context("assign worker to Windows Job Object");
            }
            Ok(Self { job: job as usize })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = child;
            Ok(Self {})
        }
    }

    pub(crate) fn terminate(&self) {
        #[cfg(unix)]
        unsafe {
            libc::kill(-self.process_group, libc::SIGKILL);
        }
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.job as _, 1);
        }
    }

    pub(crate) fn request_graceful_termination(&self) {
        #[cfg(unix)]
        unsafe {
            libc::kill(-self.process_group, libc::SIGTERM);
        }
        #[cfg(not(unix))]
        {
            // Windows Job Objects do not provide a tree-wide graceful signal.
            // The hard termination path remains bounded by the same grace period.
        }
    }
}

#[cfg(windows)]
impl Drop for ProcessTreeGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.job as _);
        }
    }
}

pub(crate) async fn run_probe(
    program: &OsStr,
    arguments: &[OsString],
    root: &Path,
) -> Result<std::process::Output> {
    let cancellation = std::future::pending::<std::io::Result<()>>();
    tokio::pin!(cancellation);
    run_probe_with_signal(program, arguments, root, cancellation.as_mut()).await
}

async fn run_probe_with_cancellation(
    program: &OsStr,
    arguments: &[OsString],
    root: &Path,
    cancellation: &CancellationToken,
) -> Result<std::process::Output> {
    let signal = async {
        cancellation.cancelled().await;
        Ok(())
    };
    tokio::pin!(signal);
    run_probe_with_signal(program, arguments, root, signal.as_mut()).await
}

async fn run_probe_with_signal<F>(
    program: &OsStr,
    arguments: &[OsString],
    root: &Path,
    mut cancellation: std::pin::Pin<&mut F>,
) -> Result<std::process::Output>
where
    F: Future<Output = std::io::Result<()>>,
{
    let neutral_cwd = neutral_working_directory(root)?;
    let mut command = Command::new(program);
    command
        .args(arguments)
        .current_dir(&neutral_cwd.path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_clear();
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.as_std_mut().process_group(0);
    }
    copy_safe_environment(&mut command, root)?;
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to start {}", Path::new(program).display()))?;
    let guard = ProcessTreeGuard::attach(&child).context("failed to isolate probe process tree")?;
    let stdout = child.stdout.take().context("probe stdout is unavailable")?;
    let stderr = child.stderr.take().context("probe stderr is unavailable")?;
    let stdout_task = tokio::spawn(read_capped(stdout, 64 * 1024));
    let stderr_task = tokio::spawn(read_capped(stderr, 64 * 1024));
    enum ProbeWait {
        Process(
            std::result::Result<
                std::io::Result<std::process::ExitStatus>,
                tokio::time::error::Elapsed,
            >,
        ),
        Cancelled(std::io::Result<()>),
    }
    let status = match tokio::select! {
        status = timeout(Duration::from_secs(5), child.wait()) => ProbeWait::Process(status),
        signal = cancellation.as_mut() => ProbeWait::Cancelled(signal),
    } {
        ProbeWait::Process(Ok(status)) => status.context("failed to wait for runtime probe")?,
        ProbeWait::Process(Err(_)) => {
            terminate_worker(&mut child, &guard).await;
            bail!("runtime probe timed out after 5 seconds");
        }
        ProbeWait::Cancelled(Ok(())) => {
            terminate_worker(&mut child, &guard).await;
            bail!("runtime probe cancelled");
        }
        ProbeWait::Cancelled(Err(error)) => {
            terminate_worker(&mut child, &guard).await;
            return Err(error).context("failed to listen for runtime probe cancellation");
        }
    };
    guard.terminate();
    let mut errors = Vec::new();
    let (stdout, _) = finish_reader(stdout_task, "probe stdout", &mut errors).await?;
    let (stderr, _) = finish_reader(stderr_task, "probe stderr", &mut errors).await?;
    if !errors.is_empty() {
        bail!(errors.join("; "));
    }
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

struct NeutralWorkingDirectory {
    path: PathBuf,
    _temporary: Option<tempfile::TempDir>,
}

fn neutral_working_directory(root: &Path) -> Result<NeutralWorkingDirectory> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let platform_default = platform_neutral_working_directory();
    if let Ok(path) = platform_default.canonicalize()
        && path.is_dir()
        && !path.starts_with(&root)
    {
        return Ok(NeutralWorkingDirectory {
            path,
            _temporary: None,
        });
    }

    let temporary = tempfile::Builder::new()
        .prefix("depgraph-worker-cwd-")
        .tempdir()
        .context("create neutral worker working directory")?;
    let temporary_path = temporary.path().canonicalize()?;
    if !temporary_path.starts_with(&root) {
        return Ok(NeutralWorkingDirectory {
            path: temporary_path,
            _temporary: Some(temporary),
        });
    }

    if let Some(parent) = root.parent()
        && let Ok(path) = parent.canonicalize()
        && path.is_dir()
        && !path.starts_with(&root)
    {
        return Ok(NeutralWorkingDirectory {
            path,
            _temporary: None,
        });
    }
    bail!("security policy violation: no neutral working directory exists outside the scan root")
}

fn platform_neutral_working_directory() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/")
    }
    #[cfg(windows)]
    {
        std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute() && path.is_dir())
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::env::temp_dir()
    }
}

pub(crate) async fn probe_worker_version_with_cancellation(
    spec: &WorkerSpec,
    root: &Path,
    cancellation: &CancellationToken,
) -> Result<String> {
    let program = resolve_worker_program(spec, root)?;
    if let Some(requirement) = &spec.runtime_requirement {
        let node = run_probe_with_cancellation(
            &program,
            &[OsString::from("--version")],
            root,
            cancellation,
        )
        .await?;
        if !node.status.success() {
            bail!("Node.js runtime version check failed");
        }
        let version = String::from_utf8(node.stdout)
            .context("Node.js runtime returned a non-UTF-8 version")?;
        verify_node_version(requirement, &version)?;
    }
    let mut arguments = spec.leading_args.clone();
    arguments.push(OsString::from("--version"));
    let output = run_probe_with_cancellation(&program, &arguments, root, cancellation).await?;
    if !output.status.success() {
        bail!(
            "worker version handshake failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

pub(crate) async fn probe_toolchain_version_with_cancellation(
    program: &str,
    argument: &str,
    root: &Path,
    cancellation: &CancellationToken,
) -> Result<String> {
    let program = resolve_safe_executable(program, root)?;
    let output = run_probe_with_cancellation(
        program.as_os_str(),
        &[OsString::from(argument)],
        root,
        cancellation,
    )
    .await?;
    if !output.status.success() {
        bail!("{program:?} version probe failed");
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

pub fn parse_and_validate_events(
    stdout: &[u8],
    expected_scan_id: &str,
    expected_adapter: &str,
    root: &Path,
    max_line_bytes: usize,
) -> Result<Vec<Value>> {
    let parsed = parse_events_preserving_prefix(
        stdout,
        expected_scan_id,
        expected_adapter,
        root,
        max_line_bytes,
        None,
        Some(false),
    );
    if let Some(error) = parsed.error {
        bail!(error);
    }
    Ok(parsed.events)
}

#[derive(Debug)]
struct ParsedProtocol {
    events: Vec<Value>,
    error: Option<String>,
    failure_kind: Option<WorkerFailureKind>,
    security_violation: bool,
}

#[derive(Debug)]
struct ParsedDelta {
    delta: Option<ValidatedDelta>,
    error: Option<String>,
    failure_kind: Option<WorkerFailureKind>,
    security_violation: bool,
}

fn parse_delta_events(
    stdout: &[u8],
    request: &WorkerDeltaRequest,
    configured_line_limit: usize,
    expected_adapter_version: Option<&str>,
) -> ParsedDelta {
    let line_limit = configured_line_limit.min(MAX_EVENT_LINE_BYTES);
    if let Some((index, _line)) = stdout
        .split(|byte| *byte == b'\n')
        .enumerate()
        .find(|(_, line)| line.len() > line_limit)
    {
        return ParsedDelta {
            delta: None,
            error: Some(format!(
                "delta protocol line {} exceeds {line_limit} bytes",
                index + 1
            )),
            failure_kind: Some(WorkerFailureKind::OutputLimit),
            security_violation: false,
        };
    }
    let base = match request.base_graph() {
        Ok(base) => base,
        Err(error) => {
            return ParsedDelta {
                delta: None,
                error: Some(format!("invalid worker delta request base: {error}")),
                failure_kind: Some(WorkerFailureKind::MalformedProtocol),
                security_violation: false,
            };
        }
    };
    match validate_delta_ndjson(Cursor::new(stdout), base) {
        Ok(delta) => {
            let common = delta
                .events
                .first()
                .expect("validated delta contains boundary events")
                .common();
            let routing_mismatch =
                common.scan_id != request.scan_id || common.adapter != request.adapter;
            let version_mismatch =
                expected_adapter_version.is_some_and(|expected| common.adapter_version != expected);
            let request_mismatch = delta.base_snapshot_id != request.base_snapshot_id
                || delta.base_graph_digest != request.base_graph_digest
                || delta.scope != request.scope;
            if routing_mismatch || version_mismatch || request_mismatch {
                ParsedDelta {
                    delta: None,
                    error: Some(
                        "security policy violation: delta worker request binding mismatch"
                            .to_owned(),
                    ),
                    failure_kind: Some(WorkerFailureKind::MalformedProtocol),
                    security_violation: expected_adapter_version.is_some(),
                }
            } else {
                ParsedDelta {
                    delta: Some(delta),
                    error: None,
                    failure_kind: None,
                    security_violation: false,
                }
            }
        }
        Err(error) => ParsedDelta {
            delta: None,
            error: Some(format!("invalid worker delta protocol: {error}")),
            failure_kind: Some(match error {
                ProtocolError::LineTooLong { .. } => WorkerFailureKind::OutputLimit,
                _ => WorkerFailureKind::MalformedProtocol,
            }),
            security_violation: false,
        },
    }
}

fn protocol_error_is_security(error: &ProtocolError) -> bool {
    match error {
        ProtocolError::UnsafeScanMode { .. } | ProtocolError::UnsafePath { .. } => true,
        ProtocolError::Invariant(message) => {
            message == "safe-mode scan reports project_code_executed=true"
                || message == "safe-mode coverage reports project_code_executed=true"
                || message == "scan coverage hides project code execution reported by a profile"
                || (message.starts_with("safe-mode profile ")
                    && message.ends_with(" reports project_code_executed=true"))
        }
        _ => false,
    }
}

fn parse_events_preserving_prefix(
    stdout: &[u8],
    expected_scan_id: &str,
    expected_adapter: &str,
    root: &Path,
    configured_line_limit: usize,
    expected_adapter_version: Option<&str>,
    release_attested: Option<bool>,
) -> ParsedProtocol {
    let mut validator = ProtocolValidator::for_safe_scan();
    let line_limit = configured_line_limit.min(MAX_EVENT_LINE_BYTES);
    let mut parse_error = None;
    let mut failure_kind = None;
    let mut security_violation = false;
    let enforce_web_definition_graph = release_attested.is_some() && expected_adapter == "web";
    let mut web_profiles = BTreeSet::new();
    let mut web_definition_profiles = BTreeSet::new();
    let mut web_import_type_profiles = BTreeSet::new();
    let mut web_call_profiles = BTreeSet::new();
    let mut web_candidate_call_profiles = BTreeSet::new();
    let mut web_framework_states = std::collections::BTreeMap::new();
    let mut web_framework_node_ids = BTreeSet::new();
    let mut web_semantic_node_ids = BTreeSet::new();
    let mut web_semantic_node_candidate_ids = BTreeSet::new();
    let mut web_semantic_endpoint_ids = BTreeSet::new();
    let mut web_discarded_site_ids = BTreeSet::new();
    let mut saw_web_framework_semantic_delta = false;
    let mut web_framework_failure = false;
    for (line_index, mut line) in stdout.split(|byte| *byte == b'\n').enumerate() {
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if line.len() > line_limit {
            parse_error = Some(format!(
                "protocol line {} exceeds {line_limit} bytes",
                line_index + 1
            ));
            failure_kind = Some(WorkerFailureKind::OutputLimit);
            break;
        }
        let event: ProtocolEvent = match serde_json::from_slice(line) {
            Ok(event) => event,
            Err(error) => {
                parse_error = Some(format!(
                    "malformed NDJSON at line {}: {error}",
                    line_index + 1
                ));
                failure_kind = Some(WorkerFailureKind::MalformedProtocol);
                break;
            }
        };
        let current_web_semantic_node_id = if enforce_web_definition_graph
            && let ProtocolEvent::NodeUpsert(upsert) = &event
            && matches!(upsert.node.kind.as_str(), "symbol" | "type")
        {
            Some(upsert.node.id.clone())
        } else {
            None
        };
        if let Some(node_id) = &current_web_semantic_node_id {
            web_semantic_node_candidate_ids.insert(node_id.clone());
        }
        let current_web_framework_node_id = if enforce_web_definition_graph
            && let ProtocolEvent::NodeUpsert(upsert) = &event
            && is_web_framework_semantic_node(&upsert.node)
        {
            Some(upsert.node.id.clone())
        } else {
            None
        };
        if enforce_web_definition_graph && is_web_semantic_delta_event(&event) {
            match &event {
                ProtocolEvent::EdgeUpsert(upsert) => {
                    web_semantic_endpoint_ids.insert(upsert.edge.source.clone());
                    web_semantic_endpoint_ids.insert(upsert.edge.target.clone());
                }
                ProtocolEvent::DependencySite(site) => {
                    web_semantic_endpoint_ids.insert(site.site.source.clone());
                    web_semantic_endpoint_ids.extend(site.site.target_ids.iter().cloned());
                }
                _ => {}
            }
        }
        let current_site_closure = if enforce_web_definition_graph {
            match &event {
                ProtocolEvent::EdgeUpsert(upsert) => upsert.edge.site_id.clone(),
                ProtocolEvent::DependencySite(site) => Some(site.site.id.clone()),
                _ => None,
            }
        } else {
            None
        };
        let current_web_semantic_complete = enforce_web_definition_graph
            && match &event {
                ProtocolEvent::ProfileCompleted(completed) => completed
                    .coverage
                    .completeness
                    .contains(&CompletenessLevel::SemanticComplete),
                ProtocolEvent::ScanCompleted(completed) => completed
                    .coverage
                    .completeness
                    .contains(&CompletenessLevel::SemanticComplete),
                _ => false,
            };
        if event.common().scan_id != expected_scan_id {
            if let Some(site_id) = &current_site_closure {
                web_discarded_site_ids.insert(site_id.clone());
            }
            parse_error = Some(format!("scan_id mismatch at line {}", line_index + 1));
            failure_kind = Some(WorkerFailureKind::MalformedProtocol);
            break;
        }
        if expected_adapter_version.is_some() && event.common().protocol_version != "1.0" {
            if let Some(site_id) = &current_site_closure {
                web_discarded_site_ids.insert(site_id.clone());
            }
            parse_error = Some(format!(
                "security policy violation at line {}: protocol_version mismatch: expected 1.0, received {}",
                line_index + 1,
                event.common().protocol_version
            ));
            failure_kind = Some(WorkerFailureKind::MalformedProtocol);
            security_violation = true;
            break;
        }
        if event.common().adapter != expected_adapter {
            if let Some(site_id) = &current_site_closure {
                web_discarded_site_ids.insert(site_id.clone());
            }
            if expected_adapter_version.is_some() {
                parse_error = Some(format!(
                    "security policy violation at line {}: adapter mismatch: expected {}, received {}",
                    line_index + 1,
                    expected_adapter,
                    event.common().adapter
                ));
                security_violation = true;
            } else {
                parse_error = Some(format!("adapter mismatch at line {}", line_index + 1));
            }
            failure_kind = Some(WorkerFailureKind::MalformedProtocol);
            break;
        }
        if expected_adapter_version
            .is_some_and(|expected| event.common().adapter_version != expected)
        {
            if let Some(site_id) = &current_site_closure {
                web_discarded_site_ids.insert(site_id.clone());
            }
            parse_error = Some(format!(
                "security policy violation at line {}: adapter_version mismatch: expected {}, received {}",
                line_index + 1,
                expected_adapter_version.unwrap_or_default(),
                event.common().adapter_version
            ));
            failure_kind = Some(WorkerFailureKind::MalformedProtocol);
            security_violation = true;
            break;
        }
        if let ProtocolEvent::ScanStarted(started) = &event {
            if !started.safe_mode || started.project_code_executed {
                parse_error = Some(format!(
                    "security policy violation at line {}: normal scans require safe_mode=true and project_code_executed=false",
                    line_index + 1
                ));
                failure_kind = Some(WorkerFailureKind::MalformedProtocol);
                security_violation = true;
                break;
            }
            let declared_root = PathBuf::from(&started.root)
                .canonicalize()
                .unwrap_or_else(|_| PathBuf::from(&started.root));
            if declared_root != root {
                parse_error = Some(format!(
                    "worker declared scan root {}, expected {}",
                    declared_root.display(),
                    root.display()
                ));
                failure_kind = Some(WorkerFailureKind::MalformedProtocol);
                break;
            }
        }
        if let (Some(release_attested), ProtocolEvent::ProfileDeclared(declared)) =
            (release_attested, &event)
        {
            let properties = &declared.profile.properties;
            let web_profile_language =
                expected_adapter != "web" || declared.profile.language == "web";
            let (web_capability, web_capability_violation) = if expected_adapter == "web" {
                match web_semantic_capability(properties) {
                    Ok(capability) => (Some(capability), None),
                    Err(error) => (None, Some(error)),
                }
            } else {
                (None, None)
            };
            let (web_framework_state, web_framework_violation) = if expected_adapter == "web" {
                match web_framework_semantic_state(properties) {
                    Ok(state) => (Some(state), None),
                    Err(error) => (None, Some(error)),
                }
            } else {
                (None, None)
            };
            let (web_framework_completeness_state, web_framework_completeness_violation) =
                if expected_adapter == "web" {
                    match web_framework_completeness_state(properties, &declared.profile.features) {
                        Ok(state) => (Some(state), None),
                        Err(error) => (None, Some(error)),
                    }
                } else {
                    (None, None)
                };
            let expected_gate = match expected_adapter {
                "rust" => Some((
                    "rust_hir_enable_gate",
                    RUST_RELEASE_GATE_PENDING,
                    RUST_RELEASE_GATE_VERIFIED,
                    "Rust",
                )),
                _ => None,
            };
            let mut violation = if !web_profile_language {
                Some("Web worker profile language must be web".to_owned())
            } else if web_capability_violation.is_some() {
                web_capability_violation
            } else if web_framework_violation.is_some() {
                web_framework_failure = true;
                web_framework_violation
            } else if web_framework_completeness_violation.is_some() {
                web_framework_failure = true;
                web_framework_completeness_violation
            } else if expected_adapter == "web"
                && matches!(
                    web_framework_completeness_state,
                    Some(
                        WebFrameworkCompletenessState::Complete
                            | WebFrameworkCompletenessState::Incomplete
                    )
                )
                && web_capability != Some(WebSemanticCapability::DefinitionImportTypeCallGraphV2)
            {
                web_framework_failure = true;
                Some(
                    "Web framework completeness ledger requires the TypeScript v2 import/type/call capability"
                        .to_owned(),
                )
            } else if expected_adapter == "web"
                && matches!(
                    web_framework_completeness_state,
                    Some(WebFrameworkCompletenessState::Complete)
                )
                && web_framework_state != Some(WebFrameworkSemanticState::Emitted)
            {
                web_framework_failure = true;
                Some(
                    "Web worker claimed complete framework semantics without an emitted framework graph"
                        .to_owned(),
                )
            } else if expected_adapter == "web"
                && web_framework_state == Some(WebFrameworkSemanticState::Emitted)
                && matches!(
                    web_framework_completeness_state,
                    Some(
                        WebFrameworkCompletenessState::Legacy
                            | WebFrameworkCompletenessState::NotDetected
                    )
                )
            {
                web_framework_failure = true;
                Some(
                    "Web worker emitted a framework graph without a matching completeness ledger"
                        .to_owned(),
                )
            } else if expected_adapter == "web" {
                let gate = properties
                    .get(TYPESCRIPT_RELEASE_GATE_PROPERTY)
                    .and_then(Value::as_str);
                match (release_attested, gate) {
                    (true, Some(TYPESCRIPT_RELEASE_GATE_VERIFIED))
                    | (false, Some(TYPESCRIPT_RELEASE_GATE_PENDING)) => None,
                    (true, Some(TYPESCRIPT_RELEASE_GATE_PENDING)) => Some(
                        "verified TypeScript release worker reported release-gate-pending"
                            .to_owned(),
                    ),
                    (false, Some(TYPESCRIPT_RELEASE_GATE_VERIFIED)) => Some(
                        "worker reported release-gate-verified without a verified TypeScript release attestation"
                            .to_owned(),
                    ),
                    (true, None) => Some(
                        "verified TypeScript release worker omitted its release gate".to_owned(),
                    ),
                    (false, None) => Some(
                        "development TypeScript worker omitted its release-gate-pending declaration"
                            .to_owned(),
                    ),
                    (attested, Some(value)) => Some(format!(
                        "TypeScript worker reported invalid release gate {value:?}; expected {}",
                        if attested {
                            TYPESCRIPT_RELEASE_GATE_VERIFIED
                        } else {
                            TYPESCRIPT_RELEASE_GATE_PENDING
                        }
                    )),
                }
            } else {
                None
            };
            if violation.is_none() {
                violation = expected_gate.and_then(|(property, pending, verified, label)| {
                    properties
                        .get(property)
                        .and_then(Value::as_str)
                        .and_then(|gate| match (release_attested, gate) {
                            (true, value) if value == pending => Some(format!(
                                "verified {label} release worker reported release-gate-pending"
                            )),
                            (false, value) if value == verified => Some(format!(
                                "worker reported release-gate-verified without a verified {label} release attestation"
                            )),
                            _ => None,
                        })
                });
            }
            for (adapter, property, verified, label) in [
                (
                    "rust",
                    "rust_hir_enable_gate",
                    RUST_RELEASE_GATE_VERIFIED,
                    "Rust",
                ),
                (
                    "web",
                    TYPESCRIPT_RELEASE_GATE_PROPERTY,
                    TYPESCRIPT_RELEASE_GATE_VERIFIED,
                    "TypeScript",
                ),
            ] {
                if adapter != expected_adapter
                    && properties.get(property).and_then(Value::as_str) == Some(verified)
                {
                    violation = Some(format!(
                        "worker reported release-gate-verified without a verified {label} release attestation"
                    ));
                    break;
                }
            }
            let mut web_definition_ready = false;
            if violation.is_none() && expected_adapter == "web" {
                match web_definition_profile_ready(
                    properties,
                    web_capability.expect("validated Web semantic capability"),
                ) {
                    Ok(ready) => web_definition_ready = ready,
                    Err(error) => violation = Some(error),
                }
            }
            if let Some(violation) = violation {
                parse_error = Some(format!(
                    "security policy violation at line {}: {violation}",
                    line_index + 1
                ));
                failure_kind = Some(WorkerFailureKind::MalformedProtocol);
                security_violation = true;
                break;
            }
            if expected_adapter == "web" {
                web_framework_states.insert(
                    declared.profile.id.clone(),
                    web_framework_state.expect("validated framework semantic state"),
                );
                web_profiles.insert(declared.profile.id.clone());
                if web_definition_ready {
                    web_definition_profiles.insert(declared.profile.id.clone());
                    if matches!(
                        web_capability,
                        Some(
                            WebSemanticCapability::DefinitionImportTypeGraphV1
                                | WebSemanticCapability::DefinitionImportTypeCallGraphV1
                                | WebSemanticCapability::DefinitionImportTypeCallGraphV2
                        )
                    ) {
                        web_import_type_profiles.insert(declared.profile.id.clone());
                    }
                    if matches!(
                        web_capability,
                        Some(
                            WebSemanticCapability::DefinitionImportTypeCallGraphV1
                                | WebSemanticCapability::DefinitionImportTypeCallGraphV2
                        )
                    ) {
                        web_call_profiles.insert(declared.profile.id.clone());
                    }
                    if web_capability
                        == Some(WebSemanticCapability::DefinitionImportTypeCallGraphV2)
                    {
                        web_candidate_call_profiles.insert(declared.profile.id.clone());
                    }
                }
            }
        }
        if enforce_web_definition_graph {
            let violation = match &event {
                ProtocolEvent::NodeUpsert(upsert)
                    if matches!(upsert.node.kind.as_str(), "symbol" | "type") =>
                {
                    let profile_id = upsert
                        .node
                        .properties
                        .get("profile_id")
                        .and_then(Value::as_str);
                    let language = upsert
                        .node
                        .properties
                        .get("language")
                        .and_then(Value::as_str);
                    if profile_id
                        .is_none_or(|profile_id| !web_definition_profiles.contains(profile_id))
                    {
                        Some(format!(
                            "Web semantic node {} is not authorized by a definition-graph-v1 profile",
                            upsert.node.id
                        ))
                    } else if !matches!(language, Some("typescript" | "javascript")) {
                        Some(format!(
                            "Web semantic node {} must declare language=typescript or javascript",
                            upsert.node.id
                        ))
                    } else {
                        None
                    }
                }
                ProtocolEvent::EdgeUpsert(upsert)
                    if is_web_semantic_delta_event(&event)
                        || web_semantic_node_ids.contains(&upsert.edge.source)
                        || web_semantic_node_ids.contains(&upsert.edge.target) =>
                {
                    let edge = &upsert.edge;
                    if edge.phase != Phase::Semantic {
                        Some(format!(
                            "Web semantic relation {} must use phase=semantic",
                            edge.id
                        ))
                    } else if is_web_framework_semantic_delta_event(&event) {
                        None
                    } else if is_web_definition_relation_kind(&edge.kind) {
                        if !web_definition_profiles.contains(&edge.profile_id) {
                            Some(format!(
                                "Web semantic edge {} is not authorized by profile {:?}",
                                edge.id, edge.profile_id
                            ))
                        } else if edge.site_id.is_some() {
                            Some(format!(
                                "Web semantic definition relation {} must remain site-less",
                                edge.id
                            ))
                        } else if edge.resolution_status != ResolutionStatus::Resolved
                            || edge.precision != Precision::Exact
                        {
                            Some(format!(
                                "Web semantic definition relation {} must use resolved/exact",
                                edge.id
                            ))
                        } else {
                            None
                        }
                    } else if is_web_semantic_dependency_edge_kind(&edge.kind) {
                        let authorized = if edge.kind == "calls" {
                            web_call_profiles.contains(&edge.profile_id)
                        } else if edge.kind == "may_call" {
                            web_candidate_call_profiles.contains(&edge.profile_id)
                        } else {
                            web_import_type_profiles.contains(&edge.profile_id)
                        };
                        if !authorized {
                            Some(format!(
                                "Web semantic dependency edge {} is not authorized by its declared cumulative semantic capability",
                                edge.id
                            ))
                        } else if edge.site_id.is_none() {
                            Some(format!(
                                "Web semantic dependency edge {} must reference a dependency site",
                                edge.id
                            ))
                        } else {
                            None
                        }
                    } else {
                        Some(format!(
                            "Web semantic profile emitted forbidden semantic edge kind {:?}",
                            edge.kind
                        ))
                    }
                }
                ProtocolEvent::DependencySite(site)
                    if is_web_semantic_delta_event(&event)
                        || web_semantic_node_ids.contains(&site.site.source)
                        || site
                            .site
                            .target_ids
                            .iter()
                            .any(|target| web_semantic_node_ids.contains(target))
                        || matches!(
                            site.site.kind.as_str(),
                            "call" | "type_use" | "rust_use" | "rust_reexport"
                        ) =>
                {
                    if is_web_framework_semantic_delta_event(&event) {
                        None
                    } else {
                        let authorized = if site.site.kind == "call" {
                            if site.site.resolution_status == ResolutionStatus::Candidates {
                                web_candidate_call_profiles.contains(&site.site.profile_id)
                            } else {
                                web_call_profiles.contains(&site.site.profile_id)
                            }
                        } else {
                            web_import_type_profiles.contains(&site.site.profile_id)
                        };
                        if authorized
                            && is_web_semantic_dependency_site_kind(&site.site.kind)
                            && site
                                .site
                                .evidence
                                .first()
                                .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic)
                        {
                            None
                        } else {
                            Some(format!(
                                "Web semantic profile emitted forbidden semantic dependency site {}",
                                site.site.id
                            ))
                        }
                    }
                }
                _ => None,
            };
            if let Some(violation) = violation {
                record_web_rejected_site_closure(&event, &mut web_discarded_site_ids);
                parse_error = Some(format!(
                    "security policy violation at line {}: {violation}",
                    line_index + 1
                ));
                failure_kind = Some(WorkerFailureKind::MalformedProtocol);
                security_violation = true;
                break;
            }
        }
        if enforce_web_definition_graph {
            let violation = match &event {
                ProtocolEvent::NodeUpsert(upsert)
                    if is_web_framework_semantic_node(&upsert.node) =>
                {
                    let profile_id = upsert
                        .node
                        .properties
                        .get("profile_id")
                        .and_then(Value::as_str);
                    if profile_id.is_none_or(|profile_id| {
                        web_framework_states.get(profile_id)
                            != Some(&WebFrameworkSemanticState::Emitted)
                    }) {
                        Some(format!(
                            "Web framework semantic node {} is not authorized by an emitted v1 capability",
                            upsert.node.id
                        ))
                    } else {
                        None
                    }
                }
                ProtocolEvent::DependencySite(site)
                    if is_web_framework_semantic_delta_event(&event)
                        || web_framework_node_ids.contains(&site.site.source)
                        || site
                            .site
                            .target_ids
                            .iter()
                            .any(|target| web_framework_node_ids.contains(target)) =>
                {
                    if web_framework_states.get(&site.site.profile_id)
                        != Some(&WebFrameworkSemanticState::Emitted)
                        || !is_web_framework_semantic_site_kind(&site.site.kind)
                    {
                        Some(format!(
                            "Web framework semantic site {} is not authorized by an emitted v1 capability",
                            site.site.id
                        ))
                    } else {
                        None
                    }
                }
                ProtocolEvent::EdgeUpsert(upsert)
                    if is_web_framework_semantic_delta_event(&event)
                        || web_framework_node_ids.contains(&upsert.edge.source)
                        || web_framework_node_ids.contains(&upsert.edge.target) =>
                {
                    if web_framework_states.get(&upsert.edge.profile_id)
                        != Some(&WebFrameworkSemanticState::Emitted)
                        || upsert.edge.phase != Phase::Semantic
                        || !is_web_framework_semantic_site_kind(&upsert.edge.kind)
                    {
                        Some(format!(
                            "Web framework semantic edge {} is not authorized by an emitted v1 capability",
                            upsert.edge.id
                        ))
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some(violation) = violation {
                record_web_rejected_site_closure(&event, &mut web_discarded_site_ids);
                parse_error = Some(format!(
                    "security policy violation at line {}: {violation}",
                    line_index + 1
                ));
                failure_kind = Some(WorkerFailureKind::MalformedProtocol);
                security_violation = true;
                web_framework_failure = true;
                break;
            }
        }
        let current_web_semantic_delta =
            enforce_web_definition_graph && is_web_semantic_delta_event(&event);
        let current_web_framework_semantic_delta =
            enforce_web_definition_graph && is_web_framework_semantic_delta_event(&event);
        saw_web_framework_semantic_delta |= current_web_framework_semantic_delta;
        if let Err(error) = validator.push(event) {
            if let Some(site_id) = current_site_closure {
                web_discarded_site_ids.insert(site_id);
            }
            security_violation = protocol_error_is_security(&error)
                || current_web_semantic_delta
                || current_web_framework_semantic_delta
                || current_web_semantic_complete;
            web_framework_failure |= current_web_framework_semantic_delta;
            parse_error = Some(format!(
                "protocol validation failed at line {}: {error}",
                line_index + 1
            ));
            failure_kind = Some(WorkerFailureKind::MalformedProtocol);
            break;
        }
        if let Some(node_id) = current_web_semantic_node_id {
            web_semantic_node_ids.insert(node_id);
        }
        if let Some(node_id) = current_web_framework_node_id {
            web_framework_node_ids.insert(node_id);
        }
    }
    let mut prefix;
    if parse_error.is_none() {
        if !matches!(
            validator.validated_events().last(),
            Some(ProtocolEvent::ScanCompleted(_))
        ) {
            prefix = validator.validated_events().to_vec();
            parse_error = Some(format!(
                "incomplete protocol stream: {}",
                ProtocolError::IncompleteStream
            ));
            failure_kind = Some(WorkerFailureKind::IncompleteProtocol);
        } else {
            match validator.finish() {
                Ok(protocol) if enforce_web_definition_graph => {
                    if let Err(error) = validate_cross_language_worker_protocol(&protocol) {
                        parse_error = Some(format!(
                            "security policy violation: invalid cross-language worker closure: {error:#}"
                        ));
                    } else if let Err(error) = validate_semantic_contract(&protocol) {
                        web_framework_failure = saw_web_framework_semantic_delta
                            && semantic_contract_failure_is_framework(&protocol);
                        parse_error = Some(format!(
                            "security policy violation: invalid Web semantic protocol: {error}"
                        ));
                    } else if let Err(error) = validate_web_definition_graph(
                        &protocol,
                        &web_profiles,
                        &web_definition_profiles,
                        &web_import_type_profiles,
                        &web_call_profiles,
                        &web_candidate_call_profiles,
                    ) {
                        parse_error = Some(format!(
                            "security policy violation: invalid Web TypeScript semantic delta: {error}"
                        ));
                    } else if let Err(error) =
                        validate_web_framework_semantic_graph(&protocol, &web_framework_states)
                    {
                        web_framework_failure = true;
                        parse_error = Some(format!(
                            "security policy violation: invalid Web framework semantic delta: {error}"
                        ));
                    }
                    if parse_error.is_some() {
                        failure_kind = Some(WorkerFailureKind::MalformedProtocol);
                        security_violation = true;
                    }
                    prefix = protocol.events;
                }
                Ok(protocol) => {
                    if let Err(error) = validate_cross_language_worker_protocol(&protocol) {
                        parse_error = Some(format!(
                            "security policy violation: invalid cross-language worker closure: {error:#}"
                        ));
                        failure_kind = Some(WorkerFailureKind::MalformedProtocol);
                        security_violation = true;
                    }
                    prefix = protocol.events;
                }
                Err(_) => {
                    unreachable!("scan_completed leaves the protocol validator completed")
                }
            }
        }
    } else {
        prefix = validator.validated_events().to_vec();
    }
    if enforce_web_definition_graph && parse_error.is_some() {
        if web_framework_failure {
            discard_web_framework_delta(&mut prefix);
        } else {
            discard_web_definition_delta(
                &mut prefix,
                &web_semantic_node_ids,
                &web_semantic_node_candidate_ids,
                &web_discarded_site_ids,
                &web_semantic_endpoint_ids,
            );
        }
    }
    let events = prefix
        .into_iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("typed protocol events always serialize");
    ParsedProtocol {
        events,
        error: parse_error,
        failure_kind,
        security_violation,
    }
}

#[cfg(test)]
mod tests;
