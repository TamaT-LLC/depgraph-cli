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
    CompletenessLevel, Condition, EvidenceKind, MAX_EVENT_LINE_BYTES, Phase, Precision,
    ProtocolError, ProtocolEvent, ProtocolValidator, ResolutionStatus, ValidatedDelta,
    ValidatedProtocol, WorkerDeltaRequest, validate_delta_ndjson, validate_semantic_contract,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    time::timeout,
};
use walkdir::{DirEntry, WalkDir};

use crate::{
    BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH, BOUNDED_QUERY_RELEASE_SMOKE_QUERY,
    RUST_SYSROOT_COMPONENT_NAME, RUST_SYSROOT_COMPONENT_ROOT, RUST_SYSROOT_COMPONENT_VERSION,
    RUST_SYSROOT_LICENSE_EXPRESSION, ReleaseCompatibilityHealth,
    cancellation::CancellationToken,
    config::{ProfileConfig, ScanConfig},
    verify_release_compatibility,
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
const TYPESCRIPT_ANALYSIS_MODE_PROPERTY: &str = "typescript_analysis_mode";
const TYPESCRIPT_ANALYSIS_MODE_DEFINITION_GRAPH: &str = "semantic-definition-graph";
const TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_GRAPH: &str = "semantic-import-type-graph";
const TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_CALL_GRAPH: &str = "semantic-import-type-call-graph";
const TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY: &str = "typescript_semantic_graph_emission";
const TYPESCRIPT_SEMANTIC_EMISSION_DEFINITION_GRAPH_V1: &str = "definition-graph-v1";
const TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_GRAPH_V1: &str = "definition-import-type-graph-v1";
const TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V1: &str =
    "definition-import-type-call-graph-v1";
const TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2: &str =
    "definition-import-type-call-graph-v2";
const TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY: &str = "typescript_semantic_site_count";
const TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY: &str = "typescript_semantic_call_site_count";
const WEB_FRAMEWORK_SEMANTIC_CAPABILITY_PROPERTY: &str = "web_framework_semantic_capability";
const WEB_FRAMEWORK_SEMANTIC_CAPABILITY_V1: &str = "framework-semantic-graph-v1";
const WEB_FRAMEWORK_SEMANTIC_STATUS_PROPERTY: &str = "web_framework_semantic_status";
const WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION_PROPERTY: &str =
    "web_framework_semantic_extractor_version";
const WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION: &str = "0.1.0";
const WEB_FRAMEWORK_SEMANTIC_NODE_COUNT_PROPERTY: &str = "web_framework_semantic_node_count";
const WEB_FRAMEWORK_SEMANTIC_SITE_COUNT_PROPERTY: &str = "web_framework_semantic_site_count";
const WEB_FRAMEWORK_SEMANTIC_EDGE_COUNT_PROPERTY: &str = "web_framework_semantic_edge_count";
const WEB_FRAMEWORK_COMPLETENESS_CAPABILITY_PROPERTY: &str =
    "web_framework_completeness_capability";
const WEB_FRAMEWORK_COMPLETENESS_CAPABILITY_V1: &str = "framework-semantic-completeness-v1";
const WEB_FRAMEWORK_COMPLETENESS_STATUS_PROPERTY: &str = "web_framework_completeness_status";
const WEB_FRAMEWORK_COMPLETENESS_ISSUE_COUNT_PROPERTY: &str =
    "web_framework_completeness_issue_count";
const WEB_FRAMEWORK_COMPLETENESS_LEDGER_PROPERTY: &str = "web_framework_completeness_ledger";
const TYPESCRIPT_SEMANTIC_EXTRACTOR: &str = "typescript-native-typechecker";
const TYPESCRIPT_SEMANTIC_BACKEND: &str = "typescript-native-compiler";
const TYPESCRIPT_CLOSED_LOCAL_CALL_FLOW_ALGORITHM: &str = "typescript-closed-local-call-flow-v1";
const TYPESCRIPT_CLOSED_LOCAL_FRESH_INSTANCE_FLOW_ALGORITHM: &str =
    "typescript-closed-local-fresh-instance-flow-v1";
const TYPESCRIPT_COMPILER_VERSION: &str = "7.0.2";
const TYPESCRIPT_PROJECT_STATUS_PROPERTY: &str = "typescript_project_model_status";
const TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY: &str = "typescript_typechecker_status";
const TYPESCRIPT_DEFINITION_STATUS_PROPERTY: &str = "typescript_definition_graph_status";
const TYPESCRIPT_DEFINITION_ISSUE_PROPERTY: &str = "typescript_definition_issue";
const TYPESCRIPT_DEPENDENCY_ISSUE_PROPERTY: &str = "typescript_dependency_issue";
const TYPESCRIPT_MAX_TYPE_ARGUMENTS: usize = 64;
const TYPESCRIPT_MAX_TYPE_DESCRIPTOR_DEPTH: usize = 64;
const TYPESCRIPT_MAX_TYPE_DESCRIPTOR_MEMBERS: usize = 256;
const TYPESCRIPT_MAX_TYPE_DESCRIPTOR_CHARS: usize = 2_048;
const TYPESCRIPT_MAX_DISPLAY_NAME_CHARS: usize = 512;
const TYPESCRIPT_MAX_RESOLVER_IDENTITY_CHARS: usize = 4_096;
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

pub fn detect_adapters(root: &Path, follow_symlinks: bool) -> Result<Vec<AdapterKind>> {
    let mut detected = BTreeSet::new();
    for entry in WalkDir::new(root)
        .follow_links(follow_symlinks)
        .into_iter()
        .filter_entry(is_scannable_entry)
    {
        let entry = entry?;
        if !entry.file_type().is_file() && !entry.file_type().is_symlink() {
            continue;
        }
        match entry.file_name().to_string_lossy().as_ref() {
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

fn is_scannable_entry(entry: &DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return true;
    }
    !matches!(
        entry.file_name().to_string_lossy().as_ref(),
        ".git"
            | ".hg"
            | ".svn"
            | "node_modules"
            | "target"
            | "dist"
            | "build"
            | ".next"
            | ".astro"
            | ".turbo"
            | ".cache"
    )
}

pub fn locate_worker(adapter: AdapterKind) -> Result<WorkerSpec> {
    let executable = std::env::current_exe().context("failed to locate depgraph executable")?;
    let executable_dir = executable.parent().unwrap_or(Path::new("."));
    if let Some(manifest_path) = release_manifest_path(executable_dir) {
        return locate_verified_bundled_worker_for_executable(
            adapter,
            &manifest_path,
            Some(&executable),
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
    if file_name.contains('/') || file_name.contains('\\') || !file_name.ends_with(".mjs") {
        bail!("security policy violation: invalid Web build runtime artifact name");
    }
    let executable = std::env::current_exe().context("failed to locate depgraph executable")?;
    let executable_dir = executable.parent().unwrap_or(Path::new("."));
    if let Some(manifest_path) = release_manifest_path(executable_dir) {
        // Verify the complete compatibility unit and the running core before
        // selecting a build-only runtime artifact from the same manifest.
        locate_verified_bundled_worker_for_executable(
            AdapterKind::Web,
            &manifest_path,
            Some(&executable),
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
    [
        executable_dir.join("release-manifest.json"),
        executable_dir.join("../release-manifest.json"),
    ]
    .into_iter()
    .find(|path| path.is_file())
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
    if spec.adapter == AdapterKind::Web {
        resolve_safe_executable("node", root).map(PathBuf::into_os_string)
    } else {
        Ok(spec.program.clone())
    }
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

pub(crate) async fn probe_worker_version(spec: &WorkerSpec, root: &Path) -> Result<String> {
    let cancellation = CancellationToken::new();
    probe_worker_version_with_cancellation(spec, root, &cancellation).await
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

pub(crate) async fn probe_toolchain_version(
    program: &str,
    argument: &str,
    root: &Path,
) -> Result<String> {
    let program = resolve_safe_executable(program, root)?;
    let output = run_probe(program.as_os_str(), &[OsString::from(argument)], root).await?;
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

fn is_web_definition_relation_kind(kind: &str) -> bool {
    matches!(kind, "declares" | "extends" | "implements" | "instantiates")
}

fn is_web_semantic_dependency_site_kind(kind: &str) -> bool {
    matches!(kind, "web_import" | "web_reexport" | "type_use" | "call")
}

fn is_web_semantic_dependency_edge_kind(kind: &str) -> bool {
    matches!(
        kind,
        "imports" | "reexports" | "type_uses" | "calls" | "may_call"
    )
}

fn is_web_framework_semantic_node(node: &depgraph_protocol::GraphNode) -> bool {
    matches!(
        node.kind.as_str(),
        "component" | "route" | "server_function" | "middleware"
    ) && node.properties.contains_key("canonical_identity")
}

fn is_web_framework_semantic_site_kind(kind: &str) -> bool {
    matches!(
        kind,
        "renders"
            | "hydrates"
            | "client_boundary"
            | "server_boundary"
            | "route_entry"
            | "parent_route"
            | "loads"
            | "before_load"
            | "navigates_to"
            | "masks_to"
            | "rpc_call"
            | "client_stub_for"
            | "handled_by"
            | "uses_middleware"
    )
}

fn is_web_framework_semantic_delta_event(event: &ProtocolEvent) -> bool {
    match event {
        ProtocolEvent::NodeUpsert(upsert) => is_web_framework_semantic_node(&upsert.node),
        ProtocolEvent::EdgeUpsert(upsert) => {
            is_web_framework_semantic_site_kind(&upsert.edge.kind)
                && (upsert.edge.phase == Phase::Semantic
                    || upsert
                        .edge
                        .evidence
                        .first()
                        .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic))
        }
        ProtocolEvent::DependencySite(site) => {
            is_web_framework_semantic_site_kind(&site.site.kind)
                && site
                    .site
                    .evidence
                    .first()
                    .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic)
        }
        _ => false,
    }
}

fn web_semantic_edge_kind_for_site(
    kind: &str,
    resolution_status: ResolutionStatus,
) -> Option<&'static str> {
    match kind {
        "web_import" => Some("imports"),
        "web_reexport" => Some("reexports"),
        "type_use" => Some("type_uses"),
        "call" if resolution_status == ResolutionStatus::Candidates => Some("may_call"),
        "call" => Some("calls"),
        _ => None,
    }
}

fn is_web_callable_symbol_kind(symbol_kind: &str) -> bool {
    matches!(
        symbol_kind,
        "function" | "method" | "constructor" | "anonymous_function" | "local_function"
    )
}

fn is_web_call_source_symbol_kind(symbol_kind: &str) -> bool {
    is_web_callable_symbol_kind(symbol_kind) || symbol_kind == "generated_module_initializer"
}

fn is_web_semantic_delta_event(event: &ProtocolEvent) -> bool {
    match event {
        ProtocolEvent::NodeUpsert(upsert) => {
            matches!(upsert.node.kind.as_str(), "symbol" | "type")
        }
        ProtocolEvent::EdgeUpsert(upsert) => {
            !is_web_framework_semantic_site_kind(&upsert.edge.kind)
                && (upsert.edge.phase == Phase::Semantic
                    || is_web_definition_relation_kind(upsert.edge.kind.as_str()))
        }
        ProtocolEvent::DependencySite(site) => {
            !is_web_framework_semantic_site_kind(&site.site.kind)
                && (matches!(
                    site.site.kind.as_str(),
                    "call"
                        | "type_use"
                        | "rust_use"
                        | "rust_reexport"
                        | "web_import"
                        | "web_reexport"
                ) || site
                    .site
                    .evidence
                    .first()
                    .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic))
        }
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebFrameworkSemanticState {
    Legacy,
    NotEmitted,
    Emitted,
    Discarded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebFrameworkCompletenessState {
    Legacy,
    NotDetected,
    Complete,
    Incomplete,
}

fn web_framework_completeness_state(
    properties: &depgraph_protocol::Properties,
    features: &[String],
) -> std::result::Result<WebFrameworkCompletenessState, String> {
    let tracked = [
        WEB_FRAMEWORK_COMPLETENESS_CAPABILITY_PROPERTY,
        WEB_FRAMEWORK_COMPLETENESS_STATUS_PROPERTY,
        WEB_FRAMEWORK_COMPLETENESS_ISSUE_COUNT_PROPERTY,
        WEB_FRAMEWORK_COMPLETENESS_LEDGER_PROPERTY,
    ];
    let present = tracked
        .iter()
        .filter(|property| properties.contains_key(**property))
        .count();
    if present == 0 {
        return if features.is_empty() {
            Ok(WebFrameworkCompletenessState::Legacy)
        } else {
            Err("Web framework profile omitted its completeness ledger".into())
        };
    }
    if present != tracked.len() {
        return Err("Web worker reported a partial framework completeness declaration".into());
    }
    if properties
        .get(WEB_FRAMEWORK_COMPLETENESS_CAPABILITY_PROPERTY)
        .and_then(Value::as_str)
        != Some(WEB_FRAMEWORK_COMPLETENESS_CAPABILITY_V1)
    {
        return Err("Web worker reported an unapproved framework completeness capability".into());
    }
    let issue_count = properties
        .get(WEB_FRAMEWORK_COMPLETENESS_ISSUE_COUNT_PROPERTY)
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| {
            "Web worker reported an invalid framework completeness issue count".to_owned()
        })?;
    let ledger_text = properties
        .get(WEB_FRAMEWORK_COMPLETENESS_LEDGER_PROPERTY)
        .and_then(Value::as_str)
        .ok_or_else(|| "Web worker omitted its framework completeness ledger".to_owned())?;
    if ledger_text.len() > 64 * 1024 {
        return Err("Web worker framework completeness ledger exceeded its bound".into());
    }
    let ledger = serde_json::from_str::<Vec<Value>>(ledger_text)
        .map_err(|_| "Web worker reported malformed framework completeness JSON".to_owned())?;
    let state = match properties
        .get(WEB_FRAMEWORK_COMPLETENESS_STATUS_PROPERTY)
        .and_then(Value::as_str)
    {
        Some("not-detected") => WebFrameworkCompletenessState::NotDetected,
        Some("complete") => WebFrameworkCompletenessState::Complete,
        Some("incomplete") => WebFrameworkCompletenessState::Incomplete,
        _ => return Err("Web worker reported an invalid framework completeness status".into()),
    };
    if features.is_empty() {
        return if state == WebFrameworkCompletenessState::NotDetected
            && issue_count == 0
            && ledger.is_empty()
        {
            Ok(state)
        } else {
            Err(
                "Web worker without framework features reported a non-empty completeness ledger"
                    .into(),
            )
        };
    }
    if state == WebFrameworkCompletenessState::NotDetected {
        return Err("Web worker detected framework features but reported not-detected".into());
    }
    let expected_frameworks = features.iter().cloned().collect::<BTreeSet<_>>();
    if expected_frameworks.len() != features.len() || ledger.len() != expected_frameworks.len() {
        return Err("Web framework features and completeness ledger cardinality disagree".into());
    }
    let specific_capability = |framework: &str| match framework {
        "next" => Some("next-route-component-boundary-v1"),
        "astro" => Some("astro-component-render-hydration-v1"),
        "tanstack-router" => Some("tanstack-router-typed-route-v1"),
        "tanstack-start" => Some("tanstack-start-rpc-middleware-v1"),
        _ => None,
    };
    let mut observed_frameworks = BTreeSet::new();
    let mut observed_issue_count = 0usize;
    let mut all_complete = true;
    let mut previous = None::<String>;
    for entry in ledger {
        let object = entry
            .as_object()
            .ok_or_else(|| "Web framework completeness ledger entry is not an object".to_owned())?;
        let framework = object
            .get("framework")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "Web framework completeness ledger entry omitted framework".to_owned()
            })?;
        if previous.as_deref().is_some_and(|value| value >= framework) {
            return Err("Web framework completeness ledger is not strictly sorted".into());
        }
        previous = Some(framework.to_owned());
        let specific = specific_capability(framework).ok_or_else(|| {
            format!("Web framework completeness ledger named unsupported framework {framework}")
        })?;
        let strings = |field: &str| -> std::result::Result<Vec<String>, String> {
            object
                .get(field)
                .and_then(Value::as_array)
                .ok_or_else(|| format!("Web framework completeness entry omitted {field}"))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .filter(|value| !value.is_empty() && value.len() <= 512)
                        .map(str::to_owned)
                        .ok_or_else(|| {
                            format!("Web framework completeness entry has invalid {field}")
                        })
                })
                .collect()
        };
        let required = strings("required_capabilities")?;
        let emitted = strings("emitted_capabilities")?;
        let reasons = strings("reasons")?;
        let expected_required = BTreeSet::from([
            "typescript-definition-import-type-call-graph-v2".to_owned(),
            WEB_FRAMEWORK_SEMANTIC_CAPABILITY_V1.to_owned(),
            specific.to_owned(),
        ]);
        let required_set = required.iter().cloned().collect::<BTreeSet<_>>();
        let emitted_set = emitted.iter().cloned().collect::<BTreeSet<_>>();
        let reason_set = reasons.iter().cloned().collect::<BTreeSet<_>>();
        let strictly_sorted = |values: &[String]| values.windows(2).all(|pair| pair[0] < pair[1]);
        if required_set != expected_required
            || required_set.len() != required.len()
            || emitted_set.len() != emitted.len()
            || reason_set.len() != reasons.len()
            || !strictly_sorted(&required)
            || !strictly_sorted(&emitted)
            || !strictly_sorted(&reasons)
            || !emitted_set.is_subset(&required_set)
        {
            return Err(format!(
                "Web framework completeness entry for {framework} has invalid capabilities or reasons"
            ));
        }
        let entry_complete = match object.get("status").and_then(Value::as_str) {
            Some("complete") => true,
            Some("incomplete") => false,
            _ => {
                return Err(format!(
                    "Web framework completeness entry for {framework} has invalid status"
                ));
            }
        };
        if entry_complete != (reasons.is_empty() && emitted_set == required_set) {
            return Err(format!(
                "Web framework completeness entry for {framework} contradicts its capability/reason ledger"
            ));
        }
        all_complete &= entry_complete;
        observed_issue_count += reasons.len();
        observed_frameworks.insert(framework.to_owned());
    }
    if observed_frameworks != expected_frameworks || observed_issue_count != issue_count {
        return Err(
            "Web framework completeness ledger does not match features or issue count".into(),
        );
    }
    if (state == WebFrameworkCompletenessState::Complete) != all_complete {
        return Err("Web framework completeness aggregate status contradicts its ledger".into());
    }
    if state == WebFrameworkCompletenessState::Incomplete && issue_count == 0 {
        return Err("Web incomplete framework profile reported zero issues".into());
    }
    Ok(state)
}

fn web_framework_semantic_state(
    properties: &depgraph_protocol::Properties,
) -> std::result::Result<WebFrameworkSemanticState, String> {
    let tracked = [
        WEB_FRAMEWORK_SEMANTIC_CAPABILITY_PROPERTY,
        WEB_FRAMEWORK_SEMANTIC_STATUS_PROPERTY,
        WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION_PROPERTY,
        WEB_FRAMEWORK_SEMANTIC_NODE_COUNT_PROPERTY,
        WEB_FRAMEWORK_SEMANTIC_SITE_COUNT_PROPERTY,
        WEB_FRAMEWORK_SEMANTIC_EDGE_COUNT_PROPERTY,
    ];
    let present = tracked
        .iter()
        .filter(|property| properties.contains_key(**property))
        .count();
    if present == 0 {
        return Ok(WebFrameworkSemanticState::Legacy);
    }
    if present != tracked.len() {
        return Err(
            "Web worker reported a partial framework semantic capability declaration".into(),
        );
    }
    if properties
        .get(WEB_FRAMEWORK_SEMANTIC_CAPABILITY_PROPERTY)
        .and_then(Value::as_str)
        != Some(WEB_FRAMEWORK_SEMANTIC_CAPABILITY_V1)
    {
        return Err("Web worker reported an unapproved framework semantic capability".into());
    }
    if properties
        .get(WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION_PROPERTY)
        .and_then(Value::as_str)
        != Some(WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION)
    {
        return Err(
            "Web worker reported an unapproved framework semantic extractor version".into(),
        );
    }
    let counts = [
        WEB_FRAMEWORK_SEMANTIC_NODE_COUNT_PROPERTY,
        WEB_FRAMEWORK_SEMANTIC_SITE_COUNT_PROPERTY,
        WEB_FRAMEWORK_SEMANTIC_EDGE_COUNT_PROPERTY,
    ]
    .map(|property| {
        properties
            .get(property)
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| format!("Web worker omitted or has invalid {property}"))
    });
    let [nodes, sites, edges] = counts;
    let (nodes, sites, edges) = (nodes?, sites?, edges?);
    let state = match properties
        .get(WEB_FRAMEWORK_SEMANTIC_STATUS_PROPERTY)
        .and_then(Value::as_str)
    {
        Some("not-emitted") => WebFrameworkSemanticState::NotEmitted,
        Some("emitted") => WebFrameworkSemanticState::Emitted,
        Some("discarded") => WebFrameworkSemanticState::Discarded,
        _ => return Err("Web worker reported an invalid framework semantic status".into()),
    };
    if state != WebFrameworkSemanticState::Emitted && (nodes != 0 || sites != 0 || edges != 0) {
        return Err(format!(
            "Web worker reported framework semantic status {state:?} with non-zero counts"
        ));
    }
    Ok(state)
}

fn is_web_semantic_sentinel_node(node: &depgraph_protocol::GraphNode) -> bool {
    match node.kind.as_str() {
        "external_system" => {
            node.properties.get("external").and_then(Value::as_bool) == Some(true)
                && node.properties.get("language").and_then(Value::as_str) == Some("typescript")
                && node
                    .properties
                    .get("profile_id")
                    .and_then(Value::as_str)
                    .is_some()
                && node
                    .properties
                    .get("compiler_version")
                    .and_then(Value::as_str)
                    == Some(TYPESCRIPT_COMPILER_VERSION)
        }
        "unknown_target" => {
            node.properties.get("language").and_then(Value::as_str) == Some("web")
                && node
                    .properties
                    .get("profile_id")
                    .and_then(Value::as_str)
                    .is_some()
        }
        _ => false,
    }
}

fn discard_web_definition_delta(
    events: &mut Vec<ProtocolEvent>,
    extra_semantic_node_ids: &BTreeSet<String>,
    semantic_node_candidate_ids: &BTreeSet<String>,
    extra_discarded_site_ids: &BTreeSet<String>,
    extra_semantic_endpoint_ids: &BTreeSet<String>,
) {
    let mut semantic_node_ids = extra_semantic_node_ids.clone();
    semantic_node_ids.extend(events.iter().filter_map(|event| match event {
        ProtocolEvent::NodeUpsert(upsert)
            if matches!(upsert.node.kind.as_str(), "symbol" | "type") =>
        {
            Some(upsert.node.id.clone())
        }
        _ => None,
    }));
    let accepted_node_ids = events
        .iter()
        .filter_map(|event| match event {
            ProtocolEvent::NodeUpsert(upsert) => Some(upsert.node.id.as_str()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let orphan_semantic_node_ids = semantic_node_candidate_ids
        .iter()
        .filter(|node_id| !accepted_node_ids.contains(node_id.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>();
    let incident_semantic_node_ids = semantic_node_ids
        .union(&orphan_semantic_node_ids)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut discarded_site_ids = extra_discarded_site_ids.clone();
    discarded_site_ids.extend(events.iter().filter_map(|event| {
        match event {
            ProtocolEvent::DependencySite(site)
                if incident_semantic_node_ids.contains(&site.site.source)
                    || site
                        .site
                        .target_ids
                        .iter()
                        .any(|target| incident_semantic_node_ids.contains(target))
                    || is_web_semantic_delta_event(event) =>
            {
                Some(site.site.id.clone())
            }
            _ => None,
        }
    }));
    discarded_site_ids.extend(events.iter().filter_map(|event| match event {
        ProtocolEvent::EdgeUpsert(upsert)
            if incident_semantic_node_ids.contains(upsert.edge.source.as_str())
                || incident_semantic_node_ids.contains(upsert.edge.target.as_str())
                || is_web_semantic_delta_event(event) =>
        {
            upsert.edge.site_id.clone()
        }
        _ => None,
    }));
    let mut semantic_endpoint_ids = extra_semantic_endpoint_ids.clone();
    for event in events.iter() {
        match event {
            ProtocolEvent::DependencySite(site) if is_web_semantic_delta_event(event) => {
                semantic_endpoint_ids.insert(site.site.source.clone());
                semantic_endpoint_ids.extend(site.site.target_ids.iter().cloned());
            }
            ProtocolEvent::EdgeUpsert(upsert) if is_web_semantic_delta_event(event) => {
                semantic_endpoint_ids.insert(upsert.edge.source.clone());
                semantic_endpoint_ids.insert(upsert.edge.target.clone());
            }
            _ => {}
        }
    }
    let retained_site_ids = events
        .iter()
        .filter_map(|event| match event {
            ProtocolEvent::DependencySite(site)
                if !discarded_site_ids.contains(site.site.id.as_str()) =>
            {
                Some(site.site.id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut retained_endpoint_ids = BTreeSet::new();
    for event in events.iter() {
        match event {
            ProtocolEvent::EdgeUpsert(upsert)
                if !incident_semantic_node_ids.contains(upsert.edge.source.as_str())
                    && !incident_semantic_node_ids.contains(upsert.edge.target.as_str())
                    && upsert
                        .edge
                        .site_id
                        .as_deref()
                        .is_none_or(|site_id| retained_site_ids.contains(site_id))
                    && !is_web_semantic_delta_event(event) =>
            {
                retained_endpoint_ids.insert(upsert.edge.source.clone());
                retained_endpoint_ids.insert(upsert.edge.target.clone());
            }
            ProtocolEvent::DependencySite(site)
                if !discarded_site_ids.contains(site.site.id.as_str()) =>
            {
                retained_endpoint_ids.insert(site.site.source.clone());
                retained_endpoint_ids.extend(site.site.target_ids.iter().cloned());
            }
            _ => {}
        }
    }
    events.retain(|event| match event {
        ProtocolEvent::NodeUpsert(upsert) => {
            let semantic_sentinel = matches!(
                upsert.node.kind.as_str(),
                "external_system" | "unknown_target"
            ) && (semantic_endpoint_ids.contains(upsert.node.id.as_str())
                || is_web_semantic_sentinel_node(&upsert.node));
            !semantic_node_ids.contains(upsert.node.id.as_str())
                && (!semantic_sentinel || retained_endpoint_ids.contains(upsert.node.id.as_str()))
        }
        ProtocolEvent::EdgeUpsert(upsert) => {
            !incident_semantic_node_ids.contains(upsert.edge.source.as_str())
                && !incident_semantic_node_ids.contains(upsert.edge.target.as_str())
                && upsert
                    .edge
                    .site_id
                    .as_deref()
                    .is_none_or(|site_id| retained_site_ids.contains(site_id))
                && !is_web_semantic_delta_event(event)
        }
        ProtocolEvent::DependencySite(site) => !discarded_site_ids.contains(&site.site.id),
        ProtocolEvent::Diagnostic(event) => ![
            TYPESCRIPT_DEFINITION_ISSUE_PROPERTY,
            TYPESCRIPT_DEPENDENCY_ISSUE_PROPERTY,
        ]
        .iter()
        .any(|property| {
            event
                .diagnostic
                .properties
                .get(*property)
                .and_then(Value::as_bool)
                == Some(true)
        }),
        ProtocolEvent::FileCompleted(_)
        | ProtocolEvent::ProfileCompleted(_)
        | ProtocolEvent::ScanCompleted(_) => false,
        _ => true,
    });
    for event in events {
        let ProtocolEvent::ProfileDeclared(declared) = event else {
            continue;
        };
        let Ok(capability) = web_semantic_capability(&declared.profile.properties) else {
            continue;
        };
        let project_failed = declared
            .profile
            .properties
            .get(TYPESCRIPT_PROJECT_STATUS_PROPERTY)
            .and_then(Value::as_str)
            == Some("failed");
        let discarded_status = match capability {
            WebSemanticCapability::DefinitionGraphV1 => "definition-graph-discarded",
            WebSemanticCapability::DefinitionImportTypeGraphV1 => {
                "definition-import-type-graph-discarded"
            }
            WebSemanticCapability::DefinitionImportTypeCallGraphV1
            | WebSemanticCapability::DefinitionImportTypeCallGraphV2 => {
                "definition-import-type-call-graph-discarded"
            }
        };
        let properties = &mut declared.profile.properties;
        properties.insert(
            TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY.to_owned(),
            Value::String(if project_failed {
                "failed".to_owned()
            } else {
                discarded_status.to_owned()
            }),
        );
        properties.insert(
            TYPESCRIPT_DEFINITION_STATUS_PROPERTY.to_owned(),
            Value::String("failed".to_owned()),
        );
        for property in [
            "typescript_semantic_node_count",
            "typescript_semantic_relation_count",
            "typescript_semantic_diagnostics",
            "typescript_emitted_semantic_diagnostics",
            "typescript_semantic_issue_count",
        ] {
            properties.insert(property.to_owned(), Value::String("0".to_owned()));
        }
        if matches!(
            capability,
            WebSemanticCapability::DefinitionImportTypeGraphV1
                | WebSemanticCapability::DefinitionImportTypeCallGraphV1
                | WebSemanticCapability::DefinitionImportTypeCallGraphV2
        ) {
            properties.insert(
                TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY.to_owned(),
                Value::String("0".to_owned()),
            );
        } else {
            properties.remove(TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY);
        }
        if matches!(
            capability,
            WebSemanticCapability::DefinitionImportTypeCallGraphV1
                | WebSemanticCapability::DefinitionImportTypeCallGraphV2
        ) {
            properties.insert(
                TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY.to_owned(),
                Value::String("0".to_owned()),
            );
        } else {
            properties.remove(TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY);
        }
    }
}

fn discard_web_framework_delta(events: &mut Vec<ProtocolEvent>) {
    let framework_node_ids = events
        .iter()
        .filter_map(|event| match event {
            ProtocolEvent::NodeUpsert(upsert) if is_web_framework_semantic_node(&upsert.node) => {
                Some(upsert.node.id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let framework_site_ids = events
        .iter()
        .filter_map(|event| match event {
            ProtocolEvent::DependencySite(site)
                if is_web_framework_semantic_delta_event(event)
                    || framework_node_ids.contains(&site.site.source)
                    || site
                        .site
                        .target_ids
                        .iter()
                        .any(|target| framework_node_ids.contains(target)) =>
            {
                Some(site.site.id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    events.retain(|event| match event {
        ProtocolEvent::NodeUpsert(upsert) => !framework_node_ids.contains(&upsert.node.id),
        ProtocolEvent::DependencySite(site) => !framework_site_ids.contains(&site.site.id),
        ProtocolEvent::EdgeUpsert(upsert) => {
            !is_web_framework_semantic_delta_event(event)
                && !framework_node_ids.contains(&upsert.edge.source)
                && !framework_node_ids.contains(&upsert.edge.target)
                && upsert
                    .edge
                    .site_id
                    .as_ref()
                    .is_none_or(|site_id| !framework_site_ids.contains(site_id))
        }
        ProtocolEvent::FileCompleted(_)
        | ProtocolEvent::ProfileCompleted(_)
        | ProtocolEvent::ScanCompleted(_) => false,
        _ => true,
    });
    for event in events {
        let ProtocolEvent::ProfileDeclared(declared) = event else {
            continue;
        };
        if web_framework_semantic_state(&declared.profile.properties)
            != Ok(WebFrameworkSemanticState::Emitted)
        {
            continue;
        }
        let properties = &mut declared.profile.properties;
        properties.insert(
            WEB_FRAMEWORK_SEMANTIC_STATUS_PROPERTY.to_owned(),
            Value::String("discarded".to_owned()),
        );
        for property in [
            WEB_FRAMEWORK_SEMANTIC_NODE_COUNT_PROPERTY,
            WEB_FRAMEWORK_SEMANTIC_SITE_COUNT_PROPERTY,
            WEB_FRAMEWORK_SEMANTIC_EDGE_COUNT_PROPERTY,
        ] {
            properties.insert(property.to_owned(), Value::String("0".to_owned()));
        }
        let Some(ledger_text) = properties
            .get(WEB_FRAMEWORK_COMPLETENESS_LEDGER_PROPERTY)
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Ok(mut ledger) = serde_json::from_str::<Vec<Value>>(ledger_text) else {
            continue;
        };
        let mut issue_count = 0usize;
        for entry in &mut ledger {
            let Some(object) = entry.as_object_mut() else {
                continue;
            };
            object.insert("status".to_owned(), Value::String("incomplete".to_owned()));
            let retained_capabilities = object
                .get("emitted_capabilities")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter(|capability| {
                    *capability == "typescript-definition-import-type-call-graph-v2"
                })
                .map(|capability| Value::String(capability.to_owned()))
                .collect::<Vec<_>>();
            object.insert(
                "emitted_capabilities".to_owned(),
                Value::Array(retained_capabilities),
            );
            let mut reasons = object
                .get("reasons")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<BTreeSet<_>>();
            reasons.insert("core_framework_delta_discarded".to_owned());
            issue_count += reasons.len();
            object.insert(
                "reasons".to_owned(),
                Value::Array(reasons.into_iter().map(Value::String).collect()),
            );
        }
        properties.insert(
            WEB_FRAMEWORK_COMPLETENESS_STATUS_PROPERTY.to_owned(),
            Value::String("incomplete".to_owned()),
        );
        properties.insert(
            WEB_FRAMEWORK_COMPLETENESS_ISSUE_COUNT_PROPERTY.to_owned(),
            Value::String(issue_count.to_string()),
        );
        if let Ok(serialized) = serde_json::to_string(&ledger) {
            properties.insert(
                WEB_FRAMEWORK_COMPLETENESS_LEDGER_PROPERTY.to_owned(),
                Value::String(serialized),
            );
        }
    }
}

fn record_web_rejected_site_closure(
    event: &ProtocolEvent,
    discarded_site_ids: &mut BTreeSet<String>,
) {
    match event {
        ProtocolEvent::EdgeUpsert(upsert) => {
            if let Some(site_id) = &upsert.edge.site_id {
                discarded_site_ids.insert(site_id.clone());
            }
        }
        ProtocolEvent::DependencySite(site) => {
            discarded_site_ids.insert(site.site.id.clone());
        }
        _ => {}
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebSemanticCapability {
    DefinitionGraphV1,
    DefinitionImportTypeGraphV1,
    DefinitionImportTypeCallGraphV1,
    DefinitionImportTypeCallGraphV2,
}

fn web_semantic_capability(
    properties: &depgraph_protocol::Properties,
) -> std::result::Result<WebSemanticCapability, String> {
    let analysis_mode = properties
        .get(TYPESCRIPT_ANALYSIS_MODE_PROPERTY)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Web worker omitted {TYPESCRIPT_ANALYSIS_MODE_PROPERTY}"))?;
    let emission = properties
        .get(TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Web worker omitted {TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY}"))?;
    match (analysis_mode, emission) {
        (
            TYPESCRIPT_ANALYSIS_MODE_DEFINITION_GRAPH,
            TYPESCRIPT_SEMANTIC_EMISSION_DEFINITION_GRAPH_V1,
        ) => Ok(WebSemanticCapability::DefinitionGraphV1),
        (
            TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_GRAPH,
            TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_GRAPH_V1,
        ) => Ok(WebSemanticCapability::DefinitionImportTypeGraphV1),
        (
            TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_CALL_GRAPH,
            TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V1,
        ) => Ok(WebSemanticCapability::DefinitionImportTypeCallGraphV1),
        (
            TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_CALL_GRAPH,
            TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2,
        ) => Ok(WebSemanticCapability::DefinitionImportTypeCallGraphV2),
        _ => Err(format!(
            "Web worker reported unsupported or mismatched semantic capability {TYPESCRIPT_ANALYSIS_MODE_PROPERTY}={analysis_mode:?}, {TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY}={emission:?}"
        )),
    }
}

fn web_definition_profile_ready(
    properties: &depgraph_protocol::Properties,
    capability: WebSemanticCapability,
) -> std::result::Result<bool, String> {
    let value = |property: &str| {
        properties
            .get(property)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Web worker omitted {property}"))
    };
    let state = (
        value(TYPESCRIPT_PROJECT_STATUS_PROPERTY)?,
        value(TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY)?,
        value(TYPESCRIPT_DEFINITION_STATUS_PROPERTY)?,
    );
    let (emitted, discarded) = match capability {
        WebSemanticCapability::DefinitionGraphV1 => {
            ("definition-graph-emitted", "definition-graph-discarded")
        }
        WebSemanticCapability::DefinitionImportTypeGraphV1 => (
            "definition-import-type-graph-emitted",
            "definition-import-type-graph-discarded",
        ),
        WebSemanticCapability::DefinitionImportTypeCallGraphV1
        | WebSemanticCapability::DefinitionImportTypeCallGraphV2 => (
            "definition-import-type-call-graph-emitted",
            "definition-import-type-call-graph-discarded",
        ),
    };
    match state {
        ("ready", checker, "ready") if checker == emitted => Ok(true),
        ("ready", checker, "failed") if checker == discarded => Ok(false),
        ("failed", "failed", "failed") => Ok(false),
        (project, checker, definition) => Err(format!(
            "Web worker reported inconsistent TypeScript semantic state project={project:?}, typechecker={checker:?}, definition={definition:?} for {capability:?}"
        )),
    }
}

fn path_belongs_to_workspace(path: &str, workspace_path: &str) -> bool {
    workspace_path == "."
        || path == workspace_path
        || path
            .strip_prefix(workspace_path)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn node_package_id(node: &depgraph_protocol::GraphNode) -> Option<&str> {
    node.properties.get("package_id").and_then(Value::as_str)
}

fn web_evidence_matches_source_span(evidence: &depgraph_protocol::Evidence, span: &Value) -> bool {
    [
        ("start_line", evidence.start_line),
        ("start_column", evidence.start_column),
        ("end_line", evidence.end_line),
        ("end_column", evidence.end_column),
    ]
    .into_iter()
    .all(|(field, coordinate)| span.get(field).and_then(Value::as_u64) == coordinate.map(u64::from))
}

fn web_evidence_has_same_anchor(
    left: &depgraph_protocol::Evidence,
    right: &depgraph_protocol::Evidence,
) -> bool {
    left.path == right.path
        && left.start_line == right.start_line
        && left.start_column == right.start_column
        && left.end_line == right.end_line
        && left.end_column == right.end_column
}

fn web_has_matching_source_support(
    evidence: &[depgraph_protocol::Evidence],
    primary: &depgraph_protocol::Evidence,
    profile_id: &str,
    occurrence_kind: &str,
) -> bool {
    evidence.iter().skip(1).any(|supporting| {
        supporting.kind == EvidenceKind::Source
            && supporting.extractor == "typescript-native-syntax"
            && supporting.extractor_version == TYPESCRIPT_COMPILER_VERSION
            && web_evidence_has_same_anchor(primary, supporting)
            && supporting
                .properties
                .get("profile_id")
                .and_then(Value::as_str)
                == Some(profile_id)
            && supporting
                .properties
                .get("occurrence_kind")
                .and_then(Value::as_str)
                == Some(occurrence_kind)
    })
}

fn web_occurrence_kind_matches_site(site_kind: &str, occurrence_kind: &str) -> bool {
    match site_kind {
        "web_import" => matches!(
            occurrence_kind,
            "named_import"
                | "default_import"
                | "namespace_import"
                | "side_effect_import"
                | "empty_import"
                | "import_equals"
                | "require_call"
                | "dynamic_import"
                | "import_type"
        ),
        "web_reexport" => matches!(
            occurrence_kind,
            "named_reexport" | "namespace_reexport" | "empty_reexport" | "export_star"
        ),
        "type_use" => matches!(
            occurrence_kind,
            "type_reference" | "heritage_type" | "jsdoc_type"
        ),
        "call" => matches!(
            occurrence_kind,
            "call_expression" | "new_expression" | "tagged_template"
        ),
        _ => false,
    }
}

fn web_optional_evidence_string<'a>(
    properties: &'a depgraph_protocol::Properties,
    field: &str,
    max_utf16_units: usize,
    allow_empty: bool,
) -> std::result::Result<Option<&'a str>, ()> {
    let Some(value) = properties.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_str() else {
        return Err(());
    };
    if (!allow_empty && value.is_empty()) || value.encode_utf16().count() > max_utf16_units {
        return Err(());
    }
    Ok(Some(value))
}

fn javascript_encode_uri_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            )
        {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}")
                .expect("writing percent encoding into a String cannot fail");
        }
    }
    encoded
}

fn web_occurrence_requires_repository_module(site_kind: &str, occurrence_kind: &str) -> bool {
    match site_kind {
        "web_import" => matches!(
            occurrence_kind,
            "namespace_import"
                | "side_effect_import"
                | "empty_import"
                | "import_equals"
                | "require_call"
                | "dynamic_import"
                | "import_type"
        ),
        "web_reexport" => matches!(
            occurrence_kind,
            "namespace_reexport" | "empty_reexport" | "export_star"
        ),
        _ => false,
    }
}

fn web_source_span_is_canonical(span: Option<&Value>) -> bool {
    let Some(object) = span.and_then(Value::as_object) else {
        return false;
    };
    if object.len() != 4
        || !["start_line", "start_column", "end_line", "end_column"]
            .iter()
            .all(|field| object.contains_key(*field))
    {
        return false;
    }
    let coordinate = |field: &str| {
        object
            .get(field)
            .and_then(Value::as_u64)
            .filter(|coordinate| *coordinate > 0 && *coordinate <= u64::from(u32::MAX))
    };
    let (Some(start_line), Some(start_column), Some(end_line), Some(end_column)) = (
        coordinate("start_line"),
        coordinate("start_column"),
        coordinate("end_line"),
        coordinate("end_column"),
    ) else {
        return false;
    };
    (start_line, start_column) <= (end_line, end_column)
}

fn resolve_web_semantic_reference<'a>(
    reference: &str,
    protocol: &'a ValidatedProtocol,
    nodes_by_resolver: &std::collections::BTreeMap<&str, &'a depgraph_protocol::GraphNode>,
) -> Option<&'a depgraph_protocol::GraphNode> {
    if let Some(node_id) = reference.strip_prefix("node:") {
        protocol.nodes.get(node_id)
    } else {
        nodes_by_resolver.get(reference).copied()
    }
}

fn web_json_object_has_exact_fields(
    object: &serde_json::Map<String, Value>,
    fields: &[&str],
) -> bool {
    object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
}

fn canonical_javascript_number(value: f64) -> Option<String> {
    if !value.is_finite() {
        return None;
    }
    if value == 0.0 {
        return Some("0".to_owned());
    }

    let negative = value.is_sign_negative();
    let representation = format!("{:?}", value.abs());
    let (mantissa, exponent) = representation.split_once(['e', 'E']).map_or(
        (representation.as_str(), 0),
        |(mantissa, exponent)| {
            (
                mantissa,
                exponent
                    .parse::<i32>()
                    .expect("finite f64 debug exponents are valid integers"),
            )
        },
    );
    let (integer, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let (mut digits, decimal_position) = if integer == "0" {
        let first_significant = fraction
            .find(|character: char| character != '0')
            .unwrap_or(fraction.len());
        (
            fraction[first_significant..].to_owned(),
            -(first_significant as i32),
        )
    } else {
        (
            format!("{integer}{fraction}"),
            integer.len() as i32 + exponent,
        )
    };
    while digits.len() > 1 && digits.ends_with('0') && !fraction.is_empty() {
        digits.pop();
    }
    if digits.is_empty() {
        return Some("0".to_owned());
    }

    let body = if decimal_position > 0 && decimal_position <= 21 {
        let decimal_position = decimal_position as usize;
        if digits.len() <= decimal_position {
            format!("{digits}{}", "0".repeat(decimal_position - digits.len()))
        } else {
            format!(
                "{}.{}",
                &digits[..decimal_position],
                &digits[decimal_position..]
            )
        }
    } else if decimal_position <= 0 && decimal_position > -6 {
        format!("0.{}{digits}", "0".repeat((-decimal_position) as usize))
    } else {
        let exponent = decimal_position - 1;
        let mantissa = if digits.len() == 1 {
            digits
        } else {
            format!("{}.{}", &digits[..1], &digits[1..])
        };
        format!(
            "{mantissa}e{}{exponent}",
            if exponent >= 0 { "+" } else { "" }
        )
    };
    Some(if negative { format!("-{body}") } else { body })
}

fn web_literal_value_is_canonical(value_kind: &str, value: &str) -> bool {
    match value_kind {
        "string" => true,
        "boolean" => matches!(value, "true" | "false"),
        "bigint" => {
            value == "0"
                || value
                    .strip_prefix('-')
                    .unwrap_or(value)
                    .as_bytes()
                    .split_first()
                    .is_some_and(|(first, rest)| {
                        first.is_ascii_digit()
                            && *first != b'0'
                            && rest.iter().all(u8::is_ascii_digit)
                    })
        }
        "number" if value == "-0" => true,
        "number" => value
            .parse::<f64>()
            .ok()
            .and_then(canonical_javascript_number)
            .is_some_and(|canonical| canonical == value),
        _ => false,
    }
}

fn compare_javascript_strings(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn web_resolver_identity_is_portable(resolver: &str) -> bool {
    let bytes = resolver.as_bytes();
    let drive_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\');
    !resolver.is_empty()
        && resolver.encode_utf16().count() <= TYPESCRIPT_MAX_RESOLVER_IDENTITY_CHARS
        && !resolver.contains('\0')
        && !resolver.starts_with('/')
        && !resolver.starts_with("\\\\")
        && !drive_absolute
        && !resolver.to_ascii_lowercase().starts_with("file://")
}

fn validate_web_type_argument_references(
    descriptor: &Value,
    protocol: &ValidatedProtocol,
    nodes_by_resolver: &std::collections::BTreeMap<&str, &depgraph_protocol::GraphNode>,
    profile_id: &str,
    instance_id: &str,
    depth: usize,
) -> std::result::Result<Value, String> {
    if depth > TYPESCRIPT_MAX_TYPE_DESCRIPTOR_DEPTH {
        return Err(format!(
            "Web generic instance {instance_id} type argument nesting exceeds {TYPESCRIPT_MAX_TYPE_DESCRIPTOR_DEPTH}"
        ));
    }
    let object = descriptor.as_object().ok_or_else(|| {
        format!("Web generic instance {instance_id} has a non-object type argument")
    })?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Web generic instance {instance_id} type argument omitted kind"))?;
    let require_reference = |field: &str| -> std::result::Result<_, String> {
        let reference = object.get(field).and_then(Value::as_str).ok_or_else(|| {
            format!("Web generic instance {instance_id} {kind} type argument omitted {field}")
        })?;
        let target = resolve_web_semantic_reference(reference, protocol, nodes_by_resolver)
            .ok_or_else(|| {
                format!(
                    "Web generic instance {instance_id} type argument references missing semantic definition {reference:?}"
                )
            })?;
        if !matches!(target.kind.as_str(), "symbol" | "type")
            || target.properties.get("profile_id").and_then(Value::as_str) != Some(profile_id)
        {
            return Err(format!(
                "Web generic instance {instance_id} type argument reference {reference:?} belongs to another profile or is not semantic"
            ));
        }
        Ok(target)
    };

    let canonical = match kind {
        "intrinsic" => {
            if !web_json_object_has_exact_fields(object, &["kind", "name"]) {
                return Err(format!(
                    "Web generic instance {instance_id} intrinsic type argument has a non-canonical shape"
                ));
            }
            let name = object.get("name").and_then(Value::as_str).ok_or_else(|| {
                format!("Web generic instance {instance_id} intrinsic type argument omitted name")
            })?;
            if !matches!(
                name,
                "any"
                    | "unknown"
                    | "string"
                    | "number"
                    | "boolean"
                    | "bigint"
                    | "symbol"
                    | "void"
                    | "undefined"
                    | "null"
                    | "never"
            ) {
                return Err(format!(
                    "Web generic instance {instance_id} has unknown intrinsic type argument {name:?}"
                ));
            }
            serde_json::json!({"kind": "intrinsic", "name": name})
        }
        "literal" => {
            if !web_json_object_has_exact_fields(object, &["kind", "value_kind", "value"]) {
                return Err(format!(
                    "Web generic instance {instance_id} literal type argument has a non-canonical shape"
                ));
            }
            let value_kind = object
                .get("value_kind")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "Web generic instance {instance_id} literal type argument omitted value_kind"
                    )
                })?;
            let value = object.get("value").and_then(Value::as_str).ok_or_else(|| {
                format!("Web generic instance {instance_id} literal type argument omitted value")
            })?;
            if !web_literal_value_is_canonical(value_kind, value) {
                return Err(format!(
                    "Web generic instance {instance_id} has a non-canonical {value_kind:?} literal {value:?}"
                ));
            }
            serde_json::json!({"kind": "literal", "value_kind": value_kind, "value": value})
        }
        "definition" => {
            if !web_json_object_has_exact_fields(object, &["kind", "resolver_identity"]) {
                return Err(format!(
                    "Web generic instance {instance_id} definition type argument has a non-canonical shape"
                ));
            }
            let target = require_reference("resolver_identity")?;
            if target.kind != "type"
                || target.properties.get("type_kind").and_then(Value::as_str)
                    == Some("generic_instance")
            {
                return Err(format!(
                    "Web generic instance {instance_id} definition argument must reference a concrete type"
                ));
            }
            serde_json::json!({
                "kind": "definition",
                "resolver_identity": object["resolver_identity"].clone(),
            })
        }
        "type_parameter" => {
            if !web_json_object_has_exact_fields(object, &["kind", "owner", "index", "name"]) {
                return Err(format!(
                    "Web generic instance {instance_id} type parameter has a non-canonical shape"
                ));
            }
            require_reference("owner")?;
            let index = object
                .get("index")
                .and_then(Value::as_u64)
                .filter(|index| *index <= 9_007_199_254_740_991)
                .ok_or_else(|| {
                    format!(
                        "Web generic instance {instance_id} type parameter has an invalid index"
                    )
                })?;
            let name = object
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| {
                    !name.is_empty()
                        && name.encode_utf16().count() <= TYPESCRIPT_MAX_DISPLAY_NAME_CHARS
                })
                .ok_or_else(|| {
                    format!("Web generic instance {instance_id} type parameter has an invalid name")
                })?;
            serde_json::json!({
                "kind": "type_parameter",
                "owner": object["owner"].clone(),
                "index": index,
                "name": name,
            })
        }
        "application" => {
            if !web_json_object_has_exact_fields(object, &["kind", "target", "type_arguments"]) {
                return Err(format!(
                    "Web generic instance {instance_id} application argument has a non-canonical shape"
                ));
            }
            let target = object.get("target").ok_or_else(|| {
                format!("Web generic instance {instance_id} application argument omitted target")
            })?;
            if !matches!(
                target.get("kind").and_then(Value::as_str),
                Some("definition" | "type_parameter")
            ) {
                return Err(format!(
                    "Web generic instance {instance_id} application target is not a definition or type parameter"
                ));
            }
            let target = validate_web_type_argument_references(
                target,
                protocol,
                nodes_by_resolver,
                profile_id,
                instance_id,
                depth + 1,
            )?;
            let arguments = object
                .get("type_arguments")
                .and_then(Value::as_array)
                .filter(|arguments| {
                    !arguments.is_empty() && arguments.len() <= TYPESCRIPT_MAX_TYPE_ARGUMENTS
                })
                .ok_or_else(|| {
                    format!(
                        "Web generic instance {instance_id} application has invalid type arguments"
                    )
                })?;
            let mut canonical_arguments = Vec::with_capacity(arguments.len());
            for argument in arguments {
                canonical_arguments.push(validate_web_type_argument_references(
                    argument,
                    protocol,
                    nodes_by_resolver,
                    profile_id,
                    instance_id,
                    depth + 1,
                )?);
            }
            serde_json::json!({
                "kind": "application",
                "target": target,
                "type_arguments": canonical_arguments,
            })
        }
        "union" | "intersection" => {
            if !web_json_object_has_exact_fields(object, &["kind", "members"]) {
                return Err(format!(
                    "Web generic instance {instance_id} {kind} has a non-canonical shape"
                ));
            }
            let members = object
                .get("members")
                .and_then(Value::as_array)
                .filter(|members| {
                    !members.is_empty() && members.len() <= TYPESCRIPT_MAX_TYPE_DESCRIPTOR_MEMBERS
                })
                .ok_or_else(|| {
                    format!("Web generic instance {instance_id} {kind} has invalid members")
                })?;
            let mut canonical_members = Vec::with_capacity(members.len());
            let mut previous = None::<String>;
            for member in members {
                let canonical_member = validate_web_type_argument_references(
                    member,
                    protocol,
                    nodes_by_resolver,
                    profile_id,
                    instance_id,
                    depth + 1,
                )?;
                let serialized = serde_json::to_string(&canonical_member)
                    .expect("canonical TypeScript type descriptors always serialize");
                if previous.as_deref().is_some_and(|previous| {
                    compare_javascript_strings(previous, &serialized) != std::cmp::Ordering::Less
                }) {
                    return Err(format!(
                        "Web generic instance {instance_id} {kind} members are not in strict canonical order"
                    ));
                }
                previous = Some(serialized);
                canonical_members.push(canonical_member);
            }
            serde_json::json!({"kind": kind, "members": canonical_members})
        }
        other => {
            return Err(format!(
                "Web generic instance {instance_id} has unsupported type argument kind {other:?}"
            ));
        }
    };
    if descriptor != &canonical {
        return Err(format!(
            "Web generic instance {instance_id} has a non-canonical {kind} type argument"
        ));
    }
    let serialized = serde_json::to_string(&canonical)
        .expect("canonical TypeScript type descriptors always serialize");
    if serialized.encode_utf16().count() > TYPESCRIPT_MAX_TYPE_DESCRIPTOR_CHARS {
        return Err(format!(
            "Web generic instance {instance_id} {kind} type argument exceeds {TYPESCRIPT_MAX_TYPE_DESCRIPTOR_CHARS} characters"
        ));
    }
    Ok(canonical)
}

fn validate_web_definition_graph(
    protocol: &ValidatedProtocol,
    web_profiles: &BTreeSet<String>,
    definition_profiles: &BTreeSet<String>,
    import_type_profiles: &BTreeSet<String>,
    call_profiles: &BTreeSet<String>,
    candidate_call_profiles: &BTreeSet<String>,
) -> std::result::Result<(), String> {
    let repository_identities = protocol
        .nodes
        .values()
        .filter(|node| node.kind == "workspace")
        .filter_map(|node| {
            node.properties
                .get("repository_identity")
                .and_then(Value::as_str)
        })
        .collect::<BTreeSet<_>>();
    let repository_identity = (repository_identities.len() == 1).then(|| {
        *repository_identities
            .first()
            .expect("one identity was checked")
    });

    let mut repository_packages = std::collections::BTreeMap::<String, (String, String)>::new();
    for node in protocol
        .nodes
        .values()
        .filter(|node| node.kind == "package_instance")
    {
        if node.properties.get("workspace").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let Some(locator) = node.properties.get("locator").and_then(Value::as_str) else {
            continue;
        };
        let workspace_path = node
            .properties
            .get("workspace_path")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "repository package {} omitted properties.workspace_path",
                    node.id
                )
            })?;
        if repository_packages
            .insert(
                locator.to_owned(),
                (node.id.clone(), workspace_path.to_owned()),
            )
            .is_some()
        {
            return Err(format!(
                "multiple repository package nodes claim locator {locator:?}"
            ));
        }
    }
    let mut files_by_path =
        std::collections::BTreeMap::<String, &depgraph_protocol::GraphNode>::new();
    for node in protocol.nodes.values().filter(|node| node.kind == "file") {
        let Some(path) = node.properties.get("path").and_then(Value::as_str) else {
            continue;
        };
        if files_by_path.insert(path.to_owned(), node).is_some() {
            return Err(format!(
                "multiple file nodes claim repository path {path:?}"
            ));
        }
    }
    let mut semantic_nodes_by_profile = std::collections::BTreeMap::<&str, usize>::new();
    for node in protocol
        .nodes
        .values()
        .filter(|node| matches!(node.kind.as_str(), "symbol" | "type"))
    {
        let profile_id = node
            .properties
            .get("profile_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "Web semantic node {} must declare properties.profile_id",
                    node.id
                )
            })?;
        if !definition_profiles.contains(profile_id) {
            return Err(format!(
                "Web semantic node {} references profile {profile_id:?} without the definition-graph-v1 capability",
                node.id
            ));
        }
        let language = node.properties.get("language").and_then(Value::as_str);
        if !matches!(language, Some("typescript" | "javascript")) {
            return Err(format!(
                "Web semantic node {} must declare language=typescript or javascript",
                node.id
            ));
        }
        if node.display_name.as_deref().is_none_or(|display_name| {
            display_name.is_empty()
                || display_name.encode_utf16().count() > TYPESCRIPT_MAX_DISPLAY_NAME_CHARS
        }) {
            return Err(format!(
                "Web semantic node {} has an invalid display name",
                node.id
            ));
        }
        let semantic_kind = node
            .properties
            .get(if node.kind == "symbol" {
                "symbol_kind"
            } else {
                "type_kind"
            })
            .and_then(Value::as_str)
            .expect("the semantic contract requires semantic kinds");
        let semantic_kind_is_supported = if node.kind == "symbol" {
            matches!(
                semantic_kind,
                "anonymous_function"
                    | "constructor"
                    | "function"
                    | "function_variable"
                    | "local_function"
                    | "local_function_variable"
                    | "method"
            ) || (semantic_kind == "variable" && import_type_profiles.contains(profile_id))
                || (semantic_kind == "generated_module_initializer"
                    && call_profiles.contains(profile_id))
        } else {
            matches!(
                semantic_kind,
                "class" | "enum" | "generic_instance" | "interface" | "type_alias"
            )
        };
        if !semantic_kind_is_supported {
            return Err(format!(
                "Web semantic node {} has unsupported {} {semantic_kind:?}",
                node.id, node.kind
            ));
        }
        if !web_source_span_is_canonical(node.properties.get("source_span")) {
            return Err(format!(
                "Web semantic node {} has an invalid source_span",
                node.id
            ));
        }
        let package_locator = node
            .properties
            .get("package_locator")
            .and_then(Value::as_str)
            .expect("the semantic contract requires package_locator");
        let (package_id, workspace_path) = repository_packages.get(package_locator).ok_or_else(|| {
            format!(
                "Web semantic node {} package locator {package_locator:?} is not a repository workspace package",
                node.id
            )
        })?;
        if node.properties.get("package_id").and_then(Value::as_str) != Some(package_id) {
            return Err(format!(
                "Web semantic node {} package_id does not match workspace package {}",
                node.id, package_id
            ));
        }
        let source_path = node
            .properties
            .get("source_path")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Web semantic node {} omitted source_path", node.id))?;
        if !path_belongs_to_workspace(source_path, workspace_path) {
            return Err(format!(
                "Web semantic node {} source_path {source_path:?} escapes workspace path {workspace_path:?}",
                node.id
            ));
        }
        let source_file = files_by_path.get(source_path).ok_or_else(|| {
            format!(
                "Web semantic node {} source_path {source_path:?} has no repository file node",
                node.id
            )
        })?;
        if source_file
            .properties
            .get("package_id")
            .and_then(Value::as_str)
            != Some(package_id)
        {
            return Err(format!(
                "Web semantic node {} and source file {} disagree on package ownership",
                node.id, source_file.id
            ));
        }
        if source_file
            .properties
            .get("language")
            .and_then(Value::as_str)
            != language
        {
            return Err(format!(
                "Web semantic node {} and source file {} disagree on language",
                node.id, source_file.id
            ));
        }
        *semantic_nodes_by_profile.entry(profile_id).or_default() += 1;
    }

    let semantic_node_ids = protocol
        .nodes
        .values()
        .filter(|node| matches!(node.kind.as_str(), "symbol" | "type"))
        .map(|node| node.id.as_str())
        .collect::<BTreeSet<_>>();
    for edge in protocol.edges.values() {
        let incident_to_definition = semantic_node_ids.contains(edge.source.as_str())
            || semantic_node_ids.contains(edge.target.as_str());
        let allowed_definition_relation = edge.phase == Phase::Semantic
            && is_web_definition_relation_kind(&edge.kind)
            && edge.site_id.is_none()
            && definition_profiles.contains(&edge.profile_id);
        let allowed_dependency_edge = edge.phase == Phase::Semantic
            && is_web_semantic_dependency_edge_kind(&edge.kind)
            && edge.site_id.is_some()
            && if edge.kind == "calls" {
                call_profiles.contains(&edge.profile_id)
            } else if edge.kind == "may_call" {
                candidate_call_profiles.contains(&edge.profile_id)
            } else {
                import_type_profiles.contains(&edge.profile_id)
            };
        let allowed_framework_edge = edge.phase == Phase::Semantic
            && is_web_framework_semantic_site_kind(&edge.kind)
            && edge.site_id.is_some();
        if incident_to_definition
            && !allowed_definition_relation
            && !allowed_dependency_edge
            && !allowed_framework_edge
        {
            return Err(format!(
                "Web edge {} incident to a semantic definition is outside its declared semantic capability",
                edge.id
            ));
        }
    }
    for site in protocol.sites.values() {
        if (semantic_node_ids.contains(site.source.as_str())
            || site
                .target_ids
                .iter()
                .any(|target| semantic_node_ids.contains(target.as_str())))
            && !(is_web_framework_semantic_site_kind(&site.kind)
                && site
                    .evidence
                    .first()
                    .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic))
            && !(is_web_semantic_dependency_site_kind(&site.kind)
                && if site.kind == "call" {
                    if site.resolution_status == ResolutionStatus::Candidates {
                        candidate_call_profiles.contains(&site.profile_id)
                    } else {
                        call_profiles.contains(&site.profile_id)
                    }
                } else {
                    import_type_profiles.contains(&site.profile_id)
                })
        {
            return Err(format!(
                "Web dependency site {} is incident to a semantic definition node outside the import/type-use capability",
                site.id
            ));
        }
    }

    let mut nodes_by_resolver =
        std::collections::BTreeMap::<&str, &depgraph_protocol::GraphNode>::new();
    for node in protocol
        .nodes
        .values()
        .filter(|node| matches!(node.kind.as_str(), "symbol" | "type"))
    {
        let identity = node
            .properties
            .get("canonical_identity")
            .and_then(Value::as_object)
            .expect("the semantic contract requires canonical_identity objects");
        if let Some(resolver) = identity.get("resolver_identity").and_then(Value::as_str)
            && let Some(existing) = nodes_by_resolver.insert(resolver, node)
        {
            return Err(format!(
                "Web semantic nodes {} and {} claim the same resolver identity {resolver:?}",
                existing.id, node.id
            ));
        }
    }

    let mut expected_symbol_origins = std::collections::BTreeMap::<&str, &str>::new();
    for node in protocol
        .nodes
        .values()
        .filter(|node| matches!(node.kind.as_str(), "symbol" | "type"))
    {
        let identity = node
            .properties
            .get("canonical_identity")
            .and_then(Value::as_object)
            .expect("the semantic contract requires canonical_identity objects");
        let profile_id = node
            .properties
            .get("profile_id")
            .and_then(Value::as_str)
            .expect("Web semantic nodes were checked above");
        let language = node
            .properties
            .get("language")
            .and_then(Value::as_str)
            .expect("Web semantic nodes were checked above");

        if node.kind == "symbol" {
            if identity.contains_key("generic_origin")
                || identity.contains_key("type_arguments")
                || node.properties.contains_key("generic_origin")
                || node.properties.contains_key("type_arguments")
            {
                return Err(format!(
                    "Web semantic symbol {} contains generic type metadata",
                    node.id
                ));
            }
            let identity_kind = identity
                .get("identity_kind")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "Web semantic symbol {} omitted canonical_identity.identity_kind",
                        node.id
                    )
                })?;
            let canonical_resolver = identity.get("resolver_identity").and_then(Value::as_str);
            let top_level_resolver = node
                .properties
                .get("resolver_identity")
                .and_then(Value::as_str);
            let origin_field = match identity_kind {
                "named" => {
                    let canonical_resolver = canonical_resolver
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| {
                        format!(
                            "Web named symbol {} omitted canonical_identity.resolver_identity",
                            node.id
                        )
                    })?;
                    if !web_json_object_has_exact_fields(
                        identity,
                        &[
                            "language",
                            "package_locator",
                            "symbol_kind",
                            "identity_kind",
                            "resolver_identity",
                        ],
                    ) || !web_resolver_identity_is_portable(canonical_resolver)
                        || top_level_resolver != Some(canonical_resolver)
                    {
                        return Err(format!(
                            "Web named symbol {} top-level resolver or canonical identity shape is inconsistent",
                            node.id
                        ));
                    }
                    None
                }
                "local" => {
                    if !web_json_object_has_exact_fields(
                        identity,
                        &[
                            "language",
                            "package_locator",
                            "symbol_kind",
                            "identity_kind",
                            "enclosing_symbol",
                            "relative_path",
                            "span",
                        ],
                    ) || node.properties.contains_key("resolver_identity")
                    {
                        return Err(format!(
                            "Web local symbol {} has a resolver or the wrong canonical origin field",
                            node.id
                        ));
                    }
                    Some("enclosing_symbol")
                }
                "anonymous" => {
                    if !web_json_object_has_exact_fields(
                        identity,
                        &[
                            "language",
                            "package_locator",
                            "symbol_kind",
                            "identity_kind",
                            "generated_from",
                            "relative_path",
                            "span",
                        ],
                    ) || node.properties.contains_key("resolver_identity")
                    {
                        return Err(format!(
                            "Web anonymous symbol {} has a resolver or the wrong canonical origin field",
                            node.id
                        ));
                    }
                    Some("generated_from")
                }
                "generated" => {
                    if node.properties.get("symbol_kind").and_then(Value::as_str)
                        != Some("generated_module_initializer")
                        || !call_profiles.contains(profile_id)
                        || !web_json_object_has_exact_fields(
                            identity,
                            &[
                                "language",
                                "package_locator",
                                "symbol_kind",
                                "identity_kind",
                                "generated_from",
                                "relative_path",
                                "span",
                            ],
                        )
                        || node.properties.contains_key("resolver_identity")
                    {
                        return Err(format!(
                            "Web generated symbol {} has an unsupported kind, capability, resolver, or canonical identity shape",
                            node.id
                        ));
                    }
                    Some("generated_from")
                }
                other => {
                    return Err(format!(
                        "Web semantic symbol {} has unsupported identity_kind {other:?}",
                        node.id
                    ));
                }
            };
            if let Some(origin_field) = origin_field {
                let origin_id = identity
                    .get(origin_field)
                    .and_then(Value::as_str)
                    .filter(|origin_id| !origin_id.is_empty())
                    .ok_or_else(|| {
                        format!(
                            "Web {identity_kind} symbol {} omitted canonical_identity.{origin_field}",
                            node.id
                        )
                    })?;
                if identity.get("relative_path").and_then(Value::as_str)
                    != node.properties.get("source_path").and_then(Value::as_str)
                    || identity.get("span") != node.properties.get("source_span")
                {
                    return Err(format!(
                        "Web {identity_kind} symbol {} canonical source anchor disagrees with its top-level source",
                        node.id
                    ));
                }
                let origin = protocol.nodes.get(origin_id).ok_or_else(|| {
                    format!(
                        "Web semantic symbol {} references missing canonical origin {origin_id}",
                        node.id
                    )
                })?;
                let origin_kind_is_valid = match identity_kind {
                    "local" => origin.kind == "symbol",
                    "generated" => origin.kind == "file",
                    _ => matches!(origin.kind.as_str(), "file" | "symbol" | "type"),
                };
                if !origin_kind_is_valid
                    || node_package_id(origin) != node_package_id(node)
                    || origin.properties.get("language").and_then(Value::as_str) != Some(language)
                {
                    return Err(format!(
                        "Web semantic symbol {} canonical origin {} has incompatible kind, package, or language",
                        node.id, origin.id
                    ));
                }
                if matches!(origin.kind.as_str(), "symbol" | "type") {
                    if origin.properties.get("profile_id").and_then(Value::as_str)
                        != Some(profile_id)
                    {
                        return Err(format!(
                            "Web semantic symbol {} canonical origin {} belongs to another profile",
                            node.id, origin.id
                        ));
                    }
                } else if origin.properties.get("path").and_then(Value::as_str)
                    != node.properties.get("source_path").and_then(Value::as_str)
                {
                    return Err(format!(
                        "Web {identity_kind} symbol {} file origin {} does not anchor its source path",
                        node.id, origin.id
                    ));
                }
                expected_symbol_origins.insert(node.id.as_str(), origin_id);
            }
        } else {
            let type_kind = node
                .properties
                .get("type_kind")
                .and_then(Value::as_str)
                .expect("the semantic contract requires type_kind");
            let canonical_resolver = identity
                .get("resolver_identity")
                .and_then(Value::as_str)
                .filter(|resolver| !resolver.is_empty())
                .expect("the semantic contract requires type resolver identities");
            let is_generic_instance = type_kind == "generic_instance";
            let has_canonical_generic_metadata =
                identity.contains_key("generic_origin") || identity.contains_key("type_arguments");
            let has_top_level_generic_metadata = node.properties.contains_key("generic_origin")
                || node.properties.contains_key("type_arguments");
            if !is_generic_instance
                && (has_canonical_generic_metadata || has_top_level_generic_metadata)
            {
                return Err(format!(
                    "Web non-generic type {} contains generic origin or type argument metadata",
                    node.id
                ));
            }
            let expected_identity_fields: &[&str] = if is_generic_instance {
                &[
                    "language",
                    "package_locator",
                    "type_kind",
                    "resolver_identity",
                    "generic_origin",
                    "type_arguments",
                ]
            } else {
                &[
                    "language",
                    "package_locator",
                    "type_kind",
                    "resolver_identity",
                ]
            };
            if !web_json_object_has_exact_fields(identity, expected_identity_fields)
                || canonical_resolver.encode_utf16().count()
                    > TYPESCRIPT_MAX_RESOLVER_IDENTITY_CHARS
                || (!is_generic_instance && !web_resolver_identity_is_portable(canonical_resolver))
                || node
                    .properties
                    .get("resolver_identity")
                    .and_then(Value::as_str)
                    != Some(canonical_resolver)
            {
                return Err(format!(
                    "Web type {} top-level resolver identity disagrees with its canonical identity",
                    node.id
                ));
            }
            if !is_generic_instance {
                continue;
            }
            let generic_origin = identity
                .get("generic_origin")
                .and_then(Value::as_str)
                .filter(|origin| !origin.is_empty())
                .ok_or_else(|| {
                    format!(
                        "Web generic instance {} omitted canonical_identity.generic_origin",
                        node.id
                    )
                })?;
            let type_arguments = identity
                .get("type_arguments")
                .filter(|arguments| {
                    arguments.as_array().is_some_and(|arguments| {
                        !arguments.is_empty() && arguments.len() <= TYPESCRIPT_MAX_TYPE_ARGUMENTS
                    })
                })
                .ok_or_else(|| {
                    format!(
                        "Web generic instance {} omitted canonical_identity.type_arguments",
                        node.id
                    )
                })?;
            let mut canonical_type_arguments = Vec::with_capacity(
                type_arguments
                    .as_array()
                    .expect("generic type arguments were checked above")
                    .len(),
            );
            for argument in type_arguments
                .as_array()
                .expect("generic type arguments were checked above")
            {
                canonical_type_arguments.push(validate_web_type_argument_references(
                    argument,
                    protocol,
                    &nodes_by_resolver,
                    profile_id,
                    &node.id,
                    0,
                )?);
            }
            let canonical_type_arguments = Value::Array(canonical_type_arguments);
            if type_arguments != &canonical_type_arguments {
                return Err(format!(
                    "Web generic instance {} type arguments are not in canonical materialized form",
                    node.id
                ));
            }
            if node
                .properties
                .get("generic_origin")
                .and_then(Value::as_str)
                != Some(generic_origin)
                || node.properties.get("type_arguments") != Some(&canonical_type_arguments)
            {
                return Err(format!(
                    "Web generic instance {} top-level origin/type arguments disagree with its canonical identity",
                    node.id
                ));
            }
            let resolver_input = Value::Array(vec![
                Value::String(generic_origin.to_owned()),
                canonical_type_arguments,
            ]);
            let expected_resolver = format!(
                "generic:{}",
                serde_json::to_string(&resolver_input)
                    .expect("canonical generic resolver input always serializes")
            );
            if identity.get("resolver_identity").and_then(Value::as_str)
                != Some(expected_resolver.as_str())
                || node
                    .properties
                    .get("resolver_identity")
                    .and_then(Value::as_str)
                    != Some(expected_resolver.as_str())
            {
                return Err(format!(
                    "Web generic instance {} resolver identity does not match its origin and type arguments",
                    node.id
                ));
            }
            let origin = nodes_by_resolver.get(generic_origin).copied().ok_or_else(|| {
                format!(
                    "Web generic instance {} references missing generic origin {generic_origin:?}",
                    node.id
                )
            })?;
            if origin.kind != "type"
                || origin.properties.get("type_kind").and_then(Value::as_str)
                    == Some("generic_instance")
                || origin.properties.get("profile_id").and_then(Value::as_str) != Some(profile_id)
                || node_package_id(origin) != node_package_id(node)
                || origin
                    .properties
                    .get("package_locator")
                    .and_then(Value::as_str)
                    != node
                        .properties
                        .get("package_locator")
                        .and_then(Value::as_str)
                || origin.properties.get("language").and_then(Value::as_str) != Some(language)
                || origin.properties.get("source_path") != node.properties.get("source_path")
                || origin.properties.get("source_span") != node.properties.get("source_span")
            {
                return Err(format!(
                    "Web generic instance {} origin {} is not a same-profile/package/language/source concrete type",
                    node.id, origin.id
                ));
            }
        }
    }

    let mut semantic_relations_by_profile = std::collections::BTreeMap::<&str, usize>::new();
    let mut declared_targets = BTreeSet::<&str>::new();
    let mut declaration_sources_by_target =
        std::collections::BTreeMap::<&str, BTreeSet<&str>>::new();
    let mut canonically_anchored_declaration_targets = BTreeSet::<&str>::new();
    let mut instantiated_targets = BTreeSet::<&str>::new();
    for edge in protocol
        .edges
        .values()
        .filter(|edge| edge.phase == Phase::Semantic && is_web_definition_relation_kind(&edge.kind))
    {
        if !definition_profiles.contains(&edge.profile_id) {
            return Err(format!(
                "Web semantic edge {} references profile {:?} without the definition-graph-v1 capability",
                edge.id, edge.profile_id
            ));
        }
        if !is_web_definition_relation_kind(&edge.kind) {
            return Err(format!(
                "Web definition-graph-v1 profile emitted forbidden semantic edge kind {:?}",
                edge.kind
            ));
        }
        let primary = edge
            .evidence
            .first()
            .expect("the semantic contract requires primary evidence");
        if primary.extractor != TYPESCRIPT_SEMANTIC_EXTRACTOR
            || primary.extractor_version != TYPESCRIPT_COMPILER_VERSION
        {
            return Err(format!(
                "Web semantic edge {} must use {}@{} primary evidence",
                edge.id, TYPESCRIPT_SEMANTIC_EXTRACTOR, TYPESCRIPT_COMPILER_VERSION
            ));
        }
        if primary.properties.get("profile_id").and_then(Value::as_str)
            != Some(edge.profile_id.as_str())
        {
            return Err(format!(
                "Web semantic edge {} primary evidence must declare profile_id={:?}",
                edge.id, edge.profile_id
            ));
        }
        if edge.environment.as_deref() != Some("any") {
            return Err(format!(
                "Web semantic definition relation {} must use environment=any",
                edge.id
            ));
        }
        let source = protocol
            .nodes
            .get(&edge.source)
            .expect("the base protocol requires relation sources");
        let target = protocol
            .nodes
            .get(&edge.target)
            .expect("the base protocol requires relation targets");
        for endpoint in [source, target]
            .into_iter()
            .filter(|node| matches!(node.kind.as_str(), "symbol" | "type"))
        {
            if endpoint
                .properties
                .get("profile_id")
                .and_then(Value::as_str)
                != Some(edge.profile_id.as_str())
            {
                return Err(format!(
                    "Web semantic relation {} endpoint {} belongs to another profile",
                    edge.id, endpoint.id
                ));
            }
        }
        let endpoints_are_valid = match edge.kind.as_str() {
            "declares" => {
                matches!(source.kind.as_str(), "file" | "symbol" | "type")
                    && matches!(target.kind.as_str(), "symbol" | "type")
            }
            "extends" | "implements" => source.kind == "type" && target.kind == "type",
            "instantiates" => {
                matches!(source.kind.as_str(), "symbol" | "type")
                    && target.kind == "type"
                    && target.properties.get("type_kind").and_then(Value::as_str)
                        == Some("generic_instance")
            }
            _ => false,
        };
        if !endpoints_are_valid {
            return Err(format!(
                "Web semantic definition relation {} of kind {} has incompatible or non-repository endpoints {} ({}) -> {} ({})",
                edge.id, edge.kind, source.id, source.kind, target.id, target.kind
            ));
        }
        let evidence_file = files_by_path
            .get(primary.path.as_deref().unwrap_or_default())
            .ok_or_else(|| {
                format!(
                    "Web semantic relation {} evidence path {:?} has no repository file node",
                    edge.id, primary.path
                )
            })?;
        let evidence_package = evidence_file
            .properties
            .get("package_id")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Web evidence file {} omitted package_id", evidence_file.id))?;
        match edge.kind.as_str() {
            "declares" => {
                if node_package_id(target) != Some(evidence_package) {
                    return Err(format!(
                        "Web declares relation {} target and evidence file disagree on package ownership",
                        edge.id
                    ));
                }
                if target.properties.get("source_path").and_then(Value::as_str)
                    != primary.path.as_deref()
                {
                    return Err(format!(
                        "Web declares relation {} target does not anchor its evidence path",
                        edge.id
                    ));
                }
                if source.kind == "file" {
                    if source.id != evidence_file.id {
                        return Err(format!(
                            "Web declares relation {} source file does not anchor its evidence",
                            edge.id
                        ));
                    }
                } else if node_package_id(source) != Some(evidence_package)
                    || source.properties.get("source_path").and_then(Value::as_str)
                        != primary.path.as_deref()
                {
                    return Err(format!(
                        "Web declares relation {} semantic owner does not anchor its evidence",
                        edge.id
                    ));
                }
                declared_targets.insert(target.id.as_str());
                declaration_sources_by_target
                    .entry(target.id.as_str())
                    .or_default()
                    .insert(source.id.as_str());
                if target
                    .properties
                    .get("source_span")
                    .is_some_and(|span| web_evidence_matches_source_span(primary, span))
                {
                    canonically_anchored_declaration_targets.insert(target.id.as_str());
                }
            }
            "extends" | "implements" | "instantiates" => {
                if node_package_id(source) != Some(evidence_package)
                    || source.properties.get("source_path").and_then(Value::as_str)
                        != primary.path.as_deref()
                {
                    return Err(format!(
                        "Web {} relation {} source does not anchor its evidence",
                        edge.kind, edge.id
                    ));
                }
                if edge.kind == "instantiates" {
                    instantiated_targets.insert(target.id.as_str());
                }
            }
            _ => unreachable!("definition relation kinds were checked above"),
        }
        *semantic_relations_by_profile
            .entry(edge.profile_id.as_str())
            .or_default() += 1;
    }

    for node in protocol
        .nodes
        .values()
        .filter(|node| matches!(node.kind.as_str(), "symbol" | "type"))
    {
        let instance = node.kind == "type"
            && node.properties.get("type_kind").and_then(Value::as_str) == Some("generic_instance");
        let owned = if instance {
            instantiated_targets.contains(node.id.as_str())
        } else {
            declared_targets.contains(node.id.as_str())
        };
        if !owned {
            return Err(format!(
                "Web semantic node {} has no canonical {} owner relation",
                node.id,
                if instance { "instantiates" } else { "declares" }
            ));
        }
        if !instance && !canonically_anchored_declaration_targets.contains(node.id.as_str()) {
            return Err(format!(
                "Web semantic node {} has no declares evidence matching its canonical source span",
                node.id
            ));
        }
        if let Some(expected_origin) = expected_symbol_origins.get(node.id.as_str()) {
            let declaration_sources = declaration_sources_by_target
                .get(node.id.as_str())
                .expect("owned local/anonymous symbols have declares relations");
            if declaration_sources.len() != 1 || !declaration_sources.contains(*expected_origin) {
                return Err(format!(
                    "Web semantic symbol {} declares owner does not match canonical origin {}",
                    node.id, expected_origin
                ));
            }
        }
    }

    let repository_package_ids = repository_packages
        .values()
        .map(|(package_id, _)| package_id.as_str())
        .collect::<BTreeSet<_>>();
    let semantic_dependency_edges = protocol
        .edges
        .values()
        .filter(|edge| {
            edge.phase == Phase::Semantic && is_web_semantic_dependency_edge_kind(&edge.kind)
        })
        .collect::<Vec<_>>();
    let mut semantic_sites_by_profile = std::collections::BTreeMap::<&str, usize>::new();
    let mut semantic_call_sites_by_profile = std::collections::BTreeMap::<&str, usize>::new();
    for site in protocol.sites.values().filter(|site| {
        is_web_semantic_dependency_site_kind(&site.kind)
            && site
                .evidence
                .first()
                .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic)
    }) {
        let authorized = if site.kind == "call" {
            if site.resolution_status == ResolutionStatus::Candidates {
                candidate_call_profiles.contains(&site.profile_id)
            } else {
                call_profiles.contains(&site.profile_id)
            }
        } else {
            import_type_profiles.contains(&site.profile_id)
        };
        if !authorized {
            return Err(format!(
                "Web semantic dependency site {} references profile {:?} without its required cumulative semantic capability",
                site.id, site.profile_id
            ));
        }
        let expected_edge_kind = web_semantic_edge_kind_for_site(&site.kind, site.resolution_status).ok_or_else(|| {
            format!(
                "Web cumulative semantic profile emitted forbidden semantic dependency site kind {:?}",
                site.kind
            )
        })?;
        if site.kind == "call"
            && ((site.resolution_status == ResolutionStatus::Candidates
                && (site.precision != Precision::Overapprox || site.target_ids.is_empty()))
                || (site.resolution_status != ResolutionStatus::Candidates
                    && (site.precision == Precision::Overapprox || site.target_ids.len() != 1)))
        {
            return Err(format!(
                "Web semantic call site {} has an invalid candidate target or precision shape",
                site.id
            ));
        }
        if site.kind == "call"
            && site.resolution_status == ResolutionStatus::Candidates
            && site.reason.is_some()
        {
            return Err(format!(
                "Web candidate call site {} must not include a reason",
                site.id
            ));
        }
        let primary = site
            .evidence
            .first()
            .expect("semantic dependency sites include primary evidence");
        if primary.extractor != TYPESCRIPT_SEMANTIC_EXTRACTOR
            || primary.extractor_version != TYPESCRIPT_COMPILER_VERSION
        {
            return Err(format!(
                "Web semantic dependency site {} must use {}@{} primary evidence",
                site.id, TYPESCRIPT_SEMANTIC_EXTRACTOR, TYPESCRIPT_COMPILER_VERSION
            ));
        }
        if primary.properties.get("profile_id").and_then(Value::as_str)
            != Some(site.profile_id.as_str())
        {
            return Err(format!(
                "Web semantic dependency site {} primary evidence must declare profile_id={:?}",
                site.id, site.profile_id
            ));
        }
        let occurrence_kind = primary
            .properties
            .get("occurrence_kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let module_specifier = web_optional_evidence_string(
            &primary.properties,
            "module_specifier",
            TYPESCRIPT_MAX_TYPE_DESCRIPTOR_CHARS,
            true,
        )
        .map_err(|()| {
            format!(
                "Web semantic dependency site {} has invalid module_specifier metadata",
                site.id
            )
        })?;
        if site.kind == "call" {
            let call_kind = primary
                .properties
                .get("call_kind")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let dispatch = primary
                .properties
                .get("dispatch")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let algorithm = primary.properties.get("algorithm").and_then(Value::as_str);
            let call_kind_is_valid = matches!(
                call_kind,
                "function" | "method" | "constructor" | "tagged_template"
            ) && (occurrence_kind != "new_expression"
                || call_kind == "constructor")
                && (occurrence_kind != "tagged_template" || call_kind == "tagged_template");
            let dispatch_is_valid = match site.resolution_status {
                ResolutionStatus::Resolved => {
                    site.precision == Precision::Exact
                        && matches!(
                            dispatch,
                            "direct" | "static" | "private" | "fresh_instance" | "super"
                        )
                }
                ResolutionStatus::External => {
                    matches!(site.precision, Precision::Exact | Precision::Heuristic)
                        && dispatch == "external"
                }
                ResolutionStatus::Unresolved => {
                    site.precision == Precision::Heuristic && matches!(dispatch, "dynamic" | "open")
                }
                ResolutionStatus::Candidates => {
                    site.precision == Precision::Overapprox
                        && match dispatch {
                            "dynamic" => {
                                algorithm == Some(TYPESCRIPT_CLOSED_LOCAL_CALL_FLOW_ALGORITHM)
                            }
                            "fresh_instance" => {
                                algorithm
                                    == Some(TYPESCRIPT_CLOSED_LOCAL_FRESH_INSTANCE_FLOW_ALGORITHM)
                                    && matches!(call_kind, "method" | "tagged_template")
                                    && occurrence_kind != "new_expression"
                            }
                            _ => false,
                        }
                }
            };
            if !call_kind_is_valid
                || !dispatch_is_valid
                || (site.resolution_status != ResolutionStatus::Candidates
                    && primary.properties.contains_key("algorithm"))
                || primary.properties.contains_key("type_only")
                || primary.properties.contains_key("imported_name")
                || primary.properties.contains_key("resolution_mode")
            {
                return Err(format!(
                    "Web semantic call site {} has invalid call_kind {call_kind:?}, dispatch {dispatch:?}, algorithm {algorithm:?}, or import-only metadata",
                    site.id
                ));
            }
        } else {
            let type_only = primary
                .properties
                .get("type_only")
                .and_then(Value::as_bool)
                .ok_or_else(|| {
                    format!(
                        "Web semantic dependency site {} primary evidence must declare boolean type_only",
                        site.id
                    )
                })?;
            if (site.kind == "type_use" || occurrence_kind == "import_type") && !type_only {
                return Err(format!(
                    "Web semantic dependency site {} occurrence_kind {occurrence_kind:?} must use type_only=true",
                    site.id
                ));
            }
            if matches!(
                occurrence_kind,
                "side_effect_import" | "require_call" | "dynamic_import"
            ) && type_only
            {
                return Err(format!(
                    "Web semantic dependency site {} occurrence_kind {occurrence_kind:?} must use type_only=false",
                    site.id
                ));
            }
            let imported_name = web_optional_evidence_string(
                &primary.properties,
                "imported_name",
                TYPESCRIPT_MAX_DISPLAY_NAME_CHARS,
                true,
            )
            .map_err(|()| {
                format!(
                    "Web semantic dependency site {} has invalid imported_name metadata",
                    site.id
                )
            })?;
            let resolution_mode = match primary.properties.get("resolution_mode") {
                None => None,
                Some(value) => match value.as_str() {
                    Some(mode @ ("import" | "require")) => Some(mode),
                    _ => {
                        return Err(format!(
                            "Web semantic dependency site {} has invalid resolution_mode metadata",
                            site.id
                        ));
                    }
                },
            };
            if resolution_mode.is_some() && (!type_only || module_specifier.is_none()) {
                return Err(format!(
                    "Web semantic dependency site {} resolution_mode contradicts its occurrence",
                    site.id
                ));
            }
            if resolution_mode.is_some() && occurrence_kind == "import_equals" {
                return Err(format!(
                    "Web semantic dependency site {} import_equals occurrence cannot expose resolution_mode",
                    site.id
                ));
            }
            let named_binding = matches!(
                occurrence_kind,
                "default_import" | "named_import" | "named_reexport"
            );
            let namespace_binding =
                matches!(occurrence_kind, "namespace_import" | "namespace_reexport");
            let module_only = matches!(
                occurrence_kind,
                "side_effect_import"
                    | "empty_import"
                    | "require_call"
                    | "dynamic_import"
                    | "import_type"
                    | "empty_reexport"
                    | "export_star"
            );
            let metadata_shape_is_valid = (site.kind == "type_use" || module_specifier.is_some())
                && (site.kind != "type_use" || imported_name.is_some())
                && (!named_binding || imported_name.is_some())
                && (!namespace_binding || imported_name == Some("*"))
                && (!module_only || imported_name.is_none())
                && (occurrence_kind != "default_import" || imported_name == Some("default"))
                && (occurrence_kind != "import_equals" || imported_name == Some("="))
                && if site.kind == "type_use" {
                    imported_name == Some(site.specifier.as_str())
                } else {
                    module_specifier == Some(site.specifier.as_str())
                };
            if !metadata_shape_is_valid {
                return Err(format!(
                    "Web semantic dependency site {} binding metadata does not match occurrence_kind {:?} or specifier {:?}",
                    site.id, occurrence_kind, site.specifier
                ));
            }
        }
        let expected_analysis_mode = if call_profiles.contains(&site.profile_id) {
            TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_CALL_GRAPH
        } else {
            TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_GRAPH
        };
        if primary.properties.get("backend").and_then(Value::as_str)
            != Some(TYPESCRIPT_SEMANTIC_BACKEND)
            || primary
                .properties
                .get("compiler_source")
                .and_then(Value::as_str)
                != Some("bundled")
            || primary
                .properties
                .get("compiler_version")
                .and_then(Value::as_str)
                != Some(TYPESCRIPT_COMPILER_VERSION)
            || primary
                .properties
                .get("analysis_mode")
                .and_then(Value::as_str)
                != Some(expected_analysis_mode)
            || primary
                .properties
                .get("project_code_executed")
                .and_then(Value::as_bool)
                != Some(false)
            || !web_occurrence_kind_matches_site(&site.kind, occurrence_kind)
        {
            return Err(format!(
                "Web semantic dependency site {} has invalid compiler provenance or occurrence_kind {:?}",
                site.id, occurrence_kind
            ));
        }
        if !web_has_matching_source_support(
            &site.evidence,
            primary,
            &site.profile_id,
            occurrence_kind,
        ) {
            return Err(format!(
                "Web semantic dependency site {} must include matching source supporting evidence",
                site.id
            ));
        }
        let evidence_path = primary
            .path
            .as_deref()
            .expect("semantic contract requires a primary evidence path");
        let evidence_file = files_by_path.get(evidence_path).ok_or_else(|| {
            format!(
                "Web semantic dependency site {} evidence path {evidence_path:?} has no repository file node",
                site.id
            )
        })?;
        let source = protocol
            .nodes
            .get(&site.source)
            .expect("base protocol requires dependency site sources");
        let source_language = source.properties.get("language").and_then(Value::as_str);
        if !matches!(source_language, Some("typescript" | "javascript")) {
            return Err(format!(
                "Web semantic dependency site {} source {} must declare language=typescript or javascript",
                site.id, source.id
            ));
        }
        let source_package = source
            .properties
            .get("package_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "Web semantic dependency site {} source {} omitted package_id",
                    site.id, source.id
                )
            })?;
        if !repository_package_ids.contains(source_package) {
            return Err(format!(
                "Web semantic dependency site {} source {} is not owned by a repository workspace package",
                site.id, source.id
            ));
        }
        if evidence_file
            .properties
            .get("package_id")
            .and_then(Value::as_str)
            != Some(source_package)
            || evidence_file
                .properties
                .get("language")
                .and_then(Value::as_str)
                != source_language
        {
            return Err(format!(
                "Web semantic dependency site {} source and evidence file disagree on package ownership or language",
                site.id
            ));
        }
        match site.kind.as_str() {
            "web_import" | "web_reexport" => {
                if source.kind != "file"
                    || source.properties.get("path").and_then(Value::as_str) != Some(evidence_path)
                    || source.id != evidence_file.id
                {
                    return Err(format!(
                        "Web semantic {} site {} source must be its evidence file",
                        site.kind, site.id
                    ));
                }
            }
            "type_use" => match source.kind.as_str() {
                "file" => {
                    if source.properties.get("path").and_then(Value::as_str) != Some(evidence_path)
                        || source.id != evidence_file.id
                    {
                        return Err(format!(
                            "Web semantic type-use site {} file fallback does not anchor its evidence",
                            site.id
                        ));
                    }
                }
                "symbol" | "type" => {
                    if source.properties.get("profile_id").and_then(Value::as_str)
                        != Some(site.profile_id.as_str())
                        || source.properties.get("source_path").and_then(Value::as_str)
                            != Some(evidence_path)
                    {
                        return Err(format!(
                            "Web semantic type-use site {} owner {} belongs to another profile or source file",
                            site.id, source.id
                        ));
                    }
                }
                _ => {
                    return Err(format!(
                        "Web semantic type-use site {} source {} must be a file, symbol, or type",
                        site.id, source.id
                    ));
                }
            },
            "call" => {
                if source.kind != "symbol"
                    || source
                        .properties
                        .get("symbol_kind")
                        .and_then(Value::as_str)
                        .is_none_or(|symbol_kind| !is_web_call_source_symbol_kind(symbol_kind))
                    || source.properties.get("profile_id").and_then(Value::as_str)
                        != Some(site.profile_id.as_str())
                    || source.properties.get("source_path").and_then(Value::as_str)
                        != Some(evidence_path)
                {
                    return Err(format!(
                        "Web semantic call site {} source {} must be a same-profile callable symbol anchored to its evidence file",
                        site.id, source.id
                    ));
                }
            }
            _ => unreachable!("Web semantic site kinds were checked above"),
        }

        if matches!(
            site.resolution_status,
            ResolutionStatus::Resolved | ResolutionStatus::Candidates
        ) {
            let has_file_target = site.target_ids.iter().any(|target_id| {
                protocol
                    .nodes
                    .get(target_id)
                    .is_some_and(|target| target.kind == "file")
            });
            let has_definition_target = site.target_ids.iter().any(|target_id| {
                protocol
                    .nodes
                    .get(target_id)
                    .is_some_and(|target| matches!(target.kind.as_str(), "symbol" | "type"))
            });
            if has_file_target && has_definition_target {
                return Err(format!(
                    "Web semantic dependency site {} mixes repository module and canonical definition targets",
                    site.id
                ));
            }
        }

        for target_id in &site.target_ids {
            let target = protocol
                .nodes
                .get(target_id)
                .expect("base protocol requires dependency site targets");
            match site.resolution_status {
                ResolutionStatus::Resolved | ResolutionStatus::Candidates => {
                    let valid_kind =
                        if web_occurrence_requires_repository_module(&site.kind, occurrence_kind) {
                            target.kind == "file"
                        } else if site.kind == "call" {
                            target.kind == "symbol"
                                && target
                                    .properties
                                    .get("symbol_kind")
                                    .and_then(Value::as_str)
                                    .is_some_and(is_web_callable_symbol_kind)
                        } else if site.kind == "type_use" {
                            target.kind == "type"
                        } else {
                            matches!(target.kind.as_str(), "file" | "symbol" | "type")
                        };
                    if !valid_kind {
                        if site.kind == "call" {
                            return Err(format!(
                                "Web semantic call site {} resolved target {} must be a canonical callable symbol",
                                site.id, target.id
                            ));
                        }
                        return Err(format!(
                            "Web semantic dependency site {} concrete target {} has incompatible kind {}",
                            site.id, target.id, target.kind
                        ));
                    }
                    if target.kind == "file" {
                        if !web_occurrence_requires_repository_module(&site.kind, occurrence_kind) {
                            return Err(format!(
                                "Web semantic dependency site {} occurrence_kind {occurrence_kind:?} cannot weaken a named binding target to a repository file",
                                site.id
                            ));
                        }
                        let target_path = target
                            .properties
                            .get("path")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                format!(
                                    "Web semantic dependency site {} target file {} omitted path",
                                    site.id, target.id
                                )
                            })?;
                        if files_by_path
                            .get(target_path)
                            .copied()
                            .map(|file| file.id.as_str())
                            != Some(target.id.as_str())
                            || target
                                .properties
                                .get("package_id")
                                .and_then(Value::as_str)
                                .is_none_or(|package_id| {
                                    !repository_package_ids.contains(package_id)
                                })
                            || !matches!(
                                target.properties.get("language").and_then(Value::as_str),
                                Some("typescript" | "javascript")
                            )
                        {
                            return Err(format!(
                                "Web semantic dependency site {} target file {} is not a repository TypeScript/JavaScript file",
                                site.id, target.id
                            ));
                        }
                    } else if target.properties.get("profile_id").and_then(Value::as_str)
                        != Some(site.profile_id.as_str())
                    {
                        return Err(format!(
                            "Web semantic dependency site {} target {} belongs to another profile",
                            site.id, target.id
                        ));
                    }
                }
                ResolutionStatus::External => {
                    let canonical_identity = target
                        .properties
                        .get("canonical_identity")
                        .and_then(Value::as_object);
                    let canonical_identity_is_valid = canonical_identity.is_some_and(|identity| {
                        web_json_object_has_exact_fields(
                            identity,
                            &["language", "compiler_version", "locator"],
                        ) && identity.get("language").and_then(Value::as_str) == Some("typescript")
                            && identity.get("compiler_version").and_then(Value::as_str)
                                == Some(TYPESCRIPT_COMPILER_VERSION)
                            && identity.get("locator").and_then(Value::as_str).is_some_and(
                                |locator| {
                                    !locator.is_empty()
                                        && locator.encode_utf16().count()
                                            <= TYPESCRIPT_MAX_TYPE_DESCRIPTOR_CHARS
                                },
                            )
                    });
                    let expected_external_id = canonical_identity.map(|identity| {
                        depgraph_protocol::stable_id_from_value(
                            "external",
                            &Value::Object(identity.clone()),
                        )
                    });
                    let external_locator = canonical_identity
                        .and_then(|identity| identity.get("locator"))
                        .and_then(Value::as_str);
                    let expected_locator = external_locator.map(|locator| {
                        format!(
                            "external://typescript/{}",
                            javascript_encode_uri_component(locator)
                        )
                    });
                    if target.kind != "external_system"
                        || target.properties.get("workspace").and_then(Value::as_bool) == Some(true)
                        || target.properties.get("external").and_then(Value::as_bool) != Some(true)
                        || target.properties.get("language").and_then(Value::as_str)
                            != Some("typescript")
                        || target.properties.get("profile_id").and_then(Value::as_str)
                            != Some(site.profile_id.as_str())
                        || target
                            .properties
                            .get("compiler_version")
                            .and_then(Value::as_str)
                            != Some(TYPESCRIPT_COMPILER_VERSION)
                        || !canonical_identity_is_valid
                        || expected_external_id.as_deref() != Some(target.id.as_str())
                        || expected_locator.as_deref() != Some(target.locator.as_str())
                        || external_locator != target.display_name.as_deref()
                    {
                        return Err(format!(
                            "Web semantic external site {} must target its canonical profile-scoped TypeScript external_system sentinel",
                            site.id
                        ));
                    }
                }
                ResolutionStatus::Unresolved => {
                    let repository_identity = repository_identity.ok_or_else(|| {
                        format!(
                            "Web semantic unresolved site {} requires exactly one repository identity",
                            site.id
                        )
                    })?;
                    let expected_unknown_id = depgraph_protocol::stable_id_from_value(
                        "unknown",
                        &serde_json::json!({
                            "repository": repository_identity,
                            "profile": site.profile_id,
                            "language": "web",
                            "identity": "unresolved_dependency_target",
                        }),
                    );
                    if target.kind != "unknown_target"
                        || target.id != expected_unknown_id
                        || target.locator != "unknown://web/unresolved-dependency"
                        || target.display_name.as_deref() != Some("Unresolved web dependency")
                        || target.properties.len() != 2
                        || target.properties.get("language").and_then(Value::as_str) != Some("web")
                        || target.properties.get("profile_id").and_then(Value::as_str)
                            != Some(site.profile_id.as_str())
                    {
                        return Err(format!(
                            "Web semantic unresolved site {} must target its profile-scoped Web unknown_target sentinel",
                            site.id
                        ));
                    }
                }
            }
        }
        let expected_target_basis = match site.resolution_status {
            ResolutionStatus::Resolved | ResolutionStatus::Candidates => {
                if site.target_ids.iter().any(|target_id| {
                    protocol
                        .nodes
                        .get(target_id)
                        .is_some_and(|target| target.kind == "file")
                }) {
                    "repository_module"
                } else {
                    "canonical_definition"
                }
            }
            ResolutionStatus::External => "external_boundary",
            ResolutionStatus::Unresolved => "unresolved",
        };
        if primary
            .properties
            .get("target_basis")
            .and_then(Value::as_str)
            != Some(expected_target_basis)
        {
            return Err(format!(
                "Web semantic dependency site {} target_basis does not match its status and targets; expected {expected_target_basis:?}",
                site.id
            ));
        }

        let linked_edges = semantic_dependency_edges
            .iter()
            .copied()
            .filter(|edge| edge.site_id.as_deref() == Some(site.id.as_str()))
            .collect::<Vec<_>>();
        if linked_edges.len() != site.target_ids.len() {
            return Err(format!(
                "Web semantic dependency site {} has {} targets but {} semantic dependency edges",
                site.id,
                site.target_ids.len(),
                linked_edges.len()
            ));
        }
        if site.kind == "call" {
            if linked_edges
                .iter()
                .any(|edge| edge.condition.canonicalized() != site.condition.canonicalized())
            {
                return Err(format!(
                    "Web semantic call edge condition does not match dependency site {}",
                    site.id
                ));
            }
        } else {
            let edge_condition_union = Condition::Any {
                conditions: linked_edges
                    .iter()
                    .map(|edge| edge.condition.clone())
                    .collect(),
            }
            .canonicalized();
            if edge_condition_union != site.condition.canonicalized() {
                return Err(format!(
                    "Web semantic dependency site {} condition is not the union of its target edge conditions",
                    site.id
                ));
            }
        }
        for edge in linked_edges {
            if edge.kind != expected_edge_kind
                || edge.source != site.source
                || edge.profile_id != site.profile_id
                || edge.resolution_status != site.resolution_status
                || edge.precision != site.precision
            {
                return Err(format!(
                    "Web semantic edge {} does not match dependency site {} kind/source/profile/status/precision",
                    edge.id, site.id
                ));
            }
            if edge.environment.as_deref() != Some("any") {
                return Err(format!(
                    "Web semantic dependency edge {} must use environment=any",
                    edge.id
                ));
            }
            let edge_primary = edge
                .evidence
                .first()
                .expect("semantic contract requires primary edge evidence");
            if edge.evidence != site.evidence
                || edge_primary.extractor != TYPESCRIPT_SEMANTIC_EXTRACTOR
                || edge_primary.extractor_version != TYPESCRIPT_COMPILER_VERSION
                || edge_primary
                    .properties
                    .get("profile_id")
                    .and_then(Value::as_str)
                    != Some(site.profile_id.as_str())
            {
                return Err(format!(
                    "Web semantic dependency edge {} has invalid TypeChecker provenance",
                    edge.id
                ));
            }
            *semantic_relations_by_profile
                .entry(edge.profile_id.as_str())
                .or_default() += 1;
        }
        *semantic_sites_by_profile
            .entry(site.profile_id.as_str())
            .or_default() += 1;
        if site.kind == "call" {
            *semantic_call_sites_by_profile
                .entry(site.profile_id.as_str())
                .or_default() += 1;
        }
    }
    for edge in semantic_dependency_edges {
        if edge.site_id.as_deref().is_none_or(|site_id| {
            protocol.sites.get(site_id).is_none_or(|site| {
                site.evidence
                    .first()
                    .is_none_or(|evidence| evidence.kind != EvidenceKind::Semantic)
            })
        }) {
            return Err(format!(
                "Web semantic dependency edge {} is not linked to a semantic dependency site",
                edge.id
            ));
        }
    }

    let mut semantic_issues_by_profile = std::collections::BTreeMap::<&str, usize>::new();
    for diagnostic in protocol.diagnostics.values().filter(|diagnostic| {
        [
            TYPESCRIPT_DEFINITION_ISSUE_PROPERTY,
            TYPESCRIPT_DEPENDENCY_ISSUE_PROPERTY,
        ]
        .iter()
        .any(|property| {
            diagnostic
                .properties
                .get(*property)
                .and_then(Value::as_bool)
                == Some(true)
        })
    }) {
        let profile_id = diagnostic.profile_id.as_deref().ok_or_else(|| {
            format!(
                "TypeScript semantic issue diagnostic {} omitted profile_id",
                diagnostic.id
            )
        })?;
        if !web_profiles.contains(profile_id) {
            return Err(format!(
                "TypeScript semantic issue diagnostic {} references unknown profile {profile_id:?}",
                diagnostic.id
            ));
        }
        *semantic_issues_by_profile.entry(profile_id).or_default() += 1;
    }

    for profile_id in web_profiles {
        let profile = protocol
            .profiles
            .get(profile_id)
            .expect("Web capability was recorded from a declared profile");
        for (property, actual) in [
            (
                "typescript_semantic_node_count",
                semantic_nodes_by_profile
                    .get(profile_id.as_str())
                    .copied()
                    .unwrap_or_default(),
            ),
            (
                "typescript_semantic_relation_count",
                semantic_relations_by_profile
                    .get(profile_id.as_str())
                    .copied()
                    .unwrap_or_default(),
            ),
            (
                "typescript_semantic_issue_count",
                semantic_issues_by_profile
                    .get(profile_id.as_str())
                    .copied()
                    .unwrap_or_default(),
            ),
        ] {
            let declared = profile
                .properties
                .get(property)
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or_else(|| {
                    format!("Web profile {profile_id:?} omitted or has invalid {property}")
                })?;
            if declared != actual {
                return Err(format!(
                    "Web profile {profile_id:?} reports {property}={declared}, observed {actual}"
                ));
            }
        }
        let semantic_site_count = profile
            .properties
            .get(TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY)
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<usize>().ok());
        let capability = web_semantic_capability(&profile.properties)
            .expect("Web profiles were validated before graph validation");
        let declares_import_type_capability = matches!(
            capability,
            WebSemanticCapability::DefinitionImportTypeGraphV1
                | WebSemanticCapability::DefinitionImportTypeCallGraphV1
                | WebSemanticCapability::DefinitionImportTypeCallGraphV2
        );
        if declares_import_type_capability {
            let declared = semantic_site_count.ok_or_else(|| {
                format!(
                    "Web profile {profile_id:?} omitted or has invalid {TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY}"
                )
            })?;
            let actual = semantic_sites_by_profile
                .get(profile_id.as_str())
                .copied()
                .unwrap_or_default();
            if declared != actual {
                return Err(format!(
                    "Web profile {profile_id:?} reports {TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY}={declared}, observed {actual}"
                ));
            }
        } else if semantic_site_count.is_some() {
            return Err(format!(
                "Web definition-graph-v1 profile {profile_id:?} must not declare {TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY}"
            ));
        }
        let semantic_call_site_count = profile
            .properties
            .get(TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY)
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<usize>().ok());
        if matches!(
            capability,
            WebSemanticCapability::DefinitionImportTypeCallGraphV1
                | WebSemanticCapability::DefinitionImportTypeCallGraphV2
        ) {
            let declared = semantic_call_site_count.ok_or_else(|| {
                format!(
                    "Web profile {profile_id:?} omitted or has invalid {TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY}"
                )
            })?;
            let actual = semantic_call_sites_by_profile
                .get(profile_id.as_str())
                .copied()
                .unwrap_or_default();
            if declared != actual {
                return Err(format!(
                    "Web profile {profile_id:?} reports {TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY}={declared}, observed {actual}"
                ));
            }
        } else if semantic_call_site_count.is_some() {
            return Err(format!(
                "Web profile {profile_id:?} without the call-graph capability must not declare {TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY}"
            ));
        }
    }
    Ok(())
}

fn validate_web_framework_semantic_graph(
    protocol: &ValidatedProtocol,
    states: &std::collections::BTreeMap<String, WebFrameworkSemanticState>,
) -> std::result::Result<(), String> {
    let mut node_counts = std::collections::BTreeMap::<&str, usize>::new();
    let mut site_counts = std::collections::BTreeMap::<&str, usize>::new();
    let mut edge_counts = std::collections::BTreeMap::<&str, usize>::new();
    for node in protocol
        .nodes
        .values()
        .filter(|node| is_web_framework_semantic_node(node))
    {
        let profile_id = node
            .properties
            .get("profile_id")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Web framework semantic node {} omitted profile_id", node.id))?;
        if states.get(profile_id) != Some(&WebFrameworkSemanticState::Emitted) {
            return Err(format!(
                "Web framework semantic node {} is not authorized by an emitted v1 capability",
                node.id
            ));
        }
        *node_counts.entry(profile_id).or_default() += 1;
    }
    for site in protocol.sites.values().filter(|site| {
        is_web_framework_semantic_site_kind(&site.kind)
            && site
                .evidence
                .first()
                .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic)
    }) {
        if states.get(&site.profile_id) != Some(&WebFrameworkSemanticState::Emitted) {
            return Err(format!(
                "Web framework semantic site {} is not authorized by an emitted v1 capability",
                site.id
            ));
        }
        let primary = site
            .evidence
            .first()
            .expect("framework semantic contract requires primary evidence");
        if primary.extractor_version != WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION
            || primary.properties.get("profile_id").and_then(Value::as_str)
                != Some(site.profile_id.as_str())
            || primary
                .properties
                .get("contract_version")
                .and_then(Value::as_str)
                != Some(WEB_FRAMEWORK_SEMANTIC_CAPABILITY_V1)
        {
            return Err(format!(
                "Web framework semantic site {} has invalid capability provenance",
                site.id
            ));
        }
        *site_counts.entry(site.profile_id.as_str()).or_default() += 1;
    }
    for edge in protocol.edges.values().filter(|edge| {
        edge.phase == Phase::Semantic && is_web_framework_semantic_site_kind(&edge.kind)
    }) {
        if states.get(&edge.profile_id) != Some(&WebFrameworkSemanticState::Emitted) {
            return Err(format!(
                "Web framework semantic edge {} is not authorized by an emitted v1 capability",
                edge.id
            ));
        }
        *edge_counts.entry(edge.profile_id.as_str()).or_default() += 1;
    }
    for (profile_id, state) in states {
        if *state == WebFrameworkSemanticState::Legacy {
            continue;
        }
        let profile = protocol
            .profiles
            .get(profile_id)
            .expect("framework semantic state comes from a declared profile");
        for (property, actual) in [
            (
                WEB_FRAMEWORK_SEMANTIC_NODE_COUNT_PROPERTY,
                node_counts
                    .get(profile_id.as_str())
                    .copied()
                    .unwrap_or_default(),
            ),
            (
                WEB_FRAMEWORK_SEMANTIC_SITE_COUNT_PROPERTY,
                site_counts
                    .get(profile_id.as_str())
                    .copied()
                    .unwrap_or_default(),
            ),
            (
                WEB_FRAMEWORK_SEMANTIC_EDGE_COUNT_PROPERTY,
                edge_counts
                    .get(profile_id.as_str())
                    .copied()
                    .unwrap_or_default(),
            ),
        ] {
            let declared = profile
                .properties
                .get(property)
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<usize>().ok())
                .expect("framework semantic profile state validates counts");
            if declared != actual {
                return Err(format!(
                    "Web profile {profile_id:?} reports {property}={declared}, observed {actual}"
                ));
            }
        }
    }
    Ok(())
}

fn semantic_contract_failure_is_framework(protocol: &ValidatedProtocol) -> bool {
    let mut without_framework = protocol.clone();
    let framework_node_ids = without_framework
        .nodes
        .values()
        .filter(|node| is_web_framework_semantic_node(node))
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    let framework_site_ids = without_framework
        .sites
        .values()
        .filter(|site| {
            (is_web_framework_semantic_site_kind(&site.kind)
                && site
                    .evidence
                    .first()
                    .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic))
                || framework_node_ids.contains(&site.source)
                || site
                    .target_ids
                    .iter()
                    .any(|target| framework_node_ids.contains(target))
        })
        .map(|site| site.id.clone())
        .collect::<BTreeSet<_>>();
    without_framework
        .nodes
        .retain(|node_id, _| !framework_node_ids.contains(node_id));
    without_framework
        .sites
        .retain(|site_id, _| !framework_site_ids.contains(site_id));
    without_framework.edges.retain(|_, edge| {
        !(framework_node_ids.contains(&edge.source)
            || framework_node_ids.contains(&edge.target)
            || edge
                .site_id
                .as_ref()
                .is_some_and(|site_id| framework_site_ids.contains(site_id))
            || edge.phase == Phase::Semantic && is_web_framework_semantic_site_kind(&edge.kind))
    });
    validate_semantic_contract(&without_framework).is_ok()
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
    let mut saw_web_semantic_delta = false;
    let mut saw_web_framework_semantic_delta = false;
    let mut saw_web_semantic_complete = false;
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
        saw_web_semantic_delta |= current_web_semantic_delta;
        saw_web_framework_semantic_delta |= current_web_framework_semantic_delta;
        saw_web_semantic_complete |= current_web_semantic_complete;
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
    let mut prefix = validator.validated_events().to_vec();
    if parse_error.is_none() {
        match validator.finish() {
            Ok(protocol) if enforce_web_definition_graph => {
                if let Err(error) = validate_semantic_contract(&protocol) {
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
            }
            Ok(_) => {}
            Err(error) => {
                if enforce_web_definition_graph
                    && (saw_web_semantic_delta
                        || saw_web_framework_semantic_delta
                        || saw_web_semantic_complete)
                    && matches!(error, ProtocolError::Invariant(_))
                {
                    web_framework_failure = saw_web_framework_semantic_delta;
                    parse_error = Some(format!(
                        "security policy violation: invalid Web semantic protocol: {error}"
                    ));
                    failure_kind = Some(WorkerFailureKind::MalformedProtocol);
                    security_violation = true;
                } else {
                    parse_error = Some(format!("incomplete protocol stream: {error}"));
                    failure_kind = Some(WorkerFailureKind::IncompleteProtocol);
                }
            }
        }
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
mod tests {
    use super::*;

    #[test]
    fn worker_capability_handshake_is_exact_sorted_and_fail_closed() {
        assert_eq!(
            worker_capabilities(
                "depgraph-web-worker 0.4.0 (protocol 1.0; capabilities alpha,worker-delta-v1,zeta)"
            ),
            ["alpha", "worker-delta-v1", "zeta"]
        );
        assert!(worker_capabilities("depgraph-web-worker 0.4.0").is_empty());
        assert!(
            worker_capabilities(
                "depgraph-web-worker 0.4.0 (protocol 1.0; capabilities worker-delta-v1,alpha)"
            )
            .is_empty()
        );
        assert!(
            worker_capabilities(
                "depgraph-web-worker 0.4.0 (protocol 1.0; capabilities worker-delta-v1,worker-delta-v1)"
            )
            .is_empty()
        );
        assert!(
            worker_capabilities(
                "depgraph-web-worker 0.4.0 (protocol 1.0; future-capabilities worker-delta-v1)"
            )
            .is_empty()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn worker_version_probe_honors_cancellation_without_waiting_for_timeout() -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir()?;
        let root = temp.path().join("root");
        std::fs::create_dir(&root)?;
        let script = temp.path().join("slow-version-worker.sh");
        std::fs::write(&script, "#!/bin/sh\nexec sleep 30\n")?;
        let mut permissions = std::fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions)?;
        let spec = WorkerSpec {
            adapter: AdapterKind::Go,
            program: script.clone().into_os_string(),
            leading_args: Vec::new(),
            display: script.display().to_string(),
            artifact_path: script,
            runtime_requirement: None,
            expected_version: None,
            release_attested: false,
            attested_rust_sysroot: None,
        };
        let cancellation = CancellationToken::new();
        let cancel = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancel.cancel();
        });

        let started = std::time::Instant::now();
        let error = probe_worker_version_with_cancellation(&spec, &root, &cancellation)
            .await
            .expect_err("the slow version probe should be cancelled");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "cancelled probe waited {:?}",
            started.elapsed()
        );
        assert!(format!("{error:#}").contains("runtime probe cancelled"));
        Ok(())
    }

    struct TestRelease {
        manifest: PathBuf,
        rust_worker: PathBuf,
        go_worker: PathBuf,
    }

    fn manifest_artifact(path: &str, contents: &[u8]) -> Value {
        serde_json::json!({
            "path": path,
            "sha256": hex::encode(Sha256::digest(contents)),
        })
    }

    fn write_manifest_artifact(release: &Path, path: &str, contents: &[u8]) -> Result<Value> {
        let artifact = release.join(path);
        if let Some(parent) = artifact.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&artifact, contents)?;
        Ok(manifest_artifact(path, contents))
    }

    fn make_test_executable(path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mut permissions = std::fs::metadata(path)?.permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions)?;
        }
        #[cfg(not(unix))]
        let _ = path;
        Ok(())
    }

    fn write_test_release_manifest(
        release: &Path,
        mut runtime_artifacts: Vec<Value>,
        mut runtime_components: Vec<Value>,
    ) -> Result<TestRelease> {
        if runtime_artifacts.is_empty() {
            for path in WEB_RUNTIME_ARTIFACT_PATHS {
                runtime_artifacts.push(write_manifest_artifact(
                    release,
                    path,
                    format!("verified {path}").as_bytes(),
                )?);
            }
        }
        if !runtime_components
            .iter()
            .any(|component| component["name"] == "astro-parser-wasm")
        {
            let astro = release.join("libexec/astro");
            std::fs::create_dir_all(&astro)?;
            std::fs::write(astro.join("astro.wasm"), b"verified wasm")?;
            runtime_components.push(serde_json::json!({
                "name": "astro-parser-wasm",
                "version": "4.0.0",
                "kind": "data-tree",
                "root": "libexec/astro",
                "entrypoint": "libexec/astro/astro.wasm",
                "license": "MIT",
                "sha256": runtime_tree_digest(&astro)?,
            }));
        }
        if !runtime_components
            .iter()
            .any(|component| component["name"] == "typescript-native-compiler")
        {
            let typescript = release.join("libexec/typescript/lib");
            std::fs::create_dir_all(&typescript)?;
            let compiler = typescript.join(executable_name("tsc"));
            std::fs::write(&compiler, b"verified compiler")?;
            make_test_executable(&compiler)?;
            std::fs::write(typescript.join("lib.d.ts"), b"verified standard library")?;
            runtime_components.push(serde_json::json!({
                "name": "typescript-native-compiler",
                "version": "7.0.2",
                "kind": "executable-tree",
                "root": "libexec/typescript/lib",
                "entrypoint": format!("libexec/typescript/lib/{}", executable_name("tsc")),
                "license": "Apache-2.0",
                "sha256": runtime_tree_digest(&typescript)?,
            }));
        }
        if !runtime_components
            .iter()
            .any(|component| component["name"] == RUST_SYSROOT_COMPONENT_NAME)
        {
            let sysroot = release.join(RUST_SYSROOT_COMPONENT_ROOT);
            let core = sysroot.join("library/core/src/lib.rs");
            std::fs::create_dir_all(core.parent().context("test core source has no parent")?)?;
            std::fs::write(&core, b"verified bundled core source")?;
            runtime_components.push(serde_json::json!({
                "name": RUST_SYSROOT_COMPONENT_NAME,
                "version": RUST_SYSROOT_COMPONENT_VERSION,
                "kind": "data-tree",
                "root": RUST_SYSROOT_COMPONENT_ROOT,
                "license": RUST_SYSROOT_LICENSE_EXPRESSION,
                "sha256": runtime_tree_digest(&sysroot)?,
            }));
        }
        write_test_release_manifest_exact(release, runtime_artifacts, runtime_components)
    }

    fn write_test_release_manifest_exact(
        release: &Path,
        runtime_artifacts: Vec<Value>,
        runtime_components: Vec<Value>,
    ) -> Result<TestRelease> {
        let core_path = format!("bin/{}", executable_name("depgraph"));
        let rust_worker_path = format!("libexec/{}", executable_name("depgraph-rust-worker"));
        let go_worker_path = format!("libexec/{}", executable_name("depgraph-go-worker"));
        let web_worker_path = "libexec/depgraph-web-worker.mjs";
        let core = write_manifest_artifact(release, &core_path, b"verified core")?;
        let schema = write_manifest_artifact(release, PROTOCOL_SCHEMA_PATH, b"verified schema")?;
        let query_fixture = write_manifest_artifact(
            release,
            BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH,
            BOUNDED_QUERY_RELEASE_SMOKE_QUERY.as_bytes(),
        )?;
        let apache_license =
            write_manifest_artifact(release, "LICENSE-APACHE", b"test Apache-2.0 license")?;
        let mit_license = write_manifest_artifact(release, "LICENSE-MIT", b"test MIT license")?;
        let rust_worker =
            write_manifest_artifact(release, &rust_worker_path, b"verified rust worker")?;
        let go_worker = write_manifest_artifact(release, &go_worker_path, b"verified go worker")?;
        let web_worker = write_manifest_artifact(release, web_worker_path, b"verified web worker")?;
        make_test_executable(&release.join(&core_path))?;
        make_test_executable(&release.join(&rust_worker_path))?;
        make_test_executable(&release.join(&go_worker_path))?;
        let manifest = release.join("release-manifest.json");
        std::fs::write(
            &manifest,
            serde_json::to_vec_pretty(&serde_json::json!({
                "release_version": env!("CARGO_PKG_VERSION"),
                "protocol_version": "1.0",
                "schema_version": "1.0",
                "compatibility": crate::release_compatibility_contract(),
                "target": "test-target",
                "license_expression": PROJECT_LICENSE_EXPRESSION,
                "project_licenses": [apache_license, mit_license],
                "core": core,
                "schema": schema,
                "query_fixture": query_fixture,
                "runtime_artifacts": runtime_artifacts,
                "runtime_components": runtime_components,
                "runtime_requirements": {"web": WEB_RUNTIME_REQUIREMENT},
                "workers": [
                    {
                        "adapter": "rust",
                        "version": env!("CARGO_PKG_VERSION"),
                        "backend": {
                            "kind": RUST_BACKEND_KIND,
                            "version": RUST_BACKEND_VERSION,
                            "revision": RUST_BACKEND_REVISION,
                            "salsa_version": RUST_BACKEND_SALSA_VERSION,
                        },
                        "path": rust_worker["path"],
                        "sha256": rust_worker["sha256"],
                    },
                    {
                        "adapter": "go",
                        "version": env!("CARGO_PKG_VERSION"),
                        "path": go_worker["path"],
                        "sha256": go_worker["sha256"],
                    },
                    {
                        "adapter": "web",
                        "version": env!("CARGO_PKG_VERSION"),
                        "semantic": {
                            "typescript_version": TYPESCRIPT_COMPILER_VERSION,
                            "capabilities": WEB_SEMANTIC_CAPABILITIES,
                            "runtime_components": WEB_SEMANTIC_RUNTIME_COMPONENTS,
                            "runtime_artifacts": WEB_SEMANTIC_RUNTIME_ARTIFACTS,
                        },
                        "path": web_worker["path"],
                        "sha256": web_worker["sha256"],
                    },
                ],
            }))?,
        )?;
        Ok(TestRelease {
            manifest,
            rust_worker: release.join(rust_worker_path),
            go_worker: release.join(go_worker_path),
        })
    }

    fn update_test_manifest(
        manifest: &Path,
        update: impl FnOnce(&mut Value) -> Result<()>,
    ) -> Result<()> {
        let mut value: Value = serde_json::from_slice(&std::fs::read(manifest)?)?;
        update(&mut value)?;
        std::fs::write(manifest, serde_json::to_vec_pretty(&value)?)?;
        Ok(())
    }

    fn rust_gate_protocol(root: &Path, gate: &str) -> Result<Vec<u8>> {
        profile_protocol(
            root,
            "rust-gate-scan",
            "rust",
            serde_json::json!({"rust_hir_enable_gate": gate}),
        )
    }

    fn typescript_gate_protocol(root: &Path, gate: &str) -> Result<Vec<u8>> {
        profile_protocol(
            root,
            "typescript-gate-scan",
            "web",
            serde_json::json!({
                TYPESCRIPT_RELEASE_GATE_PROPERTY: gate,
                TYPESCRIPT_ANALYSIS_MODE_PROPERTY: TYPESCRIPT_ANALYSIS_MODE_DEFINITION_GRAPH,
                TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY: TYPESCRIPT_SEMANTIC_EMISSION_DEFINITION_GRAPH_V1,
                TYPESCRIPT_PROJECT_STATUS_PROPERTY: "ready",
                TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY: "definition-graph-emitted",
                TYPESCRIPT_DEFINITION_STATUS_PROPERTY: "ready",
                "typescript_semantic_node_count": "0",
                "typescript_semantic_relation_count": "0",
                "typescript_semantic_issue_count": "0",
            }),
        )
    }

    fn add_framework_semantic_delta(
        events: &mut Vec<Value>,
        valid_target: bool,
        status: &str,
        capability: &str,
    ) {
        let profile_id = "web:default";
        let package_locator = "npm:workspace:definition-fixture@1.0.0#.";
        let component_identity = serde_json::json!({
            "framework":"next",
            "package_locator":package_locator,
            "component_kind":"page",
            "environment":"server",
            "resolver_identity":format!("{package_locator}::app/products/page.tsx#default"),
        });
        let route_identity = serde_json::json!({
            "framework":"next",
            "package_locator":package_locator,
            "route_kind":"page",
            "environment":"server",
            "router_instance":"next-app:app",
            "route_pattern":"/products",
        });
        let component_id =
            depgraph_protocol::stable_id_from_value("component", &component_identity);
        let route_id = depgraph_protocol::stable_id_from_value("route", &route_identity);
        let target_id = if valid_target {
            route_id.as_str()
        } else {
            component_id.as_str()
        };
        let condition = serde_json::json!({
            "op":"all",
            "conditions":[
                {"op":"eq","key":"environment","value":"server"},
                {"op":"eq","key":"mode","value":"production"}
            ],
        });
        let semantic_evidence = serde_json::json!({
            "kind":"semantic",
            "extractor":"next-static-adapter",
            "extractor_version":WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION,
            "path":"app/products/page.tsx",
            "start_line":1,
            "start_column":1,
            "end_line":1,
            "end_column":32,
            "properties":{
                "profile_id":profile_id,
                "framework":"next",
                "contract_version":WEB_FRAMEWORK_SEMANTIC_CAPABILITY_V1,
                "occurrence_kind":"page_route_entry",
            },
        });
        let source_evidence = serde_json::json!({
            "kind":"source",
            "extractor":"next-static-adapter",
            "extractor_version":WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION,
            "path":"app/products/page.tsx",
            "start_line":1,
            "start_column":1,
            "end_line":1,
            "end_column":32,
            "properties":{
                "profile_id":profile_id,
                "framework":"next",
                "occurrence_kind":"page_route_entry",
            },
        });
        let site_id = depgraph_protocol::stable_id_from_value(
            "site",
            &serde_json::json!({
                "condition":condition,
                "kind":"route_entry",
                "path":"app/products/page.tsx",
                "profile_id":profile_id,
                "source":component_id,
                "span":{"start_line":1,"start_column":1,"end_line":1,"end_column":32},
            }),
        );
        let edge_id = depgraph_protocol::stable_id_from_value(
            "edge",
            &serde_json::json!({"kind":"route_entry","site_id":site_id,"target":target_id}),
        );
        let profile = events
            .iter_mut()
            .find(|event| event["event"] == "profile_declared")
            .expect("Web profile declaration");
        profile["profile"]["features"] = serde_json::json!(["next"]);
        let properties = &mut profile["profile"]["properties"];
        properties[TYPESCRIPT_ANALYSIS_MODE_PROPERTY] =
            serde_json::json!(TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_CALL_GRAPH);
        properties[TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY] =
            serde_json::json!(TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2);
        properties[TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY] =
            serde_json::json!("definition-import-type-call-graph-emitted");
        properties[TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY] = serde_json::json!("0");
        properties[TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY] = serde_json::json!("0");
        properties[WEB_FRAMEWORK_SEMANTIC_CAPABILITY_PROPERTY] = serde_json::json!(capability);
        properties[WEB_FRAMEWORK_SEMANTIC_STATUS_PROPERTY] = serde_json::json!(status);
        properties[WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION_PROPERTY] =
            serde_json::json!(WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION);
        properties[WEB_FRAMEWORK_SEMANTIC_NODE_COUNT_PROPERTY] = serde_json::json!("2");
        properties[WEB_FRAMEWORK_SEMANTIC_SITE_COUNT_PROPERTY] = serde_json::json!("1");
        properties[WEB_FRAMEWORK_SEMANTIC_EDGE_COUNT_PROPERTY] = serde_json::json!("1");
        properties[WEB_FRAMEWORK_COMPLETENESS_CAPABILITY_PROPERTY] =
            serde_json::json!(WEB_FRAMEWORK_COMPLETENESS_CAPABILITY_V1);
        properties[WEB_FRAMEWORK_COMPLETENESS_STATUS_PROPERTY] = serde_json::json!("complete");
        properties[WEB_FRAMEWORK_COMPLETENESS_ISSUE_COUNT_PROPERTY] = serde_json::json!("0");
        properties[WEB_FRAMEWORK_COMPLETENESS_LEDGER_PROPERTY] = serde_json::json!(
            "[{\"framework\":\"next\",\"required_capabilities\":[\"framework-semantic-graph-v1\",\"next-route-component-boundary-v1\",\"typescript-definition-import-type-call-graph-v2\"],\"emitted_capabilities\":[\"framework-semantic-graph-v1\",\"next-route-component-boundary-v1\",\"typescript-definition-import-type-call-graph-v2\"],\"status\":\"complete\",\"reasons\":[]}]"
        );
        let insert_at = events
            .iter()
            .position(|event| event["event"] == "profile_completed")
            .expect("profile completion");
        let payload = vec![
            serde_json::json!({
                "event":"node_upsert",
                "node":{
                    "id":component_id,
                    "kind":"component",
                    "locator":format!("framework-component:{component_id}"),
                    "display_name":"ProductsPage",
                    "properties":{
                        "framework":"next","package_locator":package_locator,
                        "component_kind":"page","environment":"server",
                        "profile_id":profile_id,"canonical_identity":component_identity,
                    },
                },
            }),
            serde_json::json!({
                "event":"node_upsert",
                "node":{
                    "id":route_id,
                    "kind":"route",
                    "locator":format!("framework-route:{route_id}"),
                    "display_name":"/products",
                    "properties":{
                        "framework":"next","package_locator":package_locator,
                        "route_kind":"page","environment":"server",
                        "profile_id":profile_id,"canonical_identity":route_identity,
                    },
                },
            }),
            serde_json::json!({
                "event":"dependency_site",
                "site":{
                    "id":site_id,"source":component_id,"kind":"route_entry",
                    "specifier":"/products","resolution_status":"resolved",
                    "target_ids":[target_id],"profile_id":profile_id,
                    "condition":condition,"precision":"exact","reason":null,
                    "evidence":[semantic_evidence,source_evidence],
                },
            }),
            serde_json::json!({
                "event":"edge_upsert",
                "edge":{
                    "id":edge_id,"source":component_id,"target":target_id,
                    "kind":"route_entry","site_id":site_id,"phase":"semantic",
                    "environment":"server","profile_id":profile_id,"condition":condition,
                    "resolution_status":"resolved","precision":"exact","generated":false,
                    "evidence":[semantic_evidence,source_evidence],
                },
            }),
        ];
        for event in payload.into_iter().rev() {
            events.insert(insert_at, event);
        }
        for event in events.iter_mut().filter(|event| {
            matches!(
                event["event"].as_str(),
                Some("profile_completed" | "scan_completed")
            )
        }) {
            event["coverage"]["dependency_sites"] = serde_json::json!(1);
            event["coverage"]["resolved"] = serde_json::json!(1);
        }
        resequence_test_protocol(events);
        for event in events {
            event["protocol_version"] = serde_json::json!("1.0");
            event["scan_id"] = serde_json::json!("typescript-gate-scan");
            event["adapter"] = serde_json::json!("web");
            event["adapter_version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
        }
    }

    fn typescript_definition_protocol(
        root: &Path,
        gate: &str,
        relation_kind: &str,
    ) -> Result<Vec<u8>> {
        std::fs::create_dir_all(root.join("src"))?;
        std::fs::write(
            root.join("package.json"),
            br#"{"name":"definition-fixture","version":"1.0.0"}"#,
        )?;
        std::fs::write(root.join("src/index.ts"), b"export class Definition {}\n")?;
        let output = typescript_gate_protocol(root, gate)?;
        let mut events = String::from_utf8(output)?
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let profile_id = "web:default";
        let package_locator = "npm:workspace:definition-fixture@1.0.0#.";
        let package_id = depgraph_protocol::stable_id_from_value(
            "package",
            &serde_json::json!({"locator": package_locator}),
        );
        let file_id = depgraph_protocol::stable_id_from_value(
            "file",
            &serde_json::json!({"package": package_locator, "path": "src/index.ts"}),
        );
        let named_identity = |namespace: &str,
                              semantic_kind: &str,
                              resolver_suffix: &str,
                              generic_origin: Option<&str>| {
            let kind_property = if namespace == "symbol" {
                "symbol_kind"
            } else {
                "type_kind"
            };
            let mut identity = serde_json::json!({
                "language": "typescript",
                "package_locator": package_locator,
                "resolver_identity": format!("{package_locator}::module:src/index.ts#{resolver_suffix}"),
            });
            identity[kind_property] = serde_json::json!(semantic_kind);
            if namespace == "symbol" {
                identity["identity_kind"] = serde_json::json!("named");
            }
            if let Some(generic_origin) = generic_origin {
                let type_arguments = serde_json::json!([{"kind":"intrinsic","name":"string"}]);
                identity["resolver_identity"] = serde_json::json!(format!(
                    "generic:{}",
                    serde_json::to_string(&serde_json::json!([
                        generic_origin,
                        type_arguments.clone()
                    ]))
                    .expect("test generic resolver input serializes")
                ));
                identity["generic_origin"] = serde_json::json!(generic_origin);
                identity["type_arguments"] = type_arguments;
            }
            identity
        };
        let semantic_node = |namespace: &str,
                             semantic_kind: &str,
                             resolver_suffix: &str,
                             generic_origin: Option<&str>| {
            let identity =
                named_identity(namespace, semantic_kind, resolver_suffix, generic_origin);
            let kind_property = if namespace == "symbol" {
                "symbol_kind"
            } else {
                "type_kind"
            };
            let id = depgraph_protocol::stable_id_from_value(namespace, &identity);
            let mut properties = serde_json::json!({
                "language": "typescript",
                "package_locator": package_locator,
                "package_id": package_id,
                "canonical_identity": identity.clone(),
                "profile_id": profile_id,
                "source_path": "src/index.ts",
                "source_span": {
                    "start_line": 1,
                    "start_column": 1,
                    "end_line": 1,
                    "end_column": 9,
                },
            });
            properties[kind_property] = serde_json::json!(semantic_kind);
            properties["resolver_identity"] = identity["resolver_identity"].clone();
            if generic_origin.is_some() {
                properties["generic_origin"] = identity["generic_origin"].clone();
                properties["type_arguments"] = identity["type_arguments"].clone();
            }
            serde_json::json!({
                "id": id,
                "kind": namespace,
                "locator": format!("typescript-{namespace}:{id}"),
                "display_name": semantic_kind,
                "properties": properties,
            })
        };
        let condition = serde_json::json!({"op":"all","conditions":[]});
        let relation = |kind: &str, source: &str, target: &str| {
            let evidence = serde_json::json!({
                "kind": "semantic",
                "extractor": TYPESCRIPT_SEMANTIC_EXTRACTOR,
                "extractor_version": TYPESCRIPT_COMPILER_VERSION,
                "path": "src/index.ts",
                "start_line": 1,
                "start_column": 1,
                "end_line": 1,
                "end_column": 9,
                "detail": "TypeChecker definition relation",
                "properties": {"profile_id": profile_id},
            });
            let edge_id = depgraph_protocol::stable_id_from_value(
                "edge",
                &serde_json::json!({
                    "condition": condition,
                    "kind": kind,
                    "path": evidence["path"],
                    "profile_id": profile_id,
                    "source": source,
                    "span": {
                        "end_column": evidence["end_column"],
                        "end_line": evidence["end_line"],
                        "start_column": evidence["start_column"],
                        "start_line": evidence["start_line"],
                    },
                    "target": target,
                }),
            );
            serde_json::json!({
                "event":"edge_upsert",
                "edge": {
                    "id":edge_id,
                    "source":source,
                    "target":target,
                    "kind":kind,
                    "phase":"semantic",
                    "environment":"any",
                    "profile_id":profile_id,
                    "condition":condition,
                    "resolution_status":"resolved",
                    "precision":"exact",
                    "generated":false,
                    "evidence":[evidence],
                },
            })
        };
        let mut semantic_nodes = Vec::new();
        let mut semantic_edges = Vec::new();
        match relation_kind {
            "declares" => {
                let symbol = semantic_node("symbol", "function", "definition", None);
                semantic_edges.push(relation(
                    "declares",
                    &file_id,
                    symbol["id"].as_str().expect("symbol ID"),
                ));
                semantic_nodes.push(symbol);
            }
            "extends" | "implements" => {
                let left = semantic_node("type", "class", "left", None);
                let right = semantic_node("type", "interface", "right", None);
                for node in [&left, &right] {
                    semantic_edges.push(relation(
                        "declares",
                        &file_id,
                        node["id"].as_str().expect("type ID"),
                    ));
                }
                semantic_edges.push(relation(
                    relation_kind,
                    left["id"].as_str().expect("left type ID"),
                    right["id"].as_str().expect("right type ID"),
                ));
                semantic_nodes.extend([left, right]);
            }
            "instantiates" => {
                let source = semantic_node("type", "class", "source", None);
                let origin = semantic_node("type", "class", "origin", None);
                let origin_resolver =
                    origin["properties"]["canonical_identity"]["resolver_identity"]
                        .as_str()
                        .expect("origin resolver");
                let instance = semantic_node(
                    "type",
                    "generic_instance",
                    "origin<string>",
                    Some(origin_resolver),
                );
                for node in [&source, &origin] {
                    semantic_edges.push(relation(
                        "declares",
                        &file_id,
                        node["id"].as_str().expect("type ID"),
                    ));
                }
                semantic_edges.push(relation(
                    "instantiates",
                    source["id"].as_str().expect("source type ID"),
                    instance["id"].as_str().expect("instance type ID"),
                ));
                semantic_nodes.extend([source, origin, instance]);
            }
            other => bail!("unsupported test relation {other}"),
        }
        events[1]["profile"]["properties"]["typescript_semantic_node_count"] =
            serde_json::json!(semantic_nodes.len().to_string());
        events[1]["profile"]["properties"]["typescript_semantic_relation_count"] =
            serde_json::json!(semantic_edges.len().to_string());
        let mut payload = vec![
            serde_json::json!({
                "event":"node_upsert",
                "node": {
                    "id":package_id,
                    "kind":"package_instance",
                    "locator":format!("package://{package_locator}"),
                    "display_name":"definition-fixture",
                    "properties":{
                        "locator":package_locator,
                        "manifest_path":"package.json",
                        "workspace":true,
                        "workspace_path":".",
                    },
                },
            }),
            serde_json::json!({
                "event":"node_upsert",
                "node": {
                    "id":file_id,
                    "kind":"file",
                    "locator":"file://src/index.ts",
                    "display_name":"src/index.ts",
                    "properties":{
                        "path":"src/index.ts",
                        "package_id":package_id,
                        "language":"typescript",
                        "generated":false,
                    },
                },
            }),
        ];
        payload.extend(
            semantic_nodes
                .into_iter()
                .map(|node| serde_json::json!({"event":"node_upsert","node":node})),
        );
        payload.extend(semantic_edges);
        for item in payload.into_iter().rev() {
            events.insert(2, item);
        }
        for (index, event) in events.iter_mut().enumerate() {
            event["protocol_version"] = serde_json::json!("1.0");
            event["scan_id"] = serde_json::json!("typescript-gate-scan");
            event["adapter"] = serde_json::json!("web");
            event["adapter_version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
            event["seq"] = serde_json::json!(index + 1);
        }
        let mut protocol = Vec::new();
        for event in events {
            serde_json::to_writer(&mut protocol, &event)?;
            protocol.push(b'\n');
        }
        Ok(protocol)
    }

    fn typescript_import_type_protocol(root: &Path, gate: &str) -> Result<Vec<u8>> {
        let mut events =
            test_protocol_values(typescript_definition_protocol(root, gate, "extends")?)?;
        std::fs::write(root.join("src/target.ts"), b"export interface Target {}\n")?;
        let profile_id = "web:default";
        let profile = events
            .iter_mut()
            .find(|event| event["event"] == "profile_declared")
            .expect("Web profile declaration");
        profile["profile"]["properties"][TYPESCRIPT_ANALYSIS_MODE_PROPERTY] =
            serde_json::json!(TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_GRAPH);
        profile["profile"]["properties"][TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY] =
            serde_json::json!(TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_GRAPH_V1);
        profile["profile"]["properties"][TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY] =
            serde_json::json!("definition-import-type-graph-emitted");
        profile["profile"]["properties"][TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY] =
            serde_json::json!("3");

        let package = events
            .iter()
            .find(|event| event["node"]["kind"] == "package_instance")
            .expect("package node");
        let package_id = package["node"]["id"]
            .as_str()
            .expect("package ID")
            .to_owned();
        let package_locator = package["node"]["properties"]["locator"]
            .as_str()
            .expect("package locator")
            .to_owned();
        let source_file_id = events
            .iter()
            .find(|event| event["node"]["properties"]["path"] == "src/index.ts")
            .expect("source file")["node"]["id"]
            .as_str()
            .expect("source file ID")
            .to_owned();
        let target_file_id = depgraph_protocol::stable_id_from_value(
            "file",
            &serde_json::json!({"package": package_locator, "path": "src/target.ts"}),
        );
        let mut type_ids = events
            .iter()
            .filter(|event| event["node"]["kind"] == "type")
            .map(|event| event["node"]["id"].as_str().expect("type ID").to_owned())
            .collect::<Vec<_>>();
        type_ids.sort();
        let owner_type_id = type_ids.first().context("owner type")?.clone();
        let target_type_id = type_ids.get(1).context("target type")?.clone();

        let condition = serde_json::json!({"op":"all","conditions":[]});
        let evidence = |occurrence_kind: &str,
                        target_basis: &str,
                        start_column: u64,
                        end_column: u64,
                        module_specifier: Option<&str>,
                        imported_name: Option<&str>| {
            let type_only = matches!(
                occurrence_kind,
                "type_reference" | "heritage_type" | "jsdoc_type" | "import_type"
            );
            let mut primary = serde_json::json!({
                    "kind":"semantic",
                    "extractor":TYPESCRIPT_SEMANTIC_EXTRACTOR,
                    "extractor_version":TYPESCRIPT_COMPILER_VERSION,
                    "path":"src/index.ts",
                    "start_line":1,
                    "start_column":start_column,
                    "end_line":1,
                    "end_column":end_column,
                    "detail":"TypeChecker dependency occurrence",
                    "properties":{
                    "backend":TYPESCRIPT_SEMANTIC_BACKEND,
                        "compiler_source":"bundled",
                        "compiler_version":TYPESCRIPT_COMPILER_VERSION,
                        "analysis_mode":TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_GRAPH,
                        "profile_id":profile_id,
                        "project_code_executed":false,
                        "occurrence_kind":occurrence_kind,
                        "target_basis":target_basis,
                        "type_only":type_only,
                    },
            });
            if let Some(module_specifier) = module_specifier {
                primary["properties"]["module_specifier"] = serde_json::json!(module_specifier);
            }
            if let Some(imported_name) = imported_name {
                primary["properties"]["imported_name"] = serde_json::json!(imported_name);
            }
            let supporting = serde_json::json!({
                "kind":"source",
                "extractor":"typescript-native-syntax",
                "extractor_version":TYPESCRIPT_COMPILER_VERSION,
                    "path":"src/index.ts",
                    "start_line":1,
                    "start_column":start_column,
                    "end_line":1,
                    "end_column":end_column,
                    "detail":"syntax dependency occurrence",
                "properties":{
                    "profile_id":profile_id,
                    "occurrence_kind":occurrence_kind,
                },
            });
            serde_json::json!([primary, supporting])
        };
        let dependency = |kind: &str,
                          edge_kind: &str,
                          source: &str,
                          target: &str,
                          specifier: &str,
                          evidence: Value| {
            let primary = &evidence[0];
            let site_id = depgraph_protocol::stable_id_from_value(
                "site",
                &serde_json::json!({
                    "condition":condition,
                    "kind":kind,
                    "path":primary["path"],
                    "profile_id":profile_id,
                    "source":source,
                    "span":{
                        "end_column":primary["end_column"],
                        "end_line":primary["end_line"],
                        "start_column":primary["start_column"],
                        "start_line":primary["start_line"],
                    },
                }),
            );
            let edge_id = depgraph_protocol::stable_id_from_value(
                "edge",
                &serde_json::json!({
                    "kind":edge_kind,
                    "site_id":site_id,
                    "target":target,
                }),
            );
            [
                serde_json::json!({
                    "event":"dependency_site",
                    "site":{
                        "id":site_id,
                        "source":source,
                        "kind":kind,
                        "specifier":specifier,
                        "resolution_status":"resolved",
                        "target_ids":[target],
                        "profile_id":profile_id,
                        "condition":condition,
                        "precision":"exact",
                        "evidence":evidence,
                    },
                }),
                serde_json::json!({
                    "event":"edge_upsert",
                    "edge":{
                        "id":edge_id,
                        "source":source,
                        "target":target,
                        "kind":edge_kind,
                        "site_id":site_id,
                        "phase":"semantic",
                        "environment":"any",
                        "profile_id":profile_id,
                        "condition":condition,
                        "resolution_status":"resolved",
                        "precision":"exact",
                        "generated":false,
                        "evidence":evidence,
                    },
                }),
            ]
        };
        let mut payload = vec![serde_json::json!({
            "event":"node_upsert",
            "node":{
                "id":target_file_id,
                "kind":"file",
                "locator":"file://src/target.ts",
                "display_name":"src/target.ts",
                "properties":{
                    "path":"src/target.ts",
                    "package_id":package_id,
                    "language":"typescript",
                    "generated":false,
                },
            },
        })];
        payload.extend(dependency(
            "web_import",
            "imports",
            &source_file_id,
            &target_file_id,
            "./target",
            evidence(
                "namespace_import",
                "repository_module",
                1,
                8,
                Some("./target"),
                Some("*"),
            ),
        ));
        payload.extend(dependency(
            "web_reexport",
            "reexports",
            &source_file_id,
            &target_type_id,
            "./target",
            evidence(
                "named_reexport",
                "canonical_definition",
                9,
                18,
                Some("./target"),
                Some("Target"),
            ),
        ));
        payload.extend(dependency(
            "type_use",
            "type_uses",
            &owner_type_id,
            &target_type_id,
            "Target",
            evidence(
                "type_reference",
                "canonical_definition",
                19,
                25,
                None,
                Some("Target"),
            ),
        ));
        let completion_index = events
            .iter()
            .position(|event| event["event"] == "profile_completed")
            .expect("profile completion");
        for item in payload.into_iter().rev() {
            events.insert(completion_index, item);
        }
        let relation_count = events
            .iter()
            .filter(|event| event["event"] == "edge_upsert" && event["edge"]["phase"] == "semantic")
            .count();
        let profile = events
            .iter_mut()
            .find(|event| event["event"] == "profile_declared")
            .expect("Web profile declaration");
        profile["profile"]["properties"]["typescript_semantic_relation_count"] =
            serde_json::json!(relation_count.to_string());
        for event in &mut events {
            if matches!(
                event["event"].as_str(),
                Some("profile_completed" | "scan_completed")
            ) {
                event["coverage"]["dependency_sites"] = serde_json::json!(3);
                event["coverage"]["resolved"] = serde_json::json!(3);
            }
        }
        for event in &mut events {
            event["protocol_version"] = serde_json::json!("1.0");
            event["scan_id"] = serde_json::json!("typescript-gate-scan");
            event["adapter"] = serde_json::json!("web");
            event["adapter_version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
        }
        resequence_test_protocol(&mut events);
        serialize_test_protocol(events)
    }

    fn typescript_call_protocol(root: &Path, gate: &str) -> Result<Vec<u8>> {
        let mut events =
            test_protocol_values(typescript_definition_protocol(root, gate, "declares")?)?;
        let profile_id = "web:default";
        let profile = events
            .iter_mut()
            .find(|event| event["event"] == "profile_declared")
            .expect("Web profile declaration");
        let properties = &mut profile["profile"]["properties"];
        properties[TYPESCRIPT_ANALYSIS_MODE_PROPERTY] =
            serde_json::json!(TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_CALL_GRAPH);
        properties[TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY] =
            serde_json::json!(TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V1);
        properties[TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY] =
            serde_json::json!("definition-import-type-call-graph-emitted");
        properties[TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY] = serde_json::json!("1");
        properties[TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY] = serde_json::json!("1");

        let package = events
            .iter()
            .find(|event| event["node"]["kind"] == "package_instance")
            .expect("package node");
        let package_id = package["node"]["id"]
            .as_str()
            .expect("package ID")
            .to_owned();
        let package_locator = package["node"]["properties"]["locator"]
            .as_str()
            .expect("package locator")
            .to_owned();
        let source_file_id = events
            .iter()
            .find(|event| event["node"]["properties"]["path"] == "src/index.ts")
            .expect("source file")["node"]["id"]
            .as_str()
            .expect("source file ID")
            .to_owned();
        let target_symbol_id = events
            .iter()
            .find(|event| event["node"]["properties"]["symbol_kind"] == "function")
            .expect("target function")["node"]["id"]
            .as_str()
            .expect("target function ID")
            .to_owned();
        let initializer_span = serde_json::json!({
            "start_line":1,
            "start_column":1,
            "end_line":1,
            "end_column":9,
        });
        let variable_resolver_identity =
            format!("{package_locator}::module:src/index.ts#callFixtureVariable");
        let variable_identity = serde_json::json!({
            "language":"typescript",
            "package_locator":package_locator,
            "symbol_kind":"variable",
            "identity_kind":"named",
            "resolver_identity":variable_resolver_identity,
        });
        let variable_symbol_id =
            depgraph_protocol::stable_id_from_value("symbol", &variable_identity);
        let variable_node = serde_json::json!({
            "event":"node_upsert",
            "node":{
                "id":variable_symbol_id,
                "kind":"symbol",
                "locator":format!("typescript-symbol:{variable_symbol_id}"),
                "display_name":"callFixtureVariable",
                "properties":{
                    "language":"typescript",
                    "package_locator":package_locator,
                    "package_id":package_id,
                    "symbol_kind":"variable",
                    "canonical_identity":variable_identity,
                    "resolver_identity":variable_resolver_identity,
                    "profile_id":profile_id,
                    "source_path":"src/index.ts",
                    "source_span":initializer_span,
                },
            },
        });
        let initializer_identity = serde_json::json!({
            "language":"typescript",
            "package_locator":package_locator,
            "symbol_kind":"generated_module_initializer",
            "identity_kind":"generated",
            "generated_from":source_file_id,
            "relative_path":"src/index.ts",
            "span":initializer_span,
        });
        let initializer_id =
            depgraph_protocol::stable_id_from_value("symbol", &initializer_identity);
        let initializer_node = serde_json::json!({
            "event":"node_upsert",
            "node":{
                "id":initializer_id,
                "kind":"symbol",
                "locator":format!("typescript-symbol:{initializer_id}"),
                "display_name":"<module initializer>",
                "properties":{
                    "language":"typescript",
                    "package_locator":package_locator,
                    "package_id":package_id,
                    "symbol_kind":"generated_module_initializer",
                    "canonical_identity":initializer_identity,
                    "profile_id":profile_id,
                    "source_path":"src/index.ts",
                    "source_span":initializer_span,
                    "generated":true,
                },
            },
        });
        let condition = serde_json::json!({"op":"all","conditions":[]});
        let definition_evidence = serde_json::json!({
            "kind":"semantic",
            "extractor":TYPESCRIPT_SEMANTIC_EXTRACTOR,
            "extractor_version":TYPESCRIPT_COMPILER_VERSION,
            "path":"src/index.ts",
            "start_line":1,
            "start_column":1,
            "end_line":1,
            "end_column":9,
            "detail":"TypeChecker generated module initializer",
            "properties":{"profile_id":profile_id},
        });
        let declares_id = depgraph_protocol::stable_id_from_value(
            "edge",
            &serde_json::json!({
                "condition":condition,
                "kind":"declares",
                "path":"src/index.ts",
                "profile_id":profile_id,
                "source":source_file_id,
                "span":initializer_span,
                "target":initializer_id,
            }),
        );
        let declares = serde_json::json!({
            "event":"edge_upsert",
            "edge":{
                "id":declares_id,
                "source":source_file_id,
                "target":initializer_id,
                "kind":"declares",
                "phase":"semantic",
                "environment":"any",
                "profile_id":profile_id,
                "condition":condition,
                "resolution_status":"resolved",
                "precision":"exact",
                "generated":true,
                "evidence":[definition_evidence],
            },
        });
        let variable_definition_evidence = serde_json::json!({
            "kind":"semantic",
            "extractor":TYPESCRIPT_SEMANTIC_EXTRACTOR,
            "extractor_version":TYPESCRIPT_COMPILER_VERSION,
            "path":"src/index.ts",
            "start_line":1,
            "start_column":1,
            "end_line":1,
            "end_column":9,
            "detail":"TypeChecker variable declaration",
            "properties":{"profile_id":profile_id},
        });
        let variable_declares_id = depgraph_protocol::stable_id_from_value(
            "edge",
            &serde_json::json!({
                "condition":condition,
                "kind":"declares",
                "path":"src/index.ts",
                "profile_id":profile_id,
                "source":source_file_id,
                "span":initializer_span,
                "target":variable_symbol_id,
            }),
        );
        let variable_declares = serde_json::json!({
            "event":"edge_upsert",
            "edge":{
                "id":variable_declares_id,
                "source":source_file_id,
                "target":variable_symbol_id,
                "kind":"declares",
                "phase":"semantic",
                "environment":"any",
                "profile_id":profile_id,
                "condition":condition,
                "resolution_status":"resolved",
                "precision":"exact",
                "generated":false,
                "evidence":[variable_definition_evidence],
            },
        });
        let call_evidence = serde_json::json!([{
            "kind":"semantic",
            "extractor":TYPESCRIPT_SEMANTIC_EXTRACTOR,
            "extractor_version":TYPESCRIPT_COMPILER_VERSION,
            "path":"src/index.ts",
            "start_line":1,
            "start_column":1,
            "end_line":1,
            "end_column":9,
            "detail":"TypeChecker resolved-signature direct call occurrence",
            "properties":{
                "backend":TYPESCRIPT_SEMANTIC_BACKEND,
                "compiler_source":"bundled",
                "compiler_version":TYPESCRIPT_COMPILER_VERSION,
                "analysis_mode":TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_CALL_GRAPH,
                "profile_id":profile_id,
                "project_code_executed":false,
                "occurrence_kind":"call_expression",
                "target_basis":"canonical_definition",
                "call_kind":"function",
                "dispatch":"direct",
            },
        }, {
            "kind":"source",
            "extractor":"typescript-native-syntax",
            "extractor_version":TYPESCRIPT_COMPILER_VERSION,
            "path":"src/index.ts",
            "start_line":1,
            "start_column":1,
            "end_line":1,
            "end_column":9,
            "detail":"syntax call occurrence",
            "properties":{
                "profile_id":profile_id,
                "occurrence_kind":"call_expression",
            },
        }]);
        let call_site_id = depgraph_protocol::stable_id_from_value(
            "site",
            &serde_json::json!({
                "condition":condition,
                "kind":"call",
                "path":"src/index.ts",
                "profile_id":profile_id,
                "source":initializer_id,
                "span":initializer_span,
            }),
        );
        let call_edge_id = depgraph_protocol::stable_id_from_value(
            "edge",
            &serde_json::json!({
                "kind":"calls",
                "site_id":call_site_id,
                "target":target_symbol_id,
            }),
        );
        let call_site = serde_json::json!({
            "event":"dependency_site",
            "site":{
                "id":call_site_id,
                "source":initializer_id,
                "kind":"call",
                "specifier":"Definition()",
                "resolution_status":"resolved",
                "target_ids":[target_symbol_id],
                "profile_id":profile_id,
                "condition":condition,
                "precision":"exact",
                "evidence":call_evidence,
            },
        });
        let call_edge = serde_json::json!({
            "event":"edge_upsert",
            "edge":{
                "id":call_edge_id,
                "source":initializer_id,
                "target":target_symbol_id,
                "kind":"calls",
                "site_id":call_site_id,
                "phase":"semantic",
                "environment":"any",
                "profile_id":profile_id,
                "condition":condition,
                "resolution_status":"resolved",
                "precision":"exact",
                "generated":false,
                "evidence":call_evidence,
            },
        });
        let completion_index = events
            .iter()
            .position(|event| event["event"] == "profile_completed")
            .expect("profile completion");
        for item in [
            initializer_node,
            declares,
            variable_node,
            variable_declares,
            call_site,
            call_edge,
        ]
        .into_iter()
        .rev()
        {
            events.insert(completion_index, item);
        }
        let profile = events
            .iter_mut()
            .find(|event| event["event"] == "profile_declared")
            .expect("Web profile declaration");
        profile["profile"]["properties"]["typescript_semantic_node_count"] = serde_json::json!("3");
        profile["profile"]["properties"]["typescript_semantic_relation_count"] =
            serde_json::json!("4");
        for event in &mut events {
            if matches!(
                event["event"].as_str(),
                Some("profile_completed" | "scan_completed")
            ) {
                event["coverage"]["dependency_sites"] = serde_json::json!(1);
                event["coverage"]["resolved"] = serde_json::json!(1);
            }
            event["protocol_version"] = serde_json::json!("1.0");
            event["scan_id"] = serde_json::json!("typescript-gate-scan");
            event["adapter"] = serde_json::json!("web");
            event["adapter_version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
        }
        resequence_test_protocol(&mut events);
        serialize_test_protocol(events)
    }

    fn promote_typescript_semantic_complete(events: &mut [Value], gate: &str) {
        let standard_library_integrity = match gate {
            TYPESCRIPT_RELEASE_GATE_PENDING => "build-produced-pending-core-attestation",
            TYPESCRIPT_RELEASE_GATE_VERIFIED => "core-attested-whole-tree",
            unexpected => panic!("unsupported TypeScript release gate {unexpected:?}"),
        };
        {
            let profile = events
                .iter_mut()
                .find(|event| event["event"] == "profile_declared")
                .expect("Web profile declaration");
            profile["profile"]["features"] = serde_json::json!([]);
            let properties = &mut profile["profile"]["properties"];
            for (property, value) in [
                ("bundled_typescript", "true"),
                ("typescript_syntax_compiler", "native-7.0.2"),
                ("typescript_compiler_source", "bundled"),
                ("typescript_compiler_version", TYPESCRIPT_COMPILER_VERSION),
                ("typescript_compiler_selection", "bundled-only"),
                ("typescript_compiler_fallback", "fail-closed"),
                (
                    TYPESCRIPT_ANALYSIS_MODE_PROPERTY,
                    TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_CALL_GRAPH,
                ),
                ("typescript_project_local_policy", "metadata-only"),
                ("typescript_project_local_loaded", "false"),
                (
                    TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY,
                    "definition-import-type-call-graph-emitted",
                ),
                (TYPESCRIPT_PROJECT_STATUS_PROPERTY, "ready"),
                ("typescript_project_model_failure_reason", "none"),
                ("typescript_project_config", "worker-neutral-allowlist"),
                ("typescript_module_resolution", "inventory-only"),
                ("typescript_standard_library_source", "bundled"),
                (
                    "typescript_standard_library_integrity",
                    standard_library_integrity,
                ),
                (TYPESCRIPT_RELEASE_GATE_PROPERTY, gate),
                (
                    TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY,
                    TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2,
                ),
                ("typescript_compiler_processes", "1"),
                ("typescript_project_filesystem", "isolated-virtual"),
                (TYPESCRIPT_DEFINITION_STATUS_PROPERTY, "ready"),
                ("typescript_semantic_diagnostics", "0"),
                ("typescript_emitted_semantic_diagnostics", "0"),
                ("typescript_semantic_issue_count", "0"),
                ("project_code_executed", "false"),
            ] {
                properties[property] = serde_json::json!(value);
            }
            if properties
                .get(TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY)
                .is_none()
            {
                properties[TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY] = serde_json::json!("0");
            }
            if properties
                .get(TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY)
                .is_none()
            {
                properties[TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY] = serde_json::json!("0");
            }
        }
        for event in events {
            if matches!(
                event["event"].as_str(),
                Some("profile_completed" | "scan_completed")
            ) {
                event["coverage"]["completeness"] =
                    serde_json::json!(["syntax-complete", "semantic-complete"]);
                event["coverage"]["files_skipped"] = serde_json::json!(0);
                event["coverage"]["unsupported_syntax"] = serde_json::json!(0);
                event["coverage"]["unresolved"] = serde_json::json!(0);
                event["coverage"]["project_code_executed"] = serde_json::json!(false);
                event["coverage"]["reasons"] = serde_json::json!([]);
            }
        }
    }

    fn recanonicalize_typescript_call(events: &mut [Value]) {
        let site_index = events
            .iter()
            .position(|event| {
                event["event"] == "dependency_site" && event["site"]["kind"] == "call"
            })
            .expect("call site");
        let source = events[site_index]["site"]["source"]
            .as_str()
            .expect("call source")
            .to_owned();
        let target = events[site_index]["site"]["target_ids"][0]
            .as_str()
            .expect("call target")
            .to_owned();
        let profile_id = events[site_index]["site"]["profile_id"]
            .as_str()
            .expect("call profile")
            .to_owned();
        let condition = events[site_index]["site"]["condition"].clone();
        let primary = &events[site_index]["site"]["evidence"][0];
        let path = primary["path"].as_str().expect("call evidence path");
        let span = serde_json::json!({
            "start_line":primary["start_line"],
            "start_column":primary["start_column"],
            "end_line":primary["end_line"],
            "end_column":primary["end_column"],
        });
        let site_id = depgraph_protocol::stable_id_from_value(
            "site",
            &serde_json::json!({
                "condition":condition,
                "kind":"call",
                "path":path,
                "profile_id":profile_id,
                "source":source,
                "span":span,
            }),
        );
        events[site_index]["site"]["id"] = serde_json::json!(site_id);

        let edge = events
            .iter_mut()
            .find(|event| {
                event["event"] == "edge_upsert"
                    && matches!(event["edge"]["kind"].as_str(), Some("calls" | "may_call"))
            })
            .expect("call edge");
        let edge_kind = edge["edge"]["kind"]
            .as_str()
            .expect("call edge kind")
            .to_owned();
        edge["edge"]["source"] = serde_json::json!(source);
        edge["edge"]["target"] = serde_json::json!(target);
        edge["edge"]["site_id"] = serde_json::json!(site_id);
        edge["edge"]["id"] = serde_json::json!(depgraph_protocol::stable_id_from_value(
            "edge",
            &serde_json::json!({
                "kind":edge_kind,
                "site_id":site_id,
                "target":target,
            }),
        ));
    }

    fn configure_typescript_candidate_call(events: &mut Vec<Value>, emission: &str) {
        let profile = events
            .iter_mut()
            .find(|event| event["event"] == "profile_declared")
            .expect("Web profile declaration");
        profile["profile"]["properties"][TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY] =
            serde_json::json!(emission);

        let package = events
            .iter()
            .find(|event| {
                event["event"] == "node_upsert" && event["node"]["kind"] == "package_instance"
            })
            .expect("package node");
        let package_id = package["node"]["id"]
            .as_str()
            .expect("package ID")
            .to_owned();
        let package_locator = package["node"]["properties"]["locator"]
            .as_str()
            .expect("package locator")
            .to_owned();
        let source_file_id = events
            .iter()
            .find(|event| event["node"]["properties"]["path"] == "src/index.ts")
            .expect("source file")["node"]["id"]
            .as_str()
            .expect("source file ID")
            .to_owned();
        let candidate_span = serde_json::json!({
            "start_line": 1,
            "start_column": 10,
            "end_line": 1,
            "end_column": 25,
        });
        let candidate_resolver = format!("{package_locator}::module:src/index.ts#candidateTarget");
        let candidate_identity = serde_json::json!({
            "language": "typescript",
            "package_locator": package_locator,
            "symbol_kind": "function",
            "identity_kind": "named",
            "resolver_identity": candidate_resolver,
        });
        let candidate_target_id =
            depgraph_protocol::stable_id_from_value("symbol", &candidate_identity);
        let candidate_node = serde_json::json!({
            "protocol_version": "1.0",
            "scan_id": "typescript-gate-scan",
            "adapter": "web",
            "adapter_version": env!("CARGO_PKG_VERSION"),
            "event": "node_upsert",
            "node": {
                "id": candidate_target_id,
                "kind": "symbol",
                "locator": format!("typescript-symbol:{candidate_target_id}"),
                "display_name": "candidateTarget",
                "properties": {
                    "language": "typescript",
                    "package_locator": package_locator,
                    "package_id": package_id,
                    "symbol_kind": "function",
                    "canonical_identity": candidate_identity,
                    "resolver_identity": candidate_resolver,
                    "profile_id": "web:default",
                    "source_path": "src/index.ts",
                    "source_span": candidate_span,
                },
            },
        });
        let candidate_declaration_evidence = serde_json::json!({
            "kind": "semantic",
            "extractor": TYPESCRIPT_SEMANTIC_EXTRACTOR,
            "extractor_version": TYPESCRIPT_COMPILER_VERSION,
            "path": "src/index.ts",
            "start_line": 1,
            "start_column": 10,
            "end_line": 1,
            "end_column": 25,
            "detail": "TypeChecker candidate function declaration",
            "properties": {"profile_id": "web:default"},
        });
        let candidate_declaration_id = depgraph_protocol::stable_id_from_value(
            "edge",
            &serde_json::json!({
                "condition": {"op":"all","conditions":[]},
                "kind": "declares",
                "path": "src/index.ts",
                "profile_id": "web:default",
                "source": source_file_id,
                "span": candidate_span,
                "target": candidate_target_id,
            }),
        );
        let candidate_declaration = serde_json::json!({
            "protocol_version": "1.0",
            "scan_id": "typescript-gate-scan",
            "adapter": "web",
            "adapter_version": env!("CARGO_PKG_VERSION"),
            "event": "edge_upsert",
            "edge": {
                "id": candidate_declaration_id,
                "source": source_file_id,
                "target": candidate_target_id,
                "kind": "declares",
                "phase": "semantic",
                "environment": "any",
                "profile_id": "web:default",
                "condition": {"op":"all","conditions":[]},
                "resolution_status": "resolved",
                "precision": "exact",
                "generated": false,
                "evidence": [candidate_declaration_evidence],
            },
        });
        let call_site_index = events
            .iter()
            .position(|event| {
                event["event"] == "dependency_site" && event["site"]["kind"] == "call"
            })
            .expect("call site");
        events.insert(call_site_index, candidate_node);
        events.insert(call_site_index + 1, candidate_declaration);

        let call_site_index = events
            .iter()
            .position(|event| {
                event["event"] == "dependency_site" && event["site"]["kind"] == "call"
            })
            .expect("call site");
        let existing_target_id = events[call_site_index]["site"]["target_ids"][0]
            .as_str()
            .expect("existing candidate target")
            .to_owned();
        let mut target_ids = vec![existing_target_id, candidate_target_id];
        target_ids.sort();
        events[call_site_index]["site"]["target_ids"] = serde_json::json!(target_ids);
        events[call_site_index]["site"]["resolution_status"] = serde_json::json!("candidates");
        events[call_site_index]["site"]["precision"] = serde_json::json!("overapprox");
        let call_site_id = events[call_site_index]["site"]["id"]
            .as_str()
            .expect("call site ID")
            .to_owned();
        mutate_semantic_primary_properties(events, "call", |properties| {
            properties["dispatch"] = serde_json::json!("dynamic");
            properties["algorithm"] =
                serde_json::json!(TYPESCRIPT_CLOSED_LOCAL_CALL_FLOW_ALGORITHM);
        });
        let call_edge_index = events
            .iter()
            .position(|event| {
                event["event"] == "edge_upsert"
                    && event["edge"]["site_id"] == call_site_id
                    && event["edge"]["kind"] == "calls"
            })
            .expect("calls edge");
        events[call_edge_index]["edge"]["kind"] = serde_json::json!("may_call");
        events[call_edge_index]["edge"]["resolution_status"] = serde_json::json!("candidates");
        events[call_edge_index]["edge"]["precision"] = serde_json::json!("overapprox");
        recanonicalize_typescript_call(events);

        let call_edge_index = events
            .iter()
            .position(|event| {
                event["event"] == "edge_upsert"
                    && event["edge"]["site_id"] == call_site_id
                    && event["edge"]["kind"] == "may_call"
            })
            .expect("first may_call edge");
        let mut additional_edge = events[call_edge_index].clone();
        let second_target_id = events[call_site_index]["site"]["target_ids"][1]
            .as_str()
            .expect("second candidate target")
            .to_owned();
        additional_edge["edge"]["target"] = serde_json::json!(second_target_id);
        additional_edge["edge"]["id"] = serde_json::json!(depgraph_protocol::stable_id_from_value(
            "edge",
            &serde_json::json!({
                "kind": "may_call",
                "site_id": call_site_id,
                "target": second_target_id,
            }),
        ));
        events.insert(call_edge_index + 1, additional_edge);

        for event in events.iter_mut() {
            if matches!(
                event["event"].as_str(),
                Some("profile_completed" | "scan_completed")
            ) {
                event["coverage"]["dependency_sites"] = serde_json::json!(1);
                event["coverage"]["resolved"] = serde_json::json!(0);
                event["coverage"]["candidates"] = serde_json::json!(1);
                event["coverage"]["external"] = serde_json::json!(0);
                event["coverage"]["unresolved"] = serde_json::json!(0);
            }
        }
        sync_test_semantic_counts(events);
        resequence_test_protocol(events);
    }

    fn test_protocol_values(output: Vec<u8>) -> Result<Vec<Value>> {
        Ok(String::from_utf8(output)?
            .lines()
            .map(serde_json::from_str)
            .collect::<std::result::Result<_, _>>()?)
    }

    fn serialize_test_protocol(events: Vec<Value>) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        for event in events {
            serde_json::to_writer(&mut output, &event)?;
            output.push(b'\n');
        }
        Ok(output)
    }

    fn mutate_semantic_primary_properties(
        events: &mut [Value],
        site_kind: &str,
        mut mutation: impl FnMut(&mut Value),
    ) {
        let site_id = events
            .iter()
            .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == site_kind)
            .unwrap_or_else(|| panic!("missing {site_kind} site"))["site"]["id"]
            .as_str()
            .expect("semantic site ID")
            .to_owned();
        for event in events {
            if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
                mutation(&mut event["site"]["evidence"][0]["properties"]);
            } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
                mutation(&mut event["edge"]["evidence"][0]["properties"]);
            }
        }
    }

    fn rehash_test_definition_edge(edge: &mut Value) {
        let evidence = edge["evidence"][0].clone();
        let identity = serde_json::json!({
            "condition": edge["condition"].clone(),
            "kind": edge["kind"].clone(),
            "path": evidence["path"].clone(),
            "profile_id": edge["profile_id"].clone(),
            "source": edge["source"].clone(),
            "span": {
                "end_column": evidence["end_column"].clone(),
                "end_line": evidence["end_line"].clone(),
                "start_column": evidence["start_column"].clone(),
                "start_line": evidence["start_line"].clone(),
            },
            "target": edge["target"].clone(),
        });
        edge["id"] = serde_json::json!(depgraph_protocol::stable_id_from_value("edge", &identity));
    }

    fn refresh_test_semantic_node_id(events: &mut [Value], node_index: usize) -> String {
        let (old_id, new_id) = {
            let node = &mut events[node_index]["node"];
            let old_id = node["id"].as_str().expect("semantic node ID").to_owned();
            let kind = node["kind"]
                .as_str()
                .expect("semantic node kind")
                .to_owned();
            let language = node["properties"]["language"]
                .as_str()
                .expect("semantic node language")
                .to_owned();
            let new_id = depgraph_protocol::stable_id_from_value(
                &kind,
                &node["properties"]["canonical_identity"],
            );
            node["id"] = serde_json::json!(new_id);
            node["locator"] = serde_json::json!(format!("{language}-{kind}:{new_id}"));
            (old_id, new_id)
        };
        for event in events {
            if event["event"] != "edge_upsert" {
                continue;
            }
            let edge = &mut event["edge"];
            let mut changed = false;
            for endpoint in ["source", "target"] {
                if edge[endpoint].as_str() == Some(old_id.as_str()) {
                    edge[endpoint] = serde_json::json!(new_id);
                    changed = true;
                }
            }
            if changed {
                rehash_test_definition_edge(edge);
            }
        }
        new_id
    }

    fn rewrite_test_generic_instance(
        events: &mut [Value],
        type_arguments: Value,
        resolver_override: Option<String>,
    ) -> String {
        let node_index = events
            .iter()
            .position(|event| event["node"]["properties"]["type_kind"] == "generic_instance")
            .expect("generic instance node");
        let node = &mut events[node_index]["node"];
        let generic_origin = node["properties"]["canonical_identity"]["generic_origin"]
            .as_str()
            .expect("generic origin resolver")
            .to_owned();
        let resolver = resolver_override.unwrap_or_else(|| {
            format!(
                "generic:{}",
                serde_json::to_string(&serde_json::json!([generic_origin, type_arguments.clone()]))
                    .expect("test generic resolver input serializes")
            )
        });
        node["properties"]["canonical_identity"]["type_arguments"] = type_arguments.clone();
        node["properties"]["canonical_identity"]["resolver_identity"] = serde_json::json!(resolver);
        node["properties"]["type_arguments"] = type_arguments;
        node["properties"]["resolver_identity"] = serde_json::json!(resolver);
        refresh_test_semantic_node_id(events, node_index)
    }

    fn resequence_test_protocol(events: &mut [Value]) {
        for (index, event) in events.iter_mut().enumerate() {
            event["seq"] = serde_json::json!(index + 1);
        }
    }

    fn sync_test_semantic_counts(events: &mut [Value]) {
        let node_count = events
            .iter()
            .filter(|event| matches!(event["node"]["kind"].as_str(), Some("symbol" | "type")))
            .count();
        let relation_count = events
            .iter()
            .filter(|event| event["event"] == "edge_upsert" && event["edge"]["phase"] == "semantic")
            .count();
        let profile = events
            .iter_mut()
            .find(|event| event["event"] == "profile_declared")
            .expect("Web profile declaration");
        profile["profile"]["properties"]["typescript_semantic_node_count"] =
            serde_json::json!(node_count.to_string());
        profile["profile"]["properties"]["typescript_semantic_relation_count"] =
            serde_json::json!(relation_count.to_string());
    }

    fn profile_protocol(
        root: &Path,
        scan_id: &str,
        adapter: &str,
        properties: Value,
    ) -> Result<Vec<u8>> {
        let coverage = serde_json::json!({
            "profiles": 1,
            "files_discovered": 0,
            "files_analyzed": 0,
            "files_skipped": 0,
            "dependency_sites": 0,
            "resolved": 0,
            "candidates": 0,
            "external": 0,
            "unresolved": 0,
            "unsupported_syntax": 0,
            "project_code_executed": false,
            "completeness": ["syntax-complete"],
            "reasons": [],
        });
        let profile_id = format!("{adapter}:default");
        let events = [
            serde_json::json!({
                "event": "scan_started",
                "protocol_version": "1.0",
                "scan_id": scan_id,
                "adapter": adapter,
                "adapter_version": env!("CARGO_PKG_VERSION"),
                "seq": 1,
                "root": root.to_string_lossy(),
                "project_code_executed": false,
                "safe_mode": true,
            }),
            serde_json::json!({
                "event": "profile_declared",
                "protocol_version": "1.0",
                "scan_id": scan_id,
                "adapter": adapter,
                "adapter_version": env!("CARGO_PKG_VERSION"),
                "seq": 2,
                "profile": {
                    "id": profile_id,
                    "language": adapter,
                    "properties": properties,
                },
            }),
            serde_json::json!({
                "event": "profile_completed",
                "protocol_version": "1.0",
                "scan_id": scan_id,
                "adapter": adapter,
                "adapter_version": env!("CARGO_PKG_VERSION"),
                "seq": 3,
                "profile_id": profile_id,
                "coverage": coverage,
            }),
            serde_json::json!({
                "event": "scan_completed",
                "protocol_version": "1.0",
                "scan_id": scan_id,
                "adapter": adapter,
                "adapter_version": env!("CARGO_PKG_VERSION"),
                "seq": 4,
                "coverage": coverage,
            }),
        ];
        let mut output = Vec::new();
        for event in events {
            serde_json::to_writer(&mut output, &event)?;
            output.push(b'\n');
        }
        Ok(output)
    }

    #[test]
    fn normalizes_windows_verbatim_paths_for_external_runtimes() {
        let wide = |value: &str| value.encode_utf16().collect::<Vec<_>>();
        let text = |value: Vec<u16>| String::from_utf16(&value).unwrap();

        assert_eq!(
            text(without_windows_verbatim_prefix(&wide(
                r"\\?\C:\release\libexec\worker.mjs"
            ))),
            r"C:\release\libexec\worker.mjs"
        );
        assert_eq!(
            text(without_windows_verbatim_prefix(&wide(
                r"\\?\UNC\server\share\worker.mjs"
            ))),
            r"\\server\share\worker.mjs"
        );
        assert_eq!(
            text(without_windows_verbatim_prefix(&wide(
                r"C:\release\libexec\worker.mjs"
            ))),
            r"C:\release\libexec\worker.mjs"
        );
    }

    #[test]
    fn detects_workspace_markers_without_build_directories() -> Result<()> {
        let temp = tempfile::tempdir()?;
        std::fs::write(temp.path().join("Cargo.toml"), "[workspace]")?;
        std::fs::create_dir(temp.path().join("node_modules"))?;
        std::fs::write(temp.path().join("node_modules/package.json"), "{}")?;
        assert_eq!(
            detect_adapters(temp.path(), false)?,
            vec![AdapterKind::Rust]
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn detects_symlinked_workspace_markers_for_worker_confinement_reporting() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        std::fs::write(
            outside.path().join("go.mod"),
            "module outside.example/test\n",
        )?;
        symlink(outside.path().join("go.mod"), temp.path().join("go.mod"))?;

        assert_eq!(
            detect_adapters(temp.path(), false)?,
            vec![AdapterKind::Go],
            "the adapter must run so its ledger can report the confined skip"
        );
        Ok(())
    }

    #[test]
    fn rejects_unknown_and_out_of_order_events() {
        let root = Path::new("/tmp/project");
        let output = br#"{"event":"scan_started","protocol_version":"1.0","scan_id":"s","adapter":"web","adapter_version":"0.1.0","seq":1}
{"event":"mystery","protocol_version":"1.0","scan_id":"s","adapter":"web","adapter_version":"0.1.0","seq":2}
"#;
        assert!(parse_and_validate_events(output, "s", "web", root, 1024).is_err());
    }

    #[test]
    fn recognizes_security_failures_for_exit_code_mapping() {
        assert!(is_security_error(
            "safe-mode scan reports project_code_executed=true"
        ));
        assert!(is_security_error(
            "protocol path ../secret escapes scan root /project"
        ));
        assert!(!is_security_error("worker timed out"));
        assert!(!is_security_error(
            "failed to start /tmp/security policy/checksum mismatch/worker"
        ));
    }

    #[test]
    fn protocol_values_cannot_spoof_security_classification() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let output = format!(
            "{{\"event\":\"scan_started\",\"protocol_version\":\"1.0\",\"scan_id\":\"s\",\"adapter\":\"security policy\",\"adapter_version\":\"0.1.0\",\"seq\":1,\"root\":{},\"project_code_executed\":false,\"safe_mode\":true}}\n",
            serde_json::to_string(&root.to_string_lossy())?
        );
        let parsed =
            parse_events_preserving_prefix(output.as_bytes(), "s", "go", &root, 4096, None, None);
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(!parsed.security_violation);
        Ok(())
    }

    #[test]
    fn retains_a_valid_prefix_before_malformed_output() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let output = format!(
            "{{\"event\":\"scan_started\",\"protocol_version\":\"1.0\",\"scan_id\":\"s\",\"adapter\":\"go\",\"adapter_version\":\"0.1.0\",\"seq\":1,\"root\":{},\"project_code_executed\":false,\"safe_mode\":true}}\n{{\"event\":\"node_upsert\",\"protocol_version\":\"1.0\",\"scan_id\":\"s\",\"adapter\":\"go\",\"adapter_version\":\"0.1.0\",\"seq\":2,\"node\":{{\"id\":\"file:one\",\"kind\":\"file\",\"locator\":\"file://one\",\"properties\":{{}}}}}}\nnot-json\n",
            serde_json::to_string(&root.to_string_lossy())?
        );
        let parsed =
            parse_events_preserving_prefix(output.as_bytes(), "s", "go", &root, 4096, None, None);
        assert_eq!(parsed.events.len(), 2);
        assert!(parsed.error.unwrap().contains("malformed NDJSON"));
        assert!(parse_and_validate_events(output.as_bytes(), "s", "go", &root, 4096).is_err());
        Ok(())
    }

    #[test]
    fn normal_scan_rejects_an_unsafe_worker_declaration() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let output = format!(
            "{{\"event\":\"scan_started\",\"protocol_version\":\"1.0\",\"scan_id\":\"s\",\"adapter\":\"go\",\"adapter_version\":\"0.1.0\",\"seq\":1,\"root\":{},\"project_code_executed\":true,\"safe_mode\":false}}\n",
            serde_json::to_string(&root.to_string_lossy())?
        );
        let parsed =
            parse_events_preserving_prefix(output.as_bytes(), "s", "go", &root, 4096, None, None);
        let error = parsed.error.unwrap();
        assert!(error.contains("security policy"));
        assert!(is_security_error(&error));
        assert!(parsed.events.is_empty());
        Ok(())
    }

    #[test]
    fn bundled_workers_are_confined_and_checksum_verified() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let release = temp.path().join("release");
        let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
        let spec = locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest)?;
        assert_eq!(spec.artifact_path, test_release.go_worker.canonicalize()?);

        std::fs::write(&test_release.go_worker, b"tampered")?;
        assert!(
            locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest)
                .unwrap_err()
                .to_string()
                .contains("checksum mismatch")
        );
        Ok(())
    }

    #[test]
    fn bundled_workers_require_the_exact_bounded_query_contract_fixture() -> Result<()> {
        let temp = tempfile::tempdir()?;
        for mutation in ["path", "version", "missing", "tampered"] {
            let release = temp.path().join(mutation);
            let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
            match mutation {
                "path" => update_test_manifest(&test_release.manifest, |manifest| {
                    manifest["query_fixture"]["path"] =
                        Value::String("queries/other.query".to_owned());
                    Ok(())
                })?,
                "version" => update_test_manifest(&test_release.manifest, |manifest| {
                    manifest["compatibility"]["bounded_query"]["result_schema_version"] =
                        Value::String("bounded-query-result-v2".to_owned());
                    Ok(())
                })?,
                "missing" => {
                    std::fs::remove_file(release.join(BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH))?
                }
                "tampered" => std::fs::write(
                    release.join(BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH),
                    b"tampered query",
                )?,
                _ => unreachable!(),
            }
            let error = locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest)
                .unwrap_err();
            assert!(
                error.to_string().contains("bounded query")
                    || error.to_string().contains("compatibility")
                    || error.to_string().contains("checksum mismatch")
                    || error.to_string().contains("failed to canonicalize"),
                "{mutation}: {error:#}"
            );
        }
        Ok(())
    }

    #[test]
    fn bundled_workers_require_exact_project_license_metadata_and_files() -> Result<()> {
        let temp = tempfile::tempdir()?;
        for mutation in ["expression", "declaration", "missing", "tampered"] {
            let release = temp.path().join(mutation);
            let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
            match mutation {
                "expression" => update_test_manifest(&test_release.manifest, |manifest| {
                    manifest["license_expression"] = Value::String("MIT".to_owned());
                    Ok(())
                })?,
                "declaration" => update_test_manifest(&test_release.manifest, |manifest| {
                    manifest["project_licenses"]
                        .as_array_mut()
                        .context("test manifest has no project licenses")?
                        .pop();
                    Ok(())
                })?,
                "missing" => std::fs::remove_file(release.join("LICENSE-MIT"))?,
                "tampered" => std::fs::write(release.join("LICENSE-APACHE"), b"tampered")?,
                _ => unreachable!(),
            }

            let error = locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest)
                .unwrap_err();
            assert!(
                error.to_string().contains("project license")
                    || error.to_string().contains("checksum mismatch"),
                "{mutation}: {error:#}"
            );
            assert!(is_security_error(&error.to_string()));
        }
        Ok(())
    }

    #[test]
    fn packaged_layout_without_manifest_is_detected() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let bin = temp.path().join("bin");
        std::fs::create_dir_all(&bin)?;
        std::fs::create_dir_all(temp.path().join("libexec"))?;
        assert!(looks_like_packaged_layout(&bin));
        assert!(!looks_like_packaged_layout(temp.path()));
        Ok(())
    }

    #[test]
    fn parses_runtime_versions_strictly() {
        assert_eq!(parse_version_triplet("24.18.0"), Some((24, 18, 0)));
        assert_eq!(parse_version_triplet("24.18.0-rc.1"), Some((24, 18, 0)));
        assert_eq!(parse_version_triplet("24.18"), None);
        assert_eq!(parse_version_triplet("latest"), None);
    }

    #[test]
    fn safe_path_drops_relative_repository_and_symlinked_repository_entries() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("project");
        let safe = temp.path().join("safe-bin");
        std::fs::create_dir(&root)?;
        std::fs::create_dir(&safe)?;
        let entries = vec![PathBuf::from("."), root.clone(), safe.clone()];
        #[cfg(unix)]
        let entries = {
            let mut entries = entries;
            let alias = temp.path().join("project-alias");
            std::os::unix::fs::symlink(&root, &alias)?;
            entries.push(alias);
            entries
        };
        let raw = std::env::join_paths(entries)?;
        let sanitized = sanitize_path_value(&raw, &root)?;
        let paths = std::env::split_paths(&sanitized).collect::<Vec<_>>();
        assert_eq!(paths, vec![safe.canonicalize()?]);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unverified_development_worker_inside_scan_root_is_rejected() -> Result<()> {
        let root = tempfile::tempdir()?;
        let worker = root.path().join("depgraph-go-worker");
        std::fs::write(&worker, "#!/bin/sh\nexit 0\n")?;
        let spec = WorkerSpec {
            adapter: AdapterKind::Go,
            program: worker.clone().into_os_string(),
            leading_args: Vec::new(),
            display: worker.display().to_string(),
            artifact_path: worker,
            runtime_requirement: None,
            expected_version: None,
            release_attested: false,
            attested_rust_sysroot: None,
        };

        let error = resolve_worker_program(&spec, root.path()).unwrap_err();
        assert!(error.to_string().contains("security policy"));
        Ok(())
    }

    #[test]
    fn packaged_web_worker_requires_the_astro_runtime_component() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let release = temp.path().join("release");
        let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
        update_test_manifest(&test_release.manifest, |manifest| {
            manifest["runtime_components"]
                .as_array_mut()
                .context("test manifest has no runtime components")?
                .retain(|component| component["name"] != "astro-parser-wasm");
            Ok(())
        })?;
        let error =
            locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
        assert!(error.to_string().contains("astro-parser-wasm"));
        assert!(is_security_error(&error.to_string()));
        Ok(())
    }

    #[test]
    fn packaged_web_worker_requires_the_typescript_runtime_component() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let release = temp.path().join("release");
        let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
        update_test_manifest(&test_release.manifest, |manifest| {
            manifest["runtime_components"]
                .as_array_mut()
                .context("test manifest has no runtime components")?
                .retain(|component| component["name"] != "typescript-native-compiler");
            Ok(())
        })?;
        let error =
            locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
        assert!(error.to_string().contains("typescript-native-compiler"));
        assert!(is_security_error(&error.to_string()));
        Ok(())
    }

    #[test]
    fn packaged_release_requires_the_pinned_rust_sysroot_source_component() -> Result<()> {
        for mutation in ["missing", "version", "root", "entrypoint", "license"] {
            let temp = tempfile::tempdir()?;
            let release = temp.path().join(mutation);
            let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
            update_test_manifest(&test_release.manifest, |manifest| {
                let components = manifest["runtime_components"]
                    .as_array_mut()
                    .context("test manifest has no runtime components")?;
                if mutation == "missing" {
                    components.retain(|component| component["name"] != RUST_SYSROOT_COMPONENT_NAME);
                    return Ok(());
                }
                let replacement_sha256 = (mutation == "root")
                    .then(|| {
                        components
                            .iter()
                            .find(|component| component["name"] == "astro-parser-wasm")
                            .map(|component| component["sha256"].clone())
                    })
                    .flatten();
                let component = components
                    .iter_mut()
                    .find(|component| component["name"] == RUST_SYSROOT_COMPONENT_NAME)
                    .context("test manifest has no Rust sysroot component")?;
                component[mutation] = serde_json::json!(match mutation {
                    "version" => "0.0.0+wrong-rustc",
                    "root" => "libexec/astro",
                    "entrypoint" => "libexec/rust-sysroot/library/core/src/lib.rs",
                    "license" => "NOASSERTION",
                    _ => unreachable!(),
                });
                if let Some(sha256) = replacement_sha256 {
                    component["sha256"] = sha256;
                }
                Ok(())
            })?;

            let error = locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest)
                .unwrap_err();
            assert!(
                error.to_string().contains("Rust sysroot"),
                "{mutation}: {error:#}"
            );
            assert!(is_security_error(&error.to_string()));
        }
        Ok(())
    }

    #[test]
    fn packaged_release_requires_the_runtime_collector_artifact() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let release = temp.path().join("release");
        let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
        update_test_manifest(&test_release.manifest, |manifest| {
            manifest["runtime_artifacts"]
                .as_array_mut()
                .context("test manifest has no runtime artifacts")?
                .retain(|artifact| artifact["path"] != "libexec/depgraph-runtime-collector.mjs");
            Ok(())
        })?;
        let error =
            locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
        assert!(error.to_string().contains("artifact closure"));
        assert!(is_security_error(&error.to_string()));
        Ok(())
    }

    #[test]
    fn packaged_web_worker_requires_the_exact_semantic_attestation() -> Result<()> {
        let temp = tempfile::tempdir()?;
        for mutation in [
            "missing",
            "capability",
            "component",
            "artifact",
            "typescript",
        ] {
            let release = temp.path().join(mutation);
            let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
            update_test_manifest(&test_release.manifest, |manifest| {
                let web = manifest["workers"]
                    .as_array_mut()
                    .context("test manifest has no workers array")?
                    .iter_mut()
                    .find(|worker| worker["adapter"] == "web")
                    .context("test manifest has no Web worker")?;
                match mutation {
                    "missing" => {
                        web.as_object_mut()
                            .context("Web worker is not an object")?
                            .remove("semantic");
                    }
                    "capability" => {
                        web["semantic"]["capabilities"][0] =
                            serde_json::json!("unknown-capability-v1")
                    }
                    "component" => {
                        web["semantic"]["runtime_components"][0] =
                            serde_json::json!("system-typescript")
                    }
                    "artifact" => {
                        web["semantic"]["runtime_artifacts"] =
                            serde_json::json!(["system-astro.wasm"])
                    }
                    "typescript" => {
                        web["semantic"]["typescript_version"] = serde_json::json!("9.9.9")
                    }
                    _ => unreachable!(),
                }
                Ok(())
            })?;

            let error = locate_verified_bundled_worker(AdapterKind::Web, &test_release.manifest)
                .unwrap_err();
            assert!(
                error.to_string().contains("semantic"),
                "{mutation}: {error:#}"
            );
            assert!(is_security_error(&error.to_string()));
        }
        Ok(())
    }

    #[test]
    fn rust_preflight_requires_the_web_runtime_requirement() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let release = temp.path().join("release");
        let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
        update_test_manifest(&test_release.manifest, |manifest| {
            manifest["runtime_requirements"]
                .as_object_mut()
                .context("test manifest has no runtime requirement object")?
                .remove("web");
            Ok(())
        })?;

        let error =
            locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
        assert!(error.to_string().contains("Web runtime requirement"));
        assert!(is_security_error(&error.to_string()));
        Ok(())
    }

    #[test]
    fn packaged_web_runtime_requirement_must_match_the_compatibility_unit() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let release = temp.path().join("release");
        let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
        update_test_manifest(&test_release.manifest, |manifest| {
            manifest["runtime_requirements"]["web"] = Value::String("Node.js >=23.0.0".to_owned());
            Ok(())
        })?;

        let error =
            locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
        assert!(error.to_string().contains(WEB_RUNTIME_REQUIREMENT));
        assert!(is_security_error(&error.to_string()));
        Ok(())
    }

    #[test]
    fn every_packaged_worker_version_must_match_the_core() -> Result<()> {
        let temp = tempfile::tempdir()?;
        for adapter in ["go", "web"] {
            let release = temp.path().join(adapter);
            let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
            update_test_manifest(&test_release.manifest, |manifest| {
                let worker = manifest["workers"]
                    .as_array_mut()
                    .context("test manifest has no workers array")?
                    .iter_mut()
                    .find(|worker| worker["adapter"] == adapter)
                    .with_context(|| format!("test manifest has no {adapter} worker"))?;
                worker["version"] = Value::String("9.9.9".to_owned());
                Ok(())
            })?;

            let error = locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest)
                .unwrap_err();
            assert!(error.to_string().contains("does not match core version"));
            assert!(is_security_error(&error.to_string()));
        }
        Ok(())
    }

    #[test]
    fn every_packaged_worker_path_must_match_its_adapter_identity() -> Result<()> {
        let temp = tempfile::tempdir()?;
        for (adapter, invalid_path) in [
            (
                "rust",
                format!("libexec/{}", executable_name("depgraph-go-worker")),
            ),
            (
                "go",
                format!("libexec/{}", executable_name("depgraph-rust-worker")),
            ),
            ("web", "libexec/astro/astro.wasm".to_owned()),
        ] {
            let release = temp.path().join(adapter);
            let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
            update_test_manifest(&test_release.manifest, |manifest| {
                let worker = manifest["workers"]
                    .as_array_mut()
                    .context("test manifest has no workers array")?
                    .iter_mut()
                    .find(|worker| worker["adapter"] == adapter)
                    .with_context(|| format!("test manifest has no {adapter} worker"))?;
                worker["path"] = Value::String(invalid_path);
                Ok(())
            })?;

            let error = locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest)
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("{adapter} worker path"))
            );
            assert!(is_security_error(&error.to_string()));
        }
        Ok(())
    }

    #[test]
    fn packaged_core_and_schema_paths_are_exact() -> Result<()> {
        let temp = tempfile::tempdir()?;
        for (field, invalid_path) in [
            ("core", "bin/not-depgraph"),
            ("schema", "schemas/not-the-protocol-schema.json"),
        ] {
            let release = temp.path().join(field);
            let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
            update_test_manifest(&test_release.manifest, |manifest| {
                manifest[field]["path"] = Value::String(invalid_path.to_owned());
                Ok(())
            })?;

            let error = locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest)
                .unwrap_err();
            assert!(error.to_string().contains(&format!("{field} path")));
            assert!(is_security_error(&error.to_string()));
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn bundled_native_workers_must_be_executable_but_web_is_exempt() -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir()?;
        let release = temp.path().join("release");
        let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;

        // The helper intentionally leaves the Web .mjs artifact non-executable.
        locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest)?;

        for (adapter, worker) in [
            ("rust", &test_release.rust_worker),
            ("go", &test_release.go_worker),
        ] {
            let mut permissions = std::fs::metadata(worker)?.permissions();
            permissions.set_mode(0o644);
            std::fs::set_permissions(worker, permissions)?;

            let error = locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest)
                .unwrap_err();
            assert!(error.to_string().contains(&format!("{adapter} worker")));
            assert!(error.to_string().contains("not executable"));
            assert!(is_security_error(&error.to_string()));

            make_test_executable(worker)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn non_rust_worker_cannot_spoof_the_verified_rust_release_gate() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("root");
        std::fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        let script = temp.path().join("go-worker.sh");
        let scan_id = "cross-adapter-gate-scan";
        let write_protocol_script = |properties: Value| -> Result<()> {
            let output = profile_protocol(&root, scan_id, "go", properties)?;
            let mut contents = b"#!/bin/sh\ncat <<'DEPGRAPH_PROTOCOL'\n".to_vec();
            contents.extend_from_slice(&output);
            contents.extend_from_slice(b"DEPGRAPH_PROTOCOL\n");
            std::fs::write(&script, contents)?;
            make_test_executable(&script)
        };

        let spec = WorkerSpec {
            adapter: AdapterKind::Go,
            program: script.clone().into_os_string(),
            leading_args: Vec::new(),
            display: script.display().to_string(),
            artifact_path: script.clone(),
            runtime_requirement: None,
            expected_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            release_attested: false,
            attested_rust_sysroot: None,
        };

        write_protocol_script(serde_json::json!({
            "rust_hir_enable_gate": RUST_RELEASE_GATE_VERIFIED,
        }))?;
        let spoofed = execute_worker_inner_with_cancellation(
            &spec,
            &root,
            scan_id,
            &ScanConfig::default(),
            &ProfileConfig::default(),
            None,
            std::future::pending::<std::io::Result<()>>(),
        )
        .await?;
        assert_eq!(spoofed.events.len(), 1);
        assert_eq!(
            spoofed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(spoofed.security_violation);
        assert!(
            spoofed
                .error
                .as_deref()
                .is_some_and(|error| error.contains("verified Rust release attestation"))
        );

        write_protocol_script(serde_json::json!({
            TYPESCRIPT_RELEASE_GATE_PROPERTY: TYPESCRIPT_RELEASE_GATE_VERIFIED,
        }))?;
        let typescript_spoofed = execute_worker_inner_with_cancellation(
            &spec,
            &root,
            scan_id,
            &ScanConfig::default(),
            &ProfileConfig::default(),
            None,
            std::future::pending::<std::io::Result<()>>(),
        )
        .await?;
        assert_eq!(typescript_spoofed.events.len(), 1);
        assert_eq!(
            typescript_spoofed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(typescript_spoofed.security_violation);
        assert!(
            typescript_spoofed
                .error
                .as_deref()
                .is_some_and(|error| { error.contains("verified TypeScript release attestation") })
        );

        write_protocol_script(serde_json::json!({"go_list_mode": "safe"}))?;
        let normal = execute_worker_inner_with_cancellation(
            &spec,
            &root,
            scan_id,
            &ScanConfig::default(),
            &ProfileConfig::default(),
            None,
            std::future::pending::<std::io::Result<()>>(),
        )
        .await?;
        assert_eq!(normal.events.len(), 4);
        assert!(normal.error.is_none(), "{:?}", normal.error);
        assert!(!normal.security_violation);
        Ok(())
    }

    #[test]
    fn typescript_runtime_tree_is_confined_and_checksum_verified() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let release = temp.path().join("release");
        let typescript = release.join("libexec/typescript/lib");
        std::fs::create_dir_all(&typescript)?;
        let worker = release.join("libexec/depgraph-web-worker.mjs");
        let compiler = typescript.join(executable_name("tsc"));
        let standard_library = typescript.join("lib.d.ts");
        std::fs::write(&worker, b"verified worker")?;
        std::fs::write(&compiler, b"verified compiler")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut permissions = std::fs::metadata(&compiler)?.permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&compiler, permissions)?;
        }
        std::fs::write(&standard_library, b"verified standard library")?;
        let digest = runtime_tree_digest(&typescript)?;
        let component = serde_json::json!({
            "name":"typescript-native-compiler",
            "version":"7.0.2",
            "kind":"executable-tree",
            "root":"libexec/typescript/lib",
            "entrypoint":format!("libexec/typescript/lib/{}", executable_name("tsc")),
            "license":"Apache-2.0",
            "sha256":digest
        });
        let test_release = write_test_release_manifest(&release, Vec::new(), vec![component])?;
        let web_spec = locate_verified_bundled_worker(AdapterKind::Web, &test_release.manifest)?;
        assert!(web_spec.release_attested);

        #[cfg(unix)]
        {
            let typescript_parent = release.join("libexec/typescript");
            let moved = release.join("libexec/typescript-real");
            std::fs::rename(&typescript_parent, &moved)?;
            std::os::unix::fs::symlink("typescript-real", &typescript_parent)?;
            let symlinked =
                locate_verified_bundled_worker(AdapterKind::Web, &test_release.manifest)
                    .unwrap_err();
            assert!(symlinked.to_string().contains("symlink"));
            assert!(is_security_error(&symlinked.to_string()));
            std::fs::remove_file(&typescript_parent)?;
            std::fs::rename(&moved, &typescript_parent)?;

            use std::os::unix::fs::PermissionsExt as _;
            let mut permissions = std::fs::metadata(&compiler)?.permissions();
            permissions.set_mode(0o644);
            std::fs::set_permissions(&compiler, permissions)?;
            let non_executable =
                locate_verified_bundled_worker(AdapterKind::Web, &test_release.manifest)
                    .unwrap_err();
            assert!(non_executable.to_string().contains("entrypoint"));
            assert!(is_security_error(&non_executable.to_string()));
            let mut permissions = std::fs::metadata(&compiler)?.permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&compiler, permissions)?;
        }

        std::fs::write(&standard_library, b"tampered")?;
        let tampered =
            locate_verified_bundled_worker(AdapterKind::Web, &test_release.manifest).unwrap_err();
        assert!(tampered.to_string().contains("checksum mismatch"));
        assert!(is_security_error(&tampered.to_string()));

        std::fs::write(&standard_library, b"verified standard library")?;
        std::fs::remove_file(&compiler)?;
        let missing =
            locate_verified_bundled_worker(AdapterKind::Web, &test_release.manifest).unwrap_err();
        assert!(missing.to_string().contains("entrypoint"));
        assert!(is_security_error(&missing.to_string()));
        Ok(())
    }

    #[test]
    fn bundled_release_requires_exactly_one_of_each_worker() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let release = temp.path().join("release");
        let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
        update_test_manifest(&test_release.manifest, |manifest| {
            let workers = manifest["workers"]
                .as_array_mut()
                .context("test manifest has no workers array")?;
            workers.retain(|worker| worker["adapter"] != "web");
            Ok(())
        })?;

        let error =
            locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest).unwrap_err();
        assert!(error.to_string().contains("has no web worker"));
        assert!(is_security_error(&error.to_string()));
        Ok(())
    }

    #[test]
    fn bundled_release_requires_the_exact_core_compatibility_contract() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let release = temp.path().join("release");
        let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;

        update_test_manifest(&test_release.manifest, |manifest| {
            manifest["compatibility"]["store_schema_version"] =
                Value::Number((depgraph_store::STORE_SCHEMA_VERSION + 1).into());
            Ok(())
        })?;
        let drifted =
            locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest).unwrap_err();
        assert!(drifted.to_string().contains("compatibility"));
        assert!(is_security_error(&drifted.to_string()));

        update_test_manifest(&test_release.manifest, |manifest| {
            manifest
                .as_object_mut()
                .context("test manifest is not an object")?
                .remove("compatibility");
            Ok(())
        })?;
        let missing =
            locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest).unwrap_err();
        assert!(missing.to_string().contains("invalid release manifest"));
        assert!(is_security_error(&missing.to_string()));
        Ok(())
    }

    #[test]
    fn rust_backend_manifest_mismatch_is_rejected_before_worker_launch() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let release = temp.path().join("release");
        let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
        let spawn_marker = release.join("libexec/rust-worker-spawned");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::write(
                &test_release.rust_worker,
                "#!/bin/sh\n: > \"${0%/*}/rust-worker-spawned\"\nexit 0\n",
            )?;
            let mut permissions = std::fs::metadata(&test_release.rust_worker)?.permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&test_release.rust_worker, permissions)?;
        }
        let rust_digest = hex::encode(Sha256::digest(std::fs::read(&test_release.rust_worker)?));
        update_test_manifest(&test_release.manifest, |manifest| {
            let rust = manifest["workers"]
                .as_array_mut()
                .context("test manifest has no workers array")?
                .iter_mut()
                .find(|worker| worker["adapter"] == "rust")
                .context("test manifest has no Rust worker")?;
            rust["sha256"] = Value::String(rust_digest);
            rust["backend"]["revision"] = Value::String("untrusted-revision".to_owned());
            Ok(())
        })?;

        let error =
            locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
        assert!(error.to_string().contains("backend attestation"));
        assert!(is_security_error(&error.to_string()));
        assert!(
            !spawn_marker.exists(),
            "manifest validation must not launch the worker"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn bundled_release_rejects_symlinked_manifest_root_and_worker() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir()?;

        let manifest_release = temp.path().join("manifest-release");
        let manifest_test = write_test_release_manifest(&manifest_release, Vec::new(), Vec::new())?;
        let real_manifest = manifest_release.join("real-release-manifest.json");
        std::fs::rename(&manifest_test.manifest, &real_manifest)?;
        symlink("real-release-manifest.json", &manifest_test.manifest)?;
        let manifest_error =
            locate_verified_bundled_worker(AdapterKind::Go, &manifest_test.manifest).unwrap_err();
        assert!(manifest_error.to_string().contains("non-symlink"));
        assert!(is_security_error(&manifest_error.to_string()));

        let real_release = temp.path().join("real-release");
        write_test_release_manifest(&real_release, Vec::new(), Vec::new())?;
        let release_alias = temp.path().join("release-alias");
        symlink(&real_release, &release_alias)?;
        let root_error = locate_verified_bundled_worker(
            AdapterKind::Go,
            &release_alias.join("release-manifest.json"),
        )
        .unwrap_err();
        assert!(root_error.to_string().contains("release root"));
        assert!(is_security_error(&root_error.to_string()));

        let worker_release = temp.path().join("worker-release");
        let worker_test = write_test_release_manifest(&worker_release, Vec::new(), Vec::new())?;
        let real_worker = worker_release.join("libexec/real-go-worker");
        std::fs::rename(&worker_test.go_worker, &real_worker)?;
        symlink(&real_worker, &worker_test.go_worker)?;
        let worker_error =
            locate_verified_bundled_worker(AdapterKind::Go, &worker_test.manifest).unwrap_err();
        assert!(worker_error.to_string().contains("symlink"));
        assert!(is_security_error(&worker_error.to_string()));
        Ok(())
    }

    #[test]
    fn data_tree_runtime_component_allows_no_entrypoint_and_verifies_the_whole_tree() -> Result<()>
    {
        let temp = tempfile::tempdir()?;
        let release = temp.path().join("release");
        let sysroot = release.join("libexec/rust-release-data");
        let core_source = sysroot.join("library/core/src/lib.rs");
        std::fs::create_dir_all(core_source.parent().context("core source has no parent")?)?;
        std::fs::write(&core_source, b"verified sysroot source")?;
        let component = serde_json::json!({
            "name": "rust-release-data-test",
            "version": RUST_BACKEND_REVISION,
            "kind": "data-tree",
            "root": "libexec/rust-release-data",
            "license": PROJECT_LICENSE_EXPRESSION,
            "sha256": runtime_tree_digest(&sysroot)?,
        });
        let test_release = write_test_release_manifest(&release, Vec::new(), vec![component])?;
        let spec = locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest)?;
        assert!(spec.release_attested);
        assert_eq!(spec.artifact_path, test_release.rust_worker.canonicalize()?);

        std::fs::write(&core_source, b"tampered sysroot source")?;
        let tampered =
            locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
        assert!(tampered.to_string().contains("checksum mismatch"));
        assert!(is_security_error(&tampered.to_string()));
        std::fs::write(&core_source, b"verified sysroot source")?;

        let added_directory = sysroot.join("library/undeclared-empty-directory");
        std::fs::create_dir(&added_directory)?;
        let added_directory_error =
            locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
        assert!(
            added_directory_error
                .to_string()
                .contains("checksum mismatch")
        );
        assert!(is_security_error(&added_directory_error.to_string()));
        std::fs::remove_dir(added_directory)?;

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("library/core/src/lib.rs", sysroot.join("core-link.rs"))?;
            let symlinked =
                locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest)
                    .unwrap_err();
            assert!(symlinked.to_string().contains("symlink"));
            assert!(is_security_error(&symlinked.to_string()));
        }
        Ok(())
    }

    #[test]
    fn runtime_component_requires_non_empty_identity_and_paths() -> Result<()> {
        for (field, value, expected) in [
            ("name", " \t", "name, version, and license"),
            ("version", "\n", "name, version, and license"),
            ("license", "\r", "name, version, and license"),
            ("root", " ", "root must be non-empty"),
            ("entrypoint", "\t", "entrypoint must be non-empty"),
        ] {
            let temp = tempfile::tempdir()?;
            let release = temp.path().join(field);
            let runtime = release.join("libexec/runtime-data");
            std::fs::create_dir_all(&runtime)?;
            std::fs::write(runtime.join("payload"), b"verified runtime data")?;
            let mut component = serde_json::json!({
                "name": "runtime-data",
                "version": "1.0.0",
                "kind": "data-tree",
                "root": "libexec/runtime-data",
                "license": PROJECT_LICENSE_EXPRESSION,
                "sha256": runtime_tree_digest(&runtime)?,
            });
            component[field] = serde_json::json!(value);
            let test_release = write_test_release_manifest(&release, Vec::new(), vec![component])?;

            let error = locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest)
                .unwrap_err();
            assert!(error.to_string().contains(expected));
            assert!(is_security_error(&error.to_string()));
        }
        Ok(())
    }

    #[test]
    fn executable_tree_runtime_component_requires_an_entrypoint() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let release = temp.path().join("release");
        let runtime = release.join("libexec/toolchain");
        std::fs::create_dir_all(&runtime)?;
        std::fs::write(runtime.join("tool"), b"verified tool")?;
        let component = serde_json::json!({
            "name": "test-toolchain",
            "version": "1.0.0",
            "kind": "executable-tree",
            "root": "libexec/toolchain",
            "license": PROJECT_LICENSE_EXPRESSION,
            "sha256": runtime_tree_digest(&runtime)?,
        });
        let test_release = write_test_release_manifest(&release, Vec::new(), vec![component])?;

        let error =
            locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest).unwrap_err();
        assert!(error.to_string().contains("has no entrypoint"));
        assert!(is_security_error(&error.to_string()));
        Ok(())
    }

    #[test]
    fn development_rust_worker_cannot_spoof_the_verified_release_gate() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let output = rust_gate_protocol(&root, RUST_RELEASE_GATE_VERIFIED)?;
        let parsed = parse_events_preserving_prefix(
            &output,
            "rust-gate-scan",
            "rust",
            &root,
            4096,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );

        assert_eq!(parsed.events.len(), 1);
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation);
        assert!(
            parsed
                .error
                .as_deref()
                .is_some_and(|error| error.contains("without a verified Rust release attestation"))
        );
        Ok(())
    }

    #[test]
    fn attested_rust_worker_must_report_the_verified_success_gate() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let output = rust_gate_protocol(&root, RUST_RELEASE_GATE_PENDING)?;
        let parsed = parse_events_preserving_prefix(
            &output,
            "rust-gate-scan",
            "rust",
            &root,
            4096,
            Some(env!("CARGO_PKG_VERSION")),
            Some(true),
        );

        assert_eq!(parsed.events.len(), 1);
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation);
        assert!(
            parsed
                .error
                .as_deref()
                .is_some_and(|error| error.contains("reported release-gate-pending"))
        );
        Ok(())
    }

    #[test]
    fn rust_release_gate_allows_matching_and_fallback_profile_values() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        for (gate, release_attested) in [
            (RUST_RELEASE_GATE_PENDING, false),
            (RUST_RELEASE_GATE_VERIFIED, true),
            ("toolchain-unsupported", false),
            ("toolchain-unsupported", true),
            ("semantic-backend-failure", false),
            ("semantic-backend-failure", true),
        ] {
            let output = rust_gate_protocol(&root, gate)?;
            let parsed = parse_events_preserving_prefix(
                &output,
                "rust-gate-scan",
                "rust",
                &root,
                4096,
                Some(env!("CARGO_PKG_VERSION")),
                Some(release_attested),
            );
            assert!(
                parsed.error.is_none(),
                "gate {gate:?}, release_attested={release_attested}: {:?}",
                parsed.error
            );
            assert_eq!(parsed.events.len(), 4);
            assert!(!parsed.security_violation);
        }
        Ok(())
    }

    #[test]
    fn development_web_worker_cannot_spoof_the_verified_typescript_release_gate() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let output = typescript_gate_protocol(&root, TYPESCRIPT_RELEASE_GATE_VERIFIED)?;
        let parsed = parse_events_preserving_prefix(
            &output,
            "typescript-gate-scan",
            "web",
            &root,
            4096,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );

        assert_eq!(parsed.events.len(), 1);
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation);
        assert!(parsed.error.as_deref().is_some_and(|error| {
            error.contains("without a verified TypeScript release attestation")
        }));
        Ok(())
    }

    #[test]
    fn attested_web_worker_must_report_the_verified_typescript_release_gate() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let output = typescript_gate_protocol(&root, TYPESCRIPT_RELEASE_GATE_PENDING)?;
        let parsed = parse_events_preserving_prefix(
            &output,
            "typescript-gate-scan",
            "web",
            &root,
            4096,
            Some(env!("CARGO_PKG_VERSION")),
            Some(true),
        );

        assert_eq!(parsed.events.len(), 1);
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation);
        assert!(
            parsed
                .error
                .as_deref()
                .is_some_and(|error| error.contains("verified TypeScript release worker"))
        );
        Ok(())
    }

    #[test]
    fn typescript_release_gate_allows_matching_profile_values() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        for (gate, release_attested) in [
            (TYPESCRIPT_RELEASE_GATE_PENDING, false),
            (TYPESCRIPT_RELEASE_GATE_VERIFIED, true),
        ] {
            let output = typescript_gate_protocol(&root, gate)?;
            let parsed = parse_events_preserving_prefix(
                &output,
                "typescript-gate-scan",
                "web",
                &root,
                4096,
                Some(env!("CARGO_PKG_VERSION")),
                Some(release_attested),
            );
            assert!(
                parsed.error.is_none(),
                "gate {gate:?}, release_attested={release_attested}: {:?}",
                parsed.error
            );
            assert_eq!(parsed.events.len(), 4);
            assert!(!parsed.security_violation);
        }
        Ok(())
    }

    #[test]
    fn typescript_release_gate_rejects_missing_and_unknown_values() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        for (gate, release_attested) in [
            (None, false),
            (Some("unknown-gate"), false),
            (Some("unknown-gate"), true),
        ] {
            let output =
                typescript_gate_protocol(&root, gate.unwrap_or(TYPESCRIPT_RELEASE_GATE_PENDING))?;
            let mut events = String::from_utf8(output)?
                .lines()
                .map(serde_json::from_str::<Value>)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if gate.is_none() {
                events[1]["profile"]["properties"]
                    .as_object_mut()
                    .context("profile properties must be an object")?
                    .remove(TYPESCRIPT_RELEASE_GATE_PROPERTY);
            }
            let mut invalid = Vec::new();
            for event in events {
                serde_json::to_writer(&mut invalid, &event)?;
                invalid.push(b'\n');
            }
            let parsed = parse_events_preserving_prefix(
                &invalid,
                "typescript-gate-scan",
                "web",
                &root,
                4096,
                Some(env!("CARGO_PKG_VERSION")),
                Some(release_attested),
            );
            assert_eq!(parsed.events.len(), 1, "gate={gate:?}: {:?}", parsed.error);
            assert_eq!(
                parsed.failure_kind,
                Some(WorkerFailureKind::MalformedProtocol)
            );
            assert!(parsed.security_violation);
            assert!(parsed.error.is_some());
        }
        Ok(())
    }

    #[test]
    fn web_worker_requires_the_exact_definition_graph_capability() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        for property in [
            TYPESCRIPT_ANALYSIS_MODE_PROPERTY,
            TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY,
        ] {
            for value in [None, Some("unknown-capability")] {
                let output = typescript_gate_protocol(&root, TYPESCRIPT_RELEASE_GATE_PENDING)?;
                let mut events = String::from_utf8(output)?
                    .lines()
                    .map(serde_json::from_str::<Value>)
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                if let Some(value) = value {
                    events[1]["profile"]["properties"][property] = serde_json::json!(value);
                } else {
                    events[1]["profile"]["properties"]
                        .as_object_mut()
                        .context("profile properties must be an object")?
                        .remove(property);
                }
                let mut spoofed = Vec::new();
                for event in events {
                    serde_json::to_writer(&mut spoofed, &event)?;
                    spoofed.push(b'\n');
                }
                let parsed = parse_events_preserving_prefix(
                    &spoofed,
                    "typescript-gate-scan",
                    "web",
                    &root,
                    4096,
                    Some(env!("CARGO_PKG_VERSION")),
                    Some(false),
                );
                assert_eq!(
                    parsed.events.len(),
                    1,
                    "{property}={value:?}: {:?}",
                    parsed.error
                );
                assert_eq!(
                    parsed.failure_kind,
                    Some(WorkerFailureKind::MalformedProtocol)
                );
                assert!(parsed.security_violation);
                assert!(
                    parsed
                        .error
                        .as_deref()
                        .is_some_and(|error| error.contains(property)),
                    "{property}={value:?}: {:?}",
                    parsed.error
                );
            }
        }
        Ok(())
    }

    #[test]
    fn web_definition_graph_capability_accepts_only_the_definition_slice() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        for (gate, release_attested) in [
            (TYPESCRIPT_RELEASE_GATE_PENDING, false),
            (TYPESCRIPT_RELEASE_GATE_VERIFIED, true),
        ] {
            for relation_kind in ["declares", "extends", "implements", "instantiates"] {
                let output = typescript_definition_protocol(&root, gate, relation_kind)?;
                let parsed = parse_events_preserving_prefix(
                    &output,
                    "typescript-gate-scan",
                    "web",
                    &root,
                    16 * 1024,
                    Some(env!("CARGO_PKG_VERSION")),
                    Some(release_attested),
                );
                assert_eq!(parsed.error, None, "{gate}/{relation_kind}");
                assert_eq!(parsed.failure_kind, None, "{gate}/{relation_kind}");
                assert!(!parsed.security_violation, "{gate}/{relation_kind}");
                assert!(parsed.events.iter().any(|event| {
                    event["event"] == "edge_upsert"
                        && event["edge"]["kind"] == relation_kind
                        && event["edge"]["phase"] == "semantic"
                        && event["edge"]["site_id"].is_null()
                }));
            }
        }
        Ok(())
    }

    #[test]
    fn web_framework_semantic_capability_accepts_only_the_versioned_contract() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut valid = test_protocol_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        add_framework_semantic_delta(
            &mut valid,
            true,
            "emitted",
            WEB_FRAMEWORK_SEMANTIC_CAPABILITY_V1,
        );
        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(valid)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(parsed.error, None);
        assert!(!parsed.security_violation);
        assert!(parsed.events.iter().any(|event| {
            event["event"] == "edge_upsert"
                && event["edge"]["kind"] == "route_entry"
                && event["edge"]["phase"] == "semantic"
        }));

        for capability in ["framework-semantic-graph-v2", ""] {
            let mut invalid = test_protocol_values(typescript_gate_protocol(
                &root,
                TYPESCRIPT_RELEASE_GATE_PENDING,
            )?)?;
            let profile = invalid
                .iter_mut()
                .find(|event| event["event"] == "profile_declared")
                .expect("Web profile");
            let properties = &mut profile["profile"]["properties"];
            properties[WEB_FRAMEWORK_SEMANTIC_CAPABILITY_PROPERTY] = serde_json::json!(capability);
            properties[WEB_FRAMEWORK_SEMANTIC_STATUS_PROPERTY] = serde_json::json!("not-emitted");
            properties[WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION_PROPERTY] =
                serde_json::json!(WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION);
            properties[WEB_FRAMEWORK_SEMANTIC_NODE_COUNT_PROPERTY] = serde_json::json!("0");
            properties[WEB_FRAMEWORK_SEMANTIC_SITE_COUNT_PROPERTY] = serde_json::json!("0");
            properties[WEB_FRAMEWORK_SEMANTIC_EDGE_COUNT_PROPERTY] = serde_json::json!("0");
            let parsed = parse_events_preserving_prefix(
                &serialize_test_protocol(invalid)?,
                "typescript-gate-scan",
                "web",
                &root,
                64 * 1024,
                Some(env!("CARGO_PKG_VERSION")),
                Some(false),
            );
            assert_eq!(
                parsed.failure_kind,
                Some(WorkerFailureKind::MalformedProtocol)
            );
            assert!(parsed.security_violation);
            assert!(parsed.error.as_deref().is_some_and(|error| {
                error.contains("unapproved framework semantic capability")
            }));
        }
        Ok(())
    }

    #[test]
    fn web_framework_failure_preserves_syntax_and_typescript_semantic_graph() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut invalid = test_protocol_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        add_framework_semantic_delta(
            &mut invalid,
            false,
            "emitted",
            WEB_FRAMEWORK_SEMANTIC_CAPABILITY_V1,
        );
        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(invalid)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation);
        assert!(parsed.error.as_deref().is_some_and(|error| {
            error.contains("invalid Web semantic protocol") && error.contains("incompatible target")
        }));
        assert!(parsed.events.iter().any(|event| {
            event["event"] == "node_upsert"
                && matches!(event["node"]["kind"].as_str(), Some("file" | "symbol"))
        }));
        assert!(parsed.events.iter().any(|event| {
            event["event"] == "edge_upsert" && event["edge"]["kind"] == "declares"
        }));
        assert!(!parsed.events.iter().any(|event| {
            event["event"] == "node_upsert"
                && matches!(
                    event["node"]["kind"].as_str(),
                    Some("component" | "route" | "server_function" | "middleware")
                )
        }));
        assert!(!parsed.events.iter().any(|event| {
            event["event"] == "dependency_site" && event["site"]["kind"] == "route_entry"
        }));
        let properties = &parsed
            .events
            .iter()
            .find(|event| event["event"] == "profile_declared")
            .expect("preserved Web profile")["profile"]["properties"];
        assert_eq!(
            properties[WEB_FRAMEWORK_COMPLETENESS_STATUS_PROPERTY],
            "incomplete"
        );
        let ledger: Vec<Value> = serde_json::from_str(
            properties[WEB_FRAMEWORK_COMPLETENESS_LEDGER_PROPERTY]
                .as_str()
                .expect("framework completeness ledger"),
        )?;
        assert_eq!(ledger[0]["status"], "incomplete");
        assert_eq!(
            ledger[0]["emitted_capabilities"],
            serde_json::json!(["typescript-definition-import-type-call-graph-v2"])
        );
        assert!(ledger[0]["reasons"].as_array().is_some_and(|reasons| {
            reasons
                .iter()
                .any(|reason| reason == "core_framework_delta_discarded")
        }));
        Ok(())
    }

    #[test]
    fn web_framework_completeness_ledger_rejects_claimed_or_mismatched_capabilities() -> Result<()>
    {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mutations = [
            serde_json::json!([{
                "framework":"next",
                "required_capabilities":["framework-semantic-graph-v1","typescript-definition-import-type-call-graph-v2"],
                "emitted_capabilities":["framework-semantic-graph-v1","typescript-definition-import-type-call-graph-v2"],
                "status":"complete",
                "reasons":[]
            }]),
            serde_json::json!([{
                "framework":"next",
                "required_capabilities":["framework-semantic-graph-v1","next-route-component-boundary-v1","typescript-definition-import-type-call-graph-v2"],
                "emitted_capabilities":["framework-semantic-graph-v1","next-route-component-boundary-v1","typescript-definition-import-type-call-graph-v2"],
                "status":"complete",
                "reasons":["collector_delta_discarded"]
            }]),
            serde_json::json!([{
                "framework":"astro",
                "required_capabilities":["astro-component-render-hydration-v1","framework-semantic-graph-v1","typescript-definition-import-type-call-graph-v2"],
                "emitted_capabilities":["astro-component-render-hydration-v1","framework-semantic-graph-v1","typescript-definition-import-type-call-graph-v2"],
                "status":"complete",
                "reasons":[]
            }]),
            serde_json::json!([{
                "framework":"next",
                "required_capabilities":["typescript-definition-import-type-call-graph-v2","next-route-component-boundary-v1","framework-semantic-graph-v1"],
                "emitted_capabilities":["typescript-definition-import-type-call-graph-v2","next-route-component-boundary-v1","framework-semantic-graph-v1"],
                "status":"complete",
                "reasons":[]
            }]),
        ];
        for mutation in mutations {
            let mut events = test_protocol_values(typescript_definition_protocol(
                &root,
                TYPESCRIPT_RELEASE_GATE_PENDING,
                "declares",
            )?)?;
            add_framework_semantic_delta(
                &mut events,
                true,
                "emitted",
                WEB_FRAMEWORK_SEMANTIC_CAPABILITY_V1,
            );
            let properties = &mut events
                .iter_mut()
                .find(|event| event["event"] == "profile_declared")
                .expect("Web profile")["profile"]["properties"];
            properties[WEB_FRAMEWORK_COMPLETENESS_LEDGER_PROPERTY] =
                serde_json::json!(mutation.to_string());
            let parsed = parse_events_preserving_prefix(
                &serialize_test_protocol(events)?,
                "typescript-gate-scan",
                "web",
                &root,
                64 * 1024,
                Some(env!("CARGO_PKG_VERSION")),
                Some(false),
            );
            assert_eq!(
                parsed.failure_kind,
                Some(WorkerFailureKind::MalformedProtocol),
                "{mutation}"
            );
            assert!(parsed.security_violation, "{mutation}: {:?}", parsed.error);
            assert!(!parsed.events.iter().any(|event| {
                event["event"] == "node_upsert"
                    && matches!(event["node"]["kind"].as_str(), Some("component" | "route"))
            }));
        }
        Ok(())
    }

    #[test]
    fn web_import_type_capability_accepts_definition_import_reexport_and_type_use() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        for (gate, release_attested) in [
            (TYPESCRIPT_RELEASE_GATE_PENDING, false),
            (TYPESCRIPT_RELEASE_GATE_VERIFIED, true),
        ] {
            let output = typescript_import_type_protocol(&root, gate)?;
            let parsed = parse_events_preserving_prefix(
                &output,
                "typescript-gate-scan",
                "web",
                &root,
                64 * 1024,
                Some(env!("CARGO_PKG_VERSION")),
                Some(release_attested),
            );
            assert_eq!(parsed.error, None, "gate={gate:?}");
            assert_eq!(parsed.failure_kind, None, "gate={gate:?}");
            assert!(!parsed.security_violation, "gate={gate:?}");
            for (site_kind, edge_kind) in [
                ("web_import", "imports"),
                ("web_reexport", "reexports"),
                ("type_use", "type_uses"),
            ] {
                let site = parsed
                    .events
                    .iter()
                    .find(|event| {
                        event["event"] == "dependency_site" && event["site"]["kind"] == site_kind
                    })
                    .unwrap_or_else(|| panic!("missing {site_kind} site"));
                let site_id = site["site"]["id"].as_str().expect("semantic site ID");
                assert!(parsed.events.iter().any(|event| {
                    event["event"] == "edge_upsert"
                        && event["edge"]["kind"] == edge_kind
                        && event["edge"]["site_id"] == site_id
                        && event["edge"]["phase"] == "semantic"
                }));
                assert_eq!(site["site"]["evidence"][0]["kind"], "semantic");
                assert_eq!(site["site"]["evidence"][1]["kind"], "source");
            }
            let type_only_values = parsed
                .events
                .iter()
                .filter(|event| {
                    event["event"] == "dependency_site"
                        && event["site"]["evidence"][0]["kind"] == "semantic"
                })
                .filter_map(|event| {
                    event["site"]["evidence"][0]["properties"]["type_only"].as_bool()
                })
                .collect::<BTreeSet<_>>();
            assert_eq!(type_only_values, BTreeSet::from([false, true]));
            assert!(!parsed.events.iter().any(|event| {
                event["coverage"]["completeness"]
                    .as_array()
                    .is_some_and(|values| values.iter().any(|value| value == "semantic-complete"))
            }));
        }

        let mut discarded = test_protocol_values(typescript_gate_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        let properties = &mut discarded
            .iter_mut()
            .find(|event| event["event"] == "profile_declared")
            .expect("Web profile")["profile"]["properties"];
        properties[TYPESCRIPT_ANALYSIS_MODE_PROPERTY] =
            serde_json::json!(TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_GRAPH);
        properties[TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY] =
            serde_json::json!(TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_GRAPH_V1);
        properties[TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY] =
            serde_json::json!("definition-import-type-graph-discarded");
        properties[TYPESCRIPT_DEFINITION_STATUS_PROPERTY] = serde_json::json!("failed");
        properties[TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY] = serde_json::json!("0");
        properties["typescript_semantic_issue_count"] = serde_json::json!("1");
        let completion_index = discarded
            .iter()
            .position(|event| event["event"] == "profile_completed")
            .expect("profile completion");
        discarded.insert(
            completion_index,
            serde_json::json!({
                "event":"diagnostic",
                "protocol_version":"1.0",
                "scan_id":"typescript-gate-scan",
                "adapter":"web",
                "adapter_version":env!("CARGO_PKG_VERSION"),
                "seq":0,
                "diagnostic":{
                    "id":"diagnostic:web:dependency-issue",
                    "severity":"warning",
                    "code":"web.typescript_dependency_issue",
                    "message":"dependency semantic issue",
                    "profile_id":"web:default",
                    "evidence":[],
                    "properties":{
                        "typescript_definition_issue":true,
                        "typescript_dependency_issue":true,
                    },
                },
            }),
        );
        resequence_test_protocol(&mut discarded);
        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(discarded)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(parsed.error, None, "discarded profile: {:?}", parsed.error);
        assert!(!parsed.security_violation);
        Ok(())
    }

    #[test]
    fn web_call_capability_accepts_generated_initializer_and_exact_direct_call() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        for (gate, release_attested) in [
            (TYPESCRIPT_RELEASE_GATE_PENDING, false),
            (TYPESCRIPT_RELEASE_GATE_VERIFIED, true),
        ] {
            let parsed = parse_events_preserving_prefix(
                &typescript_call_protocol(&root, gate)?,
                "typescript-gate-scan",
                "web",
                &root,
                64 * 1024,
                Some(env!("CARGO_PKG_VERSION")),
                Some(release_attested),
            );
            assert_eq!(parsed.error, None, "gate={gate:?}");
            assert_eq!(parsed.failure_kind, None, "gate={gate:?}");
            assert!(!parsed.security_violation, "gate={gate:?}");
            assert!(parsed.events.iter().any(|event| {
                event["event"] == "node_upsert"
                    && event["node"]["properties"]["symbol_kind"] == "generated_module_initializer"
                    && event["node"]["properties"]["canonical_identity"]["identity_kind"]
                        == "generated"
            }));
            assert!(parsed.events.iter().any(|event| {
                event["event"] == "dependency_site"
                    && event["site"]["kind"] == "call"
                    && event["site"]["resolution_status"] == "resolved"
                    && event["site"]["precision"] == "exact"
            }));
            assert!(parsed.events.iter().any(|event| {
                event["event"] == "edge_upsert"
                    && event["edge"]["kind"] == "calls"
                    && event["edge"]["phase"] == "semantic"
            }));
            assert!(!parsed.events.iter().any(|event| {
                event["edge"]["kind"] == "may_call"
                    || event["coverage"]["completeness"]
                        .as_array()
                        .is_some_and(|values| {
                            values.iter().any(|value| value == "semantic-complete")
                        })
            }));
        }
        Ok(())
    }

    #[test]
    fn web_call_capability_v2_accepts_well_formed_candidate_calls() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut events = test_protocol_values(typescript_call_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        configure_typescript_candidate_call(
            &mut events,
            TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2,
        );
        promote_typescript_semantic_complete(&mut events, TYPESCRIPT_RELEASE_GATE_PENDING);

        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(parsed.error, None, "{:?}", parsed.error);
        assert_eq!(parsed.failure_kind, None, "{:?}", parsed.failure_kind);
        assert!(!parsed.security_violation);
        let candidate_site = parsed
            .events
            .iter()
            .find(|event| {
                event["event"] == "dependency_site"
                    && event["site"]["kind"] == "call"
                    && event["site"]["resolution_status"] == "candidates"
            })
            .expect("candidate call site");
        let target_ids = candidate_site["site"]["target_ids"]
            .as_array()
            .expect("candidate call targets");
        assert_eq!(target_ids.len(), 2);
        assert!(
            candidate_site["site"]["evidence"][0]["properties"]["algorithm"]
                .as_str()
                .is_some_and(|algorithm| !algorithm.is_empty())
        );
        let site_id = candidate_site["site"]["id"]
            .as_str()
            .expect("candidate call site ID");
        assert_eq!(
            parsed
                .events
                .iter()
                .filter(|event| {
                    event["event"] == "edge_upsert"
                        && event["edge"]["kind"] == "may_call"
                        && event["edge"]["site_id"] == site_id
                        && event["edge"]["resolution_status"] == "candidates"
                        && event["edge"]["precision"] == "overapprox"
                })
                .count(),
            2
        );
        assert!(
            parsed
                .events
                .iter()
                .filter(|event| {
                    matches!(
                        event["event"].as_str(),
                        Some("profile_completed" | "scan_completed")
                    )
                })
                .all(|event| {
                    event["coverage"]["dependency_sites"] == 1
                        && event["coverage"]["resolved"] == 0
                        && event["coverage"]["candidates"] == 1
                        && event["coverage"]["completeness"]
                            .as_array()
                            .is_some_and(|values| {
                                values.iter().any(|value| value == "semantic-complete")
                            })
                })
        );
        Ok(())
    }

    #[test]
    fn web_semantic_complete_rejects_compiler_diagnostics() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        for property in [
            "typescript_semantic_diagnostics",
            "typescript_emitted_semantic_diagnostics",
        ] {
            let mut events = test_protocol_values(typescript_call_protocol(
                &root,
                TYPESCRIPT_RELEASE_GATE_PENDING,
            )?)?;
            promote_typescript_semantic_complete(&mut events, TYPESCRIPT_RELEASE_GATE_PENDING);
            events
                .iter_mut()
                .find(|event| event["event"] == "profile_declared")
                .expect("Web profile declaration")["profile"]["properties"][property] =
                serde_json::json!("1");
            resequence_test_protocol(&mut events);

            let parsed = parse_events_preserving_prefix(
                &serialize_test_protocol(events)?,
                "typescript-gate-scan",
                "web",
                &root,
                64 * 1024,
                Some(env!("CARGO_PKG_VERSION")),
                Some(false),
            );
            assert_eq!(
                parsed.failure_kind,
                Some(WorkerFailureKind::MalformedProtocol),
                "{property}: {:?}",
                parsed.error
            );
            assert!(parsed.security_violation, "{property}: {:?}", parsed.error);
            assert!(
                parsed
                    .error
                    .as_deref()
                    .is_some_and(|error| error.contains(property)),
                "{property}: {:?}",
                parsed.error
            );
            assert!(!parsed.events.iter().any(|event| {
                event["coverage"]["completeness"]
                    .as_array()
                    .is_some_and(|values| values.iter().any(|value| value == "semantic-complete"))
            }));
        }
        Ok(())
    }

    #[test]
    fn web_call_capability_v1_rejects_candidate_calls() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut events = test_protocol_values(typescript_call_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        configure_typescript_candidate_call(
            &mut events,
            TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V1,
        );
        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation, "{:?}", parsed.error);
        assert!(
            parsed
                .error
                .as_deref()
                .is_some_and(|error| { error.contains("forbidden semantic dependency site") })
        );
        Ok(())
    }

    #[test]
    fn web_call_capability_v2_rejects_candidate_call_without_algorithm() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut events = test_protocol_values(typescript_call_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        configure_typescript_candidate_call(
            &mut events,
            TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2,
        );
        mutate_semantic_primary_properties(&mut events, "call", |properties| {
            properties
                .as_object_mut()
                .expect("primary properties")
                .remove("algorithm");
        });

        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation, "{:?}", parsed.error);
        assert!(
            parsed.error.as_deref().is_some_and(|error| {
                error.contains("may_call edge") && error.contains("algorithm")
            }),
            "{:?}",
            parsed.error
        );
        Ok(())
    }

    #[test]
    fn web_call_capability_v2_rejects_candidate_call_with_reason() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut events = test_protocol_values(typescript_call_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        configure_typescript_candidate_call(
            &mut events,
            TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2,
        );
        let call_site = events
            .iter_mut()
            .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "call")
            .expect("candidate call site");
        call_site["site"]["reason"] = serde_json::json!("spoofed_candidate_reason");

        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation, "{:?}", parsed.error);
        assert!(
            parsed.error.as_deref().is_some_and(|error| {
                error.contains("candidate call site") && error.contains("reason")
            }),
            "{:?}",
            parsed.error
        );
        Ok(())
    }

    #[test]
    fn web_call_capability_v2_rejects_spoofed_candidate_algorithm() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut events = test_protocol_values(typescript_call_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        configure_typescript_candidate_call(
            &mut events,
            TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2,
        );
        mutate_semantic_primary_properties(&mut events, "call", |properties| {
            properties["algorithm"] =
                serde_json::json!(TYPESCRIPT_CLOSED_LOCAL_FRESH_INSTANCE_FLOW_ALGORITHM);
        });

        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation, "{:?}", parsed.error);
        assert!(
            parsed.error.as_deref().is_some_and(|error| {
                error.contains("dispatch \"dynamic\"") && error.contains("algorithm")
            }),
            "{:?}",
            parsed.error
        );
        Ok(())
    }

    #[test]
    fn web_call_capability_v2_accepts_fresh_instance_method_candidate() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut events = test_protocol_values(typescript_call_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        configure_typescript_candidate_call(
            &mut events,
            TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2,
        );
        mutate_semantic_primary_properties(&mut events, "call", |properties| {
            properties["dispatch"] = serde_json::json!("fresh_instance");
            properties["algorithm"] =
                serde_json::json!(TYPESCRIPT_CLOSED_LOCAL_FRESH_INSTANCE_FLOW_ALGORITHM);
            properties["call_kind"] = serde_json::json!("method");
        });

        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(parsed.error, None, "{:?}", parsed.error);
        assert_eq!(parsed.failure_kind, None, "{:?}", parsed.failure_kind);
        assert!(!parsed.security_violation);
        Ok(())
    }

    #[test]
    fn web_call_capability_v2_rejects_fresh_instance_constructor_candidate() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut events = test_protocol_values(typescript_call_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        configure_typescript_candidate_call(
            &mut events,
            TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2,
        );
        mutate_semantic_primary_properties(&mut events, "call", |properties| {
            properties["dispatch"] = serde_json::json!("fresh_instance");
            properties["algorithm"] =
                serde_json::json!(TYPESCRIPT_CLOSED_LOCAL_FRESH_INSTANCE_FLOW_ALGORITHM);
            properties["call_kind"] = serde_json::json!("constructor");
            properties["occurrence_kind"] = serde_json::json!("new_expression");
        });

        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation, "{:?}", parsed.error);
        assert!(
            parsed.error.as_deref().is_some_and(|error| {
                error.contains("call_kind \"constructor\"")
                    && error.contains("dispatch \"fresh_instance\"")
            }),
            "{:?}",
            parsed.error
        );
        Ok(())
    }

    #[test]
    fn web_call_capability_rejects_algorithm_on_non_candidate_call() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut events = test_protocol_values(typescript_call_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        mutate_semantic_primary_properties(&mut events, "call", |properties| {
            properties["algorithm"] =
                serde_json::json!(TYPESCRIPT_CLOSED_LOCAL_CALL_FLOW_ALGORITHM);
        });

        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation, "{:?}", parsed.error);
        assert!(
            parsed.error.as_deref().is_some_and(|error| {
                error.contains("dispatch \"direct\"") && error.contains("algorithm")
            }),
            "{:?}",
            parsed.error
        );
        Ok(())
    }

    #[test]
    fn web_call_capability_rejects_non_callable_symbol_source() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut events = test_protocol_values(typescript_call_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        let variable_id = events
            .iter()
            .find(|event| {
                event["event"] == "node_upsert"
                    && event["node"]["properties"]["symbol_kind"] == "variable"
            })
            .expect("variable symbol")["node"]["id"]
            .as_str()
            .expect("variable symbol ID")
            .to_owned();
        let call_site = events
            .iter_mut()
            .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "call")
            .expect("call site");
        call_site["site"]["source"] = serde_json::json!(variable_id);
        recanonicalize_typescript_call(&mut events);

        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation, "{:?}", parsed.error);
        assert!(parsed.error.as_deref().is_some_and(|error| {
            error.contains("source") && error.contains("callable symbol")
        }));
        Ok(())
    }

    #[test]
    fn web_call_capability_rejects_non_callable_symbol_target() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut events = test_protocol_values(typescript_call_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        let variable_id = events
            .iter()
            .find(|event| {
                event["event"] == "node_upsert"
                    && event["node"]["properties"]["symbol_kind"] == "variable"
            })
            .expect("variable symbol")["node"]["id"]
            .as_str()
            .expect("variable symbol ID")
            .to_owned();
        let call_site = events
            .iter_mut()
            .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "call")
            .expect("call site");
        call_site["site"]["target_ids"] = serde_json::json!([variable_id]);
        recanonicalize_typescript_call(&mut events);

        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation, "{:?}", parsed.error);
        assert!(parsed.error.as_deref().is_some_and(|error| {
            error.contains("resolved target") && error.contains("canonical callable symbol")
        }));
        Ok(())
    }

    #[test]
    fn web_import_equals_accepts_a_repository_module_surrogate() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut events = test_protocol_values(typescript_import_type_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        let site_id = events
            .iter()
            .find(|event| {
                event["event"] == "dependency_site" && event["site"]["kind"] == "web_import"
            })
            .expect("Web import site")["site"]["id"]
            .as_str()
            .expect("site ID")
            .to_owned();
        for event in &mut events {
            if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
                event["site"]["evidence"][0]["properties"]["occurrence_kind"] =
                    serde_json::json!("import_equals");
                event["site"]["evidence"][0]["properties"]["imported_name"] =
                    serde_json::json!("=");
                event["site"]["evidence"][1]["properties"]["occurrence_kind"] =
                    serde_json::json!("import_equals");
            } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
                event["edge"]["evidence"][0]["properties"]["occurrence_kind"] =
                    serde_json::json!("import_equals");
                event["edge"]["evidence"][0]["properties"]["imported_name"] =
                    serde_json::json!("=");
                event["edge"]["evidence"][1]["properties"]["occurrence_kind"] =
                    serde_json::json!("import_equals");
            }
        }
        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(parsed.error, None, "{:?}", parsed.error);
        assert_eq!(parsed.failure_kind, None);
        assert!(!parsed.security_violation);
        Ok(())
    }

    #[test]
    fn web_literal_binding_scheme_specifier_is_not_reserved() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut events = test_protocol_values(typescript_import_type_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        let specifier = "binding:[\"pkg\",\"X\"]";
        mutate_semantic_primary_properties(&mut events, "web_import", |properties| {
            properties["module_specifier"] = serde_json::json!(specifier);
        });
        events
            .iter_mut()
            .find(|event| {
                event["event"] == "dependency_site" && event["site"]["kind"] == "web_import"
            })
            .expect("Web import site")["site"]["specifier"] = serde_json::json!(specifier);
        resequence_test_protocol(&mut events);
        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(parsed.error, None, "{:?}", parsed.error);
        assert_eq!(parsed.failure_kind, None);
        assert!(!parsed.security_violation);
        Ok(())
    }

    #[test]
    fn web_empty_clauses_and_empty_module_export_names_are_attested() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;

        for (site_kind, occurrence_kind) in [
            ("web_import", "empty_import"),
            ("web_reexport", "empty_reexport"),
        ] {
            let mut events = test_protocol_values(typescript_import_type_protocol(
                &root,
                TYPESCRIPT_RELEASE_GATE_PENDING,
            )?)?;
            let site_id = events
                .iter()
                .find(|event| {
                    event["event"] == "dependency_site" && event["site"]["kind"] == site_kind
                })
                .expect("Web semantic site")["site"]["id"]
                .as_str()
                .expect("site ID")
                .to_owned();
            for event in &mut events {
                if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
                    event["site"]["evidence"][0]["properties"]["occurrence_kind"] =
                        serde_json::json!(occurrence_kind);
                    event["site"]["evidence"][0]["properties"]
                        .as_object_mut()
                        .expect("primary properties")
                        .remove("imported_name");
                    event["site"]["evidence"][1]["properties"]["occurrence_kind"] =
                        serde_json::json!(occurrence_kind);
                } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
                    event["edge"]["evidence"][0]["properties"]["occurrence_kind"] =
                        serde_json::json!(occurrence_kind);
                    event["edge"]["evidence"][0]["properties"]
                        .as_object_mut()
                        .expect("primary properties")
                        .remove("imported_name");
                    event["edge"]["evidence"][1]["properties"]["occurrence_kind"] =
                        serde_json::json!(occurrence_kind);
                }
            }
            if occurrence_kind == "empty_reexport" {
                let mut malformed = events.clone();
                resequence_test_protocol(&mut malformed);
                let parsed = parse_events_preserving_prefix(
                    &serialize_test_protocol(malformed)?,
                    "typescript-gate-scan",
                    "web",
                    &root,
                    64 * 1024,
                    Some(env!("CARGO_PKG_VERSION")),
                    Some(false),
                );
                assert!(
                    parsed
                        .error
                        .as_deref()
                        .is_some_and(|error| error.contains("incompatible kind type")),
                    "malformed empty re-export: {:?}",
                    parsed.error
                );

                let target_file_id = events
                    .iter()
                    .find(|event| event["node"]["properties"]["path"] == "src/target.ts")
                    .expect("target file node")["node"]["id"]
                    .as_str()
                    .expect("target file ID")
                    .to_owned();
                for event in &mut events {
                    if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
                        event["site"]["target_ids"] = serde_json::json!([target_file_id.as_str()]);
                        event["site"]["evidence"][0]["properties"]["target_basis"] =
                            serde_json::json!("repository_module");
                    } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id
                    {
                        event["edge"]["target"] = serde_json::json!(target_file_id.as_str());
                        event["edge"]["evidence"][0]["properties"]["target_basis"] =
                            serde_json::json!("repository_module");
                        let edge_id = depgraph_protocol::stable_id_from_value(
                            "edge",
                            &serde_json::json!({
                                "kind": event["edge"]["kind"].clone(),
                                "site_id": site_id.as_str(),
                                "target": target_file_id.as_str(),
                            }),
                        );
                        event["edge"]["id"] = serde_json::json!(edge_id);
                    }
                }
            }
            resequence_test_protocol(&mut events);
            let parsed = parse_events_preserving_prefix(
                &serialize_test_protocol(events)?,
                "typescript-gate-scan",
                "web",
                &root,
                64 * 1024,
                Some(env!("CARGO_PKG_VERSION")),
                Some(false),
            );
            assert_eq!(parsed.error, None, "{site_kind}: {:?}", parsed.error);
            assert_eq!(parsed.failure_kind, None);
            assert!(!parsed.security_violation);
        }

        let mut events = test_protocol_values(typescript_import_type_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        mutate_semantic_primary_properties(&mut events, "web_reexport", |properties| {
            properties["imported_name"] = serde_json::json!("");
        });
        resequence_test_protocol(&mut events);
        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.error, None,
            "empty ModuleExportName: {:?}",
            parsed.error
        );
        assert_eq!(parsed.failure_kind, None);
        assert!(!parsed.security_violation);

        let mut events = test_protocol_values(typescript_import_type_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        let site_id = events
            .iter()
            .find(|event| {
                event["event"] == "dependency_site" && event["site"]["kind"] == "web_import"
            })
            .expect("Web import site")["site"]["id"]
            .as_str()
            .expect("site ID")
            .to_owned();
        for event in &mut events {
            if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
                event["site"]["specifier"] = serde_json::json!("");
                event["site"]["evidence"][0]["properties"]["module_specifier"] =
                    serde_json::json!("");
            } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
                event["edge"]["evidence"][0]["properties"]["module_specifier"] =
                    serde_json::json!("");
            }
        }
        resequence_test_protocol(&mut events);
        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.error, None,
            "empty module specifier: {:?}",
            parsed.error
        );
        assert_eq!(parsed.failure_kind, None);
        assert!(!parsed.security_violation);
        Ok(())
    }

    #[test]
    fn web_type_only_reexport_accepts_resolution_mode_attestation() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut events = test_protocol_values(typescript_import_type_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        mutate_semantic_primary_properties(&mut events, "web_reexport", |properties| {
            properties["type_only"] = serde_json::json!(true);
            properties["resolution_mode"] = serde_json::json!("require");
        });
        resequence_test_protocol(&mut events);
        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(parsed.error, None, "{:?}", parsed.error);
        assert_eq!(parsed.failure_kind, None);
        assert!(!parsed.security_violation);
        Ok(())
    }

    #[test]
    fn web_import_type_gate_rejects_mismatched_capability_and_strict_site_contract() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let baseline = test_protocol_values(typescript_import_type_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        let mut cases = Vec::<(&str, Vec<Value>, &str)>::new();

        let mut mismatched_capability = baseline.clone();
        mismatched_capability
            .iter_mut()
            .find(|event| event["event"] == "profile_declared")
            .expect("profile")["profile"]["properties"][TYPESCRIPT_ANALYSIS_MODE_PROPERTY] =
            serde_json::json!(TYPESCRIPT_ANALYSIS_MODE_DEFINITION_GRAPH);
        cases.push((
            "mismatched capability",
            mismatched_capability,
            "mismatched semantic capability",
        ));

        let mut missing_source_support = baseline.clone();
        let site_id = missing_source_support
            .iter()
            .find(|event| {
                event["event"] == "dependency_site" && event["site"]["kind"] == "web_import"
            })
            .expect("Web import site")["site"]["id"]
            .as_str()
            .expect("site ID")
            .to_owned();
        for event in &mut missing_source_support {
            if (event["event"] == "dependency_site" && event["site"]["id"] == site_id)
                || (event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id)
            {
                let evidence = if event["event"] == "dependency_site" {
                    &mut event["site"]["evidence"]
                } else {
                    &mut event["edge"]["evidence"]
                };
                *evidence = serde_json::json!([evidence[0].clone()]);
            }
        }
        cases.push((
            "missing source support",
            missing_source_support,
            "matching source supporting evidence",
        ));

        let mut spoofed_source_support = baseline.clone();
        let site_id = spoofed_source_support
            .iter()
            .find(|event| {
                event["event"] == "dependency_site" && event["site"]["kind"] == "web_import"
            })
            .expect("Web import site")["site"]["id"]
            .as_str()
            .expect("site ID")
            .to_owned();
        for event in &mut spoofed_source_support {
            if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
                event["site"]["evidence"][1]["extractor"] = serde_json::json!("typescript-static");
            } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
                event["edge"]["evidence"][1]["extractor"] = serde_json::json!("typescript-static");
            }
        }
        cases.push((
            "spoofed source support",
            spoofed_source_support,
            "matching source supporting evidence",
        ));

        let mut non_boolean_type_only = baseline.clone();
        let site_id = non_boolean_type_only
            .iter()
            .find(|event| {
                event["event"] == "dependency_site" && event["site"]["kind"] == "web_import"
            })
            .expect("Web import site")["site"]["id"]
            .as_str()
            .expect("site ID")
            .to_owned();
        for event in &mut non_boolean_type_only {
            if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
                event["site"]["evidence"][0]["properties"]["type_only"] =
                    serde_json::json!("false");
            } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
                event["edge"]["evidence"][0]["properties"]["type_only"] =
                    serde_json::json!("false");
            }
        }
        cases.push((
            "non-boolean type-only marker",
            non_boolean_type_only,
            "must declare boolean type_only",
        ));

        let mut false_type_use = baseline.clone();
        let site_id = false_type_use
            .iter()
            .find(|event| {
                event["event"] == "dependency_site" && event["site"]["kind"] == "type_use"
            })
            .expect("type-use site")["site"]["id"]
            .as_str()
            .expect("site ID")
            .to_owned();
        for event in &mut false_type_use {
            if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
                event["site"]["evidence"][0]["properties"]["type_only"] = serde_json::json!(false);
            } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
                event["edge"]["evidence"][0]["properties"]["type_only"] = serde_json::json!(false);
            }
        }
        cases.push((
            "false type-use marker",
            false_type_use,
            "must use type_only=true",
        ));

        let mut type_only_dynamic_import = baseline.clone();
        let site_id = type_only_dynamic_import
            .iter()
            .find(|event| {
                event["event"] == "dependency_site" && event["site"]["kind"] == "web_import"
            })
            .expect("Web import site")["site"]["id"]
            .as_str()
            .expect("site ID")
            .to_owned();
        for event in &mut type_only_dynamic_import {
            if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
                event["site"]["evidence"][0]["properties"]["occurrence_kind"] =
                    serde_json::json!("dynamic_import");
                event["site"]["evidence"][0]["properties"]["type_only"] = serde_json::json!(true);
                event["site"]["evidence"][1]["properties"]["occurrence_kind"] =
                    serde_json::json!("dynamic_import");
            } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
                event["edge"]["evidence"][0]["properties"]["occurrence_kind"] =
                    serde_json::json!("dynamic_import");
                event["edge"]["evidence"][0]["properties"]["type_only"] = serde_json::json!(true);
                event["edge"]["evidence"][1]["properties"]["occurrence_kind"] =
                    serde_json::json!("dynamic_import");
            }
        }
        cases.push((
            "type-only dynamic import",
            type_only_dynamic_import,
            "must use type_only=false",
        ));

        let mut invalid_resolution_mode = baseline.clone();
        mutate_semantic_primary_properties(
            &mut invalid_resolution_mode,
            "web_reexport",
            |properties| {
                properties["resolution_mode"] = serde_json::json!("node");
            },
        );
        cases.push((
            "invalid resolution mode",
            invalid_resolution_mode,
            "invalid resolution_mode metadata",
        ));

        let mut resolution_mode_on_value_import = baseline.clone();
        mutate_semantic_primary_properties(
            &mut resolution_mode_on_value_import,
            "web_import",
            |properties| {
                properties["resolution_mode"] = serde_json::json!("require");
            },
        );
        cases.push((
            "resolution mode on value import",
            resolution_mode_on_value_import,
            "resolution_mode contradicts its occurrence",
        ));

        let mut resolution_mode_on_import_equals = baseline.clone();
        let site_id = resolution_mode_on_import_equals
            .iter()
            .find(|event| {
                event["event"] == "dependency_site" && event["site"]["kind"] == "web_import"
            })
            .expect("Web import site")["site"]["id"]
            .as_str()
            .expect("site ID")
            .to_owned();
        for event in &mut resolution_mode_on_import_equals {
            let semantic = if event["event"] == "dependency_site" && event["site"]["id"] == site_id
            {
                Some(&mut event["site"]["evidence"])
            } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
                Some(&mut event["edge"]["evidence"])
            } else {
                None
            };
            if let Some(evidence) = semantic {
                evidence[0]["properties"]["occurrence_kind"] = serde_json::json!("import_equals");
                evidence[0]["properties"]["imported_name"] = serde_json::json!("=");
                evidence[0]["properties"]["type_only"] = serde_json::json!(true);
                evidence[0]["properties"]["resolution_mode"] = serde_json::json!("require");
                evidence[1]["properties"]["occurrence_kind"] = serde_json::json!("import_equals");
            }
        }
        cases.push((
            "resolution mode on import-equals",
            resolution_mode_on_import_equals,
            "import_equals occurrence cannot expose resolution_mode",
        ));

        let mut missing_module_specifier = baseline.clone();
        mutate_semantic_primary_properties(
            &mut missing_module_specifier,
            "web_import",
            |properties| {
                properties
                    .as_object_mut()
                    .expect("evidence properties")
                    .remove("module_specifier");
            },
        );
        cases.push((
            "missing module specifier",
            missing_module_specifier,
            "binding metadata does not match occurrence_kind",
        ));

        let mut missing_imported_name = baseline.clone();
        mutate_semantic_primary_properties(
            &mut missing_imported_name,
            "web_reexport",
            |properties| {
                properties
                    .as_object_mut()
                    .expect("evidence properties")
                    .remove("imported_name");
            },
        );
        cases.push((
            "missing imported name",
            missing_imported_name,
            "binding metadata does not match occurrence_kind",
        ));

        let mut mismatched_protocol_specifier = baseline.clone();
        mutate_semantic_primary_properties(
            &mut mismatched_protocol_specifier,
            "web_reexport",
            |properties| {
                properties["module_specifier"] = serde_json::json!("./other");
            },
        );
        cases.push((
            "mismatched protocol specifier",
            mismatched_protocol_specifier,
            "binding metadata does not match occurrence_kind",
        ));

        let mut named_binding_file_target = baseline.clone();
        let site_id = named_binding_file_target
            .iter()
            .find(|event| {
                event["event"] == "dependency_site" && event["site"]["kind"] == "web_import"
            })
            .expect("Web import site")["site"]["id"]
            .as_str()
            .expect("site ID")
            .to_owned();
        for event in &mut named_binding_file_target {
            if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
                event["site"]["evidence"][0]["properties"]["occurrence_kind"] =
                    serde_json::json!("named_import");
                event["site"]["evidence"][1]["properties"]["occurrence_kind"] =
                    serde_json::json!("named_import");
            } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
                event["edge"]["evidence"][0]["properties"]["occurrence_kind"] =
                    serde_json::json!("named_import");
                event["edge"]["evidence"][1]["properties"]["occurrence_kind"] =
                    serde_json::json!("named_import");
            }
        }
        cases.push((
            "named binding file target",
            named_binding_file_target,
            "cannot weaken a named binding target",
        ));

        let mut mixed_repository_and_definition_targets = baseline.clone();
        let definition_target = mixed_repository_and_definition_targets
            .iter()
            .find(|event| event["event"] == "node_upsert" && event["node"]["kind"] == "type")
            .expect("semantic type target")["node"]["id"]
            .as_str()
            .expect("semantic type ID")
            .to_owned();
        let import_site = mixed_repository_and_definition_targets
            .iter()
            .find(|event| {
                event["event"] == "dependency_site" && event["site"]["kind"] == "web_import"
            })
            .expect("Web import site");
        let site_id = import_site["site"]["id"]
            .as_str()
            .expect("site ID")
            .to_owned();
        let file_target = import_site["site"]["target_ids"][0]
            .as_str()
            .expect("file target ID")
            .to_owned();
        let mut mixed_targets = vec![file_target, definition_target.clone()];
        mixed_targets.sort();
        for event in &mut mixed_repository_and_definition_targets {
            if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
                event["site"]["target_ids"] = serde_json::json!(mixed_targets);
                event["site"]["resolution_status"] = serde_json::json!("candidates");
                event["site"]["precision"] = serde_json::json!("overapprox");
            } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
                event["edge"]["resolution_status"] = serde_json::json!("candidates");
                event["edge"]["precision"] = serde_json::json!("overapprox");
            }
            if matches!(
                event["event"].as_str(),
                Some("profile_completed" | "scan_completed")
            ) {
                event["coverage"]["resolved"] = serde_json::json!(2);
                event["coverage"]["candidates"] = serde_json::json!(1);
            }
        }
        let mut definition_edge = mixed_repository_and_definition_targets
            .iter()
            .find(|event| event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id)
            .expect("semantic import edge")
            .clone();
        definition_edge["edge"]["target"] = serde_json::json!(definition_target);
        definition_edge["edge"]["id"] = serde_json::json!(depgraph_protocol::stable_id_from_value(
            "edge",
            &serde_json::json!({
                "kind":"imports",
                "site_id":site_id,
                "target":definition_target,
            }),
        ));
        let completion_index = mixed_repository_and_definition_targets
            .iter()
            .position(|event| event["event"] == "profile_completed")
            .expect("profile completion");
        mixed_repository_and_definition_targets.insert(completion_index, definition_edge);
        let profile = mixed_repository_and_definition_targets
            .iter_mut()
            .find(|event| event["event"] == "profile_declared")
            .expect("Web profile");
        let relation_count = profile["profile"]["properties"]["typescript_semantic_relation_count"]
            .as_str()
            .expect("semantic relation count")
            .parse::<usize>()?;
        profile["profile"]["properties"]["typescript_semantic_relation_count"] =
            serde_json::json!((relation_count + 1).to_string());
        cases.push((
            "mixed repository and definition targets",
            mixed_repository_and_definition_targets,
            "mixes repository module and canonical definition targets",
        ));

        let mut wrong_ownership = baseline.clone();
        wrong_ownership
            .iter_mut()
            .find(|event| event["node"]["properties"]["path"] == "src/index.ts")
            .expect("source file")["node"]["properties"]
            .as_object_mut()
            .expect("file properties")
            .remove("package_id");
        cases.push((
            "wrong source ownership",
            wrong_ownership,
            "disagree on package ownership",
        ));

        let mut wrong_external_provenance = baseline.clone();
        let external_identity = serde_json::json!({
            "language":"typescript",
            "compiler_version":TYPESCRIPT_COMPILER_VERSION,
            "locator":"npm:external-fixture",
        });
        let external_id = depgraph_protocol::stable_id_from_value("external", &external_identity);
        let completion_index = wrong_external_provenance
            .iter()
            .position(|event| event["event"] == "profile_completed")
            .expect("profile completion");
        wrong_external_provenance.insert(
            completion_index,
            serde_json::json!({
                "event":"node_upsert",
                "protocol_version":"1.0",
                "scan_id":"typescript-gate-scan",
                "adapter":"web",
                "adapter_version":env!("CARGO_PKG_VERSION"),
                "seq":0,
                "node":{
                    "id":external_id,
                    "kind":"external_system",
                    "locator":"external://typescript/npm%3Aexternal-fixture",
                    "display_name":"external-fixture",
                    "properties":{
                        "language":"typescript",
                        "external":true,
                        "canonical_identity":external_identity,
                        "profile_id":"web:other",
                        "compiler_version":TYPESCRIPT_COMPILER_VERSION,
                    },
                },
            }),
        );
        let site_id = wrong_external_provenance
            .iter()
            .find(|event| {
                event["event"] == "dependency_site" && event["site"]["kind"] == "web_import"
            })
            .expect("Web import site")["site"]["id"]
            .as_str()
            .expect("site ID")
            .to_owned();
        for event in &mut wrong_external_provenance {
            if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
                event["site"]["resolution_status"] = serde_json::json!("external");
                event["site"]["target_ids"] = serde_json::json!([external_id]);
                event["site"]["evidence"][0]["properties"]["target_basis"] =
                    serde_json::json!("external_boundary");
            } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
                event["edge"]["target"] = serde_json::json!(external_id);
                event["edge"]["resolution_status"] = serde_json::json!("external");
                event["edge"]["evidence"][0]["properties"]["target_basis"] =
                    serde_json::json!("external_boundary");
                event["edge"]["id"] = serde_json::json!(depgraph_protocol::stable_id_from_value(
                    "edge",
                    &serde_json::json!({
                        "kind":"imports",
                        "site_id":site_id,
                        "target":external_id,
                    }),
                ));
            }
            if matches!(
                event["event"].as_str(),
                Some("profile_completed" | "scan_completed")
            ) {
                event["coverage"]["resolved"] = serde_json::json!(2);
                event["coverage"]["external"] = serde_json::json!(1);
            }
        }
        let mut spoofed_external_presentation = wrong_external_provenance.clone();
        spoofed_external_presentation
            .iter_mut()
            .find(|event| event["event"] == "node_upsert" && event["node"]["id"] == external_id)
            .expect("external target")["node"]["properties"]["profile_id"] =
            serde_json::json!("web:default");
        cases.push((
            "spoofed external presentation",
            spoofed_external_presentation,
            "canonical profile-scoped TypeScript external_system sentinel",
        ));
        cases.push((
            "wrong external provenance",
            wrong_external_provenance,
            "canonical profile-scoped TypeScript external_system sentinel",
        ));

        let mut spoofed_unknown_identity = baseline.clone();
        let repository_identity = "test:web-repository";
        let workspace_id = depgraph_protocol::stable_id_from_value(
            "workspace",
            &serde_json::json!({"repository":repository_identity,"root":"."}),
        );
        let unknown_id = "unknown:spoofed";
        for node in [
            serde_json::json!({
                "id":workspace_id,
                "kind":"workspace",
                "locator":format!("workspace://{repository_identity}"),
                "display_name":"definition-fixture",
                "properties":{
                    "repository_identity":repository_identity,
                    "package_manager":"npm",
                    "safe_scan":true,
                },
            }),
            serde_json::json!({
                "id":unknown_id,
                "kind":"unknown_target",
                "locator":"unknown://web/unresolved-dependency",
                "display_name":"Unresolved web dependency",
                "properties":{"language":"web","profile_id":"web:default"},
            }),
        ]
        .into_iter()
        .rev()
        {
            spoofed_unknown_identity.insert(
                2,
                serde_json::json!({
                    "event":"node_upsert",
                    "protocol_version":"1.0",
                    "scan_id":"typescript-gate-scan",
                    "adapter":"web",
                    "adapter_version":env!("CARGO_PKG_VERSION"),
                    "seq":0,
                    "node":node,
                }),
            );
        }
        let site_id = spoofed_unknown_identity
            .iter()
            .find(|event| {
                event["event"] == "dependency_site" && event["site"]["kind"] == "web_import"
            })
            .expect("Web import site")["site"]["id"]
            .as_str()
            .expect("site ID")
            .to_owned();
        for event in &mut spoofed_unknown_identity {
            if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
                event["site"]["resolution_status"] = serde_json::json!("unresolved");
                event["site"]["precision"] = serde_json::json!("heuristic");
                event["site"]["reason"] = serde_json::json!("typechecker_target_unresolved");
                event["site"]["target_ids"] = serde_json::json!([unknown_id]);
                event["site"]["evidence"][0]["properties"]["target_basis"] =
                    serde_json::json!("unresolved");
            } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
                event["edge"]["target"] = serde_json::json!(unknown_id);
                event["edge"]["resolution_status"] = serde_json::json!("unresolved");
                event["edge"]["precision"] = serde_json::json!("heuristic");
                event["edge"]["evidence"][0]["properties"]["target_basis"] =
                    serde_json::json!("unresolved");
                event["edge"]["id"] = serde_json::json!(depgraph_protocol::stable_id_from_value(
                    "edge",
                    &serde_json::json!({
                        "kind":"imports",
                        "site_id":site_id,
                        "target":unknown_id,
                    }),
                ));
            }
            if matches!(
                event["event"].as_str(),
                Some("profile_completed" | "scan_completed")
            ) {
                event["coverage"]["resolved"] = serde_json::json!(2);
                event["coverage"]["unresolved"] = serde_json::json!(1);
                event["coverage"]["reasons"] = serde_json::json!(["typechecker_target_unresolved"]);
            }
        }
        cases.push((
            "spoofed unknown identity",
            spoofed_unknown_identity,
            "profile-scoped Web unknown_target sentinel",
        ));

        let mut wrong_condition = baseline.clone();
        wrong_condition
            .iter_mut()
            .find(|event| event["event"] == "edge_upsert" && event["edge"]["kind"] == "imports")
            .expect("semantic import edge")["edge"]["condition"] = serde_json::json!({
            "op":"eq",
            "key":"web.condition",
            "value":"spoofed",
        });
        cases.push((
            "condition mismatch",
            wrong_condition,
            "condition is not the union of its target edge conditions",
        ));

        let mut wrong_count = baseline.clone();
        wrong_count
            .iter_mut()
            .find(|event| event["event"] == "profile_declared")
            .expect("profile")["profile"]["properties"][TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY] =
            serde_json::json!("99");
        cases.push((
            "semantic site count mismatch",
            wrong_count,
            TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY,
        ));

        for (name, mut events, expected_error) in cases {
            resequence_test_protocol(&mut events);
            let parsed = parse_events_preserving_prefix(
                &serialize_test_protocol(events)?,
                "typescript-gate-scan",
                "web",
                &root,
                64 * 1024,
                Some(env!("CARGO_PKG_VERSION")),
                Some(false),
            );
            assert_eq!(
                parsed.failure_kind,
                Some(WorkerFailureKind::MalformedProtocol),
                "{name}: {:?}",
                parsed.error
            );
            assert!(parsed.security_violation, "{name}: {:?}", parsed.error);
            assert!(
                parsed
                    .error
                    .as_deref()
                    .is_some_and(|error| error.contains(expected_error)),
                "{name}: {:?}",
                parsed.error
            );
        }
        Ok(())
    }

    #[test]
    fn web_import_type_late_failure_atomically_discards_semantics_and_keeps_syntax() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut events = test_protocol_values(typescript_import_type_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        let source_file_id = events
            .iter()
            .find(|event| event["node"]["properties"]["path"] == "src/index.ts")
            .expect("source file")["node"]["id"]
            .as_str()
            .expect("source file ID")
            .to_owned();
        let target_file_id = events
            .iter()
            .find(|event| event["node"]["properties"]["path"] == "src/target.ts")
            .expect("target file")["node"]["id"]
            .as_str()
            .expect("target file ID")
            .to_owned();
        let source_site_id = "site:syntax-import-survives";
        let source_edge_id = "edge:syntax-import-survives";
        let source_evidence = serde_json::json!({
            "kind":"source",
            "extractor":"typescript-static",
            "extractor_version":TYPESCRIPT_COMPILER_VERSION,
            "path":"src/index.ts",
            "start_line":1,
            "start_column":1,
            "end_line":1,
            "end_column":8,
            "properties":{},
        });
        let insert_at = events
            .iter()
            .position(|event| event["event"] == "profile_completed")
            .expect("profile completion");
        events.insert(
            insert_at,
            serde_json::json!({
                "event":"dependency_site",
                "site":{
                    "id":source_site_id,
                    "source":source_file_id,
                    "kind":"import",
                    "specifier":"./target",
                    "resolution_status":"resolved",
                    "target_ids":[target_file_id],
                    "profile_id":"web:default",
                    "condition":{"op":"all","conditions":[]},
                    "precision":"exact",
                    "evidence":[source_evidence],
                },
            }),
        );
        events.insert(
            insert_at + 1,
            serde_json::json!({
                "event":"edge_upsert",
                "edge":{
                    "id":source_edge_id,
                    "source":source_file_id,
                    "target":target_file_id,
                    "kind":"imports",
                    "site_id":source_site_id,
                    "phase":"source",
                    "environment":"any",
                    "profile_id":"web:default",
                    "condition":{"op":"all","conditions":[]},
                    "resolution_status":"resolved",
                    "precision":"exact",
                    "generated":false,
                    "evidence":[source_evidence],
                },
            }),
        );
        for event in &mut events {
            if matches!(
                event["event"].as_str(),
                Some("profile_completed" | "scan_completed")
            ) {
                event["coverage"]["dependency_sites"] = serde_json::json!(4);
                event["coverage"]["resolved"] = serde_json::json!(4);
            }
        }

        let external_id = "external-system:web:semantic-only";
        events.insert(
            insert_at,
            serde_json::json!({
                "event":"node_upsert",
                "node":{
                    "id":external_id,
                    "kind":"external_system",
                    "locator":"package://semantic-only@1.0.0",
                    "display_name":"semantic-only",
                    "properties":{
                        "workspace":false,
                        "external":true,
                    },
                },
            }),
        );
        let semantic_site_id = events
            .iter()
            .find(|event| {
                event["event"] == "dependency_site" && event["site"]["kind"] == "web_import"
            })
            .expect("semantic import site")["site"]["id"]
            .as_str()
            .expect("semantic site ID")
            .to_owned();
        for event in &mut events {
            if event["event"] == "dependency_site" && event["site"]["id"] == semantic_site_id {
                event["site"]["resolution_status"] = serde_json::json!("external");
                event["site"]["target_ids"] = serde_json::json!([external_id]);
                event["site"]["evidence"][0]["properties"]["target_basis"] =
                    serde_json::json!("external_boundary");
            } else if event["event"] == "edge_upsert"
                && event["edge"]["site_id"] == semantic_site_id
            {
                event["edge"]["target"] = serde_json::json!(external_id);
                event["edge"]["resolution_status"] = serde_json::json!("external");
                event["edge"]["evidence"][0]["properties"]["target_basis"] =
                    serde_json::json!("external_boundary");
                event["edge"]["id"] = serde_json::json!(depgraph_protocol::stable_id_from_value(
                    "edge",
                    &serde_json::json!({
                        "kind":"imports",
                        "site_id":semantic_site_id,
                        "target":external_id,
                    }),
                ));
            }
        }
        for event in &mut events {
            if matches!(
                event["event"].as_str(),
                Some("profile_completed" | "scan_completed")
            ) {
                event["coverage"]["resolved"] = serde_json::json!(3);
                event["coverage"]["external"] = serde_json::json!(1);
            }
        }
        promote_typescript_semantic_complete(&mut events, TYPESCRIPT_RELEASE_GATE_PENDING);
        events
            .iter_mut()
            .find(|event| event["event"] == "profile_declared")
            .expect("profile")["profile"]["properties"][TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY] =
            serde_json::json!("99");
        for event in &mut events {
            event["protocol_version"] = serde_json::json!("1.0");
            event["scan_id"] = serde_json::json!("typescript-gate-scan");
            event["adapter"] = serde_json::json!("web");
            event["adapter_version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
        }
        resequence_test_protocol(&mut events);
        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation, "{:?}", parsed.error);
        let discarded_profile = parsed
            .events
            .iter()
            .find(|event| event["event"] == "profile_declared")
            .expect("discarded Web profile");
        let properties = &discarded_profile["profile"]["properties"];
        assert_eq!(
            properties[TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY],
            "definition-import-type-call-graph-discarded"
        );
        assert_eq!(properties[TYPESCRIPT_DEFINITION_STATUS_PROPERTY], "failed");
        for property in [
            "typescript_semantic_node_count",
            "typescript_semantic_relation_count",
            "typescript_semantic_diagnostics",
            "typescript_emitted_semantic_diagnostics",
            "typescript_semantic_issue_count",
            TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY,
            TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY,
        ] {
            assert_eq!(properties[property], "0", "{property}");
        }
        assert!(!parsed.events.iter().any(|event| {
            matches!(
                event["event"].as_str(),
                Some("file_completed" | "profile_completed" | "scan_completed")
            )
        }));
        assert!(!parsed.events.iter().any(|event| {
            event["coverage"]["completeness"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value == "semantic-complete"))
        }));
        assert!(parsed.events.iter().any(|event| {
            event["event"] == "dependency_site" && event["site"]["id"] == source_site_id
        }));
        assert!(parsed.events.iter().any(|event| {
            event["event"] == "edge_upsert" && event["edge"]["id"] == source_edge_id
        }));
        assert!(!parsed.events.iter().any(|event| {
            matches!(event["node"]["kind"].as_str(), Some("symbol" | "type"))
                || event["node"]["id"] == external_id
                || (event["event"] == "dependency_site"
                    && event["site"]["evidence"][0]["kind"] == "semantic")
                || (event["event"] == "edge_upsert" && event["edge"]["phase"] == "semantic")
        }));
        assert!(parsed.events.iter().any(|event| {
            event["event"] == "node_upsert" && event["node"]["id"] == source_file_id
        }));
        assert!(parsed.events.iter().any(|event| {
            event["event"] == "node_upsert" && event["node"]["id"] == target_file_id
        }));
        Ok(())
    }

    #[test]
    fn web_rejected_semantic_node_id_collision_keeps_existing_syntax_graph() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut events = test_protocol_values(typescript_import_type_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        let source_file_id = events
            .iter()
            .find(|event| event["node"]["properties"]["path"] == "src/index.ts")
            .expect("source file")["node"]["id"]
            .as_str()
            .expect("source file ID")
            .to_owned();
        let target_file_id = events
            .iter()
            .find(|event| event["node"]["properties"]["path"] == "src/target.ts")
            .expect("target file")["node"]["id"]
            .as_str()
            .expect("target file ID")
            .to_owned();
        let source_site_id = "site:syntax-import-survives-semantic-id-collision";
        let source_edge_id = "edge:syntax-import-survives-semantic-id-collision";
        let source_evidence = serde_json::json!({
            "kind":"source",
            "extractor":"typescript-static",
            "extractor_version":TYPESCRIPT_COMPILER_VERSION,
            "path":"src/index.ts",
            "start_line":1,
            "start_column":1,
            "end_line":1,
            "end_column":8,
            "properties":{},
        });
        let insert_at = events
            .iter()
            .position(|event| event["event"] == "profile_completed")
            .expect("profile completion");
        events.insert(
            insert_at,
            serde_json::json!({
                "event":"dependency_site",
                "site":{
                    "id":source_site_id,
                    "source":source_file_id,
                    "kind":"import",
                    "specifier":"./target",
                    "resolution_status":"resolved",
                    "target_ids":[target_file_id],
                    "profile_id":"web:default",
                    "condition":{"op":"all","conditions":[]},
                    "precision":"exact",
                    "evidence":[source_evidence],
                },
            }),
        );
        events.insert(
            insert_at + 1,
            serde_json::json!({
                "event":"edge_upsert",
                "edge":{
                    "id":source_edge_id,
                    "source":source_file_id,
                    "target":target_file_id,
                    "kind":"imports",
                    "site_id":source_site_id,
                    "phase":"source",
                    "environment":"any",
                    "profile_id":"web:default",
                    "condition":{"op":"all","conditions":[]},
                    "resolution_status":"resolved",
                    "precision":"exact",
                    "generated":false,
                    "evidence":[source_evidence],
                },
            }),
        );

        let mut colliding_semantic_node = events
            .iter()
            .find(|event| matches!(event["node"]["kind"].as_str(), Some("symbol" | "type")))
            .expect("semantic node")
            .clone();
        colliding_semantic_node["node"]["id"] = serde_json::json!(source_file_id);
        events.insert(insert_at + 2, colliding_semantic_node);
        for event in &mut events {
            event["protocol_version"] = serde_json::json!("1.0");
            event["scan_id"] = serde_json::json!("typescript-gate-scan");
            event["adapter"] = serde_json::json!("web");
            event["adapter_version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
        }
        resequence_test_protocol(&mut events);

        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation, "{:?}", parsed.error);
        assert!(parsed.events.iter().any(|event| {
            event["event"] == "node_upsert"
                && event["node"]["id"] == source_file_id
                && event["node"]["kind"] == "file"
        }));
        assert!(parsed.events.iter().any(|event| {
            event["event"] == "dependency_site" && event["site"]["id"] == source_site_id
        }));
        assert!(parsed.events.iter().any(|event| {
            event["event"] == "edge_upsert" && event["edge"]["id"] == source_edge_id
        }));
        assert!(!parsed.events.iter().any(|event| {
            event["event"] == "node_upsert"
                && event["node"]["id"] == source_file_id
                && matches!(event["node"]["kind"].as_str(), Some("symbol" | "type"))
        }));
        Ok(())
    }

    #[test]
    fn web_import_type_malformed_prefix_discards_orphan_semantic_sentinels() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut events = test_protocol_values(typescript_gate_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        let properties = &mut events
            .iter_mut()
            .find(|event| event["event"] == "profile_declared")
            .expect("Web profile")["profile"]["properties"];
        properties[TYPESCRIPT_ANALYSIS_MODE_PROPERTY] =
            serde_json::json!(TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_GRAPH);
        properties[TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY] =
            serde_json::json!(TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_GRAPH_V1);
        properties[TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY] =
            serde_json::json!("definition-import-type-graph-emitted");
        properties[TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY] = serde_json::json!("0");
        let external_identity = serde_json::json!({
            "language":"typescript",
            "compiler_version":TYPESCRIPT_COMPILER_VERSION,
            "locator":"npm:orphan",
        });
        let external_id = depgraph_protocol::stable_id_from_value("external", &external_identity);
        let unknown_id = "unknown:web:orphan";
        for node in [
            serde_json::json!({
                "id":external_id,
                "kind":"external_system",
                "locator":"external://typescript/npm%3Aorphan",
                "display_name":"orphan",
                "properties":{
                    "language":"typescript",
                    "external":true,
                    "canonical_identity":external_identity,
                    "profile_id":"web:default",
                    "compiler_version":TYPESCRIPT_COMPILER_VERSION,
                },
            }),
            serde_json::json!({
                "id":unknown_id,
                "kind":"unknown_target",
                "locator":"unknown://web/unresolved-dependency",
                "display_name":"Unresolved web dependency",
                "properties":{"language":"web","profile_id":"web:default"},
            }),
        ]
        .into_iter()
        .rev()
        {
            events.insert(2, serde_json::json!({"event":"node_upsert","node":node}));
        }
        let malformed = events
            .iter_mut()
            .find(|event| event["event"] == "profile_completed")
            .expect("profile completion");
        malformed["adapter_version"] = serde_json::json!("spoofed-version");
        for event in &mut events {
            event["protocol_version"] = serde_json::json!("1.0");
            event["scan_id"] = serde_json::json!("typescript-gate-scan");
            event["adapter"] = serde_json::json!("web");
            if event["event"] != "profile_completed" {
                event["adapter_version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
            }
        }
        resequence_test_protocol(&mut events);
        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation, "{:?}", parsed.error);
        assert!(
            parsed
                .error
                .as_deref()
                .is_some_and(|error| error.contains("adapter_version mismatch")),
            "{:?}",
            parsed.error
        );
        assert!(!parsed.events.iter().any(|event| {
            event["node"]["id"] == external_id || event["node"]["id"] == unknown_id
        }));
        assert!(
            parsed
                .events
                .iter()
                .any(|event| event["event"] == "profile_declared")
        );
        Ok(())
    }

    #[test]
    fn web_definition_graph_rejects_and_discards_out_of_capability_delta() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let serialized = |events: Vec<Value>| -> Result<Vec<u8>> {
            let mut output = Vec::new();
            for event in events {
                serde_json::to_writer(&mut output, &event)?;
                output.push(b'\n');
            }
            Ok(output)
        };
        let parsed_values = |output: Vec<u8>| -> Result<Vec<Value>> {
            Ok(String::from_utf8(output)?
                .lines()
                .map(serde_json::from_str)
                .collect::<std::result::Result<_, _>>()?)
        };

        let mut forbidden_call = parsed_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        forbidden_call
            .iter_mut()
            .find(|event| event["event"] == "edge_upsert")
            .expect("definition edge")["edge"]["kind"] = serde_json::json!("calls");

        let mut wrong_hash = parsed_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        wrong_hash
            .iter_mut()
            .find(|event| event["event"] == "edge_upsert")
            .expect("definition edge")["edge"]["id"] =
            serde_json::json!(format!("edge:sha256:{}", "0".repeat(64)));

        let mut wrong_extractor = parsed_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        wrong_extractor
            .iter_mut()
            .find(|event| event["event"] == "edge_upsert")
            .expect("definition edge")["edge"]["evidence"][0]["extractor"] =
            serde_json::json!("typescript-static");

        let mut wrong_count = parsed_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        wrong_count[1]["profile"]["properties"]["typescript_semantic_node_count"] =
            serde_json::json!("99");

        let mut linked_relation = parsed_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        linked_relation
            .iter_mut()
            .find(|event| event["event"] == "edge_upsert")
            .expect("definition edge")["edge"]["site_id"] =
            serde_json::json!("site:sha256:forbidden");

        let mut candidate_relation = parsed_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        let candidate = candidate_relation
            .iter_mut()
            .find(|event| event["event"] == "edge_upsert")
            .expect("definition edge");
        candidate["edge"]["resolution_status"] = serde_json::json!("candidates");
        candidate["edge"]["precision"] = serde_json::json!("overapprox");

        let mut semantic_site = parsed_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        let edge_index = semantic_site
            .iter()
            .position(|event| event["event"] == "edge_upsert")
            .expect("definition edge index");
        semantic_site.insert(
            edge_index,
            serde_json::json!({
                "event":"dependency_site",
                "protocol_version":"1.0",
                "scan_id":"typescript-gate-scan",
                "adapter":"web",
                "adapter_version":env!("CARGO_PKG_VERSION"),
                "seq":0,
                "site":{
                    "id":"site:sha256:forbidden",
                    "source":"package:sha256:definition-fixture",
                    "kind":"call",
                    "specifier":"forbidden",
                    "resolution_status":"resolved",
                    "target_ids":["package:sha256:definition-fixture"],
                    "profile_id":"web:default",
                    "condition":{"op":"all","conditions":[]},
                    "precision":"exact",
                    "evidence":[{
                        "kind":"semantic",
                        "extractor":TYPESCRIPT_SEMANTIC_EXTRACTOR,
                        "extractor_version":TYPESCRIPT_COMPILER_VERSION,
                        "path":"src/index.ts",
                        "start_line":1,
                        "start_column":1,
                        "end_line":1,
                        "end_column":9
                    }]
                }
            }),
        );
        for (index, event) in semantic_site.iter_mut().enumerate() {
            event["seq"] = serde_json::json!(index + 1);
        }

        let mut external_package = parsed_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        external_package
            .iter_mut()
            .find(|event| event["node"]["kind"] == "package_instance")
            .expect("workspace package")["node"]["properties"]["workspace"] =
            serde_json::json!(false);

        let mut wrong_package_id = parsed_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        wrong_package_id
            .iter_mut()
            .find(|event| matches!(event["node"]["kind"].as_str(), Some("symbol" | "type")))
            .expect("semantic node")["node"]["properties"]["package_id"] =
            serde_json::json!(format!("package:sha256:{}", "f".repeat(64)));

        let mut ghost_evidence = parsed_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        let ghost_edge = &mut ghost_evidence
            .iter_mut()
            .find(|event| event["event"] == "edge_upsert")
            .expect("definition edge")["edge"];
        ghost_edge["evidence"][0]["path"] = serde_json::json!("src/ghost.ts");
        let ghost_identity = serde_json::json!({
            "condition": ghost_edge["condition"].clone(),
            "kind": ghost_edge["kind"].clone(),
            "path": ghost_edge["evidence"][0]["path"].clone(),
            "profile_id": ghost_edge["profile_id"].clone(),
            "source": ghost_edge["source"].clone(),
            "span": {
                "end_column": ghost_edge["evidence"][0]["end_column"].clone(),
                "end_line": ghost_edge["evidence"][0]["end_line"].clone(),
                "start_column": ghost_edge["evidence"][0]["start_column"].clone(),
                "start_line": ghost_edge["evidence"][0]["start_line"].clone(),
            },
            "target": ghost_edge["target"].clone(),
        });
        ghost_edge["id"] = serde_json::json!(depgraph_protocol::stable_id_from_value(
            "edge",
            &ghost_identity,
        ));

        let mut orphan_node = parsed_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        orphan_node.retain(|event| event["event"] != "edge_upsert");
        orphan_node[1]["profile"]["properties"]["typescript_semantic_relation_count"] =
            serde_json::json!("0");
        for (index, event) in orphan_node.iter_mut().enumerate() {
            event["seq"] = serde_json::json!(index + 1);
        }

        let mut wrong_issue_count = parsed_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        wrong_issue_count[1]["profile"]["properties"]["typescript_semantic_issue_count"] =
            serde_json::json!("1");

        let mut invalid_node_shape = parsed_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        invalid_node_shape
            .iter_mut()
            .find(|event| matches!(event["node"]["kind"].as_str(), Some("symbol" | "type")))
            .expect("semantic node")["node"]["locator"] = serde_json::json!("");

        let mut discarded_profile = parsed_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        discarded_profile[1]["profile"]["properties"][TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY] =
            serde_json::json!("definition-graph-discarded");
        discarded_profile[1]["profile"]["properties"][TYPESCRIPT_DEFINITION_STATUS_PROPERTY] =
            serde_json::json!("failed");

        for (name, events) in [
            ("forbidden call", forbidden_call),
            ("wrong canonical hash", wrong_hash),
            ("wrong semantic extractor", wrong_extractor),
            ("wrong semantic count", wrong_count),
            ("linked definition relation", linked_relation),
            ("candidate definition relation", candidate_relation),
            ("semantic dependency site", semantic_site),
            ("external package ownership", external_package),
            ("wrong package ID", wrong_package_id),
            ("ghost evidence file", ghost_evidence),
            ("orphan semantic node", orphan_node),
            ("wrong semantic issue count", wrong_issue_count),
            ("invalid semantic node shape", invalid_node_shape),
            ("discarded profile emitted a delta", discarded_profile),
        ] {
            let output = serialized(events)?;
            let parsed = parse_events_preserving_prefix(
                &output,
                "typescript-gate-scan",
                "web",
                &root,
                16 * 1024,
                Some(env!("CARGO_PKG_VERSION")),
                Some(false),
            );
            assert_eq!(
                parsed.failure_kind,
                Some(WorkerFailureKind::MalformedProtocol),
                "{name}: {:?}",
                parsed.error
            );
            assert!(parsed.security_violation, "{name}: {:?}", parsed.error);
            assert!(parsed.error.is_some(), "{name}");
            assert!(
                !parsed.events.iter().any(|event| {
                    matches!(event["node"]["kind"].as_str(), Some("symbol" | "type"))
                        || event["edge"]["phase"] == "semantic"
                }),
                "{name}: semantic delta survived an atomic rejection"
            );
            assert!(
                parsed.events.iter().any(|event| {
                    event["event"] == "node_upsert" && event["node"]["kind"] == "package_instance"
                }),
                "{name}: syntax/package graph was not retained"
            );
        }
        Ok(())
    }

    #[test]
    fn web_definition_graph_rejects_compromised_canonical_references_and_shapes() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let protocol = |relation_kind| {
            test_protocol_values(typescript_definition_protocol(
                &root,
                TYPESCRIPT_RELEASE_GATE_PENDING,
                relation_kind,
            )?)
        };
        let mut cases = Vec::<(&str, Vec<Value>, &str)>::new();

        let mut dangling_origin = protocol("instantiates")?;
        let origin_resolver = dangling_origin
            .iter()
            .find(|event| {
                event["node"]["properties"]["type_kind"] == "generic_instance"
            })
            .expect("generic instance")["node"]["properties"]["canonical_identity"]
            ["generic_origin"]
            .as_str()
            .expect("generic origin resolver")
            .to_owned();
        let origin_id = dangling_origin
            .iter()
            .find(|event| {
                event["node"]["properties"]["canonical_identity"]["resolver_identity"].as_str()
                    == Some(origin_resolver.as_str())
            })
            .expect("generic origin node")["node"]["id"]
            .as_str()
            .expect("generic origin ID")
            .to_owned();
        dangling_origin.retain(|event| {
            event["node"]["id"].as_str() != Some(origin_id.as_str())
                && event["edge"]["target"].as_str() != Some(origin_id.as_str())
        });
        sync_test_semantic_counts(&mut dangling_origin);
        resequence_test_protocol(&mut dangling_origin);
        cases.push((
            "dangling generic origin",
            dangling_origin,
            "missing generic origin",
        ));

        let mut dangling_argument = protocol("instantiates")?;
        rewrite_test_generic_instance(
            &mut dangling_argument,
            serde_json::json!([{
                "kind": "definition",
                "resolver_identity": "npm:missing::type",
            }]),
            None,
        );
        cases.push((
            "dangling generic type argument",
            dangling_argument,
            "references missing semantic definition",
        ));

        let mut mismatched_resolver = protocol("instantiates")?;
        rewrite_test_generic_instance(
            &mut mismatched_resolver,
            serde_json::json!([{"kind": "intrinsic", "name": "string"}]),
            Some("generic:[\"spoofed\",[]]".to_owned()),
        );
        cases.push((
            "mismatched reconstructed resolver",
            mismatched_resolver,
            "resolver identity does not match",
        ));

        let mut missing_intrinsic_name = protocol("instantiates")?;
        rewrite_test_generic_instance(
            &mut missing_intrinsic_name,
            serde_json::json!([{"kind": "intrinsic"}]),
            None,
        );
        cases.push((
            "missing intrinsic name",
            missing_intrinsic_name,
            "non-canonical shape",
        ));

        let mut non_canonical_bigint = protocol("instantiates")?;
        rewrite_test_generic_instance(
            &mut non_canonical_bigint,
            serde_json::json!([{
                "kind": "literal",
                "value_kind": "bigint",
                "value": "00",
            }]),
            None,
        );
        cases.push((
            "non-canonical bigint literal",
            non_canonical_bigint,
            "non-canonical \"bigint\" literal",
        ));

        let mut oversized_descriptor = protocol("instantiates")?;
        rewrite_test_generic_instance(
            &mut oversized_descriptor,
            serde_json::json!([{
                "kind": "literal",
                "value_kind": "string",
                "value": "x".repeat(TYPESCRIPT_MAX_TYPE_DESCRIPTOR_CHARS + 1),
            }]),
            None,
        );
        cases.push((
            "oversized descriptor",
            oversized_descriptor,
            "exceeds 2048 characters",
        ));

        let mut reordered_descriptor = protocol("instantiates")?;
        let mut reordered_intrinsic = serde_json::Map::new();
        reordered_intrinsic.insert("name".to_owned(), serde_json::json!("string"));
        reordered_intrinsic.insert("kind".to_owned(), serde_json::json!("intrinsic"));
        rewrite_test_generic_instance(
            &mut reordered_descriptor,
            Value::Array(vec![Value::Object(reordered_intrinsic)]),
            None,
        );
        cases.push((
            "reordered descriptor resolver",
            reordered_descriptor,
            "resolver identity does not match",
        ));

        let mut non_generic_metadata = protocol("extends")?;
        let non_generic_index = non_generic_metadata
            .iter()
            .position(|event| event["node"]["properties"]["type_kind"] == "class")
            .expect("non-generic class");
        non_generic_metadata[non_generic_index]["node"]["properties"]["canonical_identity"]["generic_origin"] =
            serde_json::json!("spoofed-origin");
        non_generic_metadata[non_generic_index]["node"]["properties"]["canonical_identity"]["type_arguments"] =
            serde_json::json!([{"kind": "intrinsic", "name": "string"}]);
        non_generic_metadata[non_generic_index]["node"]["properties"]["generic_origin"] =
            serde_json::json!("spoofed-origin");
        non_generic_metadata[non_generic_index]["node"]["properties"]["type_arguments"] =
            serde_json::json!([{"kind": "intrinsic", "name": "string"}]);
        refresh_test_semantic_node_id(&mut non_generic_metadata, non_generic_index);
        cases.push((
            "non-generic type metadata",
            non_generic_metadata,
            "non-generic type",
        ));

        let mut mismatched_top_resolver = protocol("declares")?;
        let named_index = mismatched_top_resolver
            .iter()
            .position(|event| event["node"]["kind"] == "symbol")
            .expect("named symbol");
        mismatched_top_resolver[named_index]["node"]["properties"]["resolver_identity"] =
            serde_json::json!("spoofed-resolver");
        cases.push((
            "mismatched named resolver",
            mismatched_top_resolver,
            "top-level resolver",
        ));

        let mut extra_identity_field = protocol("declares")?;
        let extra_identity_index = extra_identity_field
            .iter()
            .position(|event| event["node"]["kind"] == "symbol")
            .expect("named symbol");
        extra_identity_field[extra_identity_index]["node"]["properties"]["canonical_identity"]["nonce"] =
            serde_json::json!(true);
        refresh_test_semantic_node_id(&mut extra_identity_field, extra_identity_index);
        cases.push((
            "extra canonical identity field",
            extra_identity_field,
            "canonical identity shape",
        ));

        let mut absolute_resolver = protocol("declares")?;
        let absolute_resolver_index = absolute_resolver
            .iter()
            .position(|event| event["node"]["kind"] == "symbol")
            .expect("named symbol");
        let resolver = "/Users/alice/project/src/index.ts#Definition";
        absolute_resolver[absolute_resolver_index]["node"]["properties"]["canonical_identity"]["resolver_identity"] =
            serde_json::json!(resolver);
        absolute_resolver[absolute_resolver_index]["node"]["properties"]["resolver_identity"] =
            serde_json::json!(resolver);
        refresh_test_semantic_node_id(&mut absolute_resolver, absolute_resolver_index);
        cases.push((
            "absolute path resolver",
            absolute_resolver,
            "canonical identity shape",
        ));

        let mut wrong_local_origin_field = protocol("declares")?;
        let file_id = wrong_local_origin_field
            .iter()
            .find(|event| event["node"]["kind"] == "file")
            .expect("source file")["node"]["id"]
            .as_str()
            .expect("source file ID")
            .to_owned();
        let local_index = wrong_local_origin_field
            .iter()
            .position(|event| event["node"]["kind"] == "symbol")
            .expect("symbol node");
        {
            let node = &mut wrong_local_origin_field[local_index]["node"];
            let source_span = node["properties"]["source_span"].clone();
            node["properties"]["symbol_kind"] = serde_json::json!("local_function");
            node["properties"]
                .as_object_mut()
                .expect("symbol properties")
                .remove("resolver_identity");
            let identity = node["properties"]["canonical_identity"]
                .as_object_mut()
                .expect("symbol identity");
            identity.insert(
                "symbol_kind".to_owned(),
                serde_json::json!("local_function"),
            );
            identity.insert("identity_kind".to_owned(), serde_json::json!("local"));
            identity.remove("resolver_identity");
            identity.insert("generated_from".to_owned(), serde_json::json!(file_id));
            identity.insert(
                "relative_path".to_owned(),
                serde_json::json!("src/index.ts"),
            );
            identity.insert("span".to_owned(), source_span);
        }
        refresh_test_semantic_node_id(&mut wrong_local_origin_field, local_index);
        cases.push((
            "local symbol with anonymous origin field",
            wrong_local_origin_field,
            "wrong canonical origin field",
        ));

        let mut incompatible_anonymous_origin = protocol("declares")?;
        let package_id = incompatible_anonymous_origin
            .iter()
            .find(|event| event["node"]["kind"] == "package_instance")
            .expect("package node")["node"]["id"]
            .as_str()
            .expect("package ID")
            .to_owned();
        let anonymous_index = incompatible_anonymous_origin
            .iter()
            .position(|event| event["node"]["kind"] == "symbol")
            .expect("symbol node");
        {
            let node = &mut incompatible_anonymous_origin[anonymous_index]["node"];
            let source_span = node["properties"]["source_span"].clone();
            node["properties"]["symbol_kind"] = serde_json::json!("anonymous_function");
            node["properties"]
                .as_object_mut()
                .expect("symbol properties")
                .remove("resolver_identity");
            let identity = node["properties"]["canonical_identity"]
                .as_object_mut()
                .expect("symbol identity");
            identity.insert(
                "symbol_kind".to_owned(),
                serde_json::json!("anonymous_function"),
            );
            identity.insert("identity_kind".to_owned(), serde_json::json!("anonymous"));
            identity.remove("resolver_identity");
            identity.insert("generated_from".to_owned(), serde_json::json!(package_id));
            identity.insert(
                "relative_path".to_owned(),
                serde_json::json!("src/index.ts"),
            );
            identity.insert("span".to_owned(), source_span);
        }
        refresh_test_semantic_node_id(&mut incompatible_anonymous_origin, anonymous_index);
        cases.push((
            "anonymous symbol with incompatible origin",
            incompatible_anonymous_origin,
            "incompatible kind, package, or language",
        ));

        let mut unknown_kind = protocol("declares")?;
        let unknown_index = unknown_kind
            .iter()
            .position(|event| event["node"]["kind"] == "symbol")
            .expect("symbol node");
        unknown_kind[unknown_index]["node"]["properties"]["symbol_kind"] =
            serde_json::json!("namespace");
        unknown_kind[unknown_index]["node"]["properties"]["canonical_identity"]["symbol_kind"] =
            serde_json::json!("namespace");
        refresh_test_semantic_node_id(&mut unknown_kind, unknown_index);
        cases.push((
            "unsupported semantic kind",
            unknown_kind,
            "unsupported symbol",
        ));

        let mut source_edge = protocol("declares")?;
        let edge = &mut source_edge
            .iter_mut()
            .find(|event| event["event"] == "edge_upsert")
            .expect("definition edge")["edge"];
        edge["kind"] = serde_json::json!("imports");
        edge["phase"] = serde_json::json!("source");
        edge["evidence"][0]["kind"] = serde_json::json!("source");
        rehash_test_definition_edge(edge);
        cases.push((
            "source edge incident to a definition",
            source_edge,
            "must use phase=semantic",
        ));

        let mut incident_site = protocol("declares")?;
        let site_source = incident_site
            .iter()
            .find(|event| event["node"]["kind"] == "file")
            .expect("source file")["node"]["id"]
            .clone();
        let site_target = incident_site
            .iter()
            .find(|event| event["node"]["kind"] == "symbol")
            .expect("semantic symbol")["node"]["id"]
            .clone();
        let edge_index = incident_site
            .iter()
            .position(|event| event["event"] == "edge_upsert")
            .expect("definition edge");
        incident_site.insert(
            edge_index,
            serde_json::json!({
                "event": "dependency_site",
                "protocol_version": "1.0",
                "scan_id": "typescript-gate-scan",
                "adapter": "web",
                "adapter_version": env!("CARGO_PKG_VERSION"),
                "seq": 0,
                "site": {
                    "id": format!("site:sha256:{}", "1".repeat(64)),
                    "source": site_source,
                    "kind": "import",
                    "specifier": "./semantic",
                    "resolution_status": "resolved",
                    "target_ids": [site_target],
                    "profile_id": "web:default",
                    "condition": {"op": "all", "conditions": []},
                    "precision": "exact",
                    "evidence": [{
                        "kind": "source",
                        "extractor": "typescript-static",
                        "extractor_version": "1",
                        "path": "src/index.ts",
                        "start_line": 1,
                        "start_column": 1,
                        "end_line": 1,
                        "end_column": 9
                    }]
                }
            }),
        );
        resequence_test_protocol(&mut incident_site);
        cases.push((
            "dependency site incident to a definition",
            incident_site,
            "forbidden semantic dependency site",
        ));

        let mut semantic_source_site = protocol("declares")?;
        let site_source = semantic_source_site
            .iter()
            .find(|event| event["node"]["kind"] == "symbol")
            .expect("semantic symbol")["node"]["id"]
            .clone();
        let site_target = semantic_source_site
            .iter()
            .find(|event| event["node"]["kind"] == "file")
            .expect("source file")["node"]["id"]
            .clone();
        let edge_index = semantic_source_site
            .iter()
            .position(|event| event["event"] == "edge_upsert")
            .expect("definition edge");
        semantic_source_site.insert(
            edge_index,
            serde_json::json!({
                "event": "dependency_site",
                "protocol_version": "1.0",
                "scan_id": "typescript-gate-scan",
                "adapter": "web",
                "adapter_version": env!("CARGO_PKG_VERSION"),
                "seq": 0,
                "site": {
                    "id": format!("site:sha256:{}", "4".repeat(64)),
                    "source": site_source,
                    "kind": "import",
                    "specifier": "./syntax",
                    "resolution_status": "resolved",
                    "target_ids": [site_target],
                    "profile_id": "web:default",
                    "condition": {"op": "all", "conditions": []},
                    "precision": "exact",
                    "evidence": [{
                        "kind": "source",
                        "extractor": "typescript-static",
                        "extractor_version": "1",
                        "path": "src/index.ts",
                        "start_line": 1,
                        "start_column": 1,
                        "end_line": 1,
                        "end_column": 9
                    }]
                }
            }),
        );
        resequence_test_protocol(&mut semantic_source_site);
        cases.push((
            "dependency site sourced by a definition",
            semantic_source_site,
            "forbidden semantic dependency site",
        ));

        for (name, events, expected_error) in cases {
            let semantic_ids = events
                .iter()
                .filter_map(|event| {
                    matches!(event["node"]["kind"].as_str(), Some("symbol" | "type"))
                        .then(|| event["node"]["id"].as_str().map(str::to_owned))
                        .flatten()
                })
                .collect::<BTreeSet<_>>();
            let output = serialize_test_protocol(events)?;
            let parsed = parse_events_preserving_prefix(
                &output,
                "typescript-gate-scan",
                "web",
                &root,
                64 * 1024,
                Some(env!("CARGO_PKG_VERSION")),
                Some(false),
            );
            assert_eq!(
                parsed.failure_kind,
                Some(WorkerFailureKind::MalformedProtocol),
                "{name}: {:?}",
                parsed.error
            );
            assert!(parsed.security_violation, "{name}: {:?}", parsed.error);
            assert!(
                parsed
                    .error
                    .as_deref()
                    .is_some_and(|error| error.contains(expected_error)),
                "{name}: {:?}",
                parsed.error
            );
            assert!(
                !parsed.events.iter().any(|event| {
                    matches!(event["node"]["kind"].as_str(), Some("symbol" | "type"))
                        || event["edge"]["source"]
                            .as_str()
                            .is_some_and(|id| semantic_ids.contains(id))
                        || event["edge"]["target"]
                            .as_str()
                            .is_some_and(|id| semantic_ids.contains(id))
                        || event["site"]["source"]
                            .as_str()
                            .is_some_and(|id| semantic_ids.contains(id))
                        || event["site"]["target_ids"]
                            .as_array()
                            .is_some_and(|targets| {
                                targets.iter().any(|target| {
                                    target.as_str().is_some_and(|id| semantic_ids.contains(id))
                                })
                            })
                }),
                "{name}: definition incident survived atomic cleanup"
            );
            assert!(parsed.events.iter().any(|event| {
                event["event"] == "node_upsert" && event["node"]["kind"] == "package_instance"
            }));
            assert!(parsed.events.iter().any(|event| {
                event["event"] == "node_upsert" && event["node"]["kind"] == "file"
            }));
        }
        Ok(())
    }

    #[test]
    fn web_definition_cleanup_tracks_forward_references_to_rejected_events() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;

        let mut forward_definition = test_protocol_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        let semantic_index = forward_definition
            .iter()
            .position(|event| event["node"]["kind"] == "symbol")
            .expect("semantic symbol");
        forward_definition[semantic_index]["node"]["properties"]["language"] =
            serde_json::json!("rust");
        let semantic_event = forward_definition.remove(semantic_index);
        let semantic_id = semantic_event["node"]["id"].clone();
        let edge_index = forward_definition
            .iter()
            .position(|event| event["event"] == "edge_upsert")
            .expect("definition edge");
        let mut forward_edge = forward_definition.remove(edge_index);
        let forward_site_id = format!("site:sha256:{}", "5".repeat(64));
        forward_edge["edge"]["kind"] = serde_json::json!("imports");
        forward_edge["edge"]["phase"] = serde_json::json!("source");
        forward_edge["edge"]["site_id"] = serde_json::json!(forward_site_id);
        forward_edge["edge"]["evidence"][0]["kind"] = serde_json::json!("source");
        rehash_test_definition_edge(&mut forward_edge["edge"]);
        let file_id = forward_definition
            .iter()
            .find(|event| event["node"]["kind"] == "file")
            .expect("source file")["node"]["id"]
            .clone();
        let insert_at = forward_definition
            .iter()
            .position(|event| event["node"]["kind"] == "file")
            .expect("source file")
            + 1;
        forward_definition.insert(insert_at, forward_edge);
        forward_definition.insert(
            insert_at + 1,
            serde_json::json!({
                "event": "dependency_site",
                "protocol_version": "1.0",
                "scan_id": "typescript-gate-scan",
                "adapter": "web",
                "adapter_version": env!("CARGO_PKG_VERSION"),
                "seq": 0,
                "site": {
                    "id": forward_site_id,
                    "source": semantic_id,
                    "kind": "import",
                    "specifier": "./forward",
                    "resolution_status": "resolved",
                    "target_ids": [file_id],
                    "profile_id": "web:default",
                    "condition": {"op": "all", "conditions": []},
                    "precision": "exact",
                    "evidence": [{
                        "kind": "source",
                        "extractor": "typescript-static",
                        "extractor_version": "1",
                        "path": "src/index.ts",
                        "start_line": 1,
                        "start_column": 1,
                        "end_line": 1,
                        "end_column": 9
                    }]
                }
            }),
        );
        forward_definition.insert(insert_at + 2, semantic_event);
        resequence_test_protocol(&mut forward_definition);
        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(forward_definition)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation, "{:?}", parsed.error);
        assert!(
            parsed
                .error
                .as_deref()
                .is_some_and(|error| error.contains("language=typescript or javascript")),
            "{:?}",
            parsed.error
        );
        assert!(!parsed.events.iter().any(|event| {
            event["node"]["id"] == semantic_id
                || event["edge"]["site_id"] == forward_site_id
                || event["site"]["id"] == forward_site_id
        }));
        assert!(
            parsed
                .events
                .iter()
                .any(|event| event["node"]["kind"] == "package_instance")
        );
        assert!(
            parsed
                .events
                .iter()
                .any(|event| event["node"]["kind"] == "file")
        );

        let mut rejected_site = test_protocol_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        let mut linked_edge = rejected_site
            .iter()
            .find(|event| event["event"] == "edge_upsert")
            .expect("definition edge")
            .clone();
        rejected_site.retain(|event| {
            !matches!(event["node"]["kind"].as_str(), Some("symbol" | "type"))
                && event["event"] != "edge_upsert"
        });
        sync_test_semantic_counts(&mut rejected_site);
        let package_id = rejected_site
            .iter()
            .find(|event| event["node"]["kind"] == "package_instance")
            .expect("package node")["node"]["id"]
            .clone();
        let file_id = rejected_site
            .iter()
            .find(|event| event["node"]["kind"] == "file")
            .expect("source file")["node"]["id"]
            .clone();
        let rejected_site_id = format!("site:sha256:{}", "6".repeat(64));
        linked_edge["edge"]["source"] = package_id.clone();
        linked_edge["edge"]["target"] = file_id.clone();
        linked_edge["edge"]["kind"] = serde_json::json!("imports");
        linked_edge["edge"]["phase"] = serde_json::json!("source");
        linked_edge["edge"]["site_id"] = serde_json::json!(rejected_site_id);
        linked_edge["edge"]["evidence"][0]["kind"] = serde_json::json!("source");
        rehash_test_definition_edge(&mut linked_edge["edge"]);
        let insert_at = rejected_site
            .iter()
            .position(|event| event["node"]["kind"] == "file")
            .expect("source file")
            + 1;
        rejected_site.insert(insert_at, linked_edge);
        rejected_site.insert(
            insert_at + 1,
            serde_json::json!({
                "event": "dependency_site",
                "protocol_version": "1.0",
                "scan_id": "typescript-gate-scan",
                "adapter": "web",
                "adapter_version": env!("CARGO_PKG_VERSION"),
                "seq": 0,
                "site": {
                    "id": rejected_site_id,
                    "source": file_id,
                    "kind": "call",
                    "specifier": "forbidden",
                    "resolution_status": "resolved",
                    "target_ids": [package_id],
                    "profile_id": "web:default",
                    "condition": {"op": "all", "conditions": []},
                    "precision": "exact",
                    "evidence": [{
                        "kind": "source",
                        "extractor": "typescript-static",
                        "extractor_version": "1",
                        "path": "src/index.ts",
                        "start_line": 1,
                        "start_column": 1,
                        "end_line": 1,
                        "end_column": 9
                    }]
                }
            }),
        );
        resequence_test_protocol(&mut rejected_site);
        let mut metadata_invalid_site = rejected_site.clone();
        let invalid_site = metadata_invalid_site
            .iter_mut()
            .find(|event| event["event"] == "dependency_site")
            .expect("forward dependency site");
        invalid_site["adapter_version"] = serde_json::json!("spoofed-version");
        invalid_site["site"]["kind"] = serde_json::json!("import");
        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(rejected_site)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation, "{:?}", parsed.error);
        assert!(!parsed.events.iter().any(|event| {
            event["edge"]["site_id"] == rejected_site_id || event["site"]["id"] == rejected_site_id
        }));
        assert!(
            parsed
                .events
                .iter()
                .any(|event| event["node"]["kind"] == "package_instance")
        );
        assert!(
            parsed
                .events
                .iter()
                .any(|event| event["node"]["kind"] == "file")
        );

        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(metadata_invalid_site)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation, "{:?}", parsed.error);
        assert!(
            parsed
                .error
                .as_deref()
                .is_some_and(|error| error.contains("adapter_version mismatch")),
            "{:?}",
            parsed.error
        );
        assert!(!parsed.events.iter().any(|event| {
            event["edge"]["site_id"] == rejected_site_id || event["site"]["id"] == rejected_site_id
        }));
        assert!(
            parsed
                .events
                .iter()
                .any(|event| event["node"]["kind"] == "package_instance")
        );
        assert!(
            parsed
                .events
                .iter()
                .any(|event| event["node"]["kind"] == "file")
        );
        Ok(())
    }

    #[test]
    fn web_definition_delta_cleanup_closes_over_incident_edge_sites() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut events = test_protocol_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        let semantic_id = events
            .iter()
            .find(|event| event["node"]["kind"] == "symbol")
            .expect("semantic symbol")["node"]["id"]
            .clone();
        let file_id = events
            .iter()
            .find(|event| event["node"]["kind"] == "file")
            .expect("source file")["node"]["id"]
            .clone();
        let package_id = events
            .iter()
            .find(|event| event["node"]["kind"] == "package_instance")
            .expect("package node")["node"]["id"]
            .clone();
        let site_id = format!("site:sha256:{}", "2".repeat(64));
        let edge_index = events
            .iter()
            .position(|event| event["event"] == "edge_upsert")
            .expect("definition edge");
        events[edge_index]["edge"]["site_id"] = serde_json::json!(site_id);

        let mut linked_syntax_edge = events[edge_index].clone();
        linked_syntax_edge["edge"]["id"] =
            serde_json::json!(format!("edge:sha256:{}", "3".repeat(64)));
        linked_syntax_edge["edge"]["source"] = package_id.clone();
        linked_syntax_edge["edge"]["target"] = file_id.clone();
        linked_syntax_edge["edge"]["kind"] = serde_json::json!("imports");
        linked_syntax_edge["edge"]["phase"] = serde_json::json!("source");
        linked_syntax_edge["edge"]["evidence"][0]["kind"] = serde_json::json!("source");
        let missing_site_id = format!("site:sha256:{}", "7".repeat(64));
        let mut missing_site_edge = linked_syntax_edge.clone();
        missing_site_edge["edge"]["id"] =
            serde_json::json!(format!("edge:sha256:{}", "8".repeat(64)));
        missing_site_edge["edge"]["site_id"] = serde_json::json!(missing_site_id);
        events.insert(edge_index + 1, linked_syntax_edge);
        events.insert(edge_index + 2, missing_site_edge);
        events.insert(
            edge_index,
            serde_json::json!({
                "event": "dependency_site",
                "protocol_version": "1.0",
                "scan_id": "typescript-gate-scan",
                "adapter": "web",
                "adapter_version": env!("CARGO_PKG_VERSION"),
                "seq": 0,
                "site": {
                    "id": site_id,
                    "source": file_id,
                    "kind": "import",
                    "specifier": "./syntax-only",
                    "resolution_status": "resolved",
                    "target_ids": [package_id],
                    "profile_id": "web:default",
                    "condition": {"op": "all", "conditions": []},
                    "precision": "exact",
                    "evidence": [{
                        "kind": "source",
                        "extractor": "typescript-static",
                        "extractor_version": "1",
                        "path": "src/index.ts",
                        "start_line": 1,
                        "start_column": 1,
                        "end_line": 1,
                        "end_column": 9
                    }]
                }
            }),
        );
        let mut typed = events
            .into_iter()
            .map(serde_json::from_value::<ProtocolEvent>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        discard_web_definition_delta(
            &mut typed,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        );

        let values = typed
            .into_iter()
            .map(serde_json::to_value)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert!(!values.iter().any(|event| {
            event["node"]["id"] == semantic_id
                || event["site"]["id"] == site_id
                || event["edge"]["site_id"] == site_id
                || event["edge"]["site_id"] == missing_site_id
        }));
        assert!(values.iter().any(|event| event["node"]["id"] == file_id));
        assert!(values.iter().any(|event| event["node"]["id"] == package_id));
        Ok(())
    }

    #[test]
    fn web_definition_graph_accepts_canonical_generic_type_argument_shapes() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let template = test_protocol_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "instantiates",
        )?)?;
        let origin_resolver = template
            .iter()
            .find(|event| event["node"]["properties"]["type_kind"] == "generic_instance")
            .expect("generic instance")["node"]["properties"]["generic_origin"]
            .as_str()
            .expect("generic origin resolver")
            .to_owned();
        let descriptors = vec![
            (
                "string literal",
                serde_json::json!([{
                    "kind": "literal",
                    "value_kind": "string",
                    "value": "a,b",
                }]),
            ),
            (
                "small exponent number",
                serde_json::json!([{
                    "kind": "literal",
                    "value_kind": "number",
                    "value": "1e-7",
                }]),
            ),
            (
                "large exponent number",
                serde_json::json!([{
                    "kind": "literal",
                    "value_kind": "number",
                    "value": "1e+21",
                }]),
            ),
            (
                "canonical union",
                serde_json::json!([{
                    "kind": "union",
                    "members": [
                        {"kind": "intrinsic", "name": "number"},
                        {"kind": "intrinsic", "name": "string"},
                    ],
                }]),
            ),
            (
                "type parameter",
                serde_json::json!([{
                    "kind": "type_parameter",
                    "owner": origin_resolver,
                    "index": 0,
                    "name": "T",
                }]),
            ),
            (
                "generic application",
                serde_json::json!([{
                    "kind": "application",
                    "target": {
                        "kind": "definition",
                        "resolver_identity": origin_resolver,
                    },
                    "type_arguments": [
                        {"kind": "intrinsic", "name": "string"},
                    ],
                }]),
            ),
        ];

        for (name, descriptor) in descriptors {
            let mut events = test_protocol_values(typescript_definition_protocol(
                &root,
                TYPESCRIPT_RELEASE_GATE_PENDING,
                "instantiates",
            )?)?;
            rewrite_test_generic_instance(&mut events, descriptor, None);
            let output = serialize_test_protocol(events)?;
            let parsed = parse_events_preserving_prefix(
                &output,
                "typescript-gate-scan",
                "web",
                &root,
                64 * 1024,
                Some(env!("CARGO_PKG_VERSION")),
                Some(false),
            );
            assert_eq!(parsed.error, None, "{name}: {:?}", parsed.error);
            assert_eq!(parsed.failure_kind, None, "{name}");
            assert!(!parsed.security_violation, "{name}");
            assert!(
                parsed.events.iter().any(|event| {
                    event["node"]["properties"]["type_kind"] == "generic_instance"
                })
            );
        }
        Ok(())
    }

    #[test]
    fn web_definition_failure_profiles_preserve_the_syntax_delta() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;

        for (project, typechecker, definition) in [
            ("ready", "definition-graph-discarded", "failed"),
            ("failed", "failed", "failed"),
        ] {
            let output =
                typescript_definition_protocol(&root, TYPESCRIPT_RELEASE_GATE_PENDING, "declares")?;
            let mut events = String::from_utf8(output)?
                .lines()
                .map(serde_json::from_str::<Value>)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            events.retain(|event| {
                !matches!(event["node"]["kind"].as_str(), Some("symbol" | "type"))
                    && event["edge"]["phase"] != "semantic"
            });
            events[1]["profile"]["properties"][TYPESCRIPT_PROJECT_STATUS_PROPERTY] =
                serde_json::json!(project);
            events[1]["profile"]["properties"][TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY] =
                serde_json::json!(typechecker);
            events[1]["profile"]["properties"][TYPESCRIPT_DEFINITION_STATUS_PROPERTY] =
                serde_json::json!(definition);
            events[1]["profile"]["properties"]["typescript_semantic_node_count"] =
                serde_json::json!("0");
            events[1]["profile"]["properties"]["typescript_semantic_relation_count"] =
                serde_json::json!("0");
            for (index, event) in events.iter_mut().enumerate() {
                event["seq"] = serde_json::json!(index + 1);
            }
            let mut protocol = Vec::new();
            for event in events {
                serde_json::to_writer(&mut protocol, &event)?;
                protocol.push(b'\n');
            }

            let parsed = parse_events_preserving_prefix(
                &protocol,
                "typescript-gate-scan",
                "web",
                &root,
                16 * 1024,
                Some(env!("CARGO_PKG_VERSION")),
                Some(false),
            );
            assert_eq!(
                parsed.error, None,
                "state={project}/{typechecker}/{definition}"
            );
            assert_eq!(parsed.failure_kind, None);
            assert!(!parsed.security_violation);
            assert!(parsed.events.iter().any(|event| {
                event["event"] == "node_upsert" && event["node"]["kind"] == "package_instance"
            }));
            assert!(parsed.events.iter().any(|event| {
                event["event"] == "node_upsert" && event["node"]["kind"] == "file"
            }));
            assert!(!parsed.events.iter().any(|event| {
                matches!(event["node"]["kind"].as_str(), Some("symbol" | "type"))
                    || event["edge"]["phase"] == "semantic"
            }));
        }
        Ok(())
    }

    #[test]
    fn web_definition_profile_rejects_inconsistent_state_and_language() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;

        for (name, property, value) in [
            (
                "inconsistent state",
                TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY,
                "failed",
            ),
            ("wrong profile language", "language", "typescript"),
        ] {
            let output = typescript_gate_protocol(&root, TYPESCRIPT_RELEASE_GATE_PENDING)?;
            let mut events = String::from_utf8(output)?
                .lines()
                .map(serde_json::from_str::<Value>)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if property == "language" {
                events[1]["profile"]["language"] = serde_json::json!(value);
            } else {
                events[1]["profile"]["properties"][property] = serde_json::json!(value);
            }
            let mut protocol = Vec::new();
            for event in events {
                serde_json::to_writer(&mut protocol, &event)?;
                protocol.push(b'\n');
            }

            let parsed = parse_events_preserving_prefix(
                &protocol,
                "typescript-gate-scan",
                "web",
                &root,
                4096,
                Some(env!("CARGO_PKG_VERSION")),
                Some(false),
            );
            assert_eq!(parsed.events.len(), 1, "{name}: {:?}", parsed.error);
            assert_eq!(
                parsed.failure_kind,
                Some(WorkerFailureKind::MalformedProtocol),
                "{name}: {:?}",
                parsed.error
            );
            assert!(parsed.security_violation, "{name}: {:?}", parsed.error);
        }
        Ok(())
    }

    #[test]
    fn web_semantic_complete_requires_call_graph_v2_capability() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let mut events = test_protocol_values(typescript_call_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        promote_typescript_semantic_complete(&mut events, TYPESCRIPT_RELEASE_GATE_PENDING);
        events
            .iter_mut()
            .find(|event| event["event"] == "profile_declared")
            .expect("Web profile declaration")["profile"]["properties"]
            [TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY] =
            serde_json::json!(TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V1);
        resequence_test_protocol(&mut events);
        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation);
        assert!(
            parsed
                .error
                .as_deref()
                .is_some_and(|error| error.contains(TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY))
        );
        Ok(())
    }

    #[test]
    fn rust_release_handshake_covers_the_backend_compatibility_unit() -> Result<()> {
        let handshake = format!(
            "depgraph-rust-worker {} (protocol 1.0; rust-analyzer {}; rust-analyzer-revision {}; salsa {})",
            env!("CARGO_PKG_VERSION"),
            RUST_BACKEND_VERSION,
            RUST_BACKEND_REVISION,
            RUST_BACKEND_SALSA_VERSION,
        );
        verify_rust_release_handshake(
            &handshake,
            env!("CARGO_PKG_VERSION"),
            RUST_BACKEND_KIND,
            RUST_BACKEND_VERSION,
            RUST_BACKEND_REVISION,
            RUST_BACKEND_SALSA_VERSION,
        )?;

        let mismatch = handshake.replace(RUST_BACKEND_REVISION, "different-revision");
        let error = verify_rust_release_handshake(
            &mismatch,
            env!("CARGO_PKG_VERSION"),
            RUST_BACKEND_KIND,
            RUST_BACKEND_VERSION,
            RUST_BACKEND_REVISION,
            RUST_BACKEND_SALSA_VERSION,
        )
        .unwrap_err();
        assert!(error.to_string().contains("backend handshake mismatch"));
        assert!(is_security_error(&error.to_string()));
        Ok(())
    }

    #[test]
    fn web_release_handshake_covers_the_semantic_compatibility_unit() -> Result<()> {
        let capabilities = WEB_SEMANTIC_CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        let handshake = format!(
            "depgraph-web-worker {} (protocol 1.0; typescript {}; capabilities {})",
            env!("CARGO_PKG_VERSION"),
            TYPESCRIPT_COMPILER_VERSION,
            capabilities.join(","),
        );
        verify_web_release_handshake(
            &handshake,
            env!("CARGO_PKG_VERSION"),
            TYPESCRIPT_COMPILER_VERSION,
            &capabilities,
        )?;

        for mismatch in [
            handshake.replace(TYPESCRIPT_COMPILER_VERSION, "9.9.9"),
            handshake.replace("capabilities astro", "unknown astro"),
            handshake.replace(
                "astro-component-render-hydration-v1,framework-semantic-completeness-v1",
                "framework-semantic-completeness-v1,astro-component-render-hydration-v1",
            ),
        ] {
            let error = verify_web_release_handshake(
                &mismatch,
                env!("CARGO_PKG_VERSION"),
                TYPESCRIPT_COMPILER_VERSION,
                &capabilities,
            )
            .unwrap_err();
            assert!(is_security_error(&error.to_string()));
        }
        Ok(())
    }

    #[test]
    fn packaged_event_version_must_match_the_manifest() -> Result<()> {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        let output = format!(
            "{{\"event\":\"scan_started\",\"protocol_version\":\"1.0\",\"scan_id\":\"s\",\"adapter\":\"go\",\"adapter_version\":\"9.9.9\",\"seq\":1,\"root\":{},\"project_code_executed\":false,\"safe_mode\":true}}\n",
            serde_json::to_string(&root.to_string_lossy())?
        );
        let parsed = parse_events_preserving_prefix(
            output.as_bytes(),
            "s",
            "go",
            &root,
            4096,
            Some("0.1.0"),
            None,
        );
        assert!(parsed.events.is_empty());
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation);
        let error = parsed.error.unwrap();
        assert!(error.contains("security policy violation"));
        assert!(error.contains("adapter_version mismatch"));
        Ok(())
    }

    #[test]
    fn packaged_event_protocol_and_adapter_identity_mismatches_are_security_failures() -> Result<()>
    {
        let root = tempfile::tempdir()?;
        let root = root.path().canonicalize()?;
        for (protocol, adapter, expected) in [
            ("9.9", "go", "protocol_version mismatch"),
            ("1.0", "web", "adapter mismatch"),
        ] {
            let output = format!(
                "{{\"event\":\"scan_started\",\"protocol_version\":\"{protocol}\",\"scan_id\":\"s\",\"adapter\":\"{adapter}\",\"adapter_version\":\"0.1.0\",\"seq\":1,\"root\":{},\"project_code_executed\":false,\"safe_mode\":true}}\n",
                serde_json::to_string(&root.to_string_lossy())?
            );
            let parsed = parse_events_preserving_prefix(
                output.as_bytes(),
                "s",
                "go",
                &root,
                4096,
                Some("0.1.0"),
                None,
            );
            assert!(parsed.events.is_empty());
            assert_eq!(
                parsed.failure_kind,
                Some(WorkerFailureKind::MalformedProtocol)
            );
            assert!(parsed.security_violation);
            let error = parsed.error.unwrap();
            assert!(error.contains("security policy violation"));
            assert!(error.contains(expected));
        }
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn verified_rust_release_worker_receives_the_release_gate() -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir()?;
        let root = temp.path().join("root");
        std::fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        let script = temp.path().join("rust-release-worker.sh");
        let script_contents = r#"#!/bin/sh
if [ "$DEPGRAPH_RUST_RELEASE_GATE" != "release-gate-verified" ]; then
  exit 9
fi
if [ ! -d "$DEPGRAPH_RUST_SYSROOT_ROOT" ]; then
  exit 10
fi
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) root="$2"; shift 2 ;;
    --scan-id) scan="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '{"event":"scan_started","protocol_version":"1.0","scan_id":"%s","adapter":"rust","adapter_version":"__VERSION__","seq":1,"root":"%s","project_code_executed":false,"safe_mode":true}\n' "$scan" "$root"
printf '{"event":"scan_completed","protocol_version":"1.0","scan_id":"%s","adapter":"rust","adapter_version":"__VERSION__","seq":2,"coverage":{"profiles":0,"files_discovered":0,"files_analyzed":0,"files_skipped":0,"dependency_sites":0,"resolved":0,"candidates":0,"external":0,"unresolved":0,"unsupported_syntax":0,"project_code_executed":false,"completeness":["syntax-complete"],"reasons":[]}}\n' "$scan"
"#
        .replace("__VERSION__", env!("CARGO_PKG_VERSION"));
        std::fs::write(&script, script_contents)?;
        let mut permissions = std::fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions)?;
        let attested_sysroot = temp.path().join("rust-sysroot");
        std::fs::create_dir(&attested_sysroot)?;
        let mut spec = WorkerSpec {
            adapter: AdapterKind::Rust,
            program: script.clone().into_os_string(),
            leading_args: Vec::new(),
            display: script.display().to_string(),
            artifact_path: script,
            runtime_requirement: None,
            expected_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            release_attested: true,
            attested_rust_sysroot: Some(attested_sysroot.canonicalize()?),
        };
        let execution = execute_worker_inner_with_cancellation(
            &spec,
            &root,
            "release-gate-scan",
            &ScanConfig::default(),
            &ProfileConfig::default(),
            None,
            std::future::pending::<std::io::Result<()>>(),
        )
        .await?;
        assert_eq!(execution.events.len(), 2);
        assert!(execution.error.is_none(), "{:?}", execution.error);

        spec.attested_rust_sysroot = None;
        let missing_sysroot = execute_worker_inner_with_cancellation(
            &spec,
            &root,
            "missing-sysroot-scan",
            &ScanConfig::default(),
            &ProfileConfig::default(),
            None,
            std::future::pending::<std::io::Result<()>>(),
        )
        .await
        .expect_err("a verified Rust worker without an attested sysroot must fail closed");
        assert!(
            missing_sysroot
                .to_string()
                .contains("verified Rust worker has no attested sysroot component")
        );

        spec.release_attested = false;
        let unverified = execute_worker_inner_with_cancellation(
            &spec,
            &root,
            "unverified-release-gate-scan",
            &ScanConfig::default(),
            &ProfileConfig::default(),
            None,
            std::future::pending::<std::io::Result<()>>(),
        )
        .await?;
        assert_eq!(
            unverified.failure_kind,
            Some(WorkerFailureKind::NonzeroExit)
        );
        assert!(unverified.error.is_some());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn verified_web_release_worker_receives_the_typescript_release_gate() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("root");
        std::fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        let script = temp.path().join("web-release-worker.mjs");
        let protocol = String::from_utf8(typescript_gate_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_VERIFIED,
        )?)?;
        let script_contents = format!(
            "if (process.env.DEPGRAPH_TYPESCRIPT_RELEASE_GATE !== \"release-gate-verified\") process.exit(9);\nprocess.stdout.write({});\n",
            serde_json::to_string(&protocol)?,
        );
        std::fs::write(&script, script_contents)?;
        let mut spec = worker_spec_from_path(AdapterKind::Web, script, None);
        spec.expected_version = Some(env!("CARGO_PKG_VERSION").to_owned());
        spec.release_attested = true;
        let execution = execute_worker_inner_with_cancellation(
            &spec,
            &root,
            "typescript-gate-scan",
            &ScanConfig::default(),
            &ProfileConfig::default(),
            None,
            std::future::pending::<std::io::Result<()>>(),
        )
        .await?;
        assert_eq!(
            execution.events.len(),
            4,
            "error={:?}, stderr={:?}, failure_kind={:?}",
            execution.error,
            execution.stderr,
            execution.failure_kind
        );
        assert!(execution.error.is_none(), "{:?}", execution.error);

        spec.release_attested = false;
        let unverified = execute_worker_inner_with_cancellation(
            &spec,
            &root,
            "typescript-gate-scan",
            &ScanConfig::default(),
            &ProfileConfig::default(),
            None,
            std::future::pending::<std::io::Result<()>>(),
        )
        .await?;
        assert_eq!(
            unverified.failure_kind,
            Some(WorkerFailureKind::NonzeroExit)
        );
        assert!(unverified.error.is_some());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_keeps_the_worker_prefix_and_caps_stderr() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let root = temp.path().join("root");
        std::fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        let script = temp.path().join("fake-worker.sh");
        std::fs::write(
            &script,
            r#"#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) root="$2"; shift 2 ;;
    --scan-id) scan="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '{"event":"scan_started","protocol_version":"1.0","scan_id":"%s","adapter":"go","adapter_version":"0.1.0","seq":1,"root":"%s","project_code_executed":false,"safe_mode":true}\n' "$scan" "$root"
printf '{"event":"node_upsert","protocol_version":"1.0","scan_id":"%s","adapter":"go","adapter_version":"0.1.0","seq":2,"node":{"id":"file:one","kind":"file","locator":"file://one","properties":{}}}\n' "$scan"
printf '0123456789abcdef' >&2
exec sleep 10
"#,
        )?;
        let mut permissions = std::fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions)?;
        let spec = WorkerSpec {
            adapter: AdapterKind::Go,
            program: script.clone().into_os_string(),
            leading_args: Vec::new(),
            display: script.display().to_string(),
            artifact_path: script,
            runtime_requirement: None,
            expected_version: None,
            release_attested: false,
            attested_rust_sysroot: None,
        };
        // Keep this test independent from the process-wide Ctrl-C listener;
        // cancellation has its own deterministic test below.
        let execution = execute_worker_inner_with_cancellation(
            &spec,
            &root,
            "timeout-scan",
            &ScanConfig {
                // Give the child enough scheduling headroom when the Rust
                // test suite runs process-heavy cases in parallel. The
                // worker still sleeps long enough to deterministically hit
                // the timeout after its protocol prefix has been flushed.
                worker_timeout_seconds: 3,
                max_protocol_line_bytes: 4096,
                max_protocol_bytes: 64 * 1024,
                max_stderr_bytes: 8,
                follow_symlinks: false,
            },
            &ProfileConfig::default(),
            None,
            std::future::pending::<std::io::Result<()>>(),
        )
        .await?;
        assert_eq!(execution.events.len(), 2);
        assert!(execution.error.unwrap().contains("timed out"));
        assert_eq!(execution.stderr, "01234567");
        assert!(execution.stderr_truncated);
        assert_eq!(execution.failure_kind, Some(WorkerFailureKind::Timeout));
        assert!(!execution.security_violation);
        Ok(())
    }

    #[tokio::test]
    async fn web_worker_timeout_reaps_its_descendant_cross_platform() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("root");
        std::fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        let marker = temp.path().join("descendant-survived");
        let descendant_ready = temp.path().join("descendant-ready");
        let descendant_trigger = temp.path().join("descendant-trigger");
        let script = temp.path().join("timeout-worker.mjs");
        let script_contents = format!(
            r#"import {{ spawn }} from "node:child_process";
const args = process.argv.slice(2);
const value = (name) => args[args.indexOf(name) + 1];
const root = value("--root");
const scanId = value("--scan-id");
process.stdout.write(JSON.stringify({{
  event: "scan_started",
  protocol_version: "1.0",
  scan_id: scanId,
  adapter: "web",
  adapter_version: "0.1.0",
  seq: 1,
  root,
  project_code_executed: false,
  safe_mode: true,
}}) + "\n");
spawn(process.execPath, ["-e", {}], {{ stdio: "ignore" }});
setInterval(() => undefined, 1_000);
"#,
            serde_json::to_string(&format!(
                "const fs = require('node:fs'); fs.writeFileSync({}, 'ready'); setInterval(() => {{ if (fs.existsSync({})) fs.writeFileSync({}, 'survived'); }}, 25);",
                serde_json::to_string(&descendant_ready.to_string_lossy())?,
                serde_json::to_string(&descendant_trigger.to_string_lossy())?,
                serde_json::to_string(&marker.to_string_lossy())?,
            ))?,
        );
        std::fs::write(&script, script_contents)?;
        let spec = worker_spec_from_path(AdapterKind::Web, script, None);
        let execution = execute_worker_inner_with_cancellation(
            &spec,
            &root,
            "web-timeout-scan",
            &ScanConfig {
                // Windows cold-start antivirus scanning can delay the first
                // Node protocol event by several seconds. The descendant
                // handshake below keeps the reap assertion deterministic.
                worker_timeout_seconds: 10,
                max_protocol_line_bytes: 4096,
                max_protocol_bytes: 64 * 1024,
                max_stderr_bytes: 4096,
                follow_symlinks: false,
            },
            &ProfileConfig::default(),
            None,
            std::future::pending::<std::io::Result<()>>(),
        )
        .await?;
        assert_eq!(execution.events.len(), 1);
        assert_eq!(execution.failure_kind, Some(WorkerFailureKind::Timeout));
        assert!(
            execution
                .error
                .as_deref()
                .is_some_and(|error| error.contains("timed out"))
        );
        assert!(
            descendant_ready.exists(),
            "timed-out Web worker descendant never reached its ready state"
        );
        std::fs::write(&descendant_trigger, b"check")?;
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(!marker.exists(), "timed-out Web worker descendant survived");
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancellation_keeps_the_worker_prefix_and_reaps_the_process() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Instant;

        let temp = tempfile::tempdir()?;
        let root = temp.path().join("root");
        std::fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        let script = temp.path().join("cancel-worker.sh");
        std::fs::write(
            &script,
            r#"#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) root="$2"; shift 2 ;;
    --scan-id) scan="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '{"event":"scan_started","protocol_version":"1.0","scan_id":"%s","adapter":"go","adapter_version":"0.1.0","seq":1,"root":"%s","project_code_executed":false,"safe_mode":true}\n' "$scan" "$root"
printf '{"event":"node_upsert","protocol_version":"1.0","scan_id":"%s","adapter":"go","adapter_version":"0.1.0","seq":2,"node":{"id":"file:before-cancel","kind":"file","locator":"file://before-cancel","properties":{}}}\n' "$scan"
printf 'worker-log' >&2
: > "${0%/*}/ready"
exec sleep 30
"#,
        )?;
        let mut permissions = std::fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions)?;
        let spec = WorkerSpec {
            adapter: AdapterKind::Go,
            program: script.clone().into_os_string(),
            leading_args: Vec::new(),
            display: script.display().to_string(),
            artifact_path: script,
            runtime_requirement: None,
            expected_version: None,
            release_attested: false,
            attested_rust_sysroot: None,
        };
        let started = Instant::now();
        let ready = temp.path().join("ready");
        let execution = execute_worker_inner_with_cancellation(
            &spec,
            &root,
            "cancel-scan",
            &ScanConfig {
                worker_timeout_seconds: 10,
                max_protocol_line_bytes: 4096,
                max_protocol_bytes: 64 * 1024,
                max_stderr_bytes: 1024,
                follow_symlinks: false,
            },
            &ProfileConfig::default(),
            None,
            async move {
                timeout(Duration::from_secs(5), async {
                    while !ready.is_file() {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .map_err(std::io::Error::other)
            },
        )
        .await?;
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(execution.events.len(), 2);
        assert_eq!(execution.stderr, "worker-log");
        assert!(!execution.stderr_truncated);
        assert!(execution.error.unwrap().contains("cancelled by user"));
        assert_eq!(execution.failure_kind, Some(WorkerFailureKind::Cancelled));
        assert!(!execution.security_violation);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn malformed_worker_output_keeps_its_prefix_and_stderr_separate() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let root = temp.path().join("root");
        std::fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        let script = temp.path().join("malformed-worker.sh");
        std::fs::write(
            &script,
            r#"#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) root="$2"; shift 2 ;;
    --scan-id) scan="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '{"event":"scan_started","protocol_version":"1.0","scan_id":"%s","adapter":"go","adapter_version":"0.1.0","seq":1,"root":"%s","project_code_executed":false,"safe_mode":true}\n' "$scan" "$root"
printf 'not-json\n'
printf 'operational log' >&2
"#,
        )?;
        let mut permissions = std::fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions)?;
        let spec = WorkerSpec {
            adapter: AdapterKind::Go,
            program: script.clone().into_os_string(),
            leading_args: Vec::new(),
            display: script.display().to_string(),
            artifact_path: script,
            runtime_requirement: None,
            expected_version: None,
            release_attested: false,
            attested_rust_sysroot: None,
        };
        let output = execute_worker(
            spec,
            root,
            "malformed-scan".to_owned(),
            ScanConfig {
                worker_timeout_seconds: 5,
                max_protocol_line_bytes: 4096,
                max_protocol_bytes: 64 * 1024,
                max_stderr_bytes: 1024,
                follow_symlinks: false,
            },
            ProfileConfig::default(),
        )
        .await;
        assert_eq!(output.events.len(), 1);
        assert_eq!(output.stderr, "operational log");
        let error = output.error.unwrap();
        assert!(error.contains("malformed NDJSON"));
        assert!(error.contains("stderr: operational log"));
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn worker_process_starts_from_a_neutral_working_directory() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let root = temp.path().join("root");
        std::fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        let script = temp.path().join("neutral-cwd-worker.sh");
        std::fs::write(
            &script,
            r#"#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) root="$2"; shift 2 ;;
    --scan-id) scan="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [ "$PWD" = "$root" ]; then : > "$root/CWD_MARKER"; fi
printf '{"event":"scan_started","protocol_version":"1.0","scan_id":"%s","adapter":"go","adapter_version":"0.1.0","seq":1,"root":"%s","project_code_executed":false,"safe_mode":true}\n' "$scan" "$root"
printf '{"event":"scan_completed","protocol_version":"1.0","scan_id":"%s","adapter":"go","adapter_version":"0.1.0","seq":2,"coverage":{"profiles":0,"files_discovered":0,"files_analyzed":0,"files_skipped":0,"dependency_sites":0,"resolved":0,"candidates":0,"external":0,"unresolved":0,"unsupported_syntax":0,"project_code_executed":false,"completeness":["syntax-complete"],"reasons":[]}}\n' "$scan"
"#,
        )?;
        let mut permissions = std::fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions)?;
        let spec = WorkerSpec {
            adapter: AdapterKind::Go,
            program: script.clone().into_os_string(),
            leading_args: Vec::new(),
            display: script.display().to_string(),
            artifact_path: script,
            runtime_requirement: None,
            expected_version: None,
            release_attested: false,
            attested_rust_sysroot: None,
        };
        let execution = execute_worker_inner_with_cancellation(
            &spec,
            &root,
            "neutral-cwd-scan",
            &ScanConfig::default(),
            &ProfileConfig::default(),
            None,
            std::future::pending::<std::io::Result<()>>(),
        )
        .await?;
        assert_eq!(execution.events.len(), 2);
        assert!(execution.error.is_none(), "{:?}", execution.error);
        assert_eq!(execution.failure_kind, None);
        assert!(!execution.security_violation);
        assert!(!root.join("CWD_MARKER").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn normal_worker_exit_reaps_pipe_holding_descendants() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Instant;

        let temp = tempfile::tempdir()?;
        let root = temp.path().join("root");
        std::fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        let script = temp.path().join("background-worker.sh");
        std::fs::write(&script, "#!/bin/sh\nsleep 30 &\nexit 0\n")?;
        let mut permissions = std::fs::metadata(&script)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions)?;
        let spec = WorkerSpec {
            adapter: AdapterKind::Go,
            program: script.clone().into_os_string(),
            leading_args: Vec::new(),
            display: script.display().to_string(),
            artifact_path: script,
            runtime_requirement: None,
            expected_version: None,
            release_attested: false,
            attested_rust_sysroot: None,
        };
        let started = Instant::now();
        let output = execute_worker(
            spec,
            root,
            "background-scan".to_owned(),
            ScanConfig {
                worker_timeout_seconds: 5,
                max_protocol_line_bytes: 4096,
                max_protocol_bytes: 64 * 1024,
                max_stderr_bytes: 1024,
                follow_symlinks: false,
            },
            ProfileConfig::default(),
        )
        .await;
        assert!(started.elapsed() < Duration::from_millis(1500));
        assert!(output.error.unwrap().contains("incomplete protocol stream"));
        Ok(())
    }
}
