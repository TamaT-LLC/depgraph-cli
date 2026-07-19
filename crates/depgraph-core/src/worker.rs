use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    future::Future,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use depgraph_protocol::{MAX_EVENT_LINE_BYTES, ProtocolError, ProtocolEvent, ProtocolValidator};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    time::timeout,
};
use walkdir::{DirEntry, WalkDir};

use crate::config::{ProfileConfig, ScanConfig};

pub(crate) const RUST_BACKEND_KIND: &str = "rust-analyzer-library";
pub(crate) const RUST_BACKEND_VERSION: &str = "0.0.330";
pub(crate) const RUST_BACKEND_REVISION: &str = "8954b66d43225e62c92e8bbcc8500191b5cceb1e";
pub(crate) const RUST_BACKEND_SALSA_VERSION: &str = "0.26.1";
const RUST_RELEASE_GATE_ENV: &str = "DEPGRAPH_RUST_RELEASE_GATE";
const RUST_RELEASE_GATE_PENDING: &str = "release-gate-pending";
const RUST_RELEASE_GATE_VERIFIED: &str = "release-gate-verified";
const WEB_RUNTIME_REQUIREMENT: &str = "Node.js >=24.0.0";
const PROTOCOL_SCHEMA_PATH: &str = "schemas/depgraph-protocol-v1.schema.json";

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

    fn env_override(self) -> &'static str {
        match self {
            Self::Rust => "DEPGRAPH_RUST_WORKER",
            Self::Go => "DEPGRAPH_GO_WORKER",
            Self::Web => "DEPGRAPH_WEB_WORKER",
        }
    }
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
struct WorkerExecution {
    events: Vec<Value>,
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

#[derive(Debug, Deserialize)]
struct BundledManifest {
    release_version: String,
    protocol_version: String,
    schema_version: String,
    target: String,
    core: BundledArtifact,
    schema: BundledArtifact,
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
    if manifest.schema_version != "1.0" || manifest.target.trim().is_empty() {
        bail!(
            "security policy violation: release manifest has an incompatible schema or empty target"
        );
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

    if !runtime_paths.contains("libexec/astro.wasm") {
        bail!(
            "security policy violation: release manifest has no required Web runtime artifact libexec/astro.wasm"
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
    {
        bail!(
            "security policy violation: TypeScript runtime component does not match 7.0.2 at {expected_typescript_entrypoint}"
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
    spec.release_attested = adapter == AdapterKind::Rust;
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
    if component.name.trim().is_empty() || component.version.trim().is_empty() {
        bail!(
            "security policy violation: bundled runtime component name and version must be non-empty"
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

pub(crate) fn verify_release_runtime_component(
    release_root: &Path,
    name: &str,
    version: &str,
    kind: &str,
    root: &str,
    entrypoint: Option<&str>,
    sha256: &str,
) -> Result<()> {
    verify_bundled_runtime_component(
        release_root,
        &BundledRuntimeComponent {
            name: name.to_owned(),
            version: version.to_owned(),
            kind: BundledRuntimeComponentKind::parse(kind)?,
            root: root.to_owned(),
            entrypoint: entrypoint.map(ToOwned::to_owned),
            sha256: sha256.to_owned(),
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
        }
    }
}

// Windows canonicalization deliberately returns a verbatim path (`\\?\...`).
// That form is useful for integrity and confinement checks, but Node.js treats
// a verbatim drive path passed as its entry script as `C:` and fails with
// EISDIR. Preserve the canonical artifact path on WorkerSpec and normalize
// only the argument handed to the external runtime.
#[cfg(windows)]
fn process_argument_path(path: &Path) -> OsString {
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};

    let wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    OsString::from_wide(&without_windows_verbatim_prefix(&wide))
}

#[cfg(not(windows))]
fn process_argument_path(path: &Path) -> OsString {
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
    cancellation: F,
) -> Result<WorkerExecution>
where
    F: Future<Output = std::io::Result<()>>,
{
    let program = resolve_worker_program(spec, root)?;
    if let Some(requirement) = &spec.runtime_requirement {
        let output = run_probe(&program, &[OsString::from("--version")], root).await?;
        if !output.status.success() {
            bail!("Node.js runtime version check failed");
        }
        let version = String::from_utf8(output.stdout)
            .context("Node.js runtime returned a non-UTF-8 version")?;
        verify_node_version(requirement, &version)?;
    }

    let neutral_cwd = neutral_working_directory(root)?;
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
        command.env(RUST_RELEASE_GATE_ENV, RUST_RELEASE_GATE_VERIFIED);
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
    tokio::pin!(cancellation);
    let wait_result = tokio::select! {
        result = timeout(Duration::from_secs(config.worker_timeout_seconds), child.wait()) => {
            WaitResult::Process(result)
        }
        signal = &mut cancellation => WaitResult::Cancelled(signal),
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
    let parsed = parse_events_preserving_prefix(
        &stdout_bytes,
        scan_id,
        spec.adapter.name(),
        root,
        config.max_protocol_line_bytes,
        spec.expected_version.as_deref(),
        Some(spec.release_attested),
    );
    if stdout_truncated {
        errors.push(format!(
            "{} protocol output exceeded {} bytes",
            spec.display, config.max_protocol_bytes
        ));
        failure_kinds.push(WorkerFailureKind::OutputLimit);
    }
    if let Some(error) = parsed.error {
        errors.push(error);
        failure_kinds.push(
            parsed
                .failure_kind
                .expect("a protocol error always has a typed failure kind"),
        );
    }
    // Classify only supervisor/protocol errors. Worker stderr is retained for
    // diagnosis but must never be able to spoof timeout/security categories.
    let control_error = (!errors.is_empty()).then(|| errors.join("; "));
    let failure_kind = select_worker_failure_kind(&failure_kinds);
    let security_violation = parsed.security_violation;
    let error = match (control_error, stderr.is_empty()) {
        (Some(error), false) => Some(format!("{error}; stderr: {stderr}")),
        (error, _) => error,
    };
    Ok(WorkerExecution {
        events: parsed.events,
        stderr,
        stderr_truncated,
        error,
        failure_kind,
        security_violation,
    })
}

async fn read_capped(
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

async fn finish_reader(
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

async fn terminate_worker(child: &mut tokio::process::Child, guard: &ProcessTreeGuard) {
    guard.terminate();
    let _ = child.kill().await;
    let _ = child.wait().await;
}

fn copy_safe_environment(command: &mut Command, root: &Path) -> Result<()> {
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

fn sanitize_path_value(raw: &OsStr, root: &Path) -> Result<OsString> {
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

struct ProcessTreeGuard {
    #[cfg(unix)]
    process_group: i32,
    #[cfg(windows)]
    job: usize,
}

impl ProcessTreeGuard {
    fn attach(child: &tokio::process::Child) -> Result<Self> {
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

    fn terminate(&self) {
        #[cfg(unix)]
        unsafe {
            libc::kill(-self.process_group, libc::SIGKILL);
        }
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.job as _, 1);
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

async fn run_probe(
    program: &OsStr,
    arguments: &[OsString],
    root: &Path,
) -> Result<std::process::Output> {
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
    let status = match timeout(Duration::from_secs(5), child.wait()).await {
        Ok(status) => status.context("failed to wait for runtime probe")?,
        Err(_) => {
            terminate_worker(&mut child, &guard).await;
            bail!("runtime probe timed out after 5 seconds");
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
    let program = resolve_worker_program(spec, root)?;
    if let Some(requirement) = &spec.runtime_requirement {
        let node = run_probe(&program, &[OsString::from("--version")], root).await?;
        if !node.status.success() {
            bail!("Node.js runtime version check failed");
        }
        let version = String::from_utf8(node.stdout)
            .context("Node.js runtime returned a non-UTF-8 version")?;
        verify_node_version(requirement, &version)?;
    }
    let mut arguments = spec.leading_args.clone();
    arguments.push(OsString::from("--version"));
    let output = run_probe(&program, &arguments, root).await?;
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
        if event.common().scan_id != expected_scan_id {
            parse_error = Some(format!("scan_id mismatch at line {}", line_index + 1));
            failure_kind = Some(WorkerFailureKind::MalformedProtocol);
            break;
        }
        if expected_adapter_version.is_some() && event.common().protocol_version != "1.0" {
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
            && let Some(gate) = declared
                .profile
                .properties
                .get("rust_hir_enable_gate")
                .and_then(Value::as_str)
        {
            let violation = match (release_attested, gate) {
                (true, RUST_RELEASE_GATE_PENDING) => {
                    Some("verified Rust release worker reported release-gate-pending")
                }
                (false, RUST_RELEASE_GATE_VERIFIED) => Some(
                    "worker reported release-gate-verified without a verified Rust release attestation",
                ),
                _ => None,
            };
            if let Some(violation) = violation {
                parse_error = Some(format!(
                    "security policy violation at line {}: {violation}",
                    line_index + 1
                ));
                failure_kind = Some(WorkerFailureKind::MalformedProtocol);
                security_violation = true;
                break;
            }
        }
        if let Err(error) = validator.push(event) {
            security_violation = protocol_error_is_security(&error);
            parse_error = Some(format!(
                "protocol validation failed at line {}: {error}",
                line_index + 1
            ));
            failure_kind = Some(WorkerFailureKind::MalformedProtocol);
            break;
        }
    }
    let prefix = validator.validated_events().to_vec();
    if parse_error.is_none()
        && let Err(error) = validator.finish()
    {
        parse_error = Some(format!("incomplete protocol stream: {error}"));
        failure_kind = Some(WorkerFailureKind::IncompleteProtocol);
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
        if !runtime_artifacts
            .iter()
            .any(|artifact| artifact["path"] == "libexec/astro.wasm")
        {
            runtime_artifacts.push(write_manifest_artifact(
                release,
                "libexec/astro.wasm",
                b"verified wasm",
            )?);
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
                "sha256": runtime_tree_digest(&typescript)?,
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
                "target": "test-target",
                "core": core,
                "schema": schema,
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
        let mut entries = vec![PathBuf::from("."), root.clone(), safe.clone()];
        #[cfg(unix)]
        {
            let alias = temp.path().join("project-alias");
            std::os::unix::fs::symlink(&root, &alias)?;
            entries.push(alias);
        }
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
        };

        let error = resolve_worker_program(&spec, root.path()).unwrap_err();
        assert!(error.to_string().contains("security policy"));
        Ok(())
    }

    #[test]
    fn packaged_web_worker_requires_the_declared_runtime_artifact() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let release = temp.path().join("release");
        let test_release = write_test_release_manifest_exact(&release, Vec::new(), Vec::new())?;
        let error =
            locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
        assert!(error.to_string().contains("required Web runtime artifact"));
        assert!(is_security_error(&error.to_string()));
        Ok(())
    }

    #[test]
    fn packaged_web_worker_requires_the_typescript_runtime_component() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let release = temp.path().join("release");
        let astro = write_manifest_artifact(&release, "libexec/astro.wasm", b"verified wasm")?;
        let test_release = write_test_release_manifest_exact(&release, vec![astro], Vec::new())?;
        let error =
            locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
        assert!(error.to_string().contains("typescript-native-compiler"));
        assert!(is_security_error(&error.to_string()));
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
            ("web", "libexec/astro.wasm".to_owned()),
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

        write_protocol_script(serde_json::json!({"go_list_mode": "safe"}))?;
        let normal = execute_worker_inner_with_cancellation(
            &spec,
            &root,
            scan_id,
            &ScanConfig::default(),
            &ProfileConfig::default(),
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
        let astro = release.join("libexec/astro.wasm");
        let compiler = typescript.join(executable_name("tsc"));
        let standard_library = typescript.join("lib.d.ts");
        std::fs::write(&worker, b"verified worker")?;
        std::fs::write(&astro, b"verified wasm")?;
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
        let astro_artifact = manifest_artifact("libexec/astro.wasm", b"verified wasm");
        let component = serde_json::json!({
            "name":"typescript-native-compiler",
            "version":"7.0.2",
            "kind":"executable-tree",
            "root":"libexec/typescript/lib",
            "entrypoint":format!("libexec/typescript/lib/{}", executable_name("tsc")),
            "sha256":digest
        });
        let test_release =
            write_test_release_manifest(&release, vec![astro_artifact], vec![component])?;
        locate_verified_bundled_worker(AdapterKind::Web, &test_release.manifest)?;

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
        let sysroot = release.join("libexec/rust-sysroot");
        let core_source = sysroot.join("library/core/src/lib.rs");
        std::fs::create_dir_all(core_source.parent().context("core source has no parent")?)?;
        std::fs::write(&core_source, b"verified sysroot source")?;
        let component = serde_json::json!({
            "name": "rust-sysroot",
            "version": RUST_BACKEND_REVISION,
            "kind": "data-tree",
            "root": "libexec/rust-sysroot",
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
            ("name", " \t", "name and version"),
            ("version", "\n", "name and version"),
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
        let mut spec = WorkerSpec {
            adapter: AdapterKind::Rust,
            program: script.clone().into_os_string(),
            leading_args: Vec::new(),
            display: script.display().to_string(),
            artifact_path: script,
            runtime_requirement: None,
            expected_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            release_attested: true,
        };
        let execution = execute_worker_inner_with_cancellation(
            &spec,
            &root,
            "release-gate-scan",
            &ScanConfig::default(),
            &ProfileConfig::default(),
            std::future::pending::<std::io::Result<()>>(),
        )
        .await?;
        assert_eq!(execution.events.len(), 2);
        assert!(execution.error.is_none(), "{:?}", execution.error);

        spec.release_attested = false;
        let unverified = execute_worker_inner_with_cancellation(
            &spec,
            &root,
            "unverified-release-gate-scan",
            &ScanConfig::default(),
            &ProfileConfig::default(),
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
        };
        let execution = execute_worker_inner_with_cancellation(
            &spec,
            &root,
            "neutral-cwd-scan",
            &ScanConfig::default(),
            &ProfileConfig::default(),
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
