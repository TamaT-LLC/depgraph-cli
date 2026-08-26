use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context as _, Result, bail};
use depgraph_core::{
    DepgraphCapabilitySet, DepgraphServiceConfig, DepgraphServiceLimits, acquire_store_writer_lock,
    compiler_pack_host_target, default_store_path,
};
use depgraph_mcp_tools::{
    AgentHostCapabilityProfile, AgentHostFormat, agent_host_launch_arguments,
};
use depgraph_operation::{
    OperationRunnerExclusionGuard, operation_journal_path, try_acquire_operation_runner_exclusion,
};
use directories::{BaseDirs, ProjectDirs};
use serde::Deserialize;
use serde_json::{Map as JsonMap, Value as JsonValue};
use sha2::{Digest as _, Sha256};
use toml_edit::{DocumentMut, Item as TomlItem, Table as TomlTable};

use crate::agent_config::{
    AgentConfigRequest, current_snapshot_if_valid, generate_with_verified_package,
    validated_binding, verify_package_for_executable,
};

const OFFICIAL_REPOSITORY: &str = "TamaT-LLC/depgraph-cli";
const MAX_GITHUB_RELEASE_API_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RELEASE_ARCHIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_RELEASE_ARCHIVE_ENTRIES: usize = 250_000;
const MAX_RELEASE_EXPANDED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_SMALL_ASSET_BYTES: u64 = 1024 * 1024;
const MAX_HOST_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum McpHost {
    Codex,
    Claude,
    Cursor,
    Grok,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum McpScope {
    Project,
    User,
}

impl McpScope {
    const ALL: [Self; 2] = [Self::Project, Self::User];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::User => "user",
        }
    }

    fn configuration_root(self, repository_root: &Path) -> Result<PathBuf> {
        match self {
            Self::Project => Ok(repository_root.to_path_buf()),
            Self::User => BaseDirs::new()
                .context("MCP user scope has no home directory")?
                .home_dir()
                .canonicalize()
                .context("MCP user-scope home directory is unavailable"),
        }
    }

    fn server_name(self, repository_root: &Path) -> Result<String> {
        if self == Self::Project {
            return Ok("depgraph".to_owned());
        }
        let root = repository_root
            .to_str()
            .context("MCP user scope requires a UTF-8 repository path")?;
        let digest = hex::encode(Sha256::digest(root.as_bytes()));
        Ok(format!("depgraph-{}", &digest[..16]))
    }
}

impl McpHost {
    const ALL: [Self; 4] = [Self::Codex, Self::Claude, Self::Cursor, Self::Grok];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Cursor => "cursor",
            Self::Grok => "grok",
        }
    }

    pub(crate) const fn display_name(self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::Claude => "Claude Code",
            Self::Cursor => "Cursor",
            Self::Grok => "Grok",
        }
    }

    pub(crate) const fn activation_hint(self, scope: McpScope) -> &'static str {
        match (self, scope) {
            (Self::Codex, McpScope::Project) => {
                "restart Codex to connect the project-scoped depgraph server"
            }
            (Self::Codex, McpScope::User) => {
                "restart Codex to connect the user-scoped depgraph server"
            }
            (Self::Claude, McpScope::Project) => {
                "restart Claude Code and approve the project-scoped depgraph server when prompted"
            }
            (Self::Claude, McpScope::User) => {
                "restart Claude Code to connect the user-scoped depgraph server"
            }
            (Self::Cursor, McpScope::Project) => {
                "restart Cursor to connect the project-scoped depgraph server"
            }
            (Self::Cursor, McpScope::User) => {
                "restart Cursor to connect the user-scoped depgraph server"
            }
            (Self::Grok, McpScope::Project) => {
                "refresh Grok MCP servers to connect the project-scoped depgraph server"
            }
            (Self::Grok, McpScope::User) => {
                "refresh Grok MCP servers to connect the user-scoped depgraph server"
            }
        }
    }

    const fn agent_format(self) -> AgentHostFormat {
        match self {
            Self::Codex | Self::Grok => AgentHostFormat::Codex,
            Self::Claude | Self::Cursor => AgentHostFormat::ClaudeDesktop,
        }
    }

    fn config_path(self, scope: McpScope, repository_root: &Path) -> Result<PathBuf> {
        let root = scope.configuration_root(repository_root)?;
        match self {
            Self::Codex => Ok(root.join(".codex").join("config.toml")),
            Self::Claude if scope == McpScope::Project => Ok(root.join(".mcp.json")),
            Self::Claude => Ok(root.join(".claude.json")),
            Self::Cursor => Ok(root.join(".cursor").join("mcp.json")),
            Self::Grok => Ok(root.join(".grok").join("config.toml")),
        }
    }

    const fn is_json(self) -> bool {
        matches!(self, Self::Claude | Self::Cursor)
    }
}

pub(crate) struct McpWorkflowRequest {
    pub(crate) host: McpHost,
    pub(crate) scope: McpScope,
    pub(crate) requested_root: PathBuf,
    pub(crate) explicit_store: Option<PathBuf>,
}

pub(crate) struct McpSetupOutput {
    pub(crate) root: PathBuf,
    pub(crate) store: PathBuf,
    pub(crate) runtime: PathBuf,
    pub(crate) compiler_pack: PathBuf,
    pub(crate) config: PathBuf,
    pub(crate) server_name: String,
    pub(crate) snapshot_id: String,
    pub(crate) tool_count: usize,
    pub(crate) reused_assets: usize,
    pub(crate) downloaded_assets: usize,
    pub(crate) config_changed: bool,
}

pub(crate) struct McpStatusOutput {
    pub(crate) root: PathBuf,
    pub(crate) store: PathBuf,
    pub(crate) runtime: PathBuf,
    pub(crate) compiler_pack: PathBuf,
    pub(crate) config: PathBuf,
    pub(crate) server_name: String,
    pub(crate) snapshot_id: String,
    pub(crate) tool_count: usize,
}

pub(crate) struct McpUninstallOutput {
    pub(crate) root: PathBuf,
    pub(crate) store: PathBuf,
    pub(crate) config: PathBuf,
    pub(crate) server_name: String,
    pub(crate) config_changed: bool,
    pub(crate) removed_state_files: usize,
    pub(crate) state_retained_for_other_hosts: bool,
}

pub(crate) fn setup(
    request: &McpWorkflowRequest,
    refresh_snapshot: bool,
) -> Result<McpSetupOutput> {
    let binding = resolve_binding(request)?;
    let _lifecycle = acquire_repository_lifecycle_exclusion(&binding.config)?;
    let mut layout = ArtifactLayout::for_current_host()?;
    let server_name = request.scope.server_name(binding.config.canonical_root())?;
    preflight_host_ownership(
        request.host,
        request.scope,
        &server_name,
        &binding.config,
        &layout.cache_base,
    )?;
    let curl = CurlClient::discover(binding.config.canonical_root())?;
    let release = fetch_release_metadata(&curl, &layout)?;
    layout.prepare_directories()?;
    let _lock = CacheLock::acquire(&layout.target_root)?;
    let (reused_assets, downloaded_assets) = prepare_release_assets(&curl, &layout, &release)?;
    verify_checksum_sidecars(&layout, &release)?;
    prepare_extractions(&layout, false)?;

    let agent_inputs = AgentInputPaths::new(&layout);
    let agent_request = agent_inputs.request(request.host, &binding, &release, &layout)?;
    let package = match verify_package_for_executable(&agent_request, &layout.core_path()) {
        Ok(package) => package,
        Err(first_error) => {
            prepare_extractions(&layout, true)?;
            verify_package_for_executable(&agent_request, &layout.core_path()).with_context(
                || {
                    format!(
                        "MCP setup could not repair the verified artifact cache after: {first_error:#}"
                    )
                },
            )?
        }
    };
    let verified_binding = validated_binding(&agent_request)?;
    if !verified_binding.repository_root_seal().matches_live_root() {
        security_bail("repository root changed before the safe scan")?;
    }
    if refresh_snapshot || current_snapshot_if_valid(&verified_binding)?.is_none() {
        run_safe_scan(package.core(), &layout.runtime_root(), &verified_binding)?;
    }
    let generated = generate_with_verified_package(&agent_request, package)?;
    let configuration =
        lifecycle_configuration(request.host, &server_name, &generated.configuration)?;
    let config_path = request
        .host
        .config_path(request.scope, verified_binding.canonical_root())?;
    let config_changed = install_host_configuration(
        request.host,
        request.scope,
        &server_name,
        &verified_binding,
        &config_path,
        &layout.cache_base,
        &configuration,
    )?;

    Ok(McpSetupOutput {
        root: generated.canonical_root,
        store: generated.canonical_store,
        runtime: layout.runtime_root(),
        compiler_pack: layout.compiler_root(),
        config: config_path,
        server_name,
        snapshot_id: generated.current_snapshot_id,
        tool_count: generated.tool_count,
        reused_assets,
        downloaded_assets,
        config_changed,
    })
}

pub(crate) fn status(request: &McpWorkflowRequest) -> Result<McpStatusOutput> {
    let binding = resolve_binding(request)?;
    let layout = ArtifactLayout::for_current_host()?;
    layout.verify_existing_directories()?;
    let _lock = CacheLock::acquire(&layout.target_root)?;
    let curl = CurlClient::discover(binding.config.canonical_root())?;
    let release = fetch_release_metadata(&curl, &layout)?;
    verify_cached_assets(&layout, &release)?;
    verify_checksum_sidecars(&layout, &release)?;
    let agent_inputs = AgentInputPaths::new(&layout);
    let agent_request = agent_inputs.request(request.host, &binding, &release, &layout)?;
    let package = verify_package_for_executable(&agent_request, &layout.core_path())?;
    let generated = generate_with_verified_package(&agent_request, package)?;
    let server_name = request.scope.server_name(&generated.canonical_root)?;
    let configuration =
        lifecycle_configuration(request.host, &server_name, &generated.configuration)?;
    let config_path = request
        .host
        .config_path(request.scope, &generated.canonical_root)?;
    verify_host_configuration(
        request.host,
        request.scope,
        &server_name,
        &config_path,
        &configuration,
    )?;
    Ok(McpStatusOutput {
        root: generated.canonical_root,
        store: generated.canonical_store,
        runtime: layout.runtime_root(),
        compiler_pack: layout.compiler_root(),
        config: config_path,
        server_name,
        snapshot_id: generated.current_snapshot_id,
        tool_count: generated.tool_count,
    })
}

pub(crate) fn uninstall(request: &McpWorkflowRequest) -> Result<McpUninstallOutput> {
    let binding = resolve_binding(request)?;
    let _lifecycle = acquire_repository_lifecycle_exclusion(&binding.config)?;
    let layout = ArtifactLayout::for_current_host()?;
    let server_name = request.scope.server_name(binding.config.canonical_root())?;
    preflight_host_ownership(
        request.host,
        request.scope,
        &server_name,
        &binding.config,
        &layout.cache_base,
    )?;
    let _state_exclusion = acquire_repository_state_exclusion(&binding.config)?;
    let config_path = request
        .host
        .config_path(request.scope, binding.config.canonical_root())?;
    let state_retained_for_other_hosts = other_configuration_exists(
        request.host,
        request.scope,
        &binding.config,
        &layout.cache_base,
    )?;
    let config_changed = remove_host_configuration(
        request.host,
        request.scope,
        &server_name,
        &binding.config,
        &config_path,
        &layout.cache_base,
    )?;
    if !binding.config.repository_root_seal().matches_live_root() {
        security_bail("repository root changed before repository state cleanup")?;
    }
    let removed_state_files = if state_retained_for_other_hosts {
        0
    } else {
        remove_repository_state(&binding.config)?
    };
    Ok(McpUninstallOutput {
        root: binding.config.canonical_root().to_path_buf(),
        store: binding.config.store_path().to_path_buf(),
        config: config_path,
        server_name,
        config_changed,
        removed_state_files,
        state_retained_for_other_hosts,
    })
}

struct Binding {
    config: DepgraphServiceConfig,
}

fn resolve_binding(request: &McpWorkflowRequest) -> Result<Binding> {
    let root = discover_git_repository_root(&request.requested_root)?;
    let store = match &request.explicit_store {
        Some(path) if !path.is_absolute() => {
            security_bail("an explicit MCP Store path must be absolute")?;
            unreachable!()
        }
        Some(path) => path.clone(),
        None => default_store_path(&root)?,
    };
    let config = DepgraphServiceConfig::new(
        &root,
        &store,
        DepgraphCapabilitySet::read_only(),
        DepgraphServiceLimits::default(),
    )
    .context("MCP setup root/Store binding is invalid")?;
    if config.store_path().starts_with(config.canonical_root()) {
        security_bail("the repository-specific Store must be outside the repository")?;
    }
    if !config.repository_root_seal().matches_live_root() {
        security_bail("repository root changed during validation")?;
    }
    Ok(Binding { config })
}

fn discover_git_repository_root(requested: &Path) -> Result<PathBuf> {
    let start = match requested.canonicalize() {
        Ok(start) => start,
        Err(_) => security_bail("the requested MCP setup root is unavailable")?,
    };
    if !start.is_dir() {
        security_bail("the requested MCP setup root is not a directory")?;
    }
    let mut root = None;
    for candidate in start.ancestors() {
        match fs::symlink_metadata(candidate.join(".git")) {
            Ok(_) if valid_git_marker(candidate)? => {
                root = Some(candidate.to_path_buf());
                break;
            }
            Ok(_) => security_bail("the nearest Git marker is invalid or ambiguous")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("MCP setup cannot inspect the Git marker"),
        }
    }
    let Some(root) = root else {
        security_bail("MCP setup requires a directory inside a Git repository")?;
        unreachable!()
    };
    if root.parent().is_none() {
        security_bail("a filesystem root cannot be used as an MCP repository root")?;
    }
    if let Some(home) =
        BaseDirs::new().and_then(|directories| directories.home_dir().canonicalize().ok())
        && root == home
    {
        security_bail("the home directory is too broad for an MCP repository root")?;
    }
    Ok(root)
}

fn valid_git_marker(root: &Path) -> Result<bool> {
    Ok(validated_git_directory(root)?.is_some())
}

fn validated_git_directory(root: &Path) -> Result<Option<PathBuf>> {
    let marker = root.join(".git");
    let metadata = match fs::symlink_metadata(&marker) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("MCP setup cannot inspect the Git marker"),
    };
    if metadata.file_type().is_symlink() {
        return Ok(None);
    }
    let git_directory = if metadata.is_dir() {
        match marker.canonicalize() {
            Ok(directory) => directory,
            Err(_) => return Ok(None),
        }
    } else if metadata.is_file() && metadata.len() <= 4096 {
        let text = fs::read_to_string(&marker).context("Git worktree marker is not UTF-8")?;
        let line = text.strip_suffix('\n').unwrap_or(&text);
        let line = line.strip_suffix('\r').unwrap_or(line);
        let Some(value) = line.strip_prefix("gitdir: ") else {
            return Ok(None);
        };
        if value.is_empty() || value.contains('\n') || value.contains('\r') {
            return Ok(None);
        }
        let declared = Path::new(value);
        let candidate = if declared.is_absolute() {
            declared.to_path_buf()
        } else {
            root.join(declared)
        };
        match candidate.canonicalize() {
            Ok(candidate) if candidate.is_dir() => candidate,
            _ => return Ok(None),
        }
    } else {
        return Ok(None);
    };
    let head = git_directory.join("HEAD");
    if fs::symlink_metadata(head)
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
    {
        Ok(Some(git_directory))
    } else {
        Ok(None)
    }
}

#[derive(Clone)]
struct ArtifactLayout {
    version: String,
    target: String,
    tag: String,
    extension: &'static str,
    cache_base: PathBuf,
    target_root: PathBuf,
    package_name: String,
    compiler_name: String,
}

impl ArtifactLayout {
    fn for_current_host() -> Result<Self> {
        let project_dirs = ProjectDirs::from("com", "TamaT", "depgraph")
            .context("MCP setup cannot determine the operating system cache directory")?;
        Self::new(
            project_dirs.cache_dir(),
            env!("CARGO_PKG_VERSION"),
            compiler_pack_host_target().context("MCP setup does not support this host target")?,
        )
    }

    fn new(cache_base: &Path, version: &str, target: &str) -> Result<Self> {
        if !safe_identity(version) || !safe_identity(target) {
            security_bail("release version or target is unsafe for a cache identity")?;
        }
        let extension = if target.ends_with("windows-msvc") {
            "zip"
        } else {
            "tar.gz"
        };
        let cache_base = cache_base.to_path_buf();
        let target_root = cache_base
            .join("mcp")
            .join("artifacts")
            .join(version)
            .join(target);
        Ok(Self {
            version: version.to_owned(),
            target: target.to_owned(),
            tag: format!("v{version}"),
            extension,
            cache_base,
            target_root,
            package_name: format!("depgraph-{version}-{target}"),
            compiler_name: format!("depgraph-compiler-pack-{version}-{target}"),
        })
    }

    fn expected_asset_names(&self) -> Vec<String> {
        vec![
            self.release_archive_name(),
            format!("{}.sha256", self.release_archive_name()),
            self.compiler_archive_name(),
            format!("{}.sha256", self.compiler_archive_name()),
            self.requirement_name(),
            self.evidence_name(),
        ]
    }

    fn release_archive_name(&self) -> String {
        format!("{}.{}", self.package_name, self.extension)
    }

    fn compiler_archive_name(&self) -> String {
        format!("{}.{}", self.compiler_name, self.extension)
    }

    fn requirement_name(&self) -> String {
        format!("{}.requirement.json", self.compiler_name)
    }

    fn evidence_name(&self) -> String {
        format!("release-post-publish-evidence-{}.json", self.tag)
    }

    fn downloads(&self) -> PathBuf {
        self.target_root.join("downloads")
    }

    fn runtime_parent(&self) -> PathBuf {
        self.target_root.join("runtime")
    }

    fn compiler_parent(&self) -> PathBuf {
        self.target_root.join("compiler")
    }

    fn runtime_root(&self) -> PathBuf {
        self.runtime_parent().join(&self.package_name)
    }

    fn compiler_root(&self) -> PathBuf {
        self.compiler_parent().join(&self.compiler_name)
    }

    fn core_path(&self) -> PathBuf {
        self.runtime_root()
            .join("bin")
            .join(executable_name("depgraph"))
    }

    fn release_manifest(&self) -> PathBuf {
        self.runtime_root().join("release-manifest.json")
    }

    fn requirement_path(&self) -> PathBuf {
        self.compiler_parent().join(self.requirement_name())
    }

    fn asset_path(&self, name: &str) -> PathBuf {
        if name == self.requirement_name() {
            self.requirement_path()
        } else {
            self.downloads().join(name)
        }
    }

    fn prepare_directories(&mut self) -> Result<()> {
        fs::create_dir_all(&self.cache_base).context("MCP setup cannot create its cache root")?;
        let mut current = self
            .cache_base
            .canonicalize()
            .context("MCP setup cannot canonicalize its cache root")?;
        for component in ["mcp", "artifacts", &self.version, &self.target] {
            current = ensure_real_child_directory(&current, component)?;
        }
        self.target_root = current;
        for component in ["downloads", "runtime", "compiler"] {
            ensure_real_child_directory(&self.target_root, component)?;
        }
        Ok(())
    }

    fn verify_existing_directories(&self) -> Result<()> {
        let downloads = self.downloads();
        let runtime = self.runtime_parent();
        let compiler = self.compiler_parent();
        for path in [&self.target_root, &downloads, &runtime, &compiler] {
            let metadata = fs::symlink_metadata(path)
                .with_context(|| format!("MCP setup cache {} is missing", path.display()))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                security_bail("an MCP setup cache component is not a real directory")?;
            }
        }
        Ok(())
    }
}

fn safe_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn ensure_real_child_directory(parent: &Path, component: &str) -> Result<PathBuf> {
    if !safe_identity(component) {
        security_bail("an MCP setup cache component is unsafe")?;
    }
    let child = parent.join(component);
    match fs::create_dir(&child) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("MCP setup cannot create its artifact cache"),
    }
    let metadata = fs::symlink_metadata(&child)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        security_bail("an MCP setup cache component is not a real directory")?;
    }
    child
        .canonicalize()
        .context("MCP setup cannot canonicalize its artifact cache")
}

#[derive(Debug)]
struct RepositoryLifecycleGuard {
    _file: File,
}

fn acquire_repository_lifecycle_exclusion(
    config: &DepgraphServiceConfig,
) -> Result<RepositoryLifecycleGuard> {
    let git_directory = validated_git_directory(config.canonical_root())?
        .context("the repository Git marker changed before MCP lifecycle exclusion")?;
    let lock_path = git_directory.join(".depgraph-mcp-lifecycle.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .context("MCP setup cannot open its repository lifecycle lock")?;
    let file = validate_open_regular_lock(file, &lock_path, "repository lifecycle lock")?;
    match file.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => bail!(
            "another MCP setup/update/uninstall is active for this repository; retry after it completes"
        ),
        Err(fs::TryLockError::Error(error)) => {
            return Err(error).context("MCP setup cannot lock its repository lifecycle");
        }
    }
    if !config.repository_root_seal().matches_live_root()
        || validated_git_directory(config.canonical_root())?.as_deref()
            != Some(git_directory.as_path())
    {
        security_bail("repository identity changed while MCP lifecycle exclusion was acquired")?;
    }
    Ok(RepositoryLifecycleGuard { _file: file })
}

struct CacheLock {
    _file: File,
}

impl CacheLock {
    fn acquire(target_root: &Path) -> Result<Self> {
        let path = target_root.join(".setup-lock");
        let file = open_cache_lock(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(fs::TryLockError::WouldBlock) => bail!(
                "another MCP setup/update is using this version/target cache; retry after it completes"
            ),
            Err(fs::TryLockError::Error(error)) => {
                Err(error).context("MCP setup cannot lock its shared artifact cache")
            }
        }
    }
}

#[derive(Debug)]
struct HostConfigurationLock {
    _file: File,
}

impl HostConfigurationLock {
    fn acquire(host: McpHost, scope: McpScope, config_path: &Path) -> Result<Option<Self>> {
        if scope == McpScope::Project {
            return Ok(None);
        }
        let lock_root = prepare_host_configuration_lock_root(host, config_path)?;
        let rendered_path = config_path.as_os_str().to_string_lossy();
        let mut digest = Sha256::new();
        digest.update(b"depgraph-mcp-host-configuration-lock-v1");
        digest.update((rendered_path.len() as u64).to_le_bytes());
        digest.update(rendered_path.as_bytes());
        let path = lock_root.join(format!("{}.lock", hex::encode(digest.finalize())));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .context("MCP setup cannot open its Agent host configuration lock")?;
        let file = validate_open_regular_lock(file, &path, "Agent host configuration lock")?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(fs::TryLockError::WouldBlock) => bail!(
                "another MCP setup/update/uninstall is modifying this Agent host configuration; retry after it completes"
            ),
            Err(fs::TryLockError::Error(error)) => {
                Err(error).context("MCP setup cannot lock its Agent host configuration")
            }
        }
    }
}

fn prepare_host_configuration_lock_root(host: McpHost, config_path: &Path) -> Result<PathBuf> {
    let parent = config_path
        .parent()
        .context("user-scoped Agent host configuration has no parent")?;
    let home = if host == McpHost::Claude {
        parent
    } else {
        parent
            .parent()
            .context("user-scoped Agent host configuration has no home directory")?
    };
    let metadata = fs::symlink_metadata(home)
        .context("MCP setup cannot inspect the user configuration home")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || home.parent().is_none() {
        return security_bail("the user configuration home must be a real bounded directory");
    }
    let current = home
        .canonicalize()
        .context("MCP setup cannot canonicalize the user configuration home")?;
    ensure_real_child_directory(&current, ".depgraph-mcp-locks")
}

fn open_cache_lock(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .context("MCP setup cannot open its shared artifact cache lock")?;
    validate_open_regular_lock(file, path, "shared artifact cache lock")
}

fn validate_open_regular_lock(file: File, path: &Path, description: &str) -> Result<File> {
    let opened = file.metadata()?;
    let linked = fs::symlink_metadata(path)?;
    if !opened.is_file() || linked.file_type().is_symlink() || !linked.is_file() {
        security_bail(&format!(
            "the {description} is not a regular non-symlink file"
        ))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if opened.dev() != linked.dev() || opened.ino() != linked.ino() {
            security_bail(&format!("the {description} changed while it was opened"))?;
        }
    }
    Ok(file)
}

fn executable_name(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}

fn security_bail<T>(message: &str) -> Result<T> {
    bail!("MCP setup security policy violation: {message}")
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    size: u64,
    digest: Option<String>,
    browser_download_url: String,
}

#[derive(Clone)]
struct ReleaseAsset {
    name: String,
    size: u64,
    sha256: String,
    url: String,
}

struct ReleaseMetadata {
    assets: BTreeMap<String, ReleaseAsset>,
}

impl ReleaseMetadata {
    fn asset(&self, name: &str) -> Result<&ReleaseAsset> {
        self.assets
            .get(name)
            .with_context(|| format!("official release has no required asset {name}"))
    }

    fn trusted_evidence_sha256(&self, layout: &ArtifactLayout) -> Result<&str> {
        Ok(&self.asset(&layout.evidence_name())?.sha256)
    }
}

fn fetch_release_metadata(curl: &CurlClient, layout: &ArtifactLayout) -> Result<ReleaseMetadata> {
    let api_url = format!(
        "https://api.github.com/repos/{OFFICIAL_REPOSITORY}/releases/tags/{}",
        layout.tag
    );
    let bytes = curl.get_bytes(&api_url, MAX_GITHUB_RELEASE_API_BYTES)?;
    parse_release_metadata(&bytes, layout)
}

fn parse_release_metadata(bytes: &[u8], layout: &ArtifactLayout) -> Result<ReleaseMetadata> {
    let release: GithubRelease =
        serde_json::from_slice(bytes).context("official GitHub release metadata is invalid")?;
    if release.tag_name != layout.tag || release.draft || release.prerelease {
        security_bail("the selected release is not the exact published stable tag")?;
    }

    let expected = layout
        .expected_asset_names()
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut assets = BTreeMap::new();
    for asset in release.assets {
        if !expected.contains(&asset.name) {
            continue;
        }
        let digest = asset
            .digest
            .as_deref()
            .and_then(|value| value.strip_prefix("sha256:"))
            .context("official GitHub release asset has no SHA-256 digest")?;
        if !valid_sha256(digest) || asset.size == 0 || asset.size > asset_limit(&asset.name) {
            security_bail("official GitHub release asset metadata is outside its bounds")?;
        }
        let expected_url = format!(
            "https://github.com/{OFFICIAL_REPOSITORY}/releases/download/{}/{}",
            layout.tag, asset.name
        );
        if asset.browser_download_url != expected_url {
            security_bail("official GitHub release asset URL is not canonical")?;
        }
        let identity = ReleaseAsset {
            name: asset.name.clone(),
            size: asset.size,
            sha256: digest.to_owned(),
            url: expected_url,
        };
        if assets.insert(asset.name, identity).is_some() {
            security_bail("official GitHub release contains a duplicate required asset")?;
        }
    }
    if assets.keys().cloned().collect::<BTreeSet<_>>() != expected {
        security_bail("official GitHub release is missing a required setup asset")?;
    }
    Ok(ReleaseMetadata { assets })
}

fn asset_limit(name: &str) -> u64 {
    if name.ends_with(".tar.gz") || name.ends_with(".zip") {
        MAX_RELEASE_ARCHIVE_BYTES
    } else if name.ends_with(".sha256") {
        1024
    } else {
        MAX_SMALL_ASSET_BYTES
    }
}

struct CurlClient {
    executable: PathBuf,
    search_path: OsString,
    windows_system_root: Option<OsString>,
    windows_directory: Option<OsString>,
}

impl CurlClient {
    fn discover(repository_root: &Path) -> Result<Self> {
        let executable = find_curl(repository_root)?;
        let parent = executable
            .parent()
            .context("the selected curl executable has no parent")?;
        let search_path = std::env::join_paths([parent])?;
        Ok(Self {
            executable,
            search_path,
            windows_system_root: std::env::var_os("SystemRoot"),
            windows_directory: std::env::var_os("WINDIR"),
        })
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        command.env_clear().env("PATH", &self.search_path);
        if let Some(value) = &self.windows_system_root {
            command.env("SystemRoot", value);
        }
        if let Some(value) = &self.windows_directory {
            command.env("WINDIR", value);
        }
        command
    }

    fn common_arguments(command: &mut Command, maximum_bytes: u64) {
        command.args([
            "--disable",
            "--fail",
            "--location",
            "--show-error",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-redirs",
            "5",
            "--tlsv1.2",
            "--connect-timeout",
            "30",
            "--retry",
            "3",
            "--retry-all-errors",
            "--max-filesize",
        ]);
        command.arg(maximum_bytes.to_string());
    }

    fn get_bytes(&self, url: &str, maximum_bytes: u64) -> Result<Vec<u8>> {
        let mut command = self.command();
        Self::common_arguments(&mut command, maximum_bytes);
        command.args([
            "--silent",
            "--header",
            "Accept: application/vnd.github+json",
            "--header",
            "X-GitHub-Api-Version: 2022-11-28",
            "--user-agent",
            "depgraph-mcp-setup",
            url,
        ]);
        let output = command
            .output()
            .context("MCP setup could not query the official GitHub release API with curl")?;
        if !output.status.success() {
            let stderr = bounded_stderr(&output.stderr);
            bail!("official GitHub release API request failed: {stderr}");
        }
        if output.stdout.is_empty()
            || u64::try_from(output.stdout.len()).unwrap_or(u64::MAX) > maximum_bytes
        {
            security_bail("official GitHub release API response is outside its byte bound")?;
        }
        Ok(output.stdout)
    }

    fn download(&self, asset: &ReleaseAsset, destination: &Path) -> Result<()> {
        let mut command = self.command();
        Self::common_arguments(&mut command, asset.size);
        command
            .args(["--progress-bar", "--output"])
            .arg(destination)
            .arg(&asset.url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let status = command.status().with_context(|| {
            format!("MCP setup could not download official asset {}", asset.name)
        })?;
        if !status.success() {
            bail!("official release asset download failed for {}", asset.name);
        }
        Ok(())
    }
}

fn bounded_stderr(bytes: &[u8]) -> String {
    let length = bytes.len().min(4096);
    String::from_utf8_lossy(&bytes[..length]).trim().to_owned()
}

fn find_curl(repository_root: &Path) -> Result<PathBuf> {
    let path = std::env::var_os("PATH").context("MCP setup requires curl on an absolute PATH")?;
    let binary = if cfg!(windows) { "curl.exe" } else { "curl" };
    for directory in std::env::split_paths(&path) {
        if !directory.is_absolute() {
            continue;
        }
        let Ok(directory) = directory.canonicalize() else {
            continue;
        };
        if directory.starts_with(repository_root) {
            continue;
        }
        let candidate = directory.join(binary);
        let Ok(metadata) = fs::symlink_metadata(&candidate) else {
            continue;
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o111 == 0 {
                continue;
            }
        }
        let Ok(candidate) = candidate.canonicalize() else {
            continue;
        };
        if !candidate.starts_with(repository_root) {
            return Ok(candidate);
        }
    }
    bail!("MCP setup requires a real curl executable outside the repository on an absolute PATH")
}

fn prepare_release_assets(
    curl: &CurlClient,
    layout: &ArtifactLayout,
    release: &ReleaseMetadata,
) -> Result<(usize, usize)> {
    let mut reused = 0_usize;
    let mut downloaded = 0_usize;
    for name in layout.expected_asset_names() {
        let asset = release.asset(&name)?;
        let path = layout.asset_path(&name);
        if verified_cached_asset(&path, asset)? {
            reused += 1;
            continue;
        }
        eprintln!(
            "mcp setup: downloading {} ({} bytes)",
            asset.name, asset.size
        );
        download_asset_atomically(curl, asset, &path)?;
        downloaded += 1;
    }
    Ok((reused, downloaded))
}

fn verify_cached_assets(layout: &ArtifactLayout, release: &ReleaseMetadata) -> Result<()> {
    for name in layout.expected_asset_names() {
        let asset = release.asset(&name)?;
        if !verified_cached_asset(&layout.asset_path(&name), asset)? {
            bail!(
                "MCP setup asset {} is missing or does not match the official release; rerun `depgraph mcp update --host codex`",
                asset.name
            );
        }
    }
    Ok(())
}

fn verified_cached_asset(path: &Path, asset: &ReleaseAsset) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("MCP setup cannot inspect a cached asset"),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        security_bail("a cached release asset is not a regular non-symlink file")?;
    }
    if metadata.len() != asset.size {
        return Ok(false);
    }
    Ok(sha256_file(path)? == asset.sha256)
}

fn download_asset_atomically(
    curl: &CurlClient,
    asset: &ReleaseAsset,
    destination: &Path,
) -> Result<()> {
    let parent = destination
        .parent()
        .context("cached release asset has no parent")?;
    let mut builder = tempfile::Builder::new();
    builder.prefix(".depgraph-mcp-download-");
    let temporary = builder
        .tempfile_in(parent)
        .context("MCP setup cannot create a temporary asset download")?;
    curl.download(asset, temporary.path())?;
    let metadata = temporary.as_file().metadata()?;
    if metadata.len() != asset.size || sha256_file(temporary.path())? != asset.sha256 {
        security_bail("downloaded release asset differs from GitHub asset metadata")?;
    }
    temporary
        .persist(destination)
        .map(|_| ())
        .map_err(|error| error.error)
        .with_context(|| format!("MCP setup cannot publish cached asset {}", asset.name))
}

fn verify_checksum_sidecars(layout: &ArtifactLayout, release: &ReleaseMetadata) -> Result<()> {
    for archive_name in [
        layout.release_archive_name(),
        layout.compiler_archive_name(),
    ] {
        let archive = release.asset(&archive_name)?;
        let checksum_name = format!("{archive_name}.sha256");
        let checksum_path = layout.asset_path(&checksum_name);
        let expected = format!("{}  {archive_name}\n", archive.sha256);
        if fs::read(&checksum_path)? != expected.as_bytes() {
            security_bail("release checksum sidecar does not attest its selected archive")?;
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut input = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn prepare_extractions(layout: &ArtifactLayout, replace: bool) -> Result<()> {
    let runtime_root = layout.runtime_root();
    if replace || !runtime_root.exists() {
        extract_archive_atomically(
            &layout.asset_path(&layout.release_archive_name()),
            &layout.runtime_parent(),
            &layout.package_name,
            replace,
        )?;
    } else {
        require_real_directory(&runtime_root, "cached runtime")?;
    }

    let compiler_root = layout.compiler_root();
    if replace || !compiler_root.exists() {
        extract_archive_atomically(
            &layout.asset_path(&layout.compiler_archive_name()),
            &layout.compiler_parent(),
            &layout.compiler_name,
            replace,
        )?;
    } else {
        require_real_directory(&compiler_root, "cached compiler pack")?;
    }
    Ok(())
}

fn require_real_directory(path: &Path, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("MCP setup {description} is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        security_bail("a cached extraction is not a real directory")?;
    }
    Ok(())
}

fn extract_archive_atomically(
    archive: &Path,
    parent: &Path,
    expected_root_name: &str,
    replace: bool,
) -> Result<()> {
    require_real_directory(parent, "extraction parent")?;
    let staging = tempfile::Builder::new()
        .prefix(".depgraph-mcp-extract-")
        .tempdir_in(parent)?;
    if archive.extension() == Some(OsStr::new("zip")) {
        extract_zip(archive, staging.path(), expected_root_name)?;
    } else {
        extract_tar_gz(archive, staging.path(), expected_root_name)?;
    }
    let staged_root = staging.path().join(expected_root_name);
    require_real_directory(&staged_root, "staged extraction")?;
    let destination = parent.join(expected_root_name);
    let destination_exists = fs::symlink_metadata(&destination).is_ok();
    if destination_exists {
        let metadata = fs::symlink_metadata(&destination)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            security_bail("a cached extraction cannot be safely replaced")?;
        }
        if !replace {
            return Ok(());
        }
    }

    let backup = tempfile::Builder::new()
        .prefix(".depgraph-mcp-backup-")
        .tempdir_in(parent)?;
    let backup_path = backup.path().join("previous");
    if destination_exists {
        fs::rename(&destination, &backup_path)
            .context("MCP setup cannot stage the previous cached extraction")?;
    }
    if let Err(error) = fs::rename(&staged_root, &destination) {
        if destination_exists {
            let _ = fs::rename(&backup_path, &destination);
        }
        return Err(error).context("MCP setup cannot publish an extracted release archive");
    }
    Ok(())
}

fn extract_tar_gz(archive: &Path, destination: &Path, expected_root: &str) -> Result<()> {
    let decoder = flate2::read::GzDecoder::new(File::open(archive)?);
    let mut archive = tar::Archive::new(decoder);
    let mut entries = 0_usize;
    let mut expanded_bytes = 0_u64;
    let mut seen = BTreeSet::new();
    for entry in archive
        .entries()
        .context("MCP setup cannot read a release tar archive")?
    {
        let mut entry = entry?;
        entries = entries.checked_add(1).context("archive entry overflow")?;
        expanded_bytes = expanded_bytes
            .checked_add(entry.size())
            .context("archive expanded-size overflow")?;
        check_archive_bounds(entries, expanded_bytes)?;
        let relative = safe_archive_path(&entry.path()?, expected_root)?;
        if !seen.insert(relative.clone()) {
            security_bail("release archive contains a duplicate path")?;
        }
        let output = destination.join(&relative);
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            create_archive_directory(&output)?;
        } else if kind.is_file() {
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .context("MCP setup cannot create a release archive file")?;
            let copied = std::io::copy(&mut entry, &mut file)?;
            if copied != entry.size() {
                security_bail("release archive file differs from its declared size")?;
            }
            file.flush()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = entry.header().mode()? & 0o777;
                fs::set_permissions(&output, fs::Permissions::from_mode(mode))?;
            }
        } else {
            security_bail("release archive contains a link or special entry")?;
        }
    }
    if entries == 0 || !destination.join(expected_root).is_dir() {
        security_bail("release archive has no expected package root")?;
    }
    Ok(())
}

fn extract_zip(archive: &Path, destination: &Path, expected_root: &str) -> Result<()> {
    let mut archive = zip::ZipArchive::new(File::open(archive)?)
        .context("MCP setup cannot read a release zip archive")?;
    if archive.is_empty() || archive.len() > MAX_RELEASE_ARCHIVE_ENTRIES {
        security_bail("release zip entry count is outside its bound")?;
    }
    let mut expanded_bytes = 0_u64;
    let mut seen = BTreeSet::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        expanded_bytes = expanded_bytes
            .checked_add(entry.size())
            .context("archive expanded-size overflow")?;
        check_archive_bounds(index + 1, expanded_bytes)?;
        if entry.name().contains('\\') {
            security_bail("release zip contains an ambiguous path separator")?;
        }
        let relative = safe_archive_path(Path::new(entry.name()), expected_root)?;
        if !seen.insert(relative.clone()) {
            security_bail("release zip contains a duplicate path")?;
        }
        let unix_file_type = entry.unix_mode().map(|mode| mode & 0o170000);
        if unix_file_type.is_some_and(|file_type| {
            file_type != 0 && file_type != 0o040000 && file_type != 0o100000
        }) {
            security_bail("release zip contains a link or special entry")?;
        }
        let output = destination.join(&relative);
        if entry.is_dir() {
            create_archive_directory(&output)?;
        } else if entry.is_file() {
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)?;
            let copied = std::io::copy(&mut entry, &mut file)?;
            if copied != entry.size() {
                security_bail("release zip file differs from its declared size")?;
            }
            file.flush()?;
            #[cfg(unix)]
            if let Some(mode) = entry.unix_mode() {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&output, fs::Permissions::from_mode(mode & 0o777))?;
            }
        } else {
            security_bail("release zip contains a link or special entry")?;
        }
    }
    if !destination.join(expected_root).is_dir() {
        security_bail("release zip has no expected package root")?;
    }
    Ok(())
}

fn create_archive_directory(path: &Path) -> Result<()> {
    match fs::create_dir_all(path) {
        Ok(()) => {}
        Err(error) => return Err(error).context("MCP setup cannot create an archive directory"),
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        security_bail("release archive directory is not a real directory")?;
    }
    Ok(())
}

fn check_archive_bounds(entries: usize, expanded_bytes: u64) -> Result<()> {
    if entries > MAX_RELEASE_ARCHIVE_ENTRIES || expanded_bytes > MAX_RELEASE_EXPANDED_BYTES {
        security_bail("release archive exceeds its entry or expanded-size bound")?;
    }
    Ok(())
}

fn safe_archive_path(path: &Path, expected_root: &str) -> Result<PathBuf> {
    if path.is_absolute() {
        security_bail("release archive contains an absolute path")?;
    }
    let mut components = path.components();
    let Some(Component::Normal(root)) = components.next() else {
        security_bail("release archive contains an invalid path")?;
        unreachable!()
    };
    if root != OsStr::new(expected_root) {
        security_bail("release archive contains a path outside its package root")?;
    }
    let mut safe = PathBuf::from(root);
    for component in components {
        let Component::Normal(component) = component else {
            security_bail("release archive contains path traversal")?;
            unreachable!()
        };
        safe.push(component);
    }
    Ok(safe)
}

struct AgentInputPaths {
    release_archive: PathBuf,
    release_checksum: PathBuf,
    release_evidence: PathBuf,
    release_manifest: PathBuf,
    compiler_pack_requirement: PathBuf,
}

impl AgentInputPaths {
    fn new(layout: &ArtifactLayout) -> Self {
        let release_archive_name = layout.release_archive_name();
        Self {
            release_archive: layout.asset_path(&release_archive_name),
            release_checksum: layout.asset_path(&format!("{release_archive_name}.sha256")),
            release_evidence: layout.asset_path(&layout.evidence_name()),
            release_manifest: layout.release_manifest(),
            compiler_pack_requirement: layout.requirement_path(),
        }
    }

    fn request<'a>(
        &'a self,
        host: McpHost,
        binding: &'a Binding,
        release: &'a ReleaseMetadata,
        layout: &ArtifactLayout,
    ) -> Result<AgentConfigRequest<'a>> {
        Ok(AgentConfigRequest {
            root: binding.config.canonical_root(),
            store: binding.config.store_path(),
            release_archive: &self.release_archive,
            release_checksum: &self.release_checksum,
            release_evidence: &self.release_evidence,
            trusted_release_evidence_sha256: release.trusted_evidence_sha256(layout)?,
            release_manifest: &self.release_manifest,
            compiler_pack_requirement: &self.compiler_pack_requirement,
            format: host.agent_format(),
            profile: AgentHostCapabilityProfile::Read,
            acknowledge_privileged_effects: false,
            acknowledge_project_exec_human_confirmation: false,
        })
    }
}

fn run_safe_scan(core: &Path, release_root: &Path, config: &DepgraphServiceConfig) -> Result<()> {
    eprintln!(
        "mcp setup: creating a safe snapshot for {}",
        config.canonical_root().display()
    );
    let output = Command::new(core)
        .current_dir(release_root)
        .arg("--store")
        .arg(config.store_path())
        .arg("scan")
        .arg(config.canonical_root())
        .arg("--json")
        .env_remove("DEPGRAPH_RUST_WORKER")
        .env_remove("DEPGRAPH_GO_WORKER")
        .env_remove("DEPGRAPH_WEB_WORKER")
        .stdin(Stdio::null())
        .output()
        .context("MCP setup could not start the verified depgraph safe scanner")?;
    if !output.status.success() {
        bail!(
            "MCP setup safe scan failed: {}",
            bounded_stderr(&output.stderr)
        );
    }
    let outcome: serde_json::Value = serde_json::from_slice(&output.stdout)
        .context("MCP setup safe scan returned invalid JSON")?;
    if outcome["status"] != "completed" || outcome["coverage"]["project_code_executed"] != false {
        security_bail("safe scan did not produce a completed non-executing snapshot")?;
    }
    if current_snapshot_if_valid(config)?.is_none() {
        security_bail("safe scan did not publish a current snapshot for this root")?;
    }
    Ok(())
}

fn lifecycle_configuration(host: McpHost, server_name: &str, generated: &str) -> Result<String> {
    if host.is_json() {
        let mut value = parse_json(generated, "generated MCP configuration")?;
        let entry = value
            .as_object_mut()
            .and_then(|root| root.get_mut("mcpServers"))
            .and_then(JsonValue::as_object_mut)
            .and_then(|servers| servers.remove("depgraph"))
            .context("generated MCP configuration has no depgraph entry")?;
        set_json_server_entry(&mut value, server_name, entry)?;
        return serde_json::to_string_pretty(&value)
            .context("generated MCP configuration rendering failed");
    }
    let mut document = parse_edit_toml(generated, "generated MCP configuration")?;
    let mut entry = document
        .get_mut("mcp_servers")
        .and_then(TomlItem::as_table_like_mut)
        .and_then(|servers| servers.remove("depgraph"))
        .context("generated Grok MCP configuration has no depgraph entry")?;
    if host == McpHost::Grok {
        let table = entry
            .as_table_like_mut()
            .context("generated Grok MCP entry must be a TOML table")?;
        table.remove("required");
        table.remove("default_tools_approval_mode");
    }
    set_editable_server_entry(&mut document, server_name, entry)?;
    Ok(document.to_string())
}

fn install_host_configuration(
    host: McpHost,
    scope: McpScope,
    server_name: &str,
    binding: &DepgraphServiceConfig,
    config_path: &Path,
    managed_cache_base: &Path,
    generated: &str,
) -> Result<bool> {
    let _configuration_lock = HostConfigurationLock::acquire(host, scope, config_path)?;
    if host.is_json() {
        install_json_configuration(
            host,
            scope,
            server_name,
            binding,
            config_path,
            managed_cache_base,
            generated,
        )
    } else {
        install_toml_configuration(
            host,
            scope,
            server_name,
            binding,
            config_path,
            managed_cache_base,
            generated,
        )
    }
}

fn install_toml_configuration(
    host: McpHost,
    scope: McpScope,
    server_name: &str,
    binding: &DepgraphServiceConfig,
    config_path: &Path,
    managed_cache_base: &Path,
    generated: &str,
) -> Result<bool> {
    let generated_value = parse_toml(generated, "generated MCP configuration")?;
    let desired_value = server_entry(&generated_value, server_name)?.clone();
    let desired_item = editable_server_entry(generated, server_name)?;
    let existing_bytes = read_optional_bounded_config(host, config_path)?;
    let existing = match &existing_bytes {
        Some(bytes) => parse_toml_bytes(bytes, "existing project MCP configuration")?,
        None => toml::Value::Table(toml::Table::new()),
    };
    if let Some(current) = checked_server_entry(&existing, server_name)? {
        if current == &desired_value {
            return Ok(false);
        }
        if !toml_entry_matches_binding(
            host,
            current,
            binding.canonical_root(),
            binding.store_path(),
            managed_cache_base,
        ) {
            return security_bail(&format!(
                "the existing {} depgraph entry is not owned by this scoped MCP setup",
                host.display_name()
            ));
        }
    }
    let mut document = match &existing_bytes {
        Some(bytes) => parse_edit_toml_bytes(bytes, "existing project MCP configuration")?,
        None => DocumentMut::new(),
    };
    set_editable_server_entry(&mut document, server_name, desired_item)?;
    let rendered = document.to_string();
    if !binding.repository_root_seal().matches_live_root() {
        security_bail("repository root changed before MCP configuration update")?;
    }
    ensure_config_directory(host, scope, binding.canonical_root(), config_path)?;
    atomic_write(host, config_path, rendered.as_bytes())?;
    if !binding.repository_root_seal().matches_live_root() {
        security_bail("repository root changed after MCP configuration update")?;
    }
    Ok(true)
}

fn install_json_configuration(
    host: McpHost,
    scope: McpScope,
    server_name: &str,
    binding: &DepgraphServiceConfig,
    config_path: &Path,
    managed_cache_base: &Path,
    generated: &str,
) -> Result<bool> {
    let generated_value = parse_json(generated, "generated MCP configuration")?;
    let desired_value = json_server_entry(&generated_value, server_name)?.clone();
    let existing_bytes = read_optional_bounded_config(host, config_path)?;
    let mut existing = match &existing_bytes {
        Some(bytes) => parse_json_bytes(bytes, "existing project MCP configuration")?,
        None => JsonValue::Object(JsonMap::new()),
    };
    if let Some(current) = checked_json_server_entry(&existing, server_name)? {
        if current == &desired_value {
            return Ok(false);
        }
        if !json_entry_matches_binding(
            current,
            binding.canonical_root(),
            binding.store_path(),
            managed_cache_base,
        ) {
            return security_bail(&format!(
                "the existing {} depgraph entry is not owned by this scoped MCP setup",
                host.display_name()
            ));
        }
    }
    set_json_server_entry(&mut existing, server_name, desired_value)?;
    let mut rendered = serde_json::to_vec_pretty(&existing)
        .context("project MCP configuration rendering failed")?;
    rendered.push(b'\n');
    if !binding.repository_root_seal().matches_live_root() {
        security_bail("repository root changed before MCP configuration update")?;
    }
    ensure_config_directory(host, scope, binding.canonical_root(), config_path)?;
    atomic_write(host, config_path, &rendered)?;
    if !binding.repository_root_seal().matches_live_root() {
        security_bail("repository root changed after MCP configuration update")?;
    }
    Ok(true)
}

fn verify_host_configuration(
    host: McpHost,
    scope: McpScope,
    server_name: &str,
    config_path: &Path,
    generated: &str,
) -> Result<()> {
    let bytes = read_optional_bounded_config(host, config_path)?.with_context(|| {
        format!(
            "{}-scoped {} configuration is not installed",
            scope.as_str(),
            config_path.display()
        )
    })?;
    let matches = if host.is_json() {
        let existing = parse_json_bytes(&bytes, "existing project MCP configuration")?;
        let generated = parse_json(generated, "generated MCP configuration")?;
        checked_json_server_entry(&existing, server_name)?
            == Some(json_server_entry(&generated, server_name)?)
    } else {
        let existing = parse_toml_bytes(&bytes, "existing project MCP configuration")?;
        let generated = parse_toml(generated, "generated MCP configuration")?;
        checked_server_entry(&existing, server_name)?
            == Some(server_entry(&generated, server_name)?)
    };
    if !matches {
        bail!(
            "{}-scoped {} MCP entry differs from the verified binding; rerun `depgraph mcp update --host {} --scope {}`",
            scope.as_str(),
            host.display_name(),
            host.as_str(),
            scope.as_str()
        );
    }
    Ok(())
}

fn remove_host_configuration(
    host: McpHost,
    scope: McpScope,
    server_name: &str,
    binding: &DepgraphServiceConfig,
    config_path: &Path,
    managed_cache_base: &Path,
) -> Result<bool> {
    let _configuration_lock = HostConfigurationLock::acquire(host, scope, config_path)?;
    if host.is_json() {
        remove_json_configuration(
            host,
            server_name,
            binding,
            config_path,
            binding.canonical_root(),
            binding.store_path(),
            managed_cache_base,
        )
    } else {
        remove_toml_configuration(
            host,
            server_name,
            binding,
            config_path,
            binding.canonical_root(),
            binding.store_path(),
            managed_cache_base,
        )
    }
}

fn remove_toml_configuration(
    host: McpHost,
    server_name: &str,
    binding: &DepgraphServiceConfig,
    config_path: &Path,
    expected_root: &Path,
    expected_store: &Path,
    managed_cache_base: &Path,
) -> Result<bool> {
    let Some(bytes) = read_optional_bounded_config(host, config_path)? else {
        return Ok(false);
    };
    let existing = parse_toml_bytes(&bytes, "existing project MCP configuration")?;
    let Some(entry) = checked_server_entry(&existing, server_name)? else {
        return Ok(false);
    };
    if !toml_entry_matches_binding(
        host,
        entry,
        expected_root,
        expected_store,
        managed_cache_base,
    ) {
        return security_bail(&format!(
            "the existing {} depgraph entry is not owned by this scoped MCP setup",
            host.display_name()
        ));
    }
    let mut document = parse_edit_toml_bytes(&bytes, "existing project MCP configuration")?;
    remove_editable_server_entry(&mut document, server_name)?;
    let rendered = document.to_string();
    if !binding.repository_root_seal().matches_live_root() {
        security_bail("repository root changed before MCP configuration removal")?;
    }
    atomic_write(host, config_path, rendered.as_bytes())?;
    Ok(true)
}

fn remove_json_configuration(
    host: McpHost,
    server_name: &str,
    binding: &DepgraphServiceConfig,
    config_path: &Path,
    expected_root: &Path,
    expected_store: &Path,
    managed_cache_base: &Path,
) -> Result<bool> {
    let Some(bytes) = read_optional_bounded_config(host, config_path)? else {
        return Ok(false);
    };
    let mut existing = parse_json_bytes(&bytes, "existing project MCP configuration")?;
    let Some(entry) = checked_json_server_entry(&existing, server_name)? else {
        return Ok(false);
    };
    if !json_entry_matches_binding(entry, expected_root, expected_store, managed_cache_base) {
        return security_bail(&format!(
            "the existing {} depgraph entry is not owned by this scoped MCP setup",
            host.display_name()
        ));
    }
    remove_json_server_entry(&mut existing, server_name)?;
    let mut rendered = serde_json::to_vec_pretty(&existing)
        .context("project MCP configuration rendering failed")?;
    rendered.push(b'\n');
    if !binding.repository_root_seal().matches_live_root() {
        security_bail("repository root changed before MCP configuration removal")?;
    }
    atomic_write(host, config_path, &rendered)?;
    Ok(true)
}

fn parse_toml(input: &str, description: &str) -> Result<toml::Value> {
    toml::from_str(input).with_context(|| format!("{description} is invalid TOML"))
}

fn parse_toml_bytes(input: &[u8], description: &str) -> Result<toml::Value> {
    let input =
        std::str::from_utf8(input).with_context(|| format!("{description} is not UTF-8"))?;
    parse_toml(input, description)
}

fn parse_json(input: &str, description: &str) -> Result<JsonValue> {
    serde_json::from_str(input).with_context(|| format!("{description} is invalid JSON"))
}

fn parse_json_bytes(input: &[u8], description: &str) -> Result<JsonValue> {
    let input =
        std::str::from_utf8(input).with_context(|| format!("{description} is not UTF-8"))?;
    parse_json(input, description)
}

fn parse_edit_toml(input: &str, description: &str) -> Result<DocumentMut> {
    input
        .parse::<DocumentMut>()
        .with_context(|| format!("{description} is invalid editable TOML"))
}

fn parse_edit_toml_bytes(input: &[u8], description: &str) -> Result<DocumentMut> {
    let input =
        std::str::from_utf8(input).with_context(|| format!("{description} is not UTF-8"))?;
    parse_edit_toml(input, description)
}

fn editable_server_entry(generated: &str, server_name: &str) -> Result<TomlItem> {
    let document = parse_edit_toml(generated, "generated MCP configuration")?;
    let servers = document
        .get("mcp_servers")
        .and_then(TomlItem::as_table_like)
        .context("generated MCP configuration has no mcp_servers table")?;
    let mut entry = servers
        .get(server_name)
        .cloned()
        .with_context(|| format!("generated MCP configuration has no {server_name} entry"))?;
    if let Some(table) = entry.as_table_mut() {
        table.set_position(None);
    }
    Ok(entry)
}

fn server_entry<'a>(value: &'a toml::Value, server_name: &str) -> Result<&'a toml::Value> {
    checked_server_entry(value, server_name)?.with_context(|| {
        format!("generated MCP configuration has no mcp_servers.{server_name} table")
    })
}

fn checked_server_entry<'a>(
    value: &'a toml::Value,
    server_name: &str,
) -> Result<Option<&'a toml::Value>> {
    let root = value
        .as_table()
        .context("project MCP configuration root must be a TOML table")?;
    let Some(servers) = root.get("mcp_servers") else {
        return Ok(None);
    };
    let servers = servers
        .as_table()
        .context("project MCP mcp_servers must be a TOML table")?;
    Ok(servers.get(server_name))
}

fn json_server_entry<'a>(value: &'a JsonValue, server_name: &str) -> Result<&'a JsonValue> {
    checked_json_server_entry(value, server_name)?.with_context(|| {
        format!("generated MCP configuration has no mcpServers.{server_name} object")
    })
}

fn checked_json_server_entry<'a>(
    value: &'a JsonValue,
    server_name: &str,
) -> Result<Option<&'a JsonValue>> {
    let root = value
        .as_object()
        .context("project MCP configuration root must be a JSON object")?;
    let Some(servers) = root.get("mcpServers") else {
        return Ok(None);
    };
    let servers = servers
        .as_object()
        .context("project MCP mcpServers must be a JSON object")?;
    Ok(servers.get(server_name))
}

fn preflight_host_ownership(
    host: McpHost,
    scope: McpScope,
    server_name: &str,
    binding: &DepgraphServiceConfig,
    managed_cache_base: &Path,
) -> Result<()> {
    let path = host.config_path(scope, binding.canonical_root())?;
    let Some(bytes) = read_optional_bounded_config(host, &path)? else {
        return Ok(());
    };
    let owned = if host.is_json() {
        let existing = parse_json_bytes(&bytes, "existing project MCP configuration")?;
        checked_json_server_entry(&existing, server_name)?.is_none_or(|entry| {
            json_entry_matches_binding(
                entry,
                binding.canonical_root(),
                binding.store_path(),
                managed_cache_base,
            )
        })
    } else {
        let existing = parse_toml_bytes(&bytes, "existing project MCP configuration")?;
        checked_server_entry(&existing, server_name)?.is_none_or(|entry| {
            toml_entry_matches_binding(
                host,
                entry,
                binding.canonical_root(),
                binding.store_path(),
                managed_cache_base,
            )
        })
    };
    if !owned {
        return security_bail(&format!(
            "the existing {} depgraph entry is not owned by this scoped MCP setup",
            host.display_name()
        ));
    }
    Ok(())
}

fn other_configuration_exists(
    removed_host: McpHost,
    removed_scope: McpScope,
    binding: &DepgraphServiceConfig,
    managed_cache_base: &Path,
) -> Result<bool> {
    let root = binding.canonical_root();
    for scope in McpScope::ALL {
        let server_name = scope.server_name(root)?;
        for host in McpHost::ALL {
            if host == removed_host && scope == removed_scope {
                continue;
            }
            let path = host.config_path(scope, root)?;
            let Some(bytes) = read_optional_bounded_config(host, &path)? else {
                continue;
            };
            if configuration_contains_current_owned_binding(
                host,
                &bytes,
                &server_name,
                root,
                binding.store_path(),
                managed_cache_base,
            )? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn configuration_contains_current_owned_binding(
    host: McpHost,
    bytes: &[u8],
    server_name: &str,
    root: &Path,
    store: &Path,
    managed_cache_base: &Path,
) -> Result<bool> {
    if host.is_json() {
        let existing = parse_json_bytes(bytes, "existing MCP configuration")?;
        return Ok(
            checked_json_server_entry(&existing, server_name)?.is_some_and(|entry| {
                json_entry_matches_current_binding(entry, root, store, managed_cache_base)
            }),
        );
    }
    let existing = parse_toml_bytes(bytes, "existing MCP configuration")?;
    Ok(
        checked_server_entry(&existing, server_name)?.is_some_and(|entry| {
            toml_entry_matches_current_binding(host, entry, root, store, managed_cache_base)
        }),
    )
}

fn set_editable_server_entry(
    document: &mut DocumentMut,
    server_name: &str,
    entry: TomlItem,
) -> Result<()> {
    let root = document.as_table_mut();
    let servers = root
        .entry("mcp_servers")
        .or_insert_with(|| {
            let mut table = TomlTable::new();
            table.set_implicit(true);
            TomlItem::Table(table)
        })
        .as_table_like_mut()
        .context("project MCP mcp_servers must be a TOML table")?;
    servers.insert(server_name, entry);
    Ok(())
}

fn remove_editable_server_entry(document: &mut DocumentMut, server_name: &str) -> Result<()> {
    let servers = document
        .get_mut("mcp_servers")
        .and_then(TomlItem::as_table_like_mut)
        .context("project MCP mcp_servers must be a TOML table")?;
    servers.remove(server_name);
    Ok(())
}

fn set_json_server_entry(value: &mut JsonValue, server_name: &str, entry: JsonValue) -> Result<()> {
    let root = value
        .as_object_mut()
        .context("project MCP configuration root must be a JSON object")?;
    let servers = root
        .entry("mcpServers")
        .or_insert_with(|| JsonValue::Object(JsonMap::new()))
        .as_object_mut()
        .context("project MCP mcpServers must be a JSON object")?;
    servers.insert(server_name.to_owned(), entry);
    Ok(())
}

fn remove_json_server_entry(value: &mut JsonValue, server_name: &str) -> Result<()> {
    let servers = value
        .as_object_mut()
        .and_then(|root| root.get_mut("mcpServers"))
        .and_then(JsonValue::as_object_mut)
        .context("project MCP mcpServers must be a JSON object")?;
    servers.remove(server_name);
    Ok(())
}

fn toml_entry_matches_binding(
    host: McpHost,
    entry: &toml::Value,
    root: &Path,
    store: &Path,
    managed_cache_base: &Path,
) -> bool {
    toml_entry_matches_binding_version(host, entry, root, store, managed_cache_base, None)
}

fn toml_entry_matches_current_binding(
    host: McpHost,
    entry: &toml::Value,
    root: &Path,
    store: &Path,
    managed_cache_base: &Path,
) -> bool {
    toml_entry_matches_binding_version(
        host,
        entry,
        root,
        store,
        managed_cache_base,
        Some(env!("CARGO_PKG_VERSION")),
    )
}

fn toml_entry_matches_binding_version(
    host: McpHost,
    entry: &toml::Value,
    root: &Path,
    store: &Path,
    managed_cache_base: &Path,
    required_version: Option<&str>,
) -> bool {
    let Some(table) = entry.as_table() else {
        return false;
    };
    const CODEX_KEYS: [&str; 5] = [
        "command",
        "args",
        "enabled",
        "required",
        "default_tools_approval_mode",
    ];
    const GROK_KEYS: [&str; 3] = ["command", "args", "enabled"];
    let policy_matches = match host {
        McpHost::Codex => {
            table.len() == CODEX_KEYS.len()
                && CODEX_KEYS.iter().all(|key| table.contains_key(*key))
                && table.get("enabled").and_then(toml::Value::as_bool) == Some(true)
                && table.get("required").and_then(toml::Value::as_bool) == Some(true)
                && table
                    .get("default_tools_approval_mode")
                    .and_then(toml::Value::as_str)
                    == Some("approve")
        }
        McpHost::Grok => {
            table.len() == GROK_KEYS.len()
                && GROK_KEYS.iter().all(|key| table.contains_key(*key))
                && table.get("enabled").and_then(toml::Value::as_bool) == Some(true)
        }
        McpHost::Claude | McpHost::Cursor => false,
    };
    if !policy_matches {
        return false;
    }
    let Some(command) = table.get("command").and_then(toml::Value::as_str) else {
        return false;
    };
    let Some(arguments) = table.get("args").and_then(toml::Value::as_array) else {
        return false;
    };
    let Some(arguments) = arguments
        .iter()
        .map(toml::Value::as_str)
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    launch_tuple_matches_binding(
        command,
        &arguments,
        root,
        store,
        managed_cache_base,
        required_version,
    )
}

fn json_entry_matches_binding(
    entry: &JsonValue,
    root: &Path,
    store: &Path,
    managed_cache_base: &Path,
) -> bool {
    json_entry_matches_binding_version(entry, root, store, managed_cache_base, None)
}

fn json_entry_matches_current_binding(
    entry: &JsonValue,
    root: &Path,
    store: &Path,
    managed_cache_base: &Path,
) -> bool {
    json_entry_matches_binding_version(
        entry,
        root,
        store,
        managed_cache_base,
        Some(env!("CARGO_PKG_VERSION")),
    )
}

fn json_entry_matches_binding_version(
    entry: &JsonValue,
    root: &Path,
    store: &Path,
    managed_cache_base: &Path,
    required_version: Option<&str>,
) -> bool {
    let Some(object) = entry.as_object() else {
        return false;
    };
    const GENERATED_KEYS: [&str; 2] = ["command", "args"];
    if object.len() != GENERATED_KEYS.len()
        || !GENERATED_KEYS.iter().all(|key| object.contains_key(*key))
    {
        return false;
    }
    let Some(command) = object.get("command").and_then(JsonValue::as_str) else {
        return false;
    };
    let Some(arguments) = object.get("args").and_then(JsonValue::as_array) else {
        return false;
    };
    let Some(arguments) = arguments
        .iter()
        .map(JsonValue::as_str)
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    launch_tuple_matches_binding(
        command,
        &arguments,
        root,
        store,
        managed_cache_base,
        required_version,
    )
}

fn launch_tuple_matches_binding(
    command: &str,
    arguments: &[&str],
    root: &Path,
    store: &Path,
    managed_cache_base: &Path,
    required_version: Option<&str>,
) -> bool {
    if arguments.len() != 10 {
        return false;
    }
    let (Some(root), Some(store)) = (root.to_str(), store.to_str()) else {
        return false;
    };
    let requirement = arguments[7];
    let expected_arguments =
        agent_host_launch_arguments(AgentHostCapabilityProfile::Read, root, store, requirement);
    arguments
        .iter()
        .copied()
        .eq(expected_arguments.iter().map(String::as_str))
        && managed_launch_paths_match(
            Path::new(command),
            Path::new(requirement),
            managed_cache_base,
            required_version,
        )
}

fn managed_launch_paths_match(
    command: &Path,
    requirement: &Path,
    managed_cache_base: &Path,
    required_version: Option<&str>,
) -> bool {
    managed_launch_paths_match_under(command, requirement, managed_cache_base, required_version)
        || managed_cache_base
            .canonicalize()
            .ok()
            .is_some_and(|canonical| {
                canonical != managed_cache_base
                    && managed_launch_paths_match_under(
                        command,
                        requirement,
                        &canonical,
                        required_version,
                    )
            })
}

fn managed_launch_paths_match_under(
    command: &Path,
    requirement: &Path,
    managed_cache_base: &Path,
    required_version: Option<&str>,
) -> bool {
    if !command.is_absolute() || !requirement.is_absolute() || !managed_cache_base.is_absolute() {
        return false;
    }
    let Ok(relative) = command.strip_prefix(managed_cache_base) else {
        return false;
    };
    let mut components = relative.components();
    let (
        Some(Component::Normal(mcp)),
        Some(Component::Normal(artifacts)),
        Some(Component::Normal(version)),
        Some(Component::Normal(target)),
    ) = (
        components.next(),
        components.next(),
        components.next(),
        components.next(),
    )
    else {
        return false;
    };
    let (Some(version), Some(target)) = (version.to_str(), target.to_str()) else {
        return false;
    };
    if mcp != OsStr::new("mcp")
        || artifacts != OsStr::new("artifacts")
        || required_version.is_some_and(|required| version != required)
        || compiler_pack_host_target() != Some(target)
    {
        return false;
    }
    let Ok(layout) = ArtifactLayout::new(managed_cache_base, version, target) else {
        return false;
    };
    command
        == layout
            .runtime_root()
            .join("bin")
            .join(executable_name("depgraph-mcp"))
        && requirement == layout.requirement_path()
}

fn ensure_config_directory(
    host: McpHost,
    scope: McpScope,
    root: &Path,
    config_path: &Path,
) -> Result<PathBuf> {
    let path = config_path
        .parent()
        .context("scoped MCP configuration has no parent")?;
    if scope == McpScope::Project && path == root {
        return Ok(root.to_path_buf());
    }
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "cannot create {}-scoped {} configuration directory",
                    scope.as_str(),
                    host.display_name()
                )
            });
        }
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return security_bail(&format!(
            "{}-scoped {} configuration directory must be a real directory",
            scope.as_str(),
            host.display_name()
        ));
    }
    path.canonicalize().with_context(|| {
        format!(
            "cannot canonicalize {}-scoped {} configuration directory",
            scope.as_str(),
            host.display_name()
        )
    })
}

fn read_optional_bounded_config(host: McpHost, path: &Path) -> Result<Option<Vec<u8>>> {
    if let Some(parent) = path.parent() {
        match fs::symlink_metadata(parent) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return security_bail(&format!(
                    "{} configuration directory must be a real directory",
                    host.display_name()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "cannot inspect {} configuration directory",
                        host.display_name()
                    )
                });
            }
        }
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "cannot inspect {} project configuration",
                    host.display_name()
                )
            });
        }
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_HOST_CONFIG_BYTES
    {
        return security_bail(&format!(
            "{} project configuration must be a bounded regular non-symlink file",
            host.display_name()
        ));
    }
    Ok(Some(fs::read(path)?))
}

fn atomic_write(host: McpHost, path: &Path, contents: &[u8]) -> Result<()> {
    let permissions = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return security_bail(&format!(
                "{} project configuration cannot be atomically replaced",
                host.display_name()
            ));
        }
        Ok(metadata) => Some(metadata.permissions()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let parent = path
        .parent()
        .context("project MCP configuration has no parent")?;
    let mut builder = tempfile::Builder::new();
    builder.prefix(".depgraph-mcp-config-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        builder.permissions(fs::Permissions::from_mode(0o600));
    }
    let mut temporary = builder.tempfile_in(parent)?;
    if let Some(permissions) = permissions {
        temporary.as_file().set_permissions(permissions)?;
    }
    temporary.as_file_mut().write_all(contents)?;
    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map(|_| ())
        .map_err(|error| error.error)
        .with_context(|| {
            format!(
                "cannot atomically replace {} project configuration",
                host.display_name()
            )
        })
}

struct RepositoryStateExclusion {
    _operation_runner: OperationRunnerExclusionGuard,
    _store_writer: File,
}

fn acquire_repository_state_exclusion(
    config: &DepgraphServiceConfig,
) -> Result<RepositoryStateExclusion> {
    let journal = operation_journal_path(config);
    let operation_runner = try_acquire_operation_runner_exclusion(&journal)?
        .context("MCP uninstall cannot run while a durable operation runner is active")?;
    let store_writer = acquire_store_writer_lock(config.store_path())
        .context("MCP uninstall cannot run while a scan, daemon, or Store writer is active")?;
    if !config.repository_root_seal().matches_live_root() {
        security_bail("repository root changed while MCP state exclusion was acquired")?;
    }
    Ok(RepositoryStateExclusion {
        _operation_runner: operation_runner,
        _store_writer: store_writer,
    })
}

fn remove_repository_state(config: &DepgraphServiceConfig) -> Result<usize> {
    let mut removed = 0_usize;
    for candidate in removable_repository_state_paths(config) {
        let metadata = match fs::symlink_metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("cannot inspect repository-specific state"),
        };
        if metadata.is_dir() {
            security_bail("repository-specific state path unexpectedly names a directory")?;
        }
        fs::remove_file(&candidate).with_context(|| {
            format!(
                "cannot remove repository-specific MCP state {}",
                candidate.display()
            )
        })?;
        removed += 1;
    }
    Ok(removed)
}

fn removable_repository_state_paths(config: &DepgraphServiceConfig) -> Vec<PathBuf> {
    let store = config.store_path();
    let mut candidates = Vec::new();
    for suffix in [
        "",
        "-wal",
        "-shm",
        "-journal",
        ".daemon-status.json",
        ".daemon-stop",
        ".daemon-stop.lock",
        ".daemon-lock",
    ] {
        candidates.push(with_suffix(store, suffix));
    }
    let journal = with_suffix(store, ".operations.sqlite");
    for suffix in ["", "-wal", "-shm", "-journal"] {
        candidates.push(with_suffix(&journal, suffix));
    }
    candidates
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn git_repository() -> tempfile::TempDir {
        let repository = tempfile::tempdir().unwrap();
        fs::create_dir(repository.path().join(".git")).unwrap();
        fs::write(
            repository.path().join(".git/HEAD"),
            b"ref: refs/heads/main\n",
        )
        .unwrap();
        repository
    }

    fn read_binding(root: &Path, store: &Path) -> DepgraphServiceConfig {
        DepgraphServiceConfig::new(
            root,
            store,
            DepgraphCapabilitySet::read_only(),
            DepgraphServiceLimits::default(),
        )
        .unwrap()
    }

    fn codex_entry(cache_base: &Path, root: &Path, store: &Path) -> String {
        let binding = read_binding(root, store);
        let target = compiler_pack_host_target().unwrap();
        let layout = ArtifactLayout::new(cache_base, env!("CARGO_PKG_VERSION"), target).unwrap();
        let command = layout
            .runtime_root()
            .join("bin")
            .join(executable_name("depgraph-mcp"));
        depgraph_mcp_tools::render_agent_host_configuration(
            AgentHostFormat::Codex,
            AgentHostCapabilityProfile::Read,
            command.to_str().unwrap(),
            binding.canonical_root().to_str().unwrap(),
            binding.store_path().to_str().unwrap(),
            layout.requirement_path().to_str().unwrap(),
        )
        .unwrap()
    }

    fn host_entry(
        host: McpHost,
        scope: McpScope,
        cache_base: &Path,
        root: &Path,
        store: &Path,
    ) -> (String, String) {
        host_entry_for_version(
            host,
            scope,
            cache_base,
            env!("CARGO_PKG_VERSION"),
            root,
            store,
        )
    }

    fn host_entry_for_version(
        host: McpHost,
        scope: McpScope,
        cache_base: &Path,
        version: &str,
        root: &Path,
        store: &Path,
    ) -> (String, String) {
        let binding = read_binding(root, store);
        let target = compiler_pack_host_target().unwrap();
        let layout = ArtifactLayout::new(cache_base, version, target).unwrap();
        let command = layout
            .runtime_root()
            .join("bin")
            .join(executable_name("depgraph-mcp"));
        let generated = depgraph_mcp_tools::render_agent_host_configuration(
            host.agent_format(),
            AgentHostCapabilityProfile::Read,
            command.to_str().unwrap(),
            binding.canonical_root().to_str().unwrap(),
            binding.store_path().to_str().unwrap(),
            layout.requirement_path().to_str().unwrap(),
        )
        .unwrap();
        let server_name = scope.server_name(binding.canonical_root()).unwrap();
        let configuration = lifecycle_configuration(host, &server_name, &generated).unwrap();
        (server_name, configuration)
    }

    #[test]
    fn host_scope_paths_and_user_server_names_are_deterministic() {
        let repository = git_repository();
        let root = repository.path().canonicalize().unwrap();
        assert_eq!(
            McpHost::Codex
                .config_path(McpScope::Project, &root)
                .unwrap(),
            root.join(".codex/config.toml")
        );
        assert_eq!(
            McpHost::Claude
                .config_path(McpScope::Project, &root)
                .unwrap(),
            root.join(".mcp.json")
        );
        assert_eq!(
            McpHost::Cursor
                .config_path(McpScope::Project, &root)
                .unwrap(),
            root.join(".cursor/mcp.json")
        );
        assert_eq!(
            McpHost::Grok.config_path(McpScope::Project, &root).unwrap(),
            root.join(".grok/config.toml")
        );

        let home = McpScope::User.configuration_root(&root).unwrap();
        for (host, expected) in [
            (McpHost::Codex, home.join(".codex/config.toml")),
            (McpHost::Claude, home.join(".claude.json")),
            (McpHost::Cursor, home.join(".cursor/mcp.json")),
            (McpHost::Grok, home.join(".grok/config.toml")),
        ] {
            assert_eq!(host.config_path(McpScope::User, &root).unwrap(), expected);
        }
        let first = McpScope::User.server_name(&root).unwrap();
        assert!(first.starts_with("depgraph-"));
        assert_eq!(first.len(), "depgraph-".len() + 16);
        assert_eq!(first, McpScope::User.server_name(&root).unwrap());
        let other = git_repository();
        assert_ne!(
            first,
            McpScope::User
                .server_name(&other.path().canonicalize().unwrap())
                .unwrap()
        );
    }

    #[test]
    fn claude_cursor_and_grok_project_configuration_lifecycle_is_safe_and_idempotent() {
        for host in [McpHost::Claude, McpHost::Cursor, McpHost::Grok] {
            let repository = git_repository();
            let state = tempfile::tempdir().unwrap();
            let store = state.path().join("graph.db");
            let binding = read_binding(repository.path(), &store);
            let path = host
                .config_path(McpScope::Project, repository.path())
                .unwrap();
            if let Some(parent) = path.parent()
                && parent != repository.path()
            {
                fs::create_dir(parent).unwrap();
            }
            if host.is_json() {
                fs::write(
                    &path,
                    br#"{"keep":"unchanged","mcpServers":{"other":{"command":"other","args":[]}}}"#,
                )
                .unwrap();
            } else {
                fs::write(
                    &path,
                    "# keep Grok settings\ntheme = \"dark\"\n\n[mcp_servers.other]\ncommand = \"other\"\nargs = []\n",
                )
                .unwrap();
            }
            let (server_name, generated) = host_entry(
                host,
                McpScope::Project,
                state.path(),
                repository.path(),
                &store,
            );

            assert!(
                install_host_configuration(
                    host,
                    McpScope::Project,
                    &server_name,
                    &binding,
                    &path,
                    state.path(),
                    &generated,
                )
                .unwrap()
            );
            assert!(
                !install_host_configuration(
                    host,
                    McpScope::Project,
                    &server_name,
                    &binding,
                    &path,
                    state.path(),
                    &generated,
                )
                .unwrap()
            );
            verify_host_configuration(host, McpScope::Project, &server_name, &path, &generated)
                .unwrap();

            if host.is_json() {
                let value = parse_json_bytes(&fs::read(&path).unwrap(), "fixture").unwrap();
                assert_eq!(value["keep"], "unchanged");
                assert_eq!(value["mcpServers"]["other"]["command"], "other");
                assert_eq!(
                    value["mcpServers"][&server_name].as_object().unwrap().len(),
                    2
                );
            } else {
                let bytes = fs::read(&path).unwrap();
                let text = std::str::from_utf8(&bytes).unwrap();
                assert!(text.contains("# keep Grok settings"));
                let value = parse_toml_bytes(&bytes, "fixture").unwrap();
                assert_eq!(value["theme"].as_str(), Some("dark"));
                assert_eq!(
                    value["mcp_servers"]["other"]["command"].as_str(),
                    Some("other")
                );
                assert_eq!(
                    value["mcp_servers"][&server_name].as_table().unwrap().len(),
                    3
                );
            }

            assert!(
                remove_host_configuration(
                    host,
                    McpScope::Project,
                    &server_name,
                    &binding,
                    &path,
                    state.path(),
                )
                .unwrap()
            );
            if host.is_json() {
                let value = parse_json_bytes(&fs::read(&path).unwrap(), "fixture").unwrap();
                assert!(
                    checked_json_server_entry(&value, &server_name)
                        .unwrap()
                        .is_none()
                );
                assert_eq!(value["mcpServers"]["other"]["command"], "other");
            } else {
                let value = parse_toml_bytes(&fs::read(&path).unwrap(), "fixture").unwrap();
                assert!(
                    checked_server_entry(&value, &server_name)
                        .unwrap()
                        .is_none()
                );
                assert_eq!(
                    value["mcp_servers"]["other"]["command"].as_str(),
                    Some("other")
                );
            }
        }
    }

    #[test]
    fn user_scope_keeps_repository_specific_entries_side_by_side() {
        for host in McpHost::ALL {
            let configuration_home = tempfile::tempdir().unwrap();
            let config_path = match host {
                McpHost::Codex => configuration_home.path().join(".codex/config.toml"),
                McpHost::Claude => configuration_home.path().join(".claude.json"),
                McpHost::Cursor => configuration_home.path().join(".cursor/mcp.json"),
                McpHost::Grok => configuration_home.path().join(".grok/config.toml"),
            };
            let cache = tempfile::tempdir().unwrap();
            let first_repository = git_repository();
            let second_repository = git_repository();
            let first_store = cache.path().join("first.db");
            let second_store = cache.path().join("second.db");
            let first_binding = read_binding(first_repository.path(), &first_store);
            let second_binding = read_binding(second_repository.path(), &second_store);
            let (first_name, first_configuration) = host_entry(
                host,
                McpScope::User,
                cache.path(),
                first_repository.path(),
                &first_store,
            );
            let (second_name, second_configuration) = host_entry(
                host,
                McpScope::User,
                cache.path(),
                second_repository.path(),
                &second_store,
            );
            assert_ne!(first_name, second_name);

            assert!(
                install_host_configuration(
                    host,
                    McpScope::User,
                    &first_name,
                    &first_binding,
                    &config_path,
                    cache.path(),
                    &first_configuration,
                )
                .unwrap()
            );
            assert!(
                install_host_configuration(
                    host,
                    McpScope::User,
                    &second_name,
                    &second_binding,
                    &config_path,
                    cache.path(),
                    &second_configuration,
                )
                .unwrap()
            );
            verify_host_configuration(
                host,
                McpScope::User,
                &first_name,
                &config_path,
                &first_configuration,
            )
            .unwrap();
            verify_host_configuration(
                host,
                McpScope::User,
                &second_name,
                &config_path,
                &second_configuration,
            )
            .unwrap();

            assert!(
                remove_host_configuration(
                    host,
                    McpScope::User,
                    &first_name,
                    &first_binding,
                    &config_path,
                    cache.path(),
                )
                .unwrap()
            );
            verify_host_configuration(
                host,
                McpScope::User,
                &second_name,
                &config_path,
                &second_configuration,
            )
            .unwrap();
            let first_absent = if host.is_json() {
                let value = parse_json_bytes(&fs::read(&config_path).unwrap(), "fixture").unwrap();
                checked_json_server_entry(&value, &first_name)
                    .unwrap()
                    .is_none()
            } else {
                let value = parse_toml_bytes(&fs::read(&config_path).unwrap(), "fixture").unwrap();
                checked_server_entry(&value, &first_name).unwrap().is_none()
            };
            assert!(first_absent);
        }
    }

    #[test]
    fn state_retention_requires_a_current_owned_launch_tuple() {
        for host in McpHost::ALL {
            let repository = git_repository();
            let cache = tempfile::tempdir().unwrap();
            let store = cache.path().join("graph.db");
            let binding = read_binding(repository.path(), &store);
            let (server_name, configuration) = host_entry(
                host,
                McpScope::Project,
                cache.path(),
                binding.canonical_root(),
                binding.store_path(),
            );
            assert!(
                configuration_contains_current_owned_binding(
                    host,
                    configuration.as_bytes(),
                    &server_name,
                    binding.canonical_root(),
                    binding.store_path(),
                    cache.path(),
                )
                .unwrap()
            );

            let (_, stale_configuration) = host_entry_for_version(
                host,
                McpScope::Project,
                cache.path(),
                "0.0.0",
                binding.canonical_root(),
                binding.store_path(),
            );
            let stale_is_owned = if host.is_json() {
                let value = parse_json(&stale_configuration, "fixture").unwrap();
                json_entry_matches_binding(
                    json_server_entry(&value, &server_name).unwrap(),
                    binding.canonical_root(),
                    binding.store_path(),
                    cache.path(),
                )
            } else {
                let value = parse_toml(&stale_configuration, "fixture").unwrap();
                toml_entry_matches_binding(
                    host,
                    server_entry(&value, &server_name).unwrap(),
                    binding.canonical_root(),
                    binding.store_path(),
                    cache.path(),
                )
            };
            assert!(stale_is_owned);
            assert!(
                !configuration_contains_current_owned_binding(
                    host,
                    stale_configuration.as_bytes(),
                    &server_name,
                    binding.canonical_root(),
                    binding.store_path(),
                    cache.path(),
                )
                .unwrap()
            );

            let tampered = if host.is_json() {
                let mut value = parse_json(&configuration, "fixture").unwrap();
                value["mcpServers"][&server_name]["command"] = JsonValue::String("other".into());
                serde_json::to_vec(&value).unwrap()
            } else {
                let mut value = parse_toml(&configuration, "fixture").unwrap();
                value["mcp_servers"][&server_name]["command"] = toml::Value::String("other".into());
                toml::to_string(&value).unwrap().into_bytes()
            };
            assert!(
                !configuration_contains_current_owned_binding(
                    host,
                    &tampered,
                    &server_name,
                    binding.canonical_root(),
                    binding.store_path(),
                    cache.path(),
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn repository_discovery_uses_the_nearest_canonical_git_root() {
        let repository = git_repository();
        let nested = repository.path().join("packages/example/src");
        fs::create_dir_all(&nested).unwrap();
        assert_eq!(
            discover_git_repository_root(&nested).unwrap(),
            repository.path().canonicalize().unwrap()
        );

        let outside = tempfile::tempdir().unwrap();
        let error = discover_git_repository_root(outside.path()).unwrap_err();
        assert!(error.to_string().contains("Git repository"));
    }

    #[test]
    fn worktree_git_file_is_validated_without_running_project_code() {
        let common = tempfile::tempdir().unwrap();
        fs::write(common.path().join("HEAD"), b"ref: refs/heads/worktree\n").unwrap();
        let checkout = tempfile::tempdir().unwrap();
        fs::write(
            checkout.path().join(".git"),
            format!("gitdir: {}\n", common.path().display()),
        )
        .unwrap();
        assert!(valid_git_marker(checkout.path()).unwrap());

        fs::write(checkout.path().join(".git"), "gitdir: ../missing\n").unwrap();
        assert!(!valid_git_marker(checkout.path()).unwrap());
    }

    #[test]
    fn an_invalid_nearest_git_marker_cannot_fall_back_to_a_parent_repository() {
        let repository = git_repository();
        let nested = repository.path().join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join(".git"), b"not a worktree marker\n").unwrap();
        let error = discover_git_repository_root(&nested).unwrap_err();
        assert!(error.to_string().contains("nearest Git marker"));
    }

    #[test]
    fn cache_lock_recovers_after_the_previous_owner_exits() {
        let cache = tempfile::tempdir().unwrap();
        fs::write(cache.path().join(".setup-lock"), b"stale lock contents").unwrap();
        let lock = CacheLock::acquire(cache.path()).unwrap();
        assert!(CacheLock::acquire(cache.path()).is_err());
        drop(lock);
        CacheLock::acquire(cache.path()).unwrap();
    }

    #[test]
    fn host_configuration_lock_serializes_a_shared_user_file() {
        let configuration_home = tempfile::tempdir().unwrap();
        let shared = configuration_home.path().join(".cursor/mcp.json");
        let other = configuration_home.path().join(".claude.json");

        let lock = HostConfigurationLock::acquire(McpHost::Cursor, McpScope::User, &shared)
            .unwrap()
            .unwrap();
        let error =
            HostConfigurationLock::acquire(McpHost::Cursor, McpScope::User, &shared).unwrap_err();
        assert!(error.to_string().contains("Agent host configuration"));
        HostConfigurationLock::acquire(McpHost::Claude, McpScope::User, &other).unwrap();

        drop(lock);
        HostConfigurationLock::acquire(McpHost::Cursor, McpScope::User, &shared).unwrap();
    }

    #[test]
    fn artifact_layout_is_shared_by_version_and_target_but_stores_are_repository_scoped() {
        let cache = tempfile::tempdir().unwrap();
        let layout =
            ArtifactLayout::new(cache.path(), "0.5.4", "x86_64-unknown-linux-gnu").unwrap();
        let first = git_repository();
        let second = git_repository();
        assert_eq!(
            layout.target_root,
            ArtifactLayout::new(cache.path(), "0.5.4", "x86_64-unknown-linux-gnu")
                .unwrap()
                .target_root
        );
        assert_ne!(
            default_store_path(first.path()).unwrap(),
            default_store_path(second.path()).unwrap()
        );
    }

    #[test]
    fn github_metadata_closes_the_exact_setup_asset_set() {
        let cache = tempfile::tempdir().unwrap();
        let layout =
            ArtifactLayout::new(cache.path(), "0.5.4", "x86_64-unknown-linux-gnu").unwrap();
        let assets = layout
            .expected_asset_names()
            .into_iter()
            .map(|name| {
                json!({
                    "name":name,
                    "size":128,
                    "digest":format!("sha256:{}", "a".repeat(64)),
                    "browser_download_url":format!(
                        "https://github.com/{OFFICIAL_REPOSITORY}/releases/download/{}/{}",
                        layout.tag,
                        name
                    )
                })
            })
            .collect::<Vec<_>>();
        let release = serde_json::to_vec(&json!({
            "tag_name":layout.tag,
            "draft":false,
            "prerelease":false,
            "assets":assets
        }))
        .unwrap();
        let parsed = parse_release_metadata(&release, &layout).unwrap();
        assert_eq!(parsed.assets.len(), 6);

        let mut missing: serde_json::Value = serde_json::from_slice(&release).unwrap();
        missing["assets"].as_array_mut().unwrap().pop();
        assert!(parse_release_metadata(&serde_json::to_vec(&missing).unwrap(), &layout).is_err());
    }

    #[test]
    fn archive_paths_reject_traversal_and_cross_package_entries() {
        assert_eq!(
            safe_archive_path(
                Path::new("depgraph-0.5.4-target/bin/depgraph"),
                "depgraph-0.5.4-target"
            )
            .unwrap(),
            Path::new("depgraph-0.5.4-target/bin/depgraph")
        );
        for unsafe_path in [
            "../outside",
            "/absolute",
            "depgraph-0.5.4-target/../outside",
            "other-package/bin/depgraph",
        ] {
            assert!(
                safe_archive_path(Path::new(unsafe_path), "depgraph-0.5.4-target").is_err(),
                "{unsafe_path}"
            );
        }
    }

    #[test]
    fn tar_extraction_materializes_a_bounded_package_tree() {
        let temporary = tempfile::tempdir().unwrap();
        let archive_path = temporary.path().join("package.tar.gz");
        let package_root = "depgraph-0.5.4-target";
        {
            let archive_file = File::create(&archive_path).unwrap();
            let encoder =
                flate2::write::GzEncoder::new(archive_file, flate2::Compression::default());
            let mut builder = tar::Builder::new(encoder);

            let mut directory = tar::Header::new_gnu();
            directory.set_entry_type(tar::EntryType::Directory);
            directory.set_size(0);
            directory.set_mode(0o755);
            directory.set_cksum();
            builder
                .append_data(&mut directory, package_root, std::io::empty())
                .unwrap();

            let contents = b"verified runtime";
            let mut file = tar::Header::new_gnu();
            file.set_size(contents.len() as u64);
            file.set_mode(0o755);
            file.set_cksum();
            builder
                .append_data(
                    &mut file,
                    format!("{package_root}/bin/depgraph"),
                    &contents[..],
                )
                .unwrap();
            builder.into_inner().unwrap().finish().unwrap();
        }

        let extracted = temporary.path().join("extracted");
        fs::create_dir(&extracted).unwrap();
        extract_tar_gz(&archive_path, &extracted, package_root).unwrap();
        assert_eq!(
            fs::read(extracted.join(package_root).join("bin/depgraph")).unwrap(),
            b"verified runtime"
        );
    }

    #[test]
    fn codex_merge_is_idempotent_and_preserves_unrelated_settings() {
        let repository = git_repository();
        let state = tempfile::tempdir().unwrap();
        let store = state.path().join("graph.db");
        let binding = read_binding(repository.path(), &store);
        let codex = repository.path().join(".codex");
        fs::create_dir(&codex).unwrap();
        let path = codex.join("config.toml");
        let original = "# keep project model\nmodel = \"gpt-5\" # keep inline model note\n\n# keep unrelated server notes\n[mcp_servers.other]\ncommand = \"other\" # keep inline server note\nargs = []\n";
        fs::write(&path, original).unwrap();
        let generated = codex_entry(state.path(), repository.path(), &store);

        assert!(
            install_host_configuration(
                McpHost::Codex,
                McpScope::Project,
                "depgraph",
                &binding,
                &path,
                state.path(),
                &generated,
            )
            .unwrap()
        );
        assert!(
            !install_host_configuration(
                McpHost::Codex,
                McpScope::Project,
                "depgraph",
                &binding,
                &path,
                state.path(),
                &generated,
            )
            .unwrap()
        );
        verify_host_configuration(
            McpHost::Codex,
            McpScope::Project,
            "depgraph",
            &path,
            &generated,
        )
        .unwrap();
        let merged_bytes = fs::read(&path).unwrap();
        let merged_text = std::str::from_utf8(&merged_bytes).unwrap();
        for preserved in [
            "# keep project model",
            "model = \"gpt-5\" # keep inline model note",
            "# keep unrelated server notes",
            "command = \"other\" # keep inline server note",
        ] {
            assert!(merged_text.contains(preserved), "missing {preserved}");
        }
        let merged = parse_toml_bytes(&merged_bytes, "fixture").unwrap();
        assert_eq!(merged["model"].as_str(), Some("gpt-5"));
        assert_eq!(
            merged["mcp_servers"]["other"]["command"].as_str(),
            Some("other")
        );

        assert!(
            remove_host_configuration(
                McpHost::Codex,
                McpScope::Project,
                "depgraph",
                &binding,
                &path,
                state.path(),
            )
            .unwrap()
        );
        let removed_bytes = fs::read(&path).unwrap();
        let removed_text = std::str::from_utf8(&removed_bytes).unwrap();
        for preserved in [
            "# keep project model",
            "model = \"gpt-5\" # keep inline model note",
            "# keep unrelated server notes",
            "command = \"other\" # keep inline server note",
        ] {
            assert!(removed_text.contains(preserved), "missing {preserved}");
        }
        let removed = parse_toml_bytes(&removed_bytes, "fixture").unwrap();
        assert!(
            checked_server_entry(&removed, "depgraph")
                .unwrap()
                .is_none()
        );
        assert_eq!(removed["model"].as_str(), Some("gpt-5"));
        assert_eq!(
            removed["mcp_servers"]["other"]["command"].as_str(),
            Some("other")
        );
    }

    #[test]
    fn codex_merge_does_not_replace_an_entry_owned_by_another_binding() {
        let repository = git_repository();
        let state = tempfile::tempdir().unwrap();
        let store = state.path().join("graph.db");
        let other_store = state.path().join("other.db");
        let binding = read_binding(repository.path(), &store);
        let codex = repository.path().join(".codex");
        fs::create_dir(&codex).unwrap();
        let path = codex.join("config.toml");
        let existing = codex_entry(state.path(), repository.path(), &other_store);
        fs::write(&path, &existing).unwrap();

        let error = install_host_configuration(
            McpHost::Codex,
            McpScope::Project,
            "depgraph",
            &binding,
            &path,
            state.path(),
            &codex_entry(state.path(), repository.path(), &store),
        )
        .unwrap_err();
        assert!(error.to_string().contains("is not owned"));
        assert_eq!(fs::read_to_string(path).unwrap(), existing);
    }

    #[test]
    fn codex_lifecycle_rejects_same_binding_with_a_modified_launch_tuple() {
        let repository = git_repository();
        let state = tempfile::tempdir().unwrap();
        let store = state.path().join("graph.db");
        let binding = read_binding(repository.path(), &store);
        let codex = repository.path().join(".codex");
        fs::create_dir(&codex).unwrap();
        let path = codex.join("config.toml");
        let desired = codex_entry(state.path(), repository.path(), &store);
        let generated = parse_toml(&desired, "fixture").unwrap();

        let mut alternate_command = generated.clone();
        alternate_command["mcp_servers"]["depgraph"]["command"] = toml::Value::String(
            state
                .path()
                .join("manual")
                .join(executable_name("depgraph-mcp"))
                .to_string_lossy()
                .into_owned(),
        );

        let mut extra_capability = generated.clone();
        extra_capability["mcp_servers"]["depgraph"]["args"]
            .as_array_mut()
            .unwrap()
            .extend([
                toml::Value::String("--capability".to_owned()),
                toml::Value::String("store-write".to_owned()),
            ]);

        let mut alternate_requirement = generated.clone();
        alternate_requirement["mcp_servers"]["depgraph"]["args"]
            .as_array_mut()
            .unwrap()[7] = toml::Value::String(
            state
                .path()
                .join("manual.requirement.json")
                .to_string_lossy()
                .into_owned(),
        );

        let mut additional_setting = generated;
        additional_setting["mcp_servers"]["depgraph"]
            .as_table_mut()
            .unwrap()
            .insert("env".to_owned(), toml::Value::Table(toml::Table::new()));

        for modified in [
            alternate_command,
            extra_capability,
            alternate_requirement,
            additional_setting,
        ] {
            let existing = toml::to_string(&modified).unwrap();
            fs::write(&path, &existing).unwrap();

            let install_error = install_host_configuration(
                McpHost::Codex,
                McpScope::Project,
                "depgraph",
                &binding,
                &path,
                state.path(),
                &desired,
            )
            .unwrap_err();
            assert!(install_error.to_string().contains("is not owned"));
            assert_eq!(fs::read_to_string(&path).unwrap(), existing);

            let remove_error = remove_host_configuration(
                McpHost::Codex,
                McpScope::Project,
                "depgraph",
                &binding,
                &path,
                state.path(),
            )
            .unwrap_err();
            assert!(remove_error.to_string().contains("is not owned"));
            assert_eq!(fs::read_to_string(&path).unwrap(), existing);
        }
    }

    #[test]
    fn codex_merge_preserves_an_unrelated_inline_server_table() {
        let repository = git_repository();
        let state = tempfile::tempdir().unwrap();
        let store = state.path().join("graph.db");
        let binding = read_binding(repository.path(), &store);
        let codex = repository.path().join(".codex");
        fs::create_dir(&codex).unwrap();
        let path = codex.join("config.toml");
        let original = "mcp_servers = { other = { command = \"other\", args = [] } } # keep inline server table\n";
        fs::write(&path, original).unwrap();
        let generated = codex_entry(state.path(), repository.path(), &store);

        assert!(
            install_host_configuration(
                McpHost::Codex,
                McpScope::Project,
                "depgraph",
                &binding,
                &path,
                state.path(),
                &generated,
            )
            .unwrap()
        );
        verify_host_configuration(
            McpHost::Codex,
            McpScope::Project,
            "depgraph",
            &path,
            &generated,
        )
        .unwrap();
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains("# keep inline server table")
        );

        assert!(
            remove_host_configuration(
                McpHost::Codex,
                McpScope::Project,
                "depgraph",
                &binding,
                &path,
                state.path(),
            )
            .unwrap()
        );
        let removed = fs::read_to_string(&path).unwrap();
        assert!(removed.contains("# keep inline server table"));
        let parsed = parse_toml(&removed, "fixture").unwrap();
        assert_eq!(
            parsed["mcp_servers"]["other"]["command"].as_str(),
            Some("other")
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_codex_directory_is_rejected_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let repository = git_repository();
        let outside = tempfile::tempdir().unwrap();
        let outside_config = outside.path().join("config.toml");
        fs::write(&outside_config, "secret = \"unchanged\"\n").unwrap();
        symlink(outside.path(), repository.path().join(".codex")).unwrap();
        let error = read_optional_bounded_config(
            McpHost::Codex,
            &McpHost::Codex
                .config_path(McpScope::Project, repository.path())
                .unwrap(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("real directory"));
        assert_eq!(
            fs::read_to_string(outside_config).unwrap(),
            "secret = \"unchanged\"\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_claude_cursor_and_grok_configs_are_rejected() {
        use std::os::unix::fs::symlink;

        for host in [McpHost::Claude, McpHost::Cursor, McpHost::Grok] {
            let repository = git_repository();
            let outside = tempfile::tempdir().unwrap();
            let outside_config = outside.path().join("config");
            fs::write(&outside_config, b"unchanged").unwrap();
            let path = host
                .config_path(McpScope::Project, repository.path())
                .unwrap();
            if host == McpHost::Claude {
                symlink(&outside_config, &path).unwrap();
            } else {
                symlink(outside.path(), path.parent().unwrap()).unwrap();
            }
            assert!(read_optional_bounded_config(host, &path).is_err());
            assert_eq!(fs::read(&outside_config).unwrap(), b"unchanged");
        }
    }

    #[test]
    fn uninstall_removes_only_the_repository_owned_store_family() {
        let repository = git_repository();
        let state = tempfile::tempdir().unwrap();
        let store = state.path().join("graph.db");
        let binding = read_binding(repository.path(), &store);
        for suffix in ["", "-wal", ".writer-lock", ".operations.sqlite"] {
            fs::write(with_suffix(&store, suffix), b"owned").unwrap();
        }
        let unrelated = state.path().join("keep.txt");
        fs::write(&unrelated, b"keep").unwrap();
        let exclusion = acquire_repository_state_exclusion(&binding).unwrap();
        assert_eq!(remove_repository_state(&binding).unwrap(), 3);
        drop(exclusion);
        assert_eq!(fs::read(unrelated).unwrap(), b"keep");
        assert!(with_suffix(&store, ".writer-lock").is_file());
        assert!(with_suffix(&store, ".operations.sqlite.runner-purge-lock").is_file());
    }

    #[test]
    fn repository_lifecycle_lock_is_shared_across_store_bindings() {
        let repository = git_repository();
        let state = tempfile::tempdir().unwrap();
        let first = read_binding(repository.path(), &state.path().join("first.db"));
        let second = read_binding(repository.path(), &state.path().join("second.db"));

        let setup = acquire_repository_lifecycle_exclusion(&first).unwrap();
        let error = acquire_repository_lifecycle_exclusion(&second).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("setup/update/uninstall is active")
        );
        drop(setup);
        acquire_repository_lifecycle_exclusion(&second).unwrap();
    }

    #[test]
    fn uninstall_fails_before_mutation_while_setup_lifecycle_is_active() {
        let repository = git_repository();
        let state = tempfile::tempdir().unwrap();
        let store = state.path().join("graph.db");
        let binding = read_binding(repository.path(), &store);
        fs::write(&store, b"owned").unwrap();
        let codex = repository.path().join(".codex");
        fs::create_dir(&codex).unwrap();
        let config_path = codex.join("config.toml");
        let layout = ArtifactLayout::for_current_host().unwrap();
        let installed = codex_entry(&layout.cache_base, repository.path(), &store);
        fs::write(&config_path, &installed).unwrap();
        let setup = acquire_repository_lifecycle_exclusion(&binding).unwrap();

        let result = uninstall(&McpWorkflowRequest {
            host: McpHost::Codex,
            scope: McpScope::Project,
            requested_root: repository.path().to_path_buf(),
            explicit_store: Some(store.clone()),
        });
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(config_path).unwrap(), installed);
        assert!(store.is_file());
        drop(setup);
    }

    #[test]
    fn uninstall_fails_before_mutation_while_a_store_writer_is_active() {
        let repository = git_repository();
        let state = tempfile::tempdir().unwrap();
        let store = state.path().join("graph.db");
        fs::write(&store, b"owned").unwrap();
        let codex = repository.path().join(".codex");
        fs::create_dir(&codex).unwrap();
        let config_path = codex.join("config.toml");
        let layout = ArtifactLayout::for_current_host().unwrap();
        let installed = codex_entry(&layout.cache_base, repository.path(), &store);
        fs::write(&config_path, &installed).unwrap();
        let writer = acquire_store_writer_lock(&store).unwrap();

        let result = uninstall(&McpWorkflowRequest {
            host: McpHost::Codex,
            scope: McpScope::Project,
            requested_root: repository.path().to_path_buf(),
            explicit_store: Some(store.clone()),
        });
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(config_path).unwrap(), installed);
        assert!(store.is_file());
        drop(writer);
    }

    #[test]
    fn state_cleanup_refuses_an_active_durable_operation_runner() {
        let repository = git_repository();
        let state = tempfile::tempdir().unwrap();
        let store = state.path().join("graph.db");
        let binding = read_binding(repository.path(), &store);
        fs::write(&store, b"owned").unwrap();
        let journal = operation_journal_path(&binding);
        let runner = try_acquire_operation_runner_exclusion(&journal)
            .unwrap()
            .unwrap();

        assert!(acquire_repository_state_exclusion(&binding).is_err());
        drop(runner);
        assert!(acquire_repository_state_exclusion(&binding).is_ok());
    }

    #[test]
    fn state_cleanup_exclusion_exists_before_repository_state_is_created() {
        let repository = git_repository();
        let state = tempfile::tempdir().unwrap();
        let store = state.path().join("not-created/graph.db");
        let binding = read_binding(repository.path(), &store);
        assert!(!store.exists());

        let exclusion = acquire_repository_state_exclusion(&binding).unwrap();
        assert!(with_suffix(&store, ".writer-lock").is_file());
        assert!(with_suffix(&store, ".operations.sqlite.runner-purge-lock").is_file());
        assert!(!store.exists());
        drop(exclusion);
    }

    #[test]
    fn uninstall_never_removes_a_custom_store_parent() {
        let repository = git_repository();
        let state = tempfile::tempdir().unwrap();
        let store = state.path().join("graph.db");
        let binding = read_binding(repository.path(), &store);
        fs::write(&store, b"owned").unwrap();
        let exclusion = acquire_repository_state_exclusion(&binding).unwrap();
        assert_eq!(remove_repository_state(&binding).unwrap(), 1);
        drop(exclusion);
        assert!(state.path().is_dir());
    }
}
