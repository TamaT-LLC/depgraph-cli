use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    path::{Component, Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::{process::Command, time::timeout};
use uuid::Uuid;
use walkdir::{DirEntry, WalkDir};

use crate::worker::{
    ProcessTreeGuard, finish_reader, read_capped, resolve_safe_executable, run_probe,
    sanitized_path, terminate_worker,
};

pub const BUILD_SUPERVISOR_VERSION: &str = "1.0";
pub const DEFAULT_BUILD_TIMEOUT_SECONDS: u64 = 15 * 60;
pub const MAX_BUILD_TIMEOUT_SECONDS: u64 = 60 * 60;
pub const DEFAULT_OUTPUT_LIMIT_BYTES: usize = 10 * 1024 * 1024;
const MAX_STAGED_FILES: usize = 250_000;
const MAX_STAGED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct BuildExecutionPlan {
    pub adapter: String,
    pub adapter_version: String,
    pub profile_id: String,
    pub program: String,
    pub arguments: Vec<String>,
    pub logical_cwd: PathBuf,
    pub environment: BTreeMap<String, String>,
    pub timeout_seconds: u64,
    pub stdout_limit_bytes: usize,
    pub stderr_limit_bytes: usize,
    pub target: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BuildExecutionRequest {
    pub source_root: PathBuf,
    pub plan: BuildExecutionPlan,
}

pub fn create_build_execution_request(source_root: &Path) -> Result<BuildExecutionRequest> {
    let source_root = source_root
        .canonicalize()
        .context("build source root is unavailable")?;
    if !source_root.is_dir() {
        bail!("build source root is not a directory");
    }
    let manifest = source_root.join("Cargo.toml");
    let lockfile = source_root.join("Cargo.lock");
    if manifest.is_file() && lockfile.is_file() {
        return Ok(BuildExecutionRequest {
            source_root,
            plan: BuildExecutionPlan {
                adapter: "rust-build-bootstrap".to_owned(),
                adapter_version: BUILD_SUPERVISOR_VERSION.to_owned(),
                profile_id: "rust:build".to_owned(),
                program: "cargo".to_owned(),
                arguments: vec![
                    "build".to_owned(),
                    "--frozen".to_owned(),
                    "--offline".to_owned(),
                ],
                logical_cwd: PathBuf::from("."),
                environment: BTreeMap::new(),
                timeout_seconds: DEFAULT_BUILD_TIMEOUT_SECONDS,
                stdout_limit_bytes: DEFAULT_OUTPUT_LIMIT_BYTES,
                stderr_limit_bytes: DEFAULT_OUTPUT_LIMIT_BYTES,
                target: None,
            },
        });
    }
    bail!(
        "no versioned build execution plan is available for this repository; no child process was started"
    )
}

pub async fn execute_build_request(
    request: &BuildExecutionRequest,
) -> Result<BuildExecutionOutcome> {
    supervise_build(&request.source_root, &request.plan).await
}

pub async fn execute_build_request_with_cancellation<F>(
    request: &BuildExecutionRequest,
    cancellation: F,
) -> Result<BuildExecutionOutcome>
where
    F: std::future::Future<Output = ()>,
{
    supervise_build_with_cancellation(&request.source_root, &request.plan, cancellation).await
}

impl BuildExecutionPlan {
    pub fn validate(&self) -> Result<()> {
        if self.adapter.trim().is_empty()
            || self.adapter_version.trim().is_empty()
            || self.profile_id.trim().is_empty()
            || self.program.trim().is_empty()
        {
            bail!("build execution plan identity fields must not be empty");
        }
        if self.program.contains('/') || self.program.contains('\\') {
            bail!("security policy violation: build program must be a system executable name");
        }
        if self
            .arguments
            .iter()
            .any(|argument| Path::new(argument).is_absolute())
        {
            bail!("security policy violation: build arguments must not contain absolute paths");
        }
        validate_logical_path(&self.logical_cwd, true)?;
        if self.timeout_seconds == 0 || self.timeout_seconds > MAX_BUILD_TIMEOUT_SECONDS {
            bail!("build timeout must be between 1 and {MAX_BUILD_TIMEOUT_SECONDS} seconds");
        }
        if self.stdout_limit_bytes == 0 || self.stderr_limit_bytes == 0 {
            bail!("build output limits must be at least 1 byte");
        }
        for key in self.environment.keys() {
            if !is_allowed_environment_key(key) {
                bail!("security policy violation: build environment key {key} is not allowlisted");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BuildOutcomeKind {
    Completed,
    Failed,
    TimedOut,
    Cancelled,
    SecurityFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkIsolation {
    Enforced,
    BestEffort,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildAudit {
    pub schema_version: String,
    pub run_id: String,
    pub adapter: String,
    pub adapter_version: String,
    pub profile_id: String,
    pub command_program: String,
    pub command_arguments: Vec<String>,
    pub command_plan_digest: String,
    pub logical_cwd: String,
    pub source_root_digest: String,
    pub toolchain_executable_digest: String,
    pub toolchain_version: Option<String>,
    pub target: Option<String>,
    pub environment_keys: Vec<String>,
    pub environment_key_set_digest: String,
    pub redacted_secret_key_count: usize,
    pub timeout_seconds: u64,
    pub stdout_limit_bytes: usize,
    pub stderr_limit_bytes: usize,
    pub network_policy: String,
    pub network_isolation: NetworkIsolation,
    pub isolation_diagnostic: Option<String>,
    pub started_at: String,
    pub finished_at: String,
    pub duration_millis: u64,
    pub outcome: BuildOutcomeKind,
    pub exit_code: Option<i32>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub validated_output_digest: Option<String>,
    pub diagnostic_code: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuildExecutionOutcome {
    pub audit: BuildAudit,
    pub project_code_executed: bool,
}

pub async fn supervise_build(
    source_root: &Path,
    plan: &BuildExecutionPlan,
) -> Result<BuildExecutionOutcome> {
    supervise_build_with_cancellation(source_root, plan, std::future::pending()).await
}

pub async fn supervise_build_with_cancellation<F>(
    source_root: &Path,
    plan: &BuildExecutionPlan,
    cancellation: F,
) -> Result<BuildExecutionOutcome>
where
    F: std::future::Future<Output = ()>,
{
    plan.validate()?;
    let source_root = source_root
        .canonicalize()
        .context("build source root is unavailable")?;
    if !source_root.is_dir() {
        bail!("build source root is not a directory");
    }
    let program = resolve_safe_executable(&plan.program, &source_root)?;
    let executable_digest = digest_file(&program)?;
    let toolchain_version = probe_build_tool_version(&program, &source_root).await?;
    let run = BuildRunDirectories::create()?;
    stage_workspace(&source_root, &run.workspace)?;
    let cwd = run.workspace.join(&plan.logical_cwd);
    let canonical_cwd = cwd.canonicalize().with_context(|| {
        format!(
            "build logical cwd {} is unavailable",
            display_logical(&plan.logical_cwd)
        )
    })?;
    if !canonical_cwd.starts_with(&run.workspace) || !canonical_cwd.is_dir() {
        bail!("security policy violation: build logical cwd escapes staged workspace");
    }

    let started_wall = Utc::now();
    let started = Instant::now();
    let mut command = Command::new(&program);
    command
        .args(&plan.arguments)
        .current_dir(&canonical_cwd)
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
    let mut effective_environment = supervisor_environment(&source_root, &run, &plan.program)?;
    for (key, value) in &plan.environment {
        effective_environment.insert(key.clone(), value.clone());
    }
    command.envs(&effective_environment);

    let redacted_arguments = redact_arguments(&plan.arguments);
    let (environment_keys, redacted_secret_key_count) =
        audit_environment_keys(effective_environment.keys().map(String::as_str));
    let command_plan_digest = digest_json(&serde_json::json!({
        "version": BUILD_SUPERVISOR_VERSION,
        "adapter": plan.adapter,
        "adapter_version": plan.adapter_version,
        "program": plan.program,
        "arguments": redacted_arguments,
        "logical_cwd": display_logical(&plan.logical_cwd),
    }))?;
    let environment_key_set_digest = digest_json(&environment_keys)?;
    let source_root_digest = digest_workspace(&run.workspace)?;
    let (network_isolation, isolation_diagnostic) = network_isolation_capability();

    let mut child = command
        .spawn()
        .with_context(|| format!("failed to start build adapter {}", plan.adapter))?;
    let guard = ProcessTreeGuard::attach(&child).context("failed to isolate build process tree")?;
    let stdout = child.stdout.take().context("build stdout is unavailable")?;
    let stderr = child.stderr.take().context("build stderr is unavailable")?;
    let stdout_task = tokio::spawn(read_capped(stdout, plan.stdout_limit_bytes));
    let stderr_task = tokio::spawn(read_capped(stderr, plan.stderr_limit_bytes));
    tokio::pin!(cancellation);
    enum WaitResult {
        Process(std::io::Result<std::process::ExitStatus>),
        Timeout,
        Cancelled,
    }
    let wait_result = tokio::select! {
        result = timeout(Duration::from_secs(plan.timeout_seconds), child.wait()) => {
            match result { Ok(status) => WaitResult::Process(status), Err(_) => WaitResult::Timeout }
        }
        () = &mut cancellation => WaitResult::Cancelled,
    };
    let (outcome, exit_code, diagnostic_code) = match wait_result {
        WaitResult::Process(Ok(status)) if status.success() => {
            (BuildOutcomeKind::Completed, status.code(), None)
        }
        WaitResult::Process(Ok(status)) => (
            BuildOutcomeKind::Failed,
            status.code(),
            Some("build-child-failed".to_owned()),
        ),
        WaitResult::Process(Err(_)) => (
            BuildOutcomeKind::Failed,
            None,
            Some("build-wait-failed".to_owned()),
        ),
        WaitResult::Timeout => {
            terminate_build_tree(&mut child, &guard).await;
            (
                BuildOutcomeKind::TimedOut,
                None,
                Some("build-timeout".to_owned()),
            )
        }
        WaitResult::Cancelled => {
            terminate_build_tree(&mut child, &guard).await;
            (
                BuildOutcomeKind::Cancelled,
                None,
                Some("build-cancelled".to_owned()),
            )
        }
    };
    guard.terminate();
    let mut reader_errors = Vec::new();
    let (stdout, stdout_truncated) =
        finish_reader(stdout_task, "build stdout", &mut reader_errors).await?;
    let (_stderr, stderr_truncated) =
        finish_reader(stderr_task, "build stderr", &mut reader_errors).await?;
    let output_limit_exceeded = stdout_truncated || stderr_truncated;
    let mut outcome = if reader_errors.is_empty() && !output_limit_exceeded {
        outcome
    } else {
        BuildOutcomeKind::Failed
    };
    let mut diagnostic_code = if !reader_errors.is_empty() {
        Some("build-output-reader-failed".to_owned())
    } else if output_limit_exceeded {
        Some("build-output-limit".to_owned())
    } else {
        diagnostic_code
    };
    let validated_output_digest = if matches!(outcome, BuildOutcomeKind::Completed) {
        match digest_output_tree(&run.output, &stdout) {
            Ok(digest) => Some(digest),
            Err(_) => {
                outcome = BuildOutcomeKind::SecurityFailed;
                diagnostic_code = Some("build-output-security-policy".to_owned());
                None
            }
        }
    } else {
        None
    };
    let finished_wall = Utc::now();
    let audit = BuildAudit {
        schema_version: BUILD_SUPERVISOR_VERSION.to_owned(),
        run_id: Uuid::new_v4().to_string(),
        adapter: plan.adapter.clone(),
        adapter_version: plan.adapter_version.clone(),
        profile_id: plan.profile_id.clone(),
        command_program: plan.program.clone(),
        command_arguments: redacted_arguments,
        command_plan_digest,
        logical_cwd: display_logical(&plan.logical_cwd),
        source_root_digest,
        toolchain_executable_digest: executable_digest,
        toolchain_version: Some(toolchain_version),
        target: plan.target.clone(),
        environment_keys,
        environment_key_set_digest,
        redacted_secret_key_count,
        timeout_seconds: plan.timeout_seconds,
        stdout_limit_bytes: plan.stdout_limit_bytes,
        stderr_limit_bytes: plan.stderr_limit_bytes,
        network_policy: "deny".to_owned(),
        network_isolation,
        isolation_diagnostic,
        started_at: started_wall.to_rfc3339_opts(SecondsFormat::Millis, true),
        finished_at: finished_wall.to_rfc3339_opts(SecondsFormat::Millis, true),
        duration_millis: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        outcome,
        exit_code,
        stdout_truncated,
        stderr_truncated,
        validated_output_digest,
        diagnostic_code,
    };
    Ok(BuildExecutionOutcome {
        audit,
        project_code_executed: true,
    })
}

async fn terminate_build_tree(child: &mut tokio::process::Child, guard: &ProcessTreeGuard) {
    #[cfg(unix)]
    {
        guard.request_graceful_termination();
        if timeout(Duration::from_secs(5), child.wait()).await.is_err() {
            terminate_worker(child, guard).await;
        } else {
            // The direct child may exit before descendants. Always close the whole
            // process tree before readers and temporary directories are released.
            guard.terminate();
        }
    }
    #[cfg(not(unix))]
    {
        // Windows Job Objects have no tree-wide graceful signal. Waiting before
        // TerminateJobObject would let descendants keep running during the grace
        // period, so enforce the bounded tree stop immediately on this platform.
        terminate_worker(child, guard).await;
    }
}

struct BuildRunDirectories {
    _root: TempDir,
    workspace: PathBuf,
    home: PathBuf,
    output: PathBuf,
    cache: PathBuf,
    temporary: PathBuf,
}

impl BuildRunDirectories {
    fn create() -> Result<Self> {
        let root = tempfile::Builder::new()
            .prefix("depgraph-build-")
            .tempdir()?;
        let workspace = root.path().join("workspace");
        let home = root.path().join("home");
        let output = root.path().join("output");
        let cache = root.path().join("cache");
        let temporary = root.path().join("tmp");
        for path in [&workspace, &home, &output, &cache, &temporary] {
            fs::create_dir(path)?;
        }
        Ok(Self {
            _root: root,
            workspace: workspace.canonicalize()?,
            home: home.canonicalize()?,
            output: output.canonicalize()?,
            cache: cache.canonicalize()?,
            temporary: temporary.canonicalize()?,
        })
    }
}

fn supervisor_environment(
    root: &Path,
    run: &BuildRunDirectories,
    program: &str,
) -> Result<BTreeMap<String, String>> {
    let mut environment = BTreeMap::new();
    environment.insert(
        "PATH".to_owned(),
        sanitized_path(root)?.to_string_lossy().into_owned(),
    );
    environment.insert("HOME".to_owned(), run.home.to_string_lossy().into_owned());
    environment.insert(
        "USERPROFILE".to_owned(),
        run.home.to_string_lossy().into_owned(),
    );
    environment.insert(
        "TMPDIR".to_owned(),
        run.temporary.to_string_lossy().into_owned(),
    );
    environment.insert(
        "TEMP".to_owned(),
        run.temporary.to_string_lossy().into_owned(),
    );
    environment.insert(
        "TMP".to_owned(),
        run.temporary.to_string_lossy().into_owned(),
    );
    environment.insert(
        "DEPGRAPH_OUTPUT_DIR".to_owned(),
        run.output.to_string_lossy().into_owned(),
    );
    environment.insert(
        "XDG_CACHE_HOME".to_owned(),
        run.cache.to_string_lossy().into_owned(),
    );
    environment.insert("NO_COLOR".to_owned(), "1".to_owned());
    environment.insert("CI".to_owned(), "1".to_owned());
    if matches!(program, "node" | "npm" | "pnpm" | "yarn") {
        environment.insert("NPM_CONFIG_OFFLINE".to_owned(), "true".to_owned());
    }
    if program == "cargo" {
        environment.insert("CARGO_NET_OFFLINE".to_owned(), "true".to_owned());
        environment.insert("RUSTUP_AUTO_INSTALL".to_owned(), "0".to_owned());
        environment.insert(
            "CARGO_HOME".to_owned(),
            run.cache.join("cargo").to_string_lossy().into_owned(),
        );
        environment.insert(
            "CARGO_TARGET_DIR".to_owned(),
            run.output
                .join("cargo-target")
                .to_string_lossy()
                .into_owned(),
        );
        environment.insert("RUSTC_WRAPPER".to_owned(), String::new());
        environment.insert("RUSTC_WORKSPACE_WRAPPER".to_owned(), String::new());
        environment.insert("CARGO_BUILD_RUSTC_WRAPPER".to_owned(), String::new());
        environment.insert(
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER".to_owned(),
            String::new(),
        );
        let rustc = resolve_safe_executable("rustc", root)?;
        environment.insert("RUSTC".to_owned(), rustc.to_string_lossy().into_owned());
        environment.insert(
            "CARGO_BUILD_RUSTC".to_owned(),
            rustc.to_string_lossy().into_owned(),
        );
        if let Some(value) = safe_host_directory("RUSTUP_HOME", root).or_else(|| {
            BaseDirs::new().and_then(|directories| {
                safe_directory_path(&directories.home_dir().join(".rustup"), root)
            })
        }) {
            environment.insert("RUSTUP_HOME".to_owned(), value);
        }
    }
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        environment.insert(
            "SystemRoot".to_owned(),
            system_root.to_string_lossy().into_owned(),
        );
    }
    for key in ["LANG", "LC_ALL"] {
        if let Ok(value) = std::env::var(key) {
            environment.insert(key.to_owned(), value);
        }
    }
    Ok(environment)
}

fn safe_host_directory(key: &str, root: &Path) -> Option<String> {
    let value = std::env::var_os(key)?;
    safe_directory_path(&PathBuf::from(value), root)
}

fn safe_directory_path(path: &Path, root: &Path) -> Option<String> {
    let canonical = path.canonicalize().ok()?;
    (canonical.is_dir() && !canonical.starts_with(root))
        .then(|| canonical.to_string_lossy().into_owned())
}

fn is_allowed_environment_key(key: &str) -> bool {
    matches!(
        key,
        "DEPGRAPH_OBSERVER"
            | "DEPGRAPH_PROFILE"
            | "DEPGRAPH_TARGET"
            | "NODE_OPTIONS"
            | "RUSTFLAGS"
            | "CARGO_BUILD_TARGET"
    )
}

fn is_secret_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "API_KEY",
        "PRIVATE_KEY",
        "CREDENTIAL",
        "AUTH",
        "COOKIE",
        "SESSION",
    ]
    .iter()
    .any(|part| upper.contains(part))
}

fn audit_environment_keys<'a>(keys: impl IntoIterator<Item = &'a str>) -> (Vec<String>, usize) {
    let mut visible = BTreeSet::new();
    let mut redacted = 0;
    for key in keys {
        if is_secret_key(key) {
            redacted += 1;
        } else {
            visible.insert(key.to_owned());
        }
    }
    (visible.into_iter().collect(), redacted)
}

fn redact_arguments(arguments: &[String]) -> Vec<String> {
    let mut redacted = Vec::with_capacity(arguments.len());
    let mut redact_next = false;
    for argument in arguments {
        if redact_next {
            redacted.push("[REDACTED]".to_owned());
            redact_next = false;
            continue;
        }
        let looks_like_option = argument.starts_with('-');
        let key = argument
            .trim_start_matches('-')
            .split('=')
            .next()
            .unwrap_or("");
        let environment_assignment = argument
            .split_once('=')
            .is_some_and(|(key, _)| is_secret_key(key));
        if (looks_like_option && is_secret_key(key)) || environment_assignment {
            if argument.contains('=') {
                redacted.push(format!(
                    "{}=[REDACTED]",
                    argument.split('=').next().unwrap_or("--secret")
                ));
            } else {
                redacted.push(argument.clone());
                redact_next = true;
            }
        } else {
            redacted.push(argument.clone());
        }
    }
    redacted
}

async fn probe_build_tool_version(program: &Path, root: &Path) -> Result<String> {
    let output = run_probe(program.as_os_str(), &[OsString::from("--version")], root).await?;
    if !output.status.success() {
        bail!("build tool version probe failed with {}", output.status);
    }
    let raw = String::from_utf8(output.stdout).context("build tool version is not UTF-8")?;
    let version = raw.lines().next().unwrap_or_default().trim();
    if version.is_empty()
        || version.len() > 256
        || version.chars().any(|character| character.is_control())
    {
        bail!("build tool returned an invalid version");
    }
    Ok(version.to_owned())
}

fn stage_workspace(source: &Path, destination: &Path) -> Result<()> {
    let mut files = 0_usize;
    let mut bytes = 0_u64;
    for entry in WalkDir::new(source)
        .follow_links(false)
        .into_iter()
        .filter_entry(admit_stage_entry)
    {
        let entry = entry?;
        let relative = entry.path().strip_prefix(source)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            bail!(
                "security policy violation: staged workspace contains symlink {}",
                display_logical(relative)
            );
        }
        let target = destination.join(relative);
        if metadata.is_dir() {
            fs::create_dir_all(&target)?;
            continue;
        }
        if !metadata.is_file() {
            bail!(
                "security policy violation: staged workspace contains non-regular file {}",
                display_logical(relative)
            );
        }
        files += 1;
        bytes = bytes.saturating_add(metadata.len());
        if files > MAX_STAGED_FILES || bytes > MAX_STAGED_BYTES {
            bail!("security policy violation: staged workspace exceeds file or byte limit");
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(entry.path(), &target)?;
        fs::set_permissions(&target, metadata.permissions())?;
    }
    Ok(())
}

fn admit_stage_entry(entry: &DirEntry) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_dir() {
        return true;
    }
    !matches!(
        entry.file_name().to_string_lossy().as_ref(),
        ".git" | ".depgraph" | "target" | ".next" | "dist" | "build" | "coverage"
    )
}

fn digest_output_tree(output: &Path, stdout: &[u8]) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"depgraph-build-output-v1\0");
    hasher.update(stdout);
    let mut entries = WalkDir::new(output)
        .follow_links(false)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path().to_path_buf());
    let mut entry_count = 0_usize;
    let mut byte_count = stdout.len() as u64;
    for entry in entries {
        let relative = entry.path().strip_prefix(output)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
            bail!("security policy violation: build output contains an unsafe entry");
        }
        entry_count += 1;
        byte_count = byte_count.saturating_add(metadata.len());
        if entry_count > MAX_STAGED_FILES || byte_count > MAX_STAGED_BYTES {
            bail!("security policy violation: build output exceeds entry or byte limit");
        }
        hasher.update(display_logical(relative).as_bytes());
        hasher.update([0]);
        if metadata.is_file() {
            hasher.update(fs::read(entry.path())?);
        }
        hasher.update([0]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn digest_workspace(root: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"depgraph-build-source-v1\0");
    let mut entries = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path().to_path_buf());
    for entry in entries {
        let relative = entry.path().strip_prefix(root)?;
        if relative.as_os_str().is_empty() || !entry.file_type().is_file() {
            continue;
        }
        hasher.update(display_logical(relative).as_bytes());
        hasher.update([0]);
        hasher.update(fs::read(entry.path())?);
        hasher.update([0]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn validate_logical_path(path: &Path, allow_empty: bool) -> Result<()> {
    if path.is_absolute() || (!allow_empty && path.as_os_str().is_empty()) {
        bail!("security policy violation: build logical path must be relative");
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_) | Component::CurDir) {
            bail!("security policy violation: build logical path escapes workspace");
        }
    }
    Ok(())
}

fn display_logical(path: &Path) -> String {
    if path.as_os_str().is_empty() || path == Path::new(".") {
        ".".to_owned()
    } else {
        path.to_string_lossy().replace('\\', "/")
    }
}

fn digest_file(path: &Path) -> Result<String> {
    Ok(digest_bytes(&fs::read(path)?))
}

fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn digest_json(value: &impl Serialize) -> Result<String> {
    Ok(digest_bytes(&serde_json::to_vec(value)?))
}

fn network_isolation_capability() -> (NetworkIsolation, Option<String>) {
    let platform = std::env::consts::OS;
    (
        NetworkIsolation::BestEffort,
        Some(format!(
            "OS-level per-process network isolation is not enforced on {platform}; offline flags, cleared proxy and credential environment, and an external network namespace/container are required for hard isolation"
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_plan(arguments: Vec<String>) -> BuildExecutionPlan {
        BuildExecutionPlan {
            adapter: "fixture".to_owned(),
            adapter_version: "1.0".to_owned(),
            profile_id: "fixture:build".to_owned(),
            program: "node".to_owned(),
            arguments,
            logical_cwd: PathBuf::from("."),
            environment: BTreeMap::new(),
            timeout_seconds: 10,
            stdout_limit_bytes: 1024,
            stderr_limit_bytes: 1024,
            target: None,
        }
    }

    #[tokio::test]
    async fn marker_fixture_runs_only_in_staged_workspace_with_temporary_environment() -> Result<()>
    {
        let root = tempfile::tempdir()?;
        fs::write(
            root.path().join("observer.mjs"),
            r#"
            import fs from 'node:fs';
            import path from 'node:path';
            if (process.cwd() === process.env.ORIGINAL_ROOT) process.exit(91);
            if (!process.env.HOME || process.env.HOME === process.env.ORIGINAL_HOME) process.exit(92);
            fs.writeFileSync(path.join(process.env.DEPGRAPH_OUTPUT_DIR, 'PROJECT_CODE_EXECUTED'), 'yes');
            process.stdout.write('marker-observed');
        "#,
        )?;
        let outcome =
            supervise_build(root.path(), &node_plan(vec!["observer.mjs".to_owned()])).await?;
        assert_eq!(outcome.audit.outcome, BuildOutcomeKind::Completed);
        assert!(outcome.project_code_executed);
        assert!(outcome.audit.validated_output_digest.is_some());
        assert!(!root.path().join("PROJECT_CODE_EXECUTED").exists());
        let serialized = serde_json::to_string(&outcome.audit)?;
        assert!(!serialized.contains(&root.path().to_string_lossy().to_string()));
        if let Some(home) = std::env::var_os("HOME") {
            assert!(!serialized.contains(&home.to_string_lossy().to_string()));
        }
        assert!(!serialized.contains("depgraph-build-"));
        Ok(())
    }

    #[tokio::test]
    async fn timeout_and_cancel_stop_descendants() -> Result<()> {
        let root = tempfile::tempdir()?;
        let escaped_marker =
            serde_json::to_string(&root.path().join("DESCENDANT_SURVIVED").to_string_lossy())?;
        let descendant = format!(
            "setTimeout(() => require('node:fs').writeFileSync({escaped_marker}, 'unsafe'), 1500); setInterval(() => {{}}, 1000);"
        );
        let escaped_descendant = serde_json::to_string(&descendant)?;
        fs::write(
            root.path().join("hang.mjs"),
            format!(
                "import {{ spawn }} from 'node:child_process'; spawn(process.execPath, ['-e', {escaped_descendant}], {{ stdio: 'ignore' }}); setInterval(() => {{}}, 1000);\n"
            ),
        )?;
        let mut plan = node_plan(vec!["hang.mjs".to_owned()]);
        plan.timeout_seconds = 1;
        let timed_out = supervise_build(root.path(), &plan).await?;
        assert_eq!(timed_out.audit.outcome, BuildOutcomeKind::TimedOut);

        let cancelled = supervise_build_with_cancellation(root.path(), &plan, async {
            tokio::time::sleep(Duration::from_millis(100)).await;
        })
        .await?;
        assert_eq!(cancelled.audit.outcome, BuildOutcomeKind::Cancelled);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(!root.path().join("DESCENDANT_SURVIVED").exists());
        Ok(())
    }

    #[test]
    fn audit_redacts_secret_keys_and_argument_values() {
        let (keys, count) = audit_environment_keys(["LANG", "API_TOKEN", "SESSION_ID"]);
        assert_eq!(keys, vec!["LANG"]);
        assert_eq!(count, 2);
        assert_eq!(
            redact_arguments(&[
                "--token".to_owned(),
                "hunter2".to_owned(),
                "--password=secret".to_owned()
            ]),
            vec!["--token", "[REDACTED]", "--password=[REDACTED]"]
        );
    }

    #[test]
    fn execution_plan_rejects_shell_paths_and_unsafe_environment() {
        let mut plan = node_plan(Vec::new());
        plan.program = "./node".to_owned();
        assert!(plan.validate().is_err());
        plan.program = "node".to_owned();
        plan.environment
            .insert("API_TOKEN".to_owned(), "secret".to_owned());
        assert!(plan.validate().is_err());
    }
}
