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

use crate::rust_build_observer::{
    RUST_BUILD_OBSERVER, RUST_BUILD_OBSERVER_VERSION, RustBuildObservation,
    collect_rust_build_observation,
};
#[cfg(all(windows, target_env = "msvc"))]
use crate::worker::sanitize_path_value;
use crate::worker::{
    ProcessTreeGuard, finish_reader, locate_web_build_runtime, process_argument_path, read_capped,
    resolve_safe_executable, run_probe, sanitized_path, terminate_worker,
};

pub const BUILD_SUPERVISOR_VERSION: &str = "1.0";
pub const DEFAULT_BUILD_TIMEOUT_SECONDS: u64 = 15 * 60;
pub const MAX_BUILD_TIMEOUT_SECONDS: u64 = 60 * 60;
pub const DEFAULT_OUTPUT_LIMIT_BYTES: usize = 10 * 1024 * 1024;
const MAX_STAGED_FILES: usize = 250_000;
const MAX_STAGED_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_OBSERVATION_BYTES: u64 = 16 * 1024 * 1024;

pub const NEXT_BUILD_OBSERVER: &str = "next-adapter-observer";
pub const ASTRO_BUILD_OBSERVER: &str = "astro-vite-build-observer";
pub const TANSTACK_START_BUILD_OBSERVER: &str = "tanstack-start-vite-build-observer";
pub const NEXT_BUILD_OBSERVER_VERSION: &str = "0.2.0";
pub const ASTRO_BUILD_OBSERVER_VERSION: &str = "0.2.0";
pub const WEB_BUILD_OBSERVER_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WebBuildAdapter {
    Next,
    Astro,
    TanstackStart,
}

impl WebBuildAdapter {
    pub fn key(self) -> &'static str {
        match self {
            Self::Next => "next",
            Self::Astro => "astro",
            Self::TanstackStart => "tanstack-start",
        }
    }

    pub(crate) fn observer(self) -> &'static str {
        match self {
            Self::Next => NEXT_BUILD_OBSERVER,
            Self::Astro => ASTRO_BUILD_OBSERVER,
            Self::TanstackStart => TANSTACK_START_BUILD_OBSERVER,
        }
    }

    pub(crate) fn observer_version(self) -> &'static str {
        match self {
            Self::Next => NEXT_BUILD_OBSERVER_VERSION,
            Self::Astro => ASTRO_BUILD_OBSERVER_VERSION,
            Self::TanstackStart => WEB_BUILD_OBSERVER_VERSION,
        }
    }

    fn runtime_artifact(self) -> &'static str {
        match self {
            Self::Next => "next-build-adapter.mjs",
            Self::Astro => "astro-build-integration.mjs",
            Self::TanstackStart => "tanstack-start-build-observer.mjs",
        }
    }

    fn observation_file(self) -> &'static str {
        match self {
            Self::Next => "next-build-observation.json",
            Self::Astro => "astro-build-observation.json",
            Self::TanstackStart => "tanstack-start-build-observation.json",
        }
    }

    fn observation_schema(self) -> &'static str {
        match self {
            Self::Next => "next-build-observation-v2",
            Self::Astro => "astro-build-observation-v2",
            Self::TanstackStart => "tanstack-start-build-observation-v1",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WebBuildObservation {
    pub adapter: WebBuildAdapter,
    pub observation: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct WebBuildPackageConfig {
    depgraph: Option<WebDepgraphConfig>,
}

#[derive(Debug, Deserialize)]
struct WebDepgraphConfig {
    build: WebBuildConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebBuildConfig {
    adapter: WebBuildAdapter,
    entrypoint: PathBuf,
    version: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

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
                adapter: RUST_BUILD_OBSERVER.to_owned(),
                adapter_version: RUST_BUILD_OBSERVER_VERSION.to_owned(),
                profile_id: "rust:build".to_owned(),
                program: "cargo".to_owned(),
                arguments: vec![
                    "build".to_owned(),
                    "--frozen".to_owned(),
                    "--offline".to_owned(),
                    "--message-format=json-render-diagnostics".to_owned(),
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
    let package_path = source_root.join("package.json");
    if package_path.is_file() {
        let package: WebBuildPackageConfig = serde_json::from_slice(&fs::read(&package_path)?)
            .context("package.json has an invalid depgraph build configuration")?;
        let config = package
            .depgraph
            .context("package.json has no versioned depgraph.build execution plan")?
            .build;
        validate_logical_path(&config.entrypoint, false)?;
        if !source_root.join(&config.entrypoint).is_file() {
            bail!(
                "depgraph.build entrypoint {} is unavailable",
                display_logical(&config.entrypoint)
            );
        }
        if config.version.trim().is_empty()
            || config.version.len() > 128
            || config.version.chars().any(char::is_control)
        {
            bail!("depgraph.build version is invalid");
        }
        let observer = locate_web_build_runtime(config.adapter.runtime_artifact(), &source_root)?;
        let observer_argument = process_argument_path(&observer)
            .to_string_lossy()
            .into_owned();
        let mut environment =
            BTreeMap::from([("DEPGRAPH_OBSERVER".to_owned(), observer_argument.clone())]);
        match config.adapter {
            WebBuildAdapter::Next => {
                environment.insert("NEXT_ADAPTER_PATH".to_owned(), observer_argument);
            }
            WebBuildAdapter::Astro => {
                environment.insert("DEPGRAPH_ASTRO_VERSION".to_owned(), config.version.clone());
            }
            WebBuildAdapter::TanstackStart => {
                environment.insert(
                    "DEPGRAPH_TANSTACK_START_VERSION".to_owned(),
                    config.version.clone(),
                );
            }
        }
        return Ok(BuildExecutionRequest {
            source_root,
            plan: BuildExecutionPlan {
                adapter: config.adapter.observer().to_owned(),
                adapter_version: config.adapter.observer_version().to_owned(),
                profile_id: format!("web:build:{}", config.adapter.key()),
                program: "node".to_owned(),
                arguments: vec![display_logical(&config.entrypoint)],
                logical_cwd: PathBuf::from("."),
                environment,
                timeout_seconds: config
                    .timeout_seconds
                    .unwrap_or(DEFAULT_BUILD_TIMEOUT_SECONDS),
                stdout_limit_bytes: DEFAULT_OUTPUT_LIMIT_BYTES,
                stderr_limit_bytes: DEFAULT_OUTPUT_LIMIT_BYTES,
                target: Some("production".to_owned()),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rust_observation: Option<RustBuildObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_observation: Option<WebBuildObservation>,
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
    let (program, rustc) = if plan.program == "cargo" {
        let (cargo, rustc) = resolve_active_rust_toolchain(&source_root).await?;
        (cargo, Some(rustc))
    } else {
        (resolve_safe_executable(&plan.program, &source_root)?, None)
    };
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
    let mut effective_environment =
        supervisor_environment(&source_root, &run, &plan.program, rustc.as_deref())?;
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
    let mut outcome = outcome;
    let mut diagnostic_code = diagnostic_code;
    if matches!(outcome, BuildOutcomeKind::Completed) {
        if !reader_errors.is_empty() {
            outcome = BuildOutcomeKind::Failed;
            diagnostic_code = Some("build-output-reader-failed".to_owned());
        } else if output_limit_exceeded {
            outcome = BuildOutcomeKind::Failed;
            diagnostic_code = Some("build-output-limit".to_owned());
        }
    }
    let mut rust_observation = None;
    let mut web_observation = None;
    if matches!(outcome, BuildOutcomeKind::Completed) && plan.adapter == RUST_BUILD_OBSERVER {
        match collect_rust_build_observation(&stdout, &run.workspace, &run.output) {
            Ok(observation) => rust_observation = Some(observation),
            Err(_) => {
                outcome = BuildOutcomeKind::SecurityFailed;
                diagnostic_code = Some("rust-build-observation-invalid".to_owned());
            }
        }
    }
    if matches!(outcome, BuildOutcomeKind::Completed)
        && let Some(adapter) = web_adapter_for_observer(&plan.adapter)
    {
        match collect_web_build_observation(adapter, &run.output) {
            Ok(observation) => web_observation = Some(observation),
            Err(_) => {
                outcome = BuildOutcomeKind::SecurityFailed;
                diagnostic_code = Some("web-build-observation-invalid".to_owned());
            }
        }
    }
    let validated_output_digest = if matches!(outcome, BuildOutcomeKind::Completed) {
        match digest_output_tree(&run.output, &stdout) {
            Ok(digest) => Some(digest),
            Err(_) => {
                outcome = BuildOutcomeKind::SecurityFailed;
                diagnostic_code = Some("build-output-security-policy".to_owned());
                rust_observation = None;
                web_observation = None;
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
        rust_observation,
        web_observation,
    })
}

fn web_adapter_for_observer(observer: &str) -> Option<WebBuildAdapter> {
    match observer {
        NEXT_BUILD_OBSERVER => Some(WebBuildAdapter::Next),
        ASTRO_BUILD_OBSERVER => Some(WebBuildAdapter::Astro),
        TANSTACK_START_BUILD_OBSERVER => Some(WebBuildAdapter::TanstackStart),
        _ => None,
    }
}

fn collect_web_build_observation(
    adapter: WebBuildAdapter,
    output: &Path,
) -> Result<WebBuildObservation> {
    let path = output.join(adapter.observation_file());
    let metadata = fs::symlink_metadata(&path)
        .context("Web build observer did not produce its observation artifact")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_OBSERVATION_BYTES
    {
        bail!("Web build observation artifact violates the output policy");
    }
    let observation: serde_json::Value = serde_json::from_slice(&fs::read(path)?)
        .context("Web build observation is invalid JSON")?;
    let object = observation
        .as_object()
        .context("Web build observation must be an object")?;
    if object
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        != Some(adapter.observation_schema())
        || object.get("observer").and_then(serde_json::Value::as_str) != Some(adapter.observer())
        || object
            .get("observer_version")
            .and_then(serde_json::Value::as_str)
            != Some(adapter.observer_version())
    {
        bail!("Web build observation identity does not match its execution plan");
    }
    Ok(WebBuildObservation {
        adapter,
        observation,
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
    rustc: Option<&Path>,
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
        let rustc = rustc.context("active Rust toolchain compiler is unavailable")?;
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
        #[cfg(all(windows, target_env = "msvc"))]
        copy_safe_msvc_environment(&mut environment, root)?;
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

#[cfg(all(windows, target_env = "msvc"))]
fn copy_safe_msvc_environment(
    environment: &mut BTreeMap<String, String>,
    root: &Path,
) -> Result<()> {
    let tool = find_msvc_tools::find_tool(std::env::consts::ARCH, "link.exe")
        .context("Visual Studio MSVC linker is unavailable")?;
    let linker = tool
        .path()
        .canonicalize()
        .context("Visual Studio MSVC linker is unavailable")?;
    if !linker.is_file() || linker.starts_with(root) {
        bail!("security policy violation: MSVC linker is not a trusted host executable");
    }
    let linker_directory = linker
        .parent()
        .context("Visual Studio MSVC linker directory is unavailable")?;

    let mut has_linker_path = false;
    let mut has_library_path = false;
    for (key, value) in tool.env() {
        let Some(key) = key.to_str() else {
            continue;
        };
        if !matches!(key, "PATH" | "INCLUDE" | "LIB" | "LIBPATH") {
            continue;
        }
        let value = sanitize_path_value(value, root)?;
        if key == "PATH" {
            has_linker_path = std::env::split_paths(&value).any(|path| path == linker_directory);
        } else if key == "LIB" {
            has_library_path = true;
        }
        environment.insert(key.to_owned(), value.to_string_lossy().into_owned());
    }
    if !has_linker_path || !has_library_path {
        bail!("Visual Studio MSVC linker environment is incomplete");
    }
    Ok(())
}

async fn resolve_active_rust_toolchain(root: &Path) -> Result<(PathBuf, PathBuf)> {
    let rustc_proxy = resolve_safe_executable("rustc", root)?;
    let output = run_probe(
        rustc_proxy.as_os_str(),
        &[OsString::from("--print"), OsString::from("sysroot")],
        root,
    )
    .await?;
    if !output.status.success() {
        bail!("active Rust toolchain sysroot probe failed");
    }
    let sysroot =
        String::from_utf8(output.stdout).context("active Rust toolchain sysroot is not UTF-8")?;
    let sysroot = PathBuf::from(sysroot.trim())
        .canonicalize()
        .context("active Rust toolchain sysroot is unavailable")?;
    if sysroot.starts_with(root) || !sysroot.is_dir() {
        bail!("security policy violation: active Rust toolchain is inside the project root");
    }
    let cargo = rust_toolchain_executable(&sysroot, "cargo")?;
    let rustc = rust_toolchain_executable(&sysroot, "rustc")?;
    Ok((cargo, rustc))
}

fn rust_toolchain_executable(sysroot: &Path, name: &str) -> Result<PathBuf> {
    let executable = sysroot
        .join("bin")
        .join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
        .canonicalize()
        .with_context(|| format!("active Rust toolchain {name} is unavailable"))?;
    if !executable.is_file() || !executable.starts_with(sysroot) {
        bail!("active Rust toolchain {name} is not a trusted executable");
    }
    Ok(executable)
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
            | "DEPGRAPH_ASTRO_VERSION"
            | "DEPGRAPH_NEXT_EXISTING_ADAPTER"
            | "DEPGRAPH_TANSTACK_START_VERSION"
            | "DEPGRAPH_PROFILE"
            | "DEPGRAPH_TARGET"
            | "NEXT_ADAPTER_PATH"
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
    let name = entry.file_name().to_string_lossy();
    if matches!(name.as_ref(), ".git" | ".depgraph") {
        return false;
    }
    entry.depth() != 1 || !matches!(name.as_ref(), "target" | ".next")
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

    #[test]
    fn web_build_observer_versions_follow_each_observation_contract() {
        assert_eq!(
            WebBuildAdapter::Next.observer_version(),
            NEXT_BUILD_OBSERVER_VERSION
        );
        assert_eq!(
            WebBuildAdapter::Next.observation_schema(),
            "next-build-observation-v2"
        );
        assert_eq!(
            WebBuildAdapter::Astro.observer_version(),
            ASTRO_BUILD_OBSERVER_VERSION
        );
        assert_eq!(
            WebBuildAdapter::Astro.observation_schema(),
            "astro-build-observation-v2"
        );
        assert_eq!(
            WebBuildAdapter::TanstackStart.observer_version(),
            WEB_BUILD_OBSERVER_VERSION
        );
    }

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
    async fn rust_build_uses_real_active_toolchain_with_isolated_cargo_home() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join("src"))?;
        fs::write(
            root.path().join("Cargo.toml"),
            "[package]\nname = \"depgraph-isolated-rust-build\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace]\n",
        )?;
        fs::write(
            root.path().join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"depgraph-isolated-rust-build\"\nversion = \"0.1.0\"\n",
        )?;
        fs::write(
            root.path().join("build.rs"),
            "fn main() { let out = std::env::var_os(\"OUT_DIR\").unwrap(); std::fs::write(std::path::Path::new(&out).join(\"observed.rs\"), b\"pub const OBSERVED: bool = true;\\n\").unwrap(); }\n",
        )?;
        fs::write(
            root.path().join("src/lib.rs"),
            "include!(concat!(env!(\"OUT_DIR\"), \"/observed.rs\"));\n",
        )?;

        let request = create_build_execution_request(root.path())?;
        let outcome = supervise_build(&request.source_root, &request.plan).await?;
        assert_eq!(
            outcome.audit.outcome,
            BuildOutcomeKind::Completed,
            "isolated Rust build failed: {:?}",
            outcome.audit
        );
        assert!(outcome.rust_observation.is_some());
        assert!(outcome.audit.validated_output_digest.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn timeout_and_cancel_stop_descendants() -> Result<()> {
        let root = tempfile::tempdir()?;
        let escaped_marker =
            serde_json::to_string(&root.path().join("DESCENDANT_SURVIVED").to_string_lossy())?;
        let ready_marker = root.path().join("CANCELLATION_READY");
        let escaped_ready = serde_json::to_string(&ready_marker.to_string_lossy())?;
        let descendant = format!(
            "setTimeout(() => require('node:fs').writeFileSync({escaped_marker}, 'unsafe'), 1500); setInterval(() => {{}}, 1000);"
        );
        let escaped_descendant = serde_json::to_string(&descendant)?;
        fs::write(
            root.path().join("hang.mjs"),
            format!(
                "import {{ spawn }} from 'node:child_process'; import {{ writeFileSync }} from 'node:fs'; process.stdout.write('verbose output'); spawn(process.execPath, ['-e', {escaped_descendant}], {{ stdio: 'ignore' }}); writeFileSync({escaped_ready}, 'ready'); setInterval(() => {{}}, 1000);\n"
            ),
        )?;
        let mut plan = node_plan(vec!["hang.mjs".to_owned()]);
        plan.timeout_seconds = 1;
        plan.stdout_limit_bytes = 1;
        let timed_out = supervise_build(root.path(), &plan).await?;
        assert_eq!(timed_out.audit.outcome, BuildOutcomeKind::TimedOut);
        assert!(timed_out.audit.stdout_truncated);
        assert_eq!(
            timed_out.audit.diagnostic_code.as_deref(),
            Some("build-timeout")
        );
        fs::remove_file(&ready_marker)?;

        let mut cancellation_plan = plan.clone();
        cancellation_plan.timeout_seconds = 30;
        let cancelled =
            supervise_build_with_cancellation(root.path(), &cancellation_plan, async move {
                for _ in 0..3_000 {
                    if ready_marker.exists() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await?;
        assert_eq!(cancelled.audit.outcome, BuildOutcomeKind::Cancelled);
        assert!(cancelled.audit.stdout_truncated);
        assert_eq!(
            cancelled.audit.diagnostic_code.as_deref(),
            Some("build-cancelled")
        );
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

        plan.environment.clear();
        plan.environment.insert(
            "NEXT_ADAPTER_PATH".to_owned(),
            "/trusted/depgraph-next-build-adapter.mjs".to_owned(),
        );
        plan.environment.insert(
            "DEPGRAPH_NEXT_EXISTING_ADAPTER".to_owned(),
            "existing-platform-adapter".to_owned(),
        );
        plan.environment
            .insert("DEPGRAPH_ASTRO_VERSION".to_owned(), "5.12.0".to_owned());
        plan.environment.insert(
            "DEPGRAPH_TANSTACK_START_VERSION".to_owned(),
            "1.168.28".to_owned(),
        );
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn staging_preserves_source_directories_named_like_common_outputs() -> Result<()> {
        let root = tempfile::tempdir()?;
        for path in [
            "build/member/src/lib.rs",
            "src/dist/module.rs",
            "src/coverage/report.rs",
            "target/debug/generated",
            ".next/generated",
            "nested/.git/config",
        ] {
            let path = root.path().join(path);
            fs::create_dir_all(path.parent().expect("fixture path has a parent"))?;
            fs::write(path, "fixture")?;
        }
        let destination = tempfile::tempdir()?;
        stage_workspace(root.path(), destination.path())?;

        assert!(destination.path().join("build/member/src/lib.rs").is_file());
        assert!(destination.path().join("src/dist/module.rs").is_file());
        assert!(destination.path().join("src/coverage/report.rs").is_file());
        assert!(!destination.path().join("target").exists());
        assert!(!destination.path().join(".next").exists());
        assert!(!destination.path().join("nested/.git").exists());
        Ok(())
    }
}
