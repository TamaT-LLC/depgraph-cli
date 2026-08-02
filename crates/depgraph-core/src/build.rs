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

use crate::cache::{
    BuildCacheInput, COMPILER_PRECISE_CACHE_CONTRACT_VERSION, CompilerPreciseCacheInput,
};
use crate::compiler_invocation::{
    COMPILER_INVOCATION_LEDGER_SCHEMA_VERSION, COMPILER_PRECISE_INVOCATION_ADAPTER,
    COMPILER_PRECISE_INVOCATION_ADAPTER_VERSION, RustCompilerFailureContext,
    RustCompilerInvocationLedger, compiler_invocation_attempt_digest,
    diagnose_compiler_invocation_failure, validate_compiler_invocation_ledger,
    validate_compiler_invocation_unit_graph,
};
use crate::compiler_mir::{
    COMPILER_PRECISE_MIR_LEDGER_SCHEMA_VERSION, RustCompilerMirLedger,
    validate_compiler_mir_directory,
};
use crate::compiler_pack::{
    CompilerPackAttestation, CompilerPackRequirement, VerifiedCompilerPack, verify_compiler_pack,
};
use crate::compiler_precise::{
    COMPILER_PRECISE_UNIT_GRAPH_ADAPTER, COMPILER_PRECISE_UNIT_GRAPH_ADAPTER_VERSION,
    COMPILER_PRECISE_UNIT_GRAPH_SCHEMA_VERSION, RustCargoUnitGraph, install_neutral_cargo_config,
    project_neutral_cargo_config, validate_cargo_unit_graph_with_cargo_home,
};
use crate::compiler_precise_graph::COMPILER_PRECISE_GRAPH_CONTRACT_VERSION;
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
pub const TANSTACK_ROUTER_BUILD_OBSERVER: &str = "tanstack-router-vite-build-observer";
pub const TANSTACK_START_BUILD_OBSERVER: &str = "tanstack-start-vite-build-observer";
pub const NEXT_BUILD_OBSERVER_VERSION: &str = "0.2.0";
pub const ASTRO_BUILD_OBSERVER_VERSION: &str = "0.2.0";
pub const TANSTACK_ROUTER_BUILD_OBSERVER_VERSION: &str = "0.1.0";
pub const TANSTACK_START_BUILD_OBSERVER_VERSION: &str = "0.2.0";
pub const WEB_BUILD_OBSERVER_VERSION: &str = TANSTACK_ROUTER_BUILD_OBSERVER_VERSION;
pub const NEXT_BUILD_CAPABILITY: &str = "next-adapter-api-16.2-v1";
pub const ASTRO_BUILD_CAPABILITY: &str = "astro-integration-v5-v7-vite-v6-v7-v1";
pub const TANSTACK_ROUTER_BUILD_CAPABILITY: &str =
    "tanstack-router-v1-vite-v6-v7-generated-route-v1";
pub const TANSTACK_START_BUILD_CAPABILITY: &str =
    "tanstack-start-v1-vite-v7-production-rpc-manifest-v2";
pub const NEXT_BUILD_OBSERVATION_SCHEMA: &str = "next-build-observation-v2";
pub const ASTRO_BUILD_OBSERVATION_SCHEMA: &str = "astro-build-observation-v2";
pub const TANSTACK_ROUTER_BUILD_OBSERVATION_SCHEMA: &str = "tanstack-router-build-observation-v1";
pub const TANSTACK_START_BUILD_OBSERVATION_SCHEMA: &str = "tanstack-start-build-observation-v2";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WebBuildAdapter {
    Next,
    Astro,
    TanstackRouter,
    TanstackStart,
}

impl WebBuildAdapter {
    pub fn key(self) -> &'static str {
        match self {
            Self::Next => "next",
            Self::Astro => "astro",
            Self::TanstackRouter => "tanstack-router",
            Self::TanstackStart => "tanstack-start",
        }
    }

    pub(crate) fn observer(self) -> &'static str {
        match self {
            Self::Next => NEXT_BUILD_OBSERVER,
            Self::Astro => ASTRO_BUILD_OBSERVER,
            Self::TanstackRouter => TANSTACK_ROUTER_BUILD_OBSERVER,
            Self::TanstackStart => TANSTACK_START_BUILD_OBSERVER,
        }
    }

    pub(crate) fn observer_version(self) -> &'static str {
        match self {
            Self::Next => NEXT_BUILD_OBSERVER_VERSION,
            Self::Astro => ASTRO_BUILD_OBSERVER_VERSION,
            Self::TanstackRouter => WEB_BUILD_OBSERVER_VERSION,
            Self::TanstackStart => TANSTACK_START_BUILD_OBSERVER_VERSION,
        }
    }

    fn runtime_artifact(self) -> &'static str {
        match self {
            Self::Next => "next-build-adapter.mjs",
            Self::Astro => "astro-build-integration.mjs",
            Self::TanstackRouter => "tanstack-router-build-observer.mjs",
            Self::TanstackStart => "tanstack-start-build-observer.mjs",
        }
    }

    fn observation_file(self) -> &'static str {
        match self {
            Self::Next => "next-build-observation.json",
            Self::Astro => "astro-build-observation.json",
            Self::TanstackRouter => "tanstack-router-build-observation.json",
            Self::TanstackStart => "tanstack-start-build-observation.json",
        }
    }

    fn observation_schema(self) -> &'static str {
        match self {
            Self::Next => NEXT_BUILD_OBSERVATION_SCHEMA,
            Self::Astro => ASTRO_BUILD_OBSERVATION_SCHEMA,
            Self::TanstackRouter => TANSTACK_ROUTER_BUILD_OBSERVATION_SCHEMA,
            Self::TanstackStart => TANSTACK_START_BUILD_OBSERVATION_SCHEMA,
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
    pub isolation: BuildIsolation,
    pub program: String,
    pub arguments: Vec<String>,
    pub logical_cwd: PathBuf,
    pub environment: BTreeMap<String, String>,
    pub timeout_seconds: u64,
    pub stdout_limit_bytes: usize,
    pub stderr_limit_bytes: usize,
    pub target: Option<String>,
    pub compiler_pack: Option<CompilerPackRequirement>,
    pub compiler_unit_graph: Option<RustCargoUnitGraph>,
    pub expected_source_root_digest: Option<String>,
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
                isolation: BuildIsolation::BestEffort,
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
                compiler_pack: None,
                compiler_unit_graph: None,
                expected_source_root_digest: None,
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
            WebBuildAdapter::TanstackRouter => {
                environment.insert(
                    "DEPGRAPH_TANSTACK_ROUTER_VERSION".to_owned(),
                    config.version.clone(),
                );
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
                isolation: BuildIsolation::BestEffort,
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
                compiler_pack: None,
                compiler_unit_graph: None,
                expected_source_root_digest: None,
            },
        });
    }
    bail!(
        "no versioned build execution plan is available for this repository; no child process was started"
    )
}

pub fn create_compiler_precise_unit_graph_request(
    source_root: &Path,
    compiler_pack: CompilerPackRequirement,
) -> Result<BuildExecutionRequest> {
    let source_root = source_root
        .canonicalize()
        .context("compiler-precise source root is unavailable")?;
    if !source_root.is_dir() {
        bail!("compiler-precise source root is not a directory");
    }
    if !source_root.join("Cargo.toml").is_file() || !source_root.join("Cargo.lock").is_file() {
        bail!("compiler-precise Rust requires confined Cargo.toml and Cargo.lock files");
    }
    project_neutral_cargo_config(&source_root)?;
    Ok(BuildExecutionRequest {
        source_root,
        plan: BuildExecutionPlan {
            adapter: COMPILER_PRECISE_UNIT_GRAPH_ADAPTER.to_owned(),
            adapter_version: COMPILER_PRECISE_UNIT_GRAPH_ADAPTER_VERSION.to_owned(),
            profile_id: "rust:compiler-precise:unit-graph".to_owned(),
            isolation: compiler_precise_isolation(),
            program: "cargo".to_owned(),
            arguments: vec![
                "build".to_owned(),
                "--frozen".to_owned(),
                "--offline".to_owned(),
                "--unit-graph".to_owned(),
                "-Z".to_owned(),
                "unstable-options".to_owned(),
                "--target".to_owned(),
                compiler_pack.target.clone(),
            ],
            logical_cwd: PathBuf::from("."),
            environment: BTreeMap::new(),
            timeout_seconds: DEFAULT_BUILD_TIMEOUT_SECONDS,
            stdout_limit_bytes: DEFAULT_OUTPUT_LIMIT_BYTES,
            stderr_limit_bytes: DEFAULT_OUTPUT_LIMIT_BYTES,
            target: Some(compiler_pack.target.clone()),
            compiler_pack: Some(compiler_pack),
            compiler_unit_graph: None,
            expected_source_root_digest: None,
        },
    })
}

pub fn create_compiler_precise_invocation_request(
    source_root: &Path,
    compiler_pack: CompilerPackRequirement,
    unit_graph: RustCargoUnitGraph,
    expected_source_root_digest: String,
) -> Result<BuildExecutionRequest> {
    let source_root = source_root
        .canonicalize()
        .context("compiler-precise source root is unavailable")?;
    if !source_root.is_dir()
        || !source_root.join("Cargo.toml").is_file()
        || !source_root.join("Cargo.lock").is_file()
    {
        bail!("compiler-precise Rust requires confined Cargo.toml and Cargo.lock files");
    }
    project_neutral_cargo_config(&source_root)?;
    let profile_id = crate::compiler_precise_graph::compiler_precise_profile_id(
        &compiler_pack.host,
        &compiler_pack.target,
        &compiler_pack.expected_manifest_sha256,
        &unit_graph.digest,
    )?;
    if expected_source_root_digest.len() != 64
        || !expected_source_root_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("compiler-precise source identity is invalid");
    }
    Ok(BuildExecutionRequest {
        source_root,
        plan: BuildExecutionPlan {
            adapter: COMPILER_PRECISE_INVOCATION_ADAPTER.to_owned(),
            adapter_version: COMPILER_PRECISE_INVOCATION_ADAPTER_VERSION.to_owned(),
            profile_id,
            isolation: compiler_precise_isolation(),
            program: "cargo".to_owned(),
            arguments: vec![
                "build".to_owned(),
                "--frozen".to_owned(),
                "--offline".to_owned(),
                "--target".to_owned(),
                compiler_pack.target.clone(),
            ],
            logical_cwd: PathBuf::from("."),
            environment: BTreeMap::new(),
            timeout_seconds: DEFAULT_BUILD_TIMEOUT_SECONDS,
            stdout_limit_bytes: DEFAULT_OUTPUT_LIMIT_BYTES,
            stderr_limit_bytes: DEFAULT_OUTPUT_LIMIT_BYTES,
            target: Some(compiler_pack.target.clone()),
            compiler_pack: Some(compiler_pack),
            compiler_unit_graph: Some(unit_graph),
            expected_source_root_digest: Some(expected_source_root_digest),
        },
    })
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

pub async fn prepare_build_cache_input(
    request: &BuildExecutionRequest,
    base_snapshot_id: &str,
) -> Result<Option<BuildCacheInput>> {
    let plan = &request.plan;
    plan.validate()?;
    if plan.compiler_pack.is_some()
        || matches!(
            plan.adapter.as_str(),
            COMPILER_PRECISE_UNIT_GRAPH_ADAPTER | COMPILER_PRECISE_INVOCATION_ADAPTER
        )
    {
        return Ok(None);
    }
    let source_root = request
        .source_root
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
    let toolchain_executable_digest = digest_file(&program)?;
    let toolchain_version = probe_build_tool_version(&program, &source_root).await?;
    let (source_root_digest, manifest_lock_config_digest, staging_metadata_digest) =
        fingerprint_build_source(&source_root)?;
    let command_plan_digest = digest_json(&serde_json::json!({
        "version": BUILD_SUPERVISOR_VERSION,
        "adapter": plan.adapter,
        "adapter_version": plan.adapter_version,
        "isolation": plan.isolation.contract_name(),
        "program": plan.program,
        "arguments": redact_arguments(&plan.arguments),
        "logical_cwd": display_logical(&plan.logical_cwd),
        "compiler_pack_manifest_sha256": serde_json::Value::Null,
    }))?;
    let run = BuildRunDirectories::create()?;
    let mut effective_environment = supervisor_environment(
        &source_root,
        &run,
        &plan.program,
        rustc.as_deref(),
        None,
        false,
    )?;
    for (key, value) in &plan.environment {
        effective_environment.insert(key.clone(), value.clone());
    }
    let (environment_keys, _) =
        audit_environment_keys(effective_environment.keys().map(String::as_str));
    let environment_key_set_digest = digest_json(&environment_keys)?;
    let executable = std::env::current_exe()
        .context("current depgraph executable is unavailable for build cache identity")?;
    let engine_digest = digest_file(&executable)?;
    let observer_digest = plan
        .environment
        .get("DEPGRAPH_OBSERVER")
        .map(|path| digest_file(Path::new(path)))
        .transpose()?;
    let adapter_artifact_digest = digest_json(&(
        "build-adapter-artifact-v1",
        engine_digest,
        observer_digest.as_deref().unwrap_or("embedded"),
    ))?;
    Ok(Some(BuildCacheInput {
        base_snapshot_id: base_snapshot_id.to_owned(),
        adapter: plan.adapter.clone(),
        adapter_version: plan.adapter_version.clone(),
        adapter_artifact_digest,
        command_plan_digest,
        environment_key_set_digest,
        manifest_lock_config_digest,
        profile_id: plan.profile_id.clone(),
        protocol_version: BUILD_SUPERVISOR_VERSION.to_owned(),
        source_root_digest,
        staging_metadata_digest,
        target: plan.target.clone(),
        toolchain_executable_digest,
        toolchain_version,
    }))
}

pub fn prepare_compiler_precise_cache_input(
    request: &BuildExecutionRequest,
    base_snapshot_id: &str,
    profile_selection_plan_id: &str,
) -> Result<CompilerPreciseCacheInput> {
    let plan = &request.plan;
    plan.validate()?;
    if plan.adapter != COMPILER_PRECISE_UNIT_GRAPH_ADAPTER || plan.compiler_unit_graph.is_some() {
        bail!("compiler-precise cache admission requires the unit-graph execution plan");
    }
    let requirement = plan
        .compiler_pack
        .as_ref()
        .context("compiler-precise cache admission requires an exact compiler pack")?;
    let source_root = request
        .source_root
        .canonicalize()
        .context("compiler-precise cache source root is unavailable")?;
    if !source_root.is_dir() {
        bail!("compiler-precise cache source root is not a directory");
    }
    let pack = verify_compiler_pack(requirement)
        .context("compiler-precise cache pack verification failed")?;
    let neutral_cargo_config = project_neutral_cargo_config(&source_root)?;
    let (repository_content_digest, manifest_lock_config_digest, staging_metadata_digest) =
        fingerprint_build_source(&source_root)?;

    let run = BuildRunDirectories::create()?;
    let cargo_home = run.cache.join("cargo");
    stage_cargo_dependency_cache(&source_root, &cargo_home)?;
    let cargo_dependency_cache_digest = digest_workspace(&cargo_home)?;
    stage_workspace(&source_root, &run.workspace)?;
    install_neutral_cargo_config(&run.workspace, &neutral_cargo_config)?;
    let workspace_digest = digest_workspace(&run.workspace)?;
    let source_root_digest = digest_json(&(
        "depgraph-compiler-source-closure-v1",
        workspace_digest.as_str(),
        cargo_dependency_cache_digest.as_str(),
    ))?;

    let command_plan_input_digest = digest_json(&serde_json::json!({
        "schema": "depgraph-compiler-precise-command-input-v1",
        "supervisor": BUILD_SUPERVISOR_VERSION,
        "isolation": plan.isolation.contract_name(),
        "unit_graph": {
            "adapter": plan.adapter,
            "adapter_version": plan.adapter_version,
            "program": plan.program,
            "arguments": redact_arguments(&plan.arguments),
            "logical_cwd": display_logical(&plan.logical_cwd),
        },
        "invocation": {
            "adapter": COMPILER_PRECISE_INVOCATION_ADAPTER,
            "adapter_version": COMPILER_PRECISE_INVOCATION_ADAPTER_VERSION,
            "arguments": ["build", "--frozen", "--offline", "--target", &requirement.target],
        },
        "neutral_cargo_config_digest": neutral_cargo_config.digest,
        "cargo_dependency_cache_digest": cargo_dependency_cache_digest,
        "compiler_pack_manifest_sha256": pack.attestation.manifest_sha256,
    }))?;
    let approved_environment = ["LANG", "LC_ALL", "SystemRoot"]
        .into_iter()
        .filter_map(|key| std::env::var(key).ok().map(|value| (key, value)))
        .collect::<BTreeMap<_, _>>();
    let approved_environment_digest = digest_json(&(
        "compiler-precise-approved-environment-v1",
        approved_environment,
    ))?;
    let host_tool_identity_digest = compiler_precise_host_tool_identity(&source_root)?;
    let engine_digest = digest_file(
        &std::env::current_exe()
            .context("current depgraph executable is unavailable for compiler cache identity")?,
    )?;
    let contract_identity_digest = digest_json(&serde_json::json!({
        "cache": COMPILER_PRECISE_CACHE_CONTRACT_VERSION,
        "compiler": crate::compiler_pack::COMPILER_PRECISE_CONTRACT_VERSION,
        "graph": COMPILER_PRECISE_GRAPH_CONTRACT_VERSION,
        "unit_graph": COMPILER_PRECISE_UNIT_GRAPH_SCHEMA_VERSION,
        "invocation_ledger": COMPILER_INVOCATION_LEDGER_SCHEMA_VERSION,
        "mir_ledger": COMPILER_PRECISE_MIR_LEDGER_SCHEMA_VERSION,
        "store_schema": depgraph_store::STORE_SCHEMA_VERSION,
        "cache_contract": depgraph_store::CACHE_CONTRACT_VERSION,
    }))?;
    Ok(CompilerPreciseCacheInput {
        base_snapshot_id: base_snapshot_id.to_owned(),
        profile_selection_plan_id: profile_selection_plan_id.to_owned(),
        repository_content_digest,
        source_root_digest,
        manifest_lock_config_digest,
        staging_metadata_digest,
        cargo_dependency_cache_digest,
        compiler_pack_attestation: pack.attestation,
        rustc_commit: crate::compiler_pack::COMPILER_PACK_RUSTC_COMMIT.to_owned(),
        command_plan_input_digest,
        host_tool_identity_digest,
        approved_environment_digest,
        engine_digest,
        target: requirement.target.clone(),
        contract_identity_digest,
    })
}

pub fn validate_compiler_precise_cache_input(
    expected: &CompilerPreciseCacheInput,
    request: &BuildExecutionRequest,
    profile_selection_plan_id: &str,
) -> Result<()> {
    let observed = prepare_compiler_precise_cache_input(
        request,
        &expected.base_snapshot_id,
        profile_selection_plan_id,
    )?;
    if &observed != expected {
        bail!("compiler-precise cache input changed before promotion");
    }
    Ok(())
}

pub fn compiler_precise_cache_hit_audit(source: &BuildAudit) -> BuildAudit {
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let mut audit = source.clone();
    audit.run_id = Uuid::new_v4().to_string();
    audit.started_at = timestamp.clone();
    audit.finished_at = timestamp;
    audit.duration_millis = 0;
    audit.outcome = BuildOutcomeKind::Completed;
    audit.exit_code = None;
    audit.stdout_truncated = false;
    audit.stderr_truncated = false;
    audit.diagnostic_code = None;
    audit.compiler_failure = None;
    audit
}

pub fn validate_build_cache_source(input: &BuildCacheInput, source_root: &Path) -> Result<()> {
    let source_root = source_root
        .canonicalize()
        .context("build cache source root is unavailable")?;
    let (source_digest, controls_digest, staging_metadata_digest) =
        fingerprint_build_source(&source_root)?;
    if source_digest != input.source_root_digest
        || controls_digest != input.manifest_lock_config_digest
        || staging_metadata_digest != input.staging_metadata_digest
    {
        bail!("build cache source input changed before publication");
    }
    Ok(())
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
        if self.isolation == BuildIsolation::EnforcedLinuxNamespace && !cfg!(target_os = "linux") {
            bail!("enforced build isolation requires the Linux namespace boundary");
        }
        for key in self.environment.keys() {
            if !is_allowed_environment_key(key) {
                bail!("security policy violation: build environment key {key} is not allowlisted");
            }
        }
        if let Some(requirement) = &self.compiler_pack {
            if self.program != "cargo" {
                bail!("compiler pack execution requires the exact packed Cargo");
            }
            if self.target.as_deref() != Some(requirement.target.as_str()) {
                bail!("compiler pack execution target does not match the build plan");
            }
        }
        if self.adapter == COMPILER_PRECISE_UNIT_GRAPH_ADAPTER {
            if self.compiler_pack.is_none() {
                bail!("compiler-precise unit graph requires an exact compiler pack");
            }
            if self.arguments
                != [
                    "build",
                    "--frozen",
                    "--offline",
                    "--unit-graph",
                    "-Z",
                    "unstable-options",
                    "--target",
                    self.target.as_deref().unwrap_or_default(),
                ]
            {
                bail!("compiler-precise unit graph command plan is not exact");
            }
            if !self.environment.is_empty() {
                bail!("compiler-precise unit graph does not admit caller environment values");
            }
            if self.compiler_unit_graph.is_some() || self.expected_source_root_digest.is_some() {
                bail!("compiler-precise unit graph cannot carry invocation-stage state");
            }
        } else if self.adapter == COMPILER_PRECISE_INVOCATION_ADAPTER {
            let expected_profile_id = self
                .compiler_pack
                .as_ref()
                .zip(self.compiler_unit_graph.as_ref())
                .map(|(pack, graph)| {
                    crate::compiler_precise_graph::compiler_precise_profile_id(
                        &pack.host,
                        &pack.target,
                        &pack.expected_manifest_sha256,
                        &graph.digest,
                    )
                })
                .transpose()?;
            if self.adapter_version != COMPILER_PRECISE_INVOCATION_ADAPTER_VERSION
                || expected_profile_id.as_deref() != Some(self.profile_id.as_str())
                || self.compiler_pack.is_none()
                || self.compiler_unit_graph.is_none()
                || self.expected_source_root_digest.is_none()
            {
                bail!("compiler-precise invocation ledger requires its exact prior stage");
            }
            if self.arguments
                != [
                    "build",
                    "--frozen",
                    "--offline",
                    "--target",
                    self.target.as_deref().unwrap_or_default(),
                ]
            {
                bail!("compiler-precise invocation command plan is not exact");
            }
            if !self.environment.is_empty() {
                bail!("compiler-precise invocation does not admit caller environment values");
            }
            validate_compiler_invocation_unit_graph(
                self.compiler_unit_graph
                    .as_ref()
                    .context("compiler invocation unit graph is unavailable")?,
            )?;
        } else if self.compiler_unit_graph.is_some() || self.expected_source_root_digest.is_some() {
            bail!("non-compiler execution cannot carry compiler invocation state");
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BuildIsolation {
    BestEffort,
    EnforcedLinuxNamespace,
}

impl BuildIsolation {
    fn contract_name(self) -> &'static str {
        match self {
            Self::BestEffort => "best-effort",
            Self::EnforcedLinuxNamespace => "linux-bubblewrap-v1",
        }
    }
}

const fn compiler_precise_isolation() -> BuildIsolation {
    if cfg!(target_os = "linux") {
        BuildIsolation::EnforcedLinuxNamespace
    } else {
        BuildIsolation::BestEffort
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiler_failure: Option<RustCompilerFailureContext>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuildExecutionOutcome {
    pub audit: BuildAudit,
    pub project_code_executed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler_pack_attestation: Option<CompilerPackAttestation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rust_cargo_unit_graph: Option<RustCargoUnitGraph>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rust_compiler_invocation_ledger: Option<RustCompilerInvocationLedger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rust_compiler_mir_ledger: Option<RustCompilerMirLedger>,
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
    let compiler_precise_stage = matches!(
        plan.adapter.as_str(),
        COMPILER_PRECISE_UNIT_GRAPH_ADAPTER | COMPILER_PRECISE_INVOCATION_ADAPTER
    );
    let neutral_cargo_config = compiler_precise_stage
        .then(|| project_neutral_cargo_config(&source_root))
        .transpose()?;
    let compiler_pack_preflight = plan
        .compiler_pack
        .as_ref()
        .map(verify_compiler_pack)
        .transpose()
        .context(
            "compiler-precise backend is unsupported: exact compiler pack verification failed; no rustup, PATH, system, or project toolchain fallback was attempted",
        )?;
    if compiler_pack_preflight
        .as_ref()
        .is_some_and(|pack| pack.root.starts_with(&source_root))
    {
        bail!("security policy violation: compiler pack must not be inside the project root");
    }
    let (program, rustc) = if let Some(pack) = &compiler_pack_preflight {
        (pack.cargo_path.clone(), Some(pack.rustc_path.clone()))
    } else if plan.program == "cargo" {
        let (cargo, rustc) = resolve_active_rust_toolchain(&source_root).await?;
        (cargo, Some(rustc))
    } else {
        (resolve_safe_executable(&plan.program, &source_root)?, None)
    };
    let executable_digest = digest_file(&program)?;
    let toolchain_version = probe_build_tool_version(&program, &source_root).await?;
    let run = BuildRunDirectories::create()?;
    let cargo_dependency_cache_digest = if compiler_precise_stage {
        let cargo_home = run.cache.join("cargo");
        stage_cargo_dependency_cache(&source_root, &cargo_home)?;
        Some(digest_workspace(&cargo_home)?)
    } else {
        None
    };
    stage_workspace(&source_root, &run.workspace)?;
    if let Some(config) = &neutral_cargo_config {
        install_neutral_cargo_config(&run.workspace, config)?;
    }
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
    let mut effective_environment = supervisor_environment(
        &source_root,
        &run,
        &plan.program,
        rustc.as_deref(),
        compiler_pack_preflight.as_ref(),
        plan.adapter == COMPILER_PRECISE_INVOCATION_ADAPTER,
    )?;
    for (key, value) in &plan.environment {
        effective_environment.insert(key.clone(), value.clone());
    }
    let redacted_arguments = redact_arguments(&plan.arguments);
    let mut command_plan = serde_json::json!({
        "version": BUILD_SUPERVISOR_VERSION,
        "adapter": plan.adapter,
        "adapter_version": plan.adapter_version,
        "isolation": plan.isolation.contract_name(),
        "program": plan.program,
        "arguments": redacted_arguments,
        "logical_cwd": display_logical(&plan.logical_cwd),
        "compiler_pack_manifest_sha256": compiler_pack_preflight
            .as_ref()
            .map(|pack| pack.attestation.manifest_sha256.as_str()),
    });
    if let Some(config) = &neutral_cargo_config {
        command_plan
            .as_object_mut()
            .context("build command plan is not an object")?
            .insert(
                "neutral_cargo_config_digest".to_owned(),
                serde_json::Value::String(config.digest.clone()),
            );
    }
    if let Some(digest) = &cargo_dependency_cache_digest {
        command_plan
            .as_object_mut()
            .context("build command plan is not an object")?
            .insert(
                "cargo_dependency_cache_digest".to_owned(),
                serde_json::Value::String(digest.clone()),
            );
    }
    let command_plan_digest = digest_json(&command_plan)?;
    let workspace_digest = digest_workspace(&run.workspace)?;
    let source_root_digest = if let Some(cache_digest) = &cargo_dependency_cache_digest {
        digest_json(&(
            "depgraph-compiler-source-closure-v1",
            workspace_digest.as_str(),
            cache_digest.as_str(),
        ))?
    } else {
        workspace_digest
    };
    let compiler_invocation_context = if plan.adapter == COMPILER_PRECISE_INVOCATION_ADAPTER {
        if plan.expected_source_root_digest.as_deref() != Some(source_root_digest.as_str()) {
            bail!(
                "security policy violation: compiler-precise source changed after unit-graph admission"
            );
        }
        let pack = compiler_pack_preflight
            .as_ref()
            .context("compiler invocation compiler pack is unavailable")?;
        let graph = plan
            .compiler_unit_graph
            .as_ref()
            .context("compiler invocation unit graph is unavailable")?;
        let rustc_verbose = run_probe(
            pack.rustc_path.as_os_str(),
            &[OsString::from("-vV")],
            &source_root,
        )
        .await?;
        if !rustc_verbose.status.success()
            || rustc_verbose.stdout.is_empty()
            || rustc_verbose.stdout.len() > 64 * 1024
        {
            bail!("compiler invocation rustc verbose identity is unavailable");
        }
        let rustc_verbose_sha256 = digest_bytes(&rustc_verbose.stdout);
        let attempt_digest = compiler_invocation_attempt_digest(
            &source_root_digest,
            &command_plan_digest,
            &pack.attestation.manifest_sha256,
            &graph.digest,
        )?;
        let expected_graph_path = run.output.join("expected-unit-graph.json");
        fs::write(&expected_graph_path, serde_json::to_vec(graph)?)?;
        let ledger_directory = run.output.join("compiler-invocation-ledger");
        fs::create_dir(&ledger_directory)?;
        let mir_directory = run.output.join("compiler-typed-mir");
        fs::create_dir(&mir_directory)?;
        for (key, value) in [
            ("DEPGRAPH_COMPILER_ATTEMPT_DIGEST", attempt_digest.clone()),
            (
                "DEPGRAPH_COMPILER_EXPECTED_UNIT_GRAPH",
                expected_graph_path.to_string_lossy().into_owned(),
            ),
            (
                "DEPGRAPH_COMPILER_EXPECTED_RUSTC",
                pack.rustc_path.to_string_lossy().into_owned(),
            ),
            (
                "DEPGRAPH_COMPILER_EXPECTED_RUSTC_SHA256",
                pack.attestation.rustc_sha256.clone(),
            ),
            (
                "DEPGRAPH_COMPILER_EXPECTED_RUSTC_VERBOSE_SHA256",
                rustc_verbose_sha256.clone(),
            ),
            (
                "DEPGRAPH_COMPILER_LEDGER_DIR",
                ledger_directory.to_string_lossy().into_owned(),
            ),
            (
                "DEPGRAPH_COMPILER_MIR_DIR",
                mir_directory.to_string_lossy().into_owned(),
            ),
            (
                "DEPGRAPH_COMPILER_OUTPUT_ROOT",
                run.output.to_string_lossy().into_owned(),
            ),
            (
                "DEPGRAPH_COMPILER_PACK_ROOT",
                pack.root.to_string_lossy().into_owned(),
            ),
            (
                "DEPGRAPH_COMPILER_PACK_MANIFEST_SHA256",
                pack.attestation.manifest_sha256.clone(),
            ),
            (
                "DEPGRAPH_COMPILER_QUERY",
                pack.query_path.to_string_lossy().into_owned(),
            ),
            (
                "DEPGRAPH_COMPILER_QUERY_SHA256",
                pack.attestation.query_sha256.clone(),
            ),
            (
                "DEPGRAPH_COMPILER_WORKSPACE_ROOT",
                run.workspace.to_string_lossy().into_owned(),
            ),
        ] {
            effective_environment.insert(key.to_owned(), value);
        }
        Some((
            attempt_digest,
            rustc_verbose_sha256,
            ledger_directory,
            mir_directory,
        ))
    } else {
        None
    };
    let (mut command, network_isolation, isolation_diagnostic) = build_child_command(
        &program,
        &plan.arguments,
        &canonical_cwd,
        &run,
        compiler_pack_preflight.as_ref(),
        plan.isolation,
    )?;
    command.envs(&effective_environment);
    let (environment_keys, redacted_secret_key_count) =
        audit_environment_keys(effective_environment.keys().map(String::as_str));
    let environment_key_set_digest = digest_json(&environment_keys)?;

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
        WaitResult::Process(Ok(status)) => {
            let exit_code = status.code();
            (
                BuildOutcomeKind::Failed,
                exit_code,
                Some(child_failure_diagnostic(&plan.adapter, exit_code).to_owned()),
            )
        }
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
    let mut compiler_pack_attestation = compiler_pack_preflight
        .as_ref()
        .map(|pack| pack.attestation.clone());
    if let (Some(requirement), Some(preflight)) = (&plan.compiler_pack, &compiler_pack_preflight) {
        match verify_compiler_pack(requirement) {
            Ok(postflight) if postflight.attestation == preflight.attestation => {
                compiler_pack_attestation = Some(postflight.attestation);
            }
            Ok(_) | Err(_) => {
                outcome = BuildOutcomeKind::SecurityFailed;
                diagnostic_code = Some("compiler-pack-postflight-failed".to_owned());
                compiler_pack_attestation = None;
            }
        }
    }
    let mut compiler_failure = None;
    if matches!(outcome, BuildOutcomeKind::Failed)
        && plan.adapter == COMPILER_PRECISE_INVOCATION_ADAPTER
        && let (Some(graph), Some(pack), Some(context)) = (
            plan.compiler_unit_graph.as_ref(),
            compiler_pack_preflight.as_ref(),
            compiler_invocation_context.as_ref(),
        )
    {
        let (attempt_digest, rustc_verbose_sha256, ledger_directory, _) = context;
        if let Ok(Some(failure)) = diagnose_compiler_invocation_failure(
            ledger_directory,
            &run.workspace,
            &run.cache.join("cargo"),
            graph,
            attempt_digest,
            &pack.attestation.rustc_sha256,
            rustc_verbose_sha256,
        ) {
            diagnostic_code = Some(failure.reason_code.clone());
            compiler_failure = Some(failure);
        }
    }
    let mut rust_observation = None;
    let mut web_observation = None;
    let mut rust_cargo_unit_graph = None;
    let mut rust_compiler_invocation_ledger = None;
    let mut rust_compiler_mir_ledger = None;
    if matches!(outcome, BuildOutcomeKind::Completed)
        && plan.adapter == COMPILER_PRECISE_UNIT_GRAPH_ADAPTER
    {
        match validate_cargo_unit_graph_with_cargo_home(
            &stdout,
            &run.workspace,
            Some(&run.cache.join("cargo")),
        ) {
            Ok(graph) => rust_cargo_unit_graph = Some(graph),
            Err(_) => {
                outcome = BuildOutcomeKind::SecurityFailed;
                diagnostic_code = Some("rust-compiler-unit-graph-invalid".to_owned());
            }
        }
    }
    if matches!(outcome, BuildOutcomeKind::Completed)
        && plan.adapter == COMPILER_PRECISE_INVOCATION_ADAPTER
    {
        let validation = (|| {
            let graph = plan
                .compiler_unit_graph
                .as_ref()
                .context("compiler invocation unit graph is unavailable")?;
            let (attempt_digest, rustc_verbose_sha256, ledger_directory, mir_directory) =
                compiler_invocation_context
                    .as_ref()
                    .context("compiler invocation context is unavailable")?;
            let pack = compiler_pack_preflight
                .as_ref()
                .context("compiler invocation compiler pack is unavailable")?;
            let ledger = validate_compiler_invocation_ledger(
                ledger_directory,
                &run.workspace,
                &run.cache.join("cargo"),
                graph,
                attempt_digest,
                &pack.attestation.rustc_sha256,
                rustc_verbose_sha256,
            )?;
            let mir = validate_compiler_mir_directory(
                mir_directory,
                &run.workspace,
                &run.cache.join("cargo"),
                graph,
                &ledger,
                &pack.attestation,
            )?;
            Ok::<_, anyhow::Error>((graph.clone(), ledger, mir))
        })();
        match validation {
            Ok((graph, ledger, mir)) => {
                rust_cargo_unit_graph = Some(graph);
                rust_compiler_invocation_ledger = Some(ledger);
                rust_compiler_mir_ledger = Some(mir);
            }
            Err(_) => {
                outcome = BuildOutcomeKind::SecurityFailed;
                diagnostic_code = Some("rust-compiler-typed-mir-invalid".to_owned());
            }
        }
    }
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
                rust_cargo_unit_graph = None;
                rust_compiler_invocation_ledger = None;
                rust_compiler_mir_ledger = None;
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
        compiler_failure,
    };
    Ok(BuildExecutionOutcome {
        audit,
        project_code_executed: plan.adapter != COMPILER_PRECISE_UNIT_GRAPH_ADAPTER,
        compiler_pack_attestation,
        rust_cargo_unit_graph,
        rust_compiler_invocation_ledger,
        rust_compiler_mir_ledger,
        rust_observation,
        web_observation,
    })
}

fn child_failure_diagnostic(adapter: &str, exit_code: Option<i32>) -> &'static str {
    match (adapter, exit_code.is_none()) {
        (COMPILER_PRECISE_UNIT_GRAPH_ADAPTER, true) => "rust-compiler-unit-graph-child-signalled",
        (COMPILER_PRECISE_UNIT_GRAPH_ADAPTER, false) => "rust-compiler-unit-graph-child-failed",
        (COMPILER_PRECISE_INVOCATION_ADAPTER, true) => "rust-compiler-invocation-child-signalled",
        (COMPILER_PRECISE_INVOCATION_ADAPTER, false) => "rust-compiler-invocation-child-failed",
        (_, true) => "build-child-signalled",
        (_, false) => "build-child-failed",
    }
}

fn web_adapter_for_observer(observer: &str) -> Option<WebBuildAdapter> {
    match observer {
        NEXT_BUILD_OBSERVER => Some(WebBuildAdapter::Next),
        ASTRO_BUILD_OBSERVER => Some(WebBuildAdapter::Astro),
        TANSTACK_ROUTER_BUILD_OBSERVER => Some(WebBuildAdapter::TanstackRouter),
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

fn build_child_command(
    program: &Path,
    arguments: &[String],
    cwd: &Path,
    run: &BuildRunDirectories,
    compiler_pack: Option<&VerifiedCompilerPack>,
    isolation: BuildIsolation,
) -> Result<(Command, NetworkIsolation, Option<String>)> {
    let (mut command, network_isolation, isolation_diagnostic) = match isolation {
        BuildIsolation::BestEffort => {
            let command = Command::new(program);
            let (network_isolation, isolation_diagnostic) =
                best_effort_network_isolation_capability();
            (command, network_isolation, isolation_diagnostic)
        }
        BuildIsolation::EnforcedLinuxNamespace => {
            #[cfg(target_os = "linux")]
            {
                (
                    linux_namespace_command(program, arguments, cwd, run, compiler_pack)?,
                    NetworkIsolation::Enforced,
                    None,
                )
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (program, arguments, cwd, run, compiler_pack);
                bail!("enforced build isolation requires the Linux namespace boundary");
            }
        }
    };
    if isolation == BuildIsolation::BestEffort {
        command.args(arguments);
    }
    command
        .current_dir(cwd)
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
    Ok((command, network_isolation, isolation_diagnostic))
}

#[cfg(target_os = "linux")]
fn linux_namespace_command(
    program: &Path,
    arguments: &[String],
    cwd: &Path,
    run: &BuildRunDirectories,
    compiler_pack: Option<&VerifiedCompilerPack>,
) -> Result<Command> {
    use std::os::unix::fs::MetadataExt as _;

    let bwrap = [Path::new("/usr/bin/bwrap"), Path::new("/bin/bwrap")]
        .into_iter()
        .find_map(|candidate| {
            let canonical = candidate.canonicalize().ok()?;
            let metadata = fs::metadata(&canonical).ok()?;
            (metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
                .then_some(canonical)
        })
        .context(
            "enforced build isolation requires a root-owned, non-writable bubblewrap executable",
        )?;
    let program = program
        .canonicalize()
        .context("enforced build executable is unavailable")?;
    let mut command = Command::new(bwrap);
    command.args([
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-uts",
        "--cap-drop",
        "ALL",
        "--hostname",
        "depgraph-build",
    ]);
    add_linux_runtime_mounts(&mut command)?;
    add_sandbox_parent_directories(&mut command, run._root.path())?;
    command
        .arg("--ro-bind")
        .arg(&run.workspace)
        .arg(&run.workspace);
    for directory in [&run.home, &run.output, &run.cache, &run.temporary] {
        command.arg("--bind").arg(directory).arg(directory);
    }
    if let Some(pack) = compiler_pack {
        add_sandbox_parent_directories(&mut command, &pack.root)?;
        command.arg("--ro-bind").arg(&pack.root).arg(&pack.root);
    } else if !["/usr", "/bin", "/sbin", "/lib", "/lib64"]
        .iter()
        .any(|root| program.starts_with(root))
    {
        add_sandbox_parent_directories(&mut command, &program)?;
        command.arg("--ro-bind").arg(&program).arg(&program);
    }
    command
        .arg("--chdir")
        .arg(cwd)
        .arg("--")
        .arg(program)
        .args(arguments);
    Ok(command)
}

#[cfg(target_os = "linux")]
fn add_linux_runtime_mounts(command: &mut Command) -> Result<()> {
    let usr = Path::new("/usr");
    if !usr.is_dir() {
        bail!("enforced build isolation requires the system /usr runtime");
    }
    command.arg("--ro-bind").arg(usr).arg(usr);
    for path in ["/bin", "/sbin", "/lib", "/lib64"] {
        let path = Path::new(path);
        let Ok(metadata) = fs::symlink_metadata(path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            command.arg("--symlink").arg(fs::read_link(path)?).arg(path);
        } else if metadata.is_dir() {
            command.arg("--ro-bind").arg(path).arg(path);
        } else {
            bail!("enforced build runtime path {} is unsafe", path.display());
        }
    }
    command.args(["--dir", "/etc"]);
    let loader_cache = Path::new("/etc/ld.so.cache");
    if loader_cache.is_file() {
        command.arg("--ro-bind").arg(loader_cache).arg(loader_cache);
    }
    command.args(["--dir", "/tmp", "--proc", "/proc", "--dev", "/dev"]);
    Ok(())
}

#[cfg(target_os = "linux")]
fn add_sandbox_parent_directories(command: &mut Command, path: &Path) -> Result<()> {
    let parent = path.parent();
    let Some(parent) = parent else {
        return Ok(());
    };
    let mut directories = parent
        .ancestors()
        .filter(|ancestor| *ancestor != Path::new("/"))
        .collect::<Vec<_>>();
    directories.reverse();
    for directory in directories {
        command.arg("--dir").arg(directory);
    }
    Ok(())
}

fn supervisor_environment(
    root: &Path,
    run: &BuildRunDirectories,
    program: &str,
    rustc: Option<&Path>,
    compiler_pack: Option<&VerifiedCompilerPack>,
    compiler_wrapper_enabled: bool,
) -> Result<BTreeMap<String, String>> {
    let mut environment = BTreeMap::new();
    let path = if let Some(pack) = compiler_pack {
        let mut directories = BTreeSet::new();
        for executable in [
            &pack.cargo_path,
            &pack.rustc_path,
            &pack.wrapper_path,
            &pack.query_path,
        ] {
            directories.insert(
                executable
                    .parent()
                    .context("compiler pack executable has no parent directory")?
                    .to_path_buf(),
            );
        }
        std::env::join_paths(directories)
            .context("compiler pack PATH is invalid")?
            .to_string_lossy()
            .into_owned()
    } else {
        sanitized_path(root)?.to_string_lossy().into_owned()
    };
    environment.insert("PATH".to_owned(), path);
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
        let rustc_wrapper = compiler_pack
            .filter(|_| compiler_wrapper_enabled)
            .map(|pack| pack.wrapper_path.to_string_lossy().into_owned())
            .unwrap_or_default();
        environment.insert("RUSTC_WRAPPER".to_owned(), rustc_wrapper.clone());
        environment.insert("RUSTC_WORKSPACE_WRAPPER".to_owned(), String::new());
        environment.insert("CARGO_BUILD_RUSTC_WRAPPER".to_owned(), rustc_wrapper);
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
        let rustup_home = compiler_pack.is_none().then(|| {
            safe_host_directory("RUSTUP_HOME", root).or_else(|| {
                BaseDirs::new().and_then(|directories| {
                    safe_directory_path(&directories.home_dir().join(".rustup"), root)
                })
            })
        });
        if let Some(Some(value)) = rustup_home {
            environment.insert("RUSTUP_HOME".to_owned(), value);
        }
        #[cfg(unix)]
        if compiler_pack.is_some() && compiler_wrapper_enabled {
            extend_trusted_host_linker_path(&mut environment, root)?;
        }
        #[cfg(all(windows, target_env = "msvc"))]
        if compiler_pack.is_none() || compiler_wrapper_enabled {
            copy_safe_msvc_environment(&mut environment, root)?;
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

#[cfg(unix)]
fn extend_trusted_host_linker_path(
    environment: &mut BTreeMap<String, String>,
    root: &Path,
) -> Result<()> {
    let mut directories = environment
        .get("PATH")
        .map(|value| std::env::split_paths(value).collect::<Vec<_>>())
        .unwrap_or_default();
    for executable in [trusted_host_executable(
        "C compiler",
        &[Path::new("/usr/bin/cc"), Path::new("/bin/cc")],
        root,
    )?]
    .into_iter()
    .chain(trusted_macos_sdk_tools(root)?)
    {
        let directory = executable
            .parent()
            .context("trusted host linker executable has no parent directory")?
            .to_path_buf();
        if !directories.contains(&directory) {
            directories.push(directory);
        }
    }
    environment.insert(
        "PATH".to_owned(),
        std::env::join_paths(directories)
            .context("trusted host linker PATH is invalid")?
            .to_string_lossy()
            .into_owned(),
    );
    Ok(())
}

#[cfg(unix)]
fn trusted_host_executable(label: &str, candidates: &[&Path], root: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt as _;

    for candidate in candidates {
        let Ok(executable) = candidate.canonicalize() else {
            continue;
        };
        let Ok(metadata) = fs::metadata(&executable) else {
            continue;
        };
        let Some(directory) = executable.parent() else {
            continue;
        };
        let Ok(directory_metadata) = fs::metadata(directory) else {
            continue;
        };
        if metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && directory_metadata.is_dir()
            && directory_metadata.uid() == 0
            && directory_metadata.mode() & 0o022 == 0
            && !executable.starts_with(root)
        {
            return Ok(executable);
        }
    }
    bail!("compiler-precise build-script support requires a root-owned, non-writable host {label}")
}

#[cfg(unix)]
fn compiler_precise_host_tool_identity(root: &Path) -> Result<String> {
    let mut tools = vec![trusted_host_executable(
        "C compiler",
        &[Path::new("/usr/bin/cc"), Path::new("/bin/cc")],
        root,
    )?];
    tools.extend(trusted_macos_sdk_tools(root)?);
    tools.sort();
    let identities = tools
        .into_iter()
        .map(|path| {
            Ok((
                path.file_name()
                    .and_then(|name| name.to_str())
                    .context("trusted compiler host tool name is not UTF-8")?
                    .to_owned(),
                digest_file(&path)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    digest_json(&("compiler-precise-host-tools-v1", identities))
}

#[cfg(target_os = "macos")]
fn trusted_macos_sdk_tools(root: &Path) -> Result<Vec<PathBuf>> {
    Ok(vec![trusted_host_executable(
        "macOS SDK resolver",
        &[Path::new("/usr/bin/xcrun")],
        root,
    )?])
}

#[cfg(all(unix, not(target_os = "macos")))]
fn trusted_macos_sdk_tools(_root: &Path) -> Result<Vec<PathBuf>> {
    Ok(Vec::new())
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
        let mut value = sanitize_path_value(value, root)?;
        if key == "PATH" {
            has_linker_path = std::env::split_paths(&value).any(|path| path == linker_directory);
            let mut paths = std::env::split_paths(&value).collect::<Vec<_>>();
            let existing_paths = environment
                .get("PATH")
                .map(|existing| std::env::split_paths(existing).collect::<Vec<_>>())
                .unwrap_or_default();
            for path in existing_paths {
                if !paths.contains(&path) {
                    paths.push(path);
                }
            }
            value =
                std::env::join_paths(paths).context("Visual Studio MSVC linker PATH is invalid")?;
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

#[cfg(all(windows, target_env = "msvc"))]
fn compiler_precise_host_tool_identity(root: &Path) -> Result<String> {
    let tool = find_msvc_tools::find_tool(std::env::consts::ARCH, "link.exe")
        .context("Visual Studio MSVC linker is unavailable")?;
    let linker = tool
        .path()
        .canonicalize()
        .context("Visual Studio MSVC linker is unavailable")?;
    if !linker.is_file() || linker.starts_with(root) {
        bail!("security policy violation: MSVC linker is not a trusted host executable");
    }
    let environment = tool
        .env()
        .iter()
        .filter_map(|(key, value)| {
            let key = key.to_str()?;
            matches!(key, "PATH" | "INCLUDE" | "LIB" | "LIBPATH")
                .then(|| (key.to_owned(), value.to_string_lossy().into_owned()))
        })
        .collect::<BTreeMap<_, _>>();
    digest_json(&(
        "compiler-precise-host-tools-v1",
        digest_file(&linker)?,
        environment,
    ))
}

#[cfg(not(any(unix, all(windows, target_env = "msvc"))))]
fn compiler_precise_host_tool_identity(_root: &Path) -> Result<String> {
    bail!("compiler-precise validated cache has no trusted host-tool contract on this platform")
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
            | "DEPGRAPH_TANSTACK_ROUTER_VERSION"
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

fn stage_cargo_dependency_cache(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    let lockfile = source.join("Cargo.lock");
    let lock_text = fs::read_to_string(&lockfile)
        .context("compiler-precise Cargo.lock is unavailable or not UTF-8")?;
    if lock_text.len() > 16 * 1024 * 1024 {
        bail!("compiler-precise Cargo.lock exceeds its byte limit");
    }
    let lock: toml::Value =
        toml::from_str(&lock_text).context("compiler-precise Cargo.lock is invalid TOML")?;
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut registry_packages = BTreeSet::new();
    let mut git = false;
    for package in packages {
        let Some(package) = package.as_table() else {
            bail!("compiler-precise Cargo.lock package entry is not a table");
        };
        let Some(source) = package.get("source").and_then(toml::Value::as_str) else {
            continue;
        };
        if source.starts_with("registry+") || source.starts_with("sparse+") {
            let name = package
                .get("name")
                .and_then(toml::Value::as_str)
                .context("compiler-precise registry package has no name")?;
            let version = package
                .get("version")
                .and_then(toml::Value::as_str)
                .context("compiler-precise registry package has no version")?;
            validate_cache_package_identity(name)?;
            validate_cache_package_identity(version)?;
            registry_packages.insert((name.to_owned(), version.to_owned()));
        } else if source.starts_with("git+") {
            git = true;
        } else {
            bail!("compiler-precise Cargo.lock contains an unsupported external source");
        }
    }
    if registry_packages.is_empty() && !git {
        return Ok(());
    }
    let host_cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| BaseDirs::new().map(|directories| directories.home_dir().join(".cargo")))
        .and_then(|path| path.canonicalize().ok())
        .filter(|path| path.is_dir() && !path.starts_with(source))
        .context(
            "compiler-precise external dependencies require an existing host Cargo cache; network and credential fallback remain disabled",
        )?;
    let mut file_count = 0_usize;
    let mut byte_count = 0_u64;
    if !registry_packages.is_empty() {
        stage_registry_dependency_cache(
            &host_cargo_home,
            destination,
            &registry_packages,
            &mut file_count,
            &mut byte_count,
        )?;
    }
    if git {
        for relative in [Path::new("git/db"), Path::new("git/checkouts")] {
            let source_path = host_cargo_home.join(relative);
            if source_path.exists() {
                copy_bounded_regular_tree(
                    &source_path,
                    &destination.join(relative),
                    &mut file_count,
                    &mut byte_count,
                )?;
            }
        }
    }
    if git && !destination.join("git/checkouts").is_dir() {
        bail!("compiler-precise Git dependencies are unavailable in the offline Cargo cache");
    }
    Ok(())
}

fn stage_registry_dependency_cache(
    host_cargo_home: &Path,
    destination: &Path,
    packages: &BTreeSet<(String, String)>,
    file_count: &mut usize,
    byte_count: &mut u64,
) -> Result<()> {
    let registry = host_cargo_home.join("registry");
    let mut staged_sources = BTreeSet::new();
    let source_roots = sorted_child_directories(&registry.join("src"))?;
    for source_root in &source_roots {
        for (name, version) in packages {
            let package = format!("{name}-{version}");
            let source_path = source_root.join(&package);
            if source_path.is_dir() {
                let registry_name = source_root
                    .file_name()
                    .context("Cargo registry source root has no name")?;
                copy_bounded_regular_tree(
                    &source_path,
                    &destination
                        .join("registry/src")
                        .join(registry_name)
                        .join(&package),
                    file_count,
                    byte_count,
                )?;
                staged_sources.insert((name.clone(), version.clone()));
            }
        }
    }
    if staged_sources.len() != packages.len() {
        bail!("compiler-precise registry dependency sources are incomplete in the offline cache");
    }

    for cache_root in sorted_child_directories(&registry.join("cache"))? {
        let registry_name = cache_root
            .file_name()
            .context("Cargo registry cache root has no name")?;
        for (name, version) in packages {
            let archive = format!("{name}-{version}.crate");
            let source_path = cache_root.join(&archive);
            if source_path.is_file() {
                copy_bounded_regular_file(
                    &source_path,
                    &destination
                        .join("registry/cache")
                        .join(registry_name)
                        .join(archive),
                    file_count,
                    byte_count,
                )?;
            }
        }
    }

    for index_root in sorted_child_directories(&registry.join("index"))? {
        let registry_name = index_root
            .file_name()
            .context("Cargo registry index root has no name")?;
        let output_root = destination.join("registry/index").join(registry_name);
        let config = index_root.join("config.json");
        if config.is_file() {
            copy_bounded_regular_file(
                &config,
                &output_root.join("config.json"),
                file_count,
                byte_count,
            )?;
        }
        for (name, _) in packages {
            let relative = cargo_registry_index_path(name)?;
            for candidate in [
                index_root.join(".cache").join(&relative),
                index_root.join(&relative),
            ] {
                if candidate.is_file() {
                    let prefix = candidate
                        .strip_prefix(&index_root)
                        .context("Cargo registry index entry escapes its root")?;
                    copy_bounded_regular_file(
                        &candidate,
                        &output_root.join(prefix),
                        file_count,
                        byte_count,
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn sorted_child_directories(root: &Path) -> Result<Vec<PathBuf>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("security policy violation: offline Cargo cache root is not a regular directory");
    }
    let mut directories = fs::read_dir(root)?
        .map(|entry| {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                bail!("security policy violation: offline Cargo cache root contains a symlink");
            }
            Ok(metadata.is_dir().then_some(path))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    directories.sort();
    Ok(directories)
}

fn cargo_registry_index_path(name: &str) -> Result<PathBuf> {
    validate_cache_package_identity(name)?;
    let lowercase = name.to_ascii_lowercase();
    let bytes = lowercase.as_bytes();
    Ok(match bytes.len() {
        1 => PathBuf::from("1").join(&lowercase),
        2 => PathBuf::from("2").join(&lowercase),
        3 => PathBuf::from("3").join(&lowercase[..1]).join(&lowercase),
        _ => PathBuf::from(&lowercase[..2])
            .join(&lowercase[2..4])
            .join(&lowercase),
    })
}

fn validate_cache_package_identity(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || value.chars().any(|character| {
            !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '+' | '.'))
        })
    {
        bail!("compiler-precise Cargo.lock package identity is invalid");
    }
    Ok(())
}

fn copy_bounded_regular_file(
    source: &Path,
    destination: &Path,
    file_count: &mut usize,
    byte_count: &mut u64,
) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("security policy violation: offline Cargo cache entry is not a regular file");
    }
    if matches!(
        source.file_name().and_then(|name| name.to_str()),
        Some("config" | "config.json")
    ) {
        validate_cargo_cache_metadata(source, metadata.len())?;
    }
    *file_count = file_count
        .checked_add(1)
        .context("offline Cargo cache file count overflowed")?;
    *byte_count = byte_count
        .checked_add(metadata.len())
        .context("offline Cargo cache byte count overflowed")?;
    if *file_count > MAX_STAGED_FILES || *byte_count > MAX_STAGED_BYTES {
        bail!("security policy violation: offline Cargo cache exceeds its staged bounds");
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, destination)?;
    fs::set_permissions(destination, metadata.permissions())?;
    Ok(())
}

fn copy_bounded_regular_tree(
    source: &Path,
    destination: &Path,
    file_count: &mut usize,
    byte_count: &mut u64,
) -> Result<()> {
    let source = source
        .canonicalize()
        .context("offline Cargo cache source is unavailable")?;
    for entry in WalkDir::new(&source).follow_links(false) {
        let entry = entry?;
        let relative = entry.path().strip_prefix(&source)?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            bail!("security policy violation: offline Cargo cache contains a symlink");
        }
        let target = destination.join(relative);
        if metadata.is_dir() {
            fs::create_dir_all(&target)?;
            continue;
        }
        if !metadata.is_file() {
            bail!("security policy violation: offline Cargo cache contains a special file");
        }
        copy_bounded_regular_file(entry.path(), &target, file_count, byte_count)?;
    }
    Ok(())
}

fn validate_cargo_cache_metadata(path: &Path, size: u64) -> Result<()> {
    if size > 1024 * 1024 {
        bail!("security policy violation: offline Cargo cache metadata exceeds its byte limit");
    }
    let bytes = fs::read(path)?;
    let text = std::str::from_utf8(&bytes)
        .context("security policy violation: offline Cargo cache metadata is not UTF-8")?;
    for line in text.lines() {
        let lowercase = line.to_ascii_lowercase();
        let key = lowercase
            .split_once('=')
            .map(|(key, _)| key.trim())
            .unwrap_or_default();
        if ["token", "secret", "password", "credential", "authorization"]
            .iter()
            .any(|name| key.contains(name))
        {
            bail!("security policy violation: offline Cargo cache metadata is secret-shaped");
        }
        if let Some((_, authority_and_path)) = line.split_once("://")
            && authority_and_path
                .split(['/', '\\'])
                .next()
                .is_some_and(|authority| authority.contains('@'))
        {
            bail!("security policy violation: offline Cargo cache URL contains user information");
        }
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

fn fingerprint_build_source(root: &Path) -> Result<(String, String, String)> {
    let mut source = Sha256::new();
    source.update(b"depgraph-build-source-v1\0");
    let mut controls = Sha256::new();
    controls.update(b"depgraph-build-manifest-lock-config-v1\0");
    let mut staging_metadata = Sha256::new();
    staging_metadata.update(b"depgraph-build-staging-metadata-v1\0");
    let mut entries = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(admit_stage_entry)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path().to_path_buf());
    let mut files = 0_usize;
    let mut bytes = 0_u64;
    for entry in entries {
        let relative = entry.path().strip_prefix(root)?;
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
        let logical = display_logical(relative);
        if metadata.is_dir() {
            staging_metadata.update(b"directory\0");
            staging_metadata.update(logical.as_bytes());
            staging_metadata.update([0]);
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
        let contents = fs::read(entry.path())?;
        staging_metadata.update(b"file\0");
        staging_metadata.update(logical.as_bytes());
        staging_metadata.update([0]);
        staging_metadata.update(staged_file_permission_fingerprint(&metadata).to_le_bytes());
        source.update(logical.as_bytes());
        source.update([0]);
        source.update(&contents);
        source.update([0]);
        if is_build_control_path(relative) {
            controls.update(logical.as_bytes());
            controls.update([0]);
            controls.update(&contents);
            controls.update([0]);
        }
    }
    Ok((
        hex::encode(source.finalize()),
        hex::encode(controls.finalize()),
        hex::encode(staging_metadata.finalize()),
    ))
}

#[cfg(unix)]
fn staged_file_permission_fingerprint(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn staged_file_permission_fingerprint(metadata: &fs::Metadata) -> u32 {
    u32::from(metadata.permissions().readonly())
}

fn is_build_control_path(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    matches!(
        name,
        "Cargo.toml"
            | "Cargo.lock"
            | "package.json"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "bun.lock"
            | "bun.lockb"
            | "rust-toolchain"
            | "rust-toolchain.toml"
            | "tsconfig.json"
    ) || name.starts_with("next.config.")
        || name.starts_with("astro.config.")
        || name.starts_with("vite.config.")
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

fn best_effort_network_isolation_capability() -> (NetworkIsolation, Option<String>) {
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
    use crate::compiler_pack::{
        CompilerPackBuildComponent, CompilerPackBuildSpec, build_compiler_pack,
    };

    #[test]
    fn build_cache_source_fingerprint_covers_empty_directories_and_staged_permissions() -> Result<()>
    {
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join("empty"))?;
        let source = root.path().join("source.rs");
        fs::write(&source, "pub fn observed() {}\n")?;
        let (_, _, original_metadata) = fingerprint_build_source(root.path())?;

        fs::remove_dir(root.path().join("empty"))?;
        let (_, _, without_empty_directory) = fingerprint_build_source(root.path())?;
        assert_ne!(original_metadata, without_empty_directory);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = fs::metadata(&source)?.permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&source, permissions)?;
            let (_, _, executable_metadata) = fingerprint_build_source(root.path())?;
            assert_ne!(without_empty_directory, executable_metadata);
        }
        Ok(())
    }

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
            TANSTACK_START_BUILD_OBSERVER_VERSION
        );
        assert_eq!(
            WebBuildAdapter::TanstackStart.observation_schema(),
            "tanstack-start-build-observation-v2"
        );
        assert_eq!(
            WebBuildAdapter::TanstackRouter.observer_version(),
            WEB_BUILD_OBSERVER_VERSION
        );
        assert_eq!(
            WebBuildAdapter::TanstackRouter.observation_schema(),
            "tanstack-router-build-observation-v1"
        );
    }

    #[test]
    fn registry_cache_staging_copies_only_locked_packages_and_rejects_credentials() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let host = temporary.path().join("host-cargo");
        let output = temporary.path().join("run-cargo");
        let registry_name = "index.crates.io-fixture";
        for package in ["wanted-1.2.3", "unrelated-9.9.9"] {
            fs::create_dir_all(
                host.join("registry/src")
                    .join(registry_name)
                    .join(package)
                    .join("src"),
            )?;
            fs::write(
                host.join("registry/src")
                    .join(registry_name)
                    .join(package)
                    .join("src/lib.rs"),
                package,
            )?;
            fs::create_dir_all(host.join("registry/cache").join(registry_name))?;
            fs::write(
                host.join("registry/cache")
                    .join(registry_name)
                    .join(format!("{package}.crate")),
                package,
            )?;
        }
        let index = host.join("registry/index").join(registry_name);
        fs::create_dir_all(index.join(".cache/wa/nt"))?;
        fs::write(
            index.join("config.json"),
            r#"{"dl":"https://static.crates.io/crates"}"#,
        )?;
        fs::write(index.join(".cache/wa/nt/wanted"), b"index")?;
        let packages = BTreeSet::from([("wanted".to_owned(), "1.2.3".to_owned())]);
        let mut files = 0;
        let mut bytes = 0;
        stage_registry_dependency_cache(&host, &output, &packages, &mut files, &mut bytes)?;
        assert!(
            output
                .join("registry/src")
                .join(registry_name)
                .join("wanted-1.2.3/src/lib.rs")
                .is_file()
        );
        assert!(
            !output
                .join("registry/src")
                .join(registry_name)
                .join("unrelated-9.9.9")
                .exists()
        );

        fs::write(
            index.join("config.json"),
            r#"{"dl":"https://token@example.invalid/crates"}"#,
        )?;
        let rejected = temporary.path().join("rejected");
        let mut files = 0;
        let mut bytes = 0;
        assert!(
            stage_registry_dependency_cache(&host, &rejected, &packages, &mut files, &mut bytes)
                .is_err()
        );
        Ok(())
    }

    fn node_plan(arguments: Vec<String>) -> BuildExecutionPlan {
        BuildExecutionPlan {
            adapter: "fixture".to_owned(),
            adapter_version: "1.0".to_owned(),
            profile_id: "fixture:build".to_owned(),
            isolation: BuildIsolation::BestEffort,
            program: "node".to_owned(),
            arguments,
            logical_cwd: PathBuf::from("."),
            environment: BTreeMap::new(),
            timeout_seconds: 10,
            stdout_limit_bytes: 1024,
            stderr_limit_bytes: 1024,
            target: None,
            compiler_pack: None,
            compiler_unit_graph: None,
            expected_source_root_digest: None,
        }
    }

    #[cfg(unix)]
    fn compiler_pack_fixture(
        temp: &tempfile::TempDir,
    ) -> Result<(CompilerPackRequirement, PathBuf)> {
        compiler_pack_fixture_with_scripts(
            temp,
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'cargo 1.99.0-nightly\\n'; exit 0; fi\nprintf 'tampered' > \"$DEPGRAPH_TARGET\"\n",
            "fixture",
            "fixture",
        )
    }

    #[cfg(unix)]
    fn compiler_pack_fixture_with_scripts(
        temp: &tempfile::TempDir,
        cargo_script: &str,
        rustc_script: &str,
        wrapper_script: &str,
    ) -> Result<(CompilerPackRequirement, PathBuf)> {
        use std::os::unix::fs::PermissionsExt as _;

        let source = temp.path().join("compiler-pack-source");
        let pack = temp.path().join("compiler-pack");
        fs::create_dir(&source)?;
        let component = |name: &str, files: Vec<String>| CompilerPackBuildComponent {
            name: name.to_owned(),
            archive_sha256: hex::encode(Sha256::digest(format!("archive:{name}"))),
            source: format!(
                "https://static.rust-lang.org/dist/2026-07-17/{name}-nightly-fixture.tar.xz"
            ),
            files,
        };
        let spec = CompilerPackBuildSpec {
            host: "x86_64-unknown-linux-gnu".to_owned(),
            target: "x86_64-unknown-linux-gnu".to_owned(),
            release_checksum_reference:
                "release-checksums:v0.4.0/compiler-pack-x86_64-unknown-linux-gnu".to_owned(),
            cargo_path: "toolchain/cargo/bin/cargo".to_owned(),
            rustc_path: "toolchain/rustc/bin/rustc".to_owned(),
            wrapper_path: "bin/depgraph-rustc-wrapper".to_owned(),
            query_path: "bin/depgraph-rustc-query".to_owned(),
            wrapper_protocol_schema_path: "schemas/depgraph-rust-compiler-precise-v1.schema.json"
                .to_owned(),
            components: vec![
                component("cargo", vec!["toolchain/cargo/bin/cargo".to_owned()]),
                component(
                    "llvm-tools",
                    vec!["toolchain/llvm-tools/bin/llvm-config".to_owned()],
                ),
                component(
                    "rust-src",
                    vec!["toolchain/rust-src/library/core/src/lib.rs".to_owned()],
                ),
                component(
                    "rust-std",
                    vec!["toolchain/rust-std/lib/libstd.rlib".to_owned()],
                ),
                component("rustc", vec!["toolchain/rustc/bin/rustc".to_owned()]),
                component(
                    "rustc-dev",
                    vec!["toolchain/rustc-dev/lib/librustc_driver.rlib".to_owned()],
                ),
            ],
        };
        for component in &spec.components {
            for relative in &component.files {
                let path = source.join(relative);
                fs::create_dir_all(path.parent().context("fixture file has no parent")?)?;
                fs::write(&path, format!("fixture:{}", component.name))?;
            }
        }
        for relative in [
            spec.wrapper_path.as_str(),
            spec.query_path.as_str(),
            spec.wrapper_protocol_schema_path.as_str(),
            "licenses/LICENSE-APACHE",
            "licenses/LICENSE-MIT",
        ] {
            let path = source.join(relative);
            fs::create_dir_all(path.parent().context("fixture file has no parent")?)?;
            fs::write(path, b"fixture")?;
        }
        let cargo = source.join(&spec.cargo_path);
        fs::write(&cargo, cargo_script)?;
        fs::write(source.join(&spec.rustc_path), rustc_script)?;
        fs::write(source.join(&spec.wrapper_path), wrapper_script)?;
        fs::write(source.join(&spec.query_path), wrapper_script)?;
        for relative in [
            &spec.cargo_path,
            &spec.rustc_path,
            &spec.wrapper_path,
            &spec.query_path,
        ] {
            let path = source.join(relative);
            let mut permissions = fs::metadata(&path)?.permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions)?;
        }
        let verified = build_compiler_pack(&source, &pack, &spec)?;
        let tamper_path = pack.join("toolchain/rust-src/library/core/src/lib.rs");
        Ok((
            CompilerPackRequirement {
                root: pack,
                expected_manifest_sha256: verified.attestation.manifest_sha256,
                release_checksum_reference: spec.release_checksum_reference,
                host: spec.host,
                target: spec.target,
            },
            tamper_path,
        ))
    }

    #[cfg(unix)]
    #[test]
    fn compiler_precise_cache_admission_is_repeatable_and_source_sensitive() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let project = temp.path().join("project");
        fs::create_dir_all(project.join("src"))?;
        fs::create_dir(project.join("empty"))?;
        fs::write(
            project.join("Cargo.toml"),
            "[package]\nname='cache-fixture'\nversion='0.1.0'\nedition='2024'\n",
        )?;
        fs::write(
            project.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"cache-fixture\"\nversion = \"0.1.0\"\n",
        )?;
        fs::write(project.join("src/lib.rs"), "pub fn cold() {}\n")?;
        let (requirement, _) = compiler_pack_fixture(&temp)?;
        let request = create_compiler_precise_unit_graph_request(&project, requirement)?;
        let first = prepare_compiler_precise_cache_input(
            &request,
            "snapshot:safe",
            "profile-plan:fixture",
        )?;
        let repeated = prepare_compiler_precise_cache_input(
            &request,
            "snapshot:safe",
            "profile-plan:fixture",
        )?;
        assert_eq!(first, repeated);

        fs::write(project.join("src/lib.rs"), "pub fn changed() {}\n")?;
        let changed = prepare_compiler_precise_cache_input(
            &request,
            "snapshot:safe",
            "profile-plan:fixture",
        )?;
        assert_ne!(
            crate::compiler_precise_cache_key(&first).key,
            crate::compiler_precise_cache_key(&changed).key
        );
        assert!(
            validate_compiler_precise_cache_input(&first, &request, "profile-plan:fixture")
                .is_err()
        );
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn compiler_pack_postflight_tamper_is_security_failed() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let project = temp.path().join("project");
        fs::create_dir(&project)?;
        fs::write(project.join("input"), b"fixture")?;
        let (requirement, tamper_path) = compiler_pack_fixture(&temp)?;
        let verified = verify_compiler_pack(&requirement)?;
        let run = BuildRunDirectories::create()?;
        let environment = supervisor_environment(
            &project,
            &run,
            "cargo",
            Some(&verified.rustc_path),
            Some(&verified),
            true,
        )?;
        assert_eq!(
            environment.get("RUSTC_WRAPPER").map(String::as_str),
            Some(verified.wrapper_path.to_string_lossy().as_ref())
        );
        assert_eq!(
            environment
                .get("CARGO_BUILD_RUSTC_WRAPPER")
                .map(String::as_str),
            Some(verified.wrapper_path.to_string_lossy().as_ref())
        );
        assert_eq!(
            environment
                .get("RUSTC_WORKSPACE_WRAPPER")
                .map(String::as_str),
            Some("")
        );
        let trusted_cc = trusted_host_executable(
            "C compiler",
            &[Path::new("/usr/bin/cc"), Path::new("/bin/cc")],
            &project,
        )?;
        assert!(
            std::env::split_paths(
                environment
                    .get("PATH")
                    .context("compiler PATH is missing")?
            )
            .any(|path| trusted_cc.parent() == Some(path.as_path()))
        );
        let unit_graph_environment = supervisor_environment(
            &project,
            &run,
            "cargo",
            Some(&verified.rustc_path),
            Some(&verified),
            false,
        )?;
        assert_eq!(
            unit_graph_environment
                .get("RUSTC_WRAPPER")
                .map(String::as_str),
            Some("")
        );
        assert!(
            !std::env::split_paths(
                unit_graph_environment
                    .get("PATH")
                    .context("unit graph PATH is missing")?
            )
            .any(|path| trusted_cc.parent() == Some(path.as_path()))
        );
        let mut plan = BuildExecutionPlan {
            adapter: "compiler-pack-fixture".to_owned(),
            adapter_version: "1.0".to_owned(),
            profile_id: "rust:compiler-precise".to_owned(),
            isolation: BuildIsolation::BestEffort,
            program: "cargo".to_owned(),
            arguments: vec!["build".to_owned()],
            logical_cwd: PathBuf::from("."),
            environment: BTreeMap::from([(
                "DEPGRAPH_TARGET".to_owned(),
                tamper_path.to_string_lossy().into_owned(),
            )]),
            timeout_seconds: 10,
            stdout_limit_bytes: 1024,
            stderr_limit_bytes: 1024,
            target: Some(requirement.target.clone()),
            compiler_pack: Some(requirement),
            compiler_unit_graph: None,
            expected_source_root_digest: None,
        };
        let outcome = supervise_build(&project, &plan).await?;
        assert_eq!(outcome.audit.outcome, BuildOutcomeKind::SecurityFailed);
        assert_eq!(
            outcome.audit.diagnostic_code.as_deref(),
            Some("compiler-pack-postflight-failed")
        );
        assert!(outcome.audit.validated_output_digest.is_none());
        assert!(outcome.compiler_pack_attestation.is_none());
        assert!(outcome.rust_observation.is_none());
        assert!(outcome.web_observation.is_none());

        plan.compiler_pack = Some(CompilerPackRequirement {
            root: temp.path().join("missing-pack"),
            expected_manifest_sha256: "0".repeat(64),
            release_checksum_reference:
                "release-checksums:v0.4.0/compiler-pack-x86_64-unknown-linux-gnu".to_owned(),
            host: "x86_64-unknown-linux-gnu".to_owned(),
            target: "x86_64-unknown-linux-gnu".to_owned(),
        });
        let error = supervise_build(&project, &plan).await.unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("compiler-precise backend is unsupported"));
        assert!(message.contains("no rustup, PATH, system, or project toolchain fallback"));
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn compiler_precise_unit_graph_is_supervised_without_starting_rustc_or_hooks()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let project = temp.path().join("project");
        fs::create_dir_all(project.join("src"))?;
        fs::create_dir(project.join(".cargo"))?;
        fs::write(
            project.join("Cargo.toml"),
            "[package]\nname = \"unit-graph-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\nbuild = \"build.rs\"\n\n[workspace]\n",
        )?;
        fs::write(project.join("Cargo.lock"), "version = 4\n")?;
        fs::write(project.join("src/lib.rs"), "pub fn fixture() {}\n")?;
        fs::write(
            project.join(".cargo/config.toml"),
            "[build]\nrustflags = [\"--cfg\", \"depgraph_fixture\"]\n",
        )?;
        let rustc_marker = temp.path().join("RUSTC_STARTED");
        let wrapper_marker = temp.path().join("WRAPPER_STARTED");
        let build_script_marker = temp.path().join("BUILD_SCRIPT_STARTED");
        fs::write(
            project.join("build.rs"),
            format!(
                "fn main() {{ std::fs::write({:?}, b\"started\").unwrap(); }}\n",
                build_script_marker
            ),
        )?;
        let cargo_script = r#"#!/bin/sh
if [ "$1" = "--version" ]; then printf 'cargo 1.99.0-nightly\n'; exit 0; fi
if [ "$*" != "build --frozen --offline --unit-graph -Z unstable-options --target x86_64-unknown-linux-gnu" ]; then exit 91; fi
found_offline=false
while IFS= read -r line; do
  if [ "$line" = "offline = true" ]; then found_offline=true; fi
done < .cargo/config.toml
if [ "$found_offline" != "true" ]; then exit 92; fi
workspace=$(pwd)
printf '{"version":1,"units":[{"pkg_id":"path+file://%s#0.1.0","target":{"kind":["lib"],"crate_types":["lib"],"name":"unit_graph_fixture","src_path":"%s/src/lib.rs","edition":"2024","doc":true,"doctest":true,"test":true},"profile":{"name":"dev","opt_level":"0","lto":"false","codegen_units":null,"debuginfo":2,"split_debuginfo":null,"debug_assertions":true,"overflow_checks":true,"rpath":false,"incremental":false,"panic":"unwind","strip":{"deferred":"None"},"codegen_backend":null},"platform":null,"mode":"build","features":[],"dependencies":[]}],"roots":[0]}\n' "$workspace" "$workspace"
"#;
        let rustc_script = format!(
            "#!/bin/sh\nprintf started > '{}'\nexit 93\n",
            rustc_marker.display()
        );
        let wrapper_script = format!(
            "#!/bin/sh\nprintf started > '{}'\nexit 94\n",
            wrapper_marker.display()
        );
        let (requirement, _) = compiler_pack_fixture_with_scripts(
            &temp,
            cargo_script,
            &rustc_script,
            &wrapper_script,
        )?;
        let request = create_compiler_precise_unit_graph_request(&project, requirement)?;
        let outcome = execute_build_request(&request).await?;
        assert_eq!(
            outcome.audit.outcome,
            BuildOutcomeKind::Completed,
            "{:?}",
            outcome.audit
        );
        assert!(!outcome.project_code_executed);
        assert!(outcome.compiler_pack_attestation.is_some());
        let graph = outcome
            .rust_cargo_unit_graph
            .context("validated Cargo unit graph is missing")?;
        assert_eq!(graph.units.len(), 1);
        assert_eq!(graph.roots.len(), 1);
        assert!(!rustc_marker.exists());
        assert!(!wrapper_marker.exists());
        assert!(!build_script_marker.exists());
        Ok(())
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

    #[tokio::test]
    async fn child_output_and_disk_failures_are_reason_coded_and_leave_no_validated_delta()
    -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::write(
            root.path().join("failed.mjs"),
            "process.stderr.write('compiler panic fixture'); process.exit(71);\n",
        )?;
        let failed =
            supervise_build(root.path(), &node_plan(vec!["failed.mjs".to_owned()])).await?;
        assert_eq!(failed.audit.outcome, BuildOutcomeKind::Failed);
        assert_eq!(failed.audit.exit_code, Some(71));
        assert_eq!(
            failed.audit.diagnostic_code.as_deref(),
            Some("build-child-failed")
        );
        assert!(failed.audit.validated_output_digest.is_none());

        fs::write(
            root.path().join("noisy.mjs"),
            "process.stdout.write('x'.repeat(4096));\n",
        )?;
        let mut noisy_plan = node_plan(vec!["noisy.mjs".to_owned()]);
        noisy_plan.stdout_limit_bytes = 64;
        let noisy = supervise_build(root.path(), &noisy_plan).await?;
        assert_eq!(noisy.audit.outcome, BuildOutcomeKind::Failed);
        assert!(noisy.audit.stdout_truncated);
        assert_eq!(
            noisy.audit.diagnostic_code.as_deref(),
            Some("build-output-limit")
        );
        assert!(noisy.audit.validated_output_digest.is_none());

        #[cfg(unix)]
        {
            fs::write(root.path().join("signal.sh"), "kill -SEGV $$\n")?;
            let mut signal_plan = node_plan(vec!["signal.sh".to_owned()]);
            signal_plan.program = "bash".to_owned();
            let signalled = supervise_build(root.path(), &signal_plan).await?;
            assert_eq!(signalled.audit.outcome, BuildOutcomeKind::Failed);
            assert_eq!(signalled.audit.exit_code, None);
            assert_eq!(
                signalled.audit.diagnostic_code.as_deref(),
                Some("build-child-signalled")
            );
            assert!(signalled.audit.validated_output_digest.is_none());
        }

        fs::write(
            root.path().join("disk.mjs"),
            format!(
                "import fs from 'node:fs'; fs.closeSync(fs.openSync(process.env.DEPGRAPH_OUTPUT_DIR + '/oversized', 'w')); fs.truncateSync(process.env.DEPGRAPH_OUTPUT_DIR + '/oversized', {});\n",
                MAX_STAGED_BYTES + 1
            ),
        )?;
        let disk = supervise_build(root.path(), &node_plan(vec!["disk.mjs".to_owned()])).await?;
        assert_eq!(disk.audit.outcome, BuildOutcomeKind::SecurityFailed);
        assert_eq!(
            disk.audit.diagnostic_code.as_deref(),
            Some("build-output-security-policy")
        );
        assert!(disk.audit.validated_output_digest.is_none());
        Ok(())
    }

    #[test]
    fn compiler_child_failures_have_stage_and_signal_specific_reason_codes() {
        assert_eq!(
            child_failure_diagnostic(COMPILER_PRECISE_UNIT_GRAPH_ADAPTER, Some(1)),
            "rust-compiler-unit-graph-child-failed"
        );
        assert_eq!(
            child_failure_diagnostic(COMPILER_PRECISE_UNIT_GRAPH_ADAPTER, None),
            "rust-compiler-unit-graph-child-signalled"
        );
        assert_eq!(
            child_failure_diagnostic(COMPILER_PRECISE_INVOCATION_ADAPTER, Some(1)),
            "rust-compiler-invocation-child-failed"
        );
        assert_eq!(
            child_failure_diagnostic(COMPILER_PRECISE_INVOCATION_ADAPTER, None),
            "rust-compiler-invocation-child-signalled"
        );
        assert_eq!(
            child_failure_diagnostic("fixture", None),
            "build-child-signalled"
        );
    }

    #[test]
    fn compiler_precise_requests_never_fall_back_from_the_linux_namespace_boundary() {
        let expected = if cfg!(target_os = "linux") {
            BuildIsolation::EnforcedLinuxNamespace
        } else {
            BuildIsolation::BestEffort
        };
        assert_eq!(compiler_precise_isolation(), expected);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires the dedicated Linux bubblewrap hostile CI boundary"]
    async fn enforced_hostile_boundary_denies_parent_secret_network_and_private_paths() -> Result<()>
    {
        use std::net::TcpListener;

        let parent_secret = std::env::var("DEPGRAPH_HOSTILE_PARENT_SECRET")
            .context("hostile gate did not install its parent-only secret")?;
        let root = tempfile::tempdir()?;
        let project = root.path().join("project");
        fs::create_dir(&project)?;
        let private_file = root.path().join("parent-private-credential");
        let store_file = root.path().join("parent-store.db");
        let descendant_marker = root.path().join("DESCENDANT_SURVIVED");
        let descendant_token = format!("depgraph-hostile-descendant-{}", std::process::id());
        fs::write(&private_file, &parent_secret)?;
        fs::write(&store_file, &parent_secret)?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();

        fs::write(
            project.join("benign-hostile-boundary.sh"),
            format!(
                r#"set -eu
if [ "${{DEPGRAPH_HOSTILE_PARENT_SECRET+x}}" = x ]; then exit 81; fi
if [ -r "{private}" ]; then exit 82; fi
if [ -r "{store}" ]; then exit 83; fi
if timeout 1 bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}' 2>/dev/null; then exit 84; fi
printf yes > "$DEPGRAPH_OUTPUT_DIR/PROJECT_CODE_EXECUTED"
"#,
                private = private_file.display(),
                store = store_file.display(),
            ),
        )?;
        let mut benign = node_plan(vec!["benign-hostile-boundary.sh".to_owned()]);
        benign.program = "bash".to_owned();
        benign.isolation = BuildIsolation::EnforcedLinuxNamespace;
        let outcome = supervise_build(&project, &benign).await?;
        assert_eq!(outcome.audit.outcome, BuildOutcomeKind::Completed);
        assert_eq!(outcome.audit.network_isolation, NetworkIsolation::Enforced);
        assert!(outcome.project_code_executed);
        assert!(listener.accept().is_err());
        let audit = serde_json::to_string(&outcome.audit)?;
        assert!(!audit.contains(&parent_secret));
        assert!(!audit.contains(private_file.to_string_lossy().as_ref()));
        assert!(!audit.contains(store_file.to_string_lossy().as_ref()));

        fs::write(
            project.join("armed-descendant.sh"),
            format!(
                "bash -c 'sleep 30; printf unsafe > \"{}\"' '{}' &\nwait\n",
                descendant_marker.display(),
                descendant_token,
            ),
        )?;
        let mut armed = node_plan(vec!["armed-descendant.sh".to_owned()]);
        armed.program = "bash".to_owned();
        armed.isolation = BuildIsolation::EnforcedLinuxNamespace;
        armed.timeout_seconds = 1;
        let timed_out = supervise_build(&project, &armed).await?;
        assert_eq!(timed_out.audit.outcome, BuildOutcomeKind::TimedOut);
        assert_eq!(
            timed_out.audit.network_isolation,
            NetworkIsolation::Enforced
        );
        assert_eq!(
            timed_out.audit.diagnostic_code.as_deref(),
            Some("build-timeout")
        );
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(!descendant_marker.exists());
        let escaped_descendant = fs::read_dir("/proc")?.filter_map(Result::ok).any(|entry| {
            fs::read(entry.path().join("cmdline"))
                .map(|command_line| {
                    String::from_utf8_lossy(&command_line).contains(&descendant_token)
                })
                .unwrap_or(false)
        });
        assert!(!escaped_descendant);
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
            "DEPGRAPH_TANSTACK_ROUTER_VERSION".to_owned(),
            "1.170.18".to_owned(),
        );
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
