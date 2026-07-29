use std::{
    fs::OpenOptions,
    io::{Cursor, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use depgraph_core::{
    BoundedQueryExecutionError, BoundedQueryPlan, BoundedQueryResult, BuildOutcomeKind,
    CancellationToken, Config, CycleLevel, DaemonStatus, ExportFormat, GraphQueryFilter,
    ImpactFilters, ImpactResult, PolicyAnnotation, PolicyResult, QueryDiagnostic,
    QueryFailureClass, RepositoryProfilePlanPreview, ScanCacheMode, TypedProjection,
    acquire_store_writer_lock, build_cache_key, create_build_execution_request,
    create_compiler_precise_unit_graph_request, default_store_path, doctor, evaluate_policy_diff,
    execute_bounded_query, execute_build_request_with_cancellation, export_filtered,
    export_graphml_filtered_to_writer, impact, impact_query_cache_key, init_config,
    match_runtime_trace, open_store, open_store_read_only, parse_and_type_check_bounded_query,
    plan_bounded_query, plan_explicit_profile_selection, plan_repository_profiles,
    policy_annotations, profile_selection_human_summary, read_bounded_query_file,
    read_compiler_pack_requirement, read_explicit_profile_selection_file, read_git_changed_set,
    read_runtime_trace, render_condition, render_github_annotations, run_scan_with_cache_mode,
    runtime_session_delta, rust_build_protocol_ndjson, stage_build_evidence,
    start_repository_daemon, traverse_filtered, unresolved,
    validate_explicit_profile_selection_capabilities, web_build_protocol_ndjson, why_filtered,
};
use depgraph_protocol::canonical_json;
use depgraph_store::{CompletedSnapshotDetails, CoverageRecord};
use serde::Serialize;

mod snapshot_diff;

use snapshot_diff::{DiffCommandData, DiffFilters, render_human_diff};

#[derive(Debug, Parser)]
#[command(
    name = "depgraph",
    version,
    about = "Explainable semantic dependency graph scanner"
)]
struct Cli {
    #[arg(long, global = true, value_name = "PATH")]
    store: Option<PathBuf>,

    #[arg(long, global = true, value_name = "ID")]
    scan_id: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Create a versioned .depgraph.toml without scanning the project.
    Init {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Safely scan supported workspaces without executing project code.
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        json: bool,
        /// Bypass cache lookup and storage for this scan.
        #[arg(long)]
        no_cache: bool,
    },
    /// Preview the bounded default or explicit profile set without launching workers.
    Profiles {
        #[command(subcommand)]
        command: ProfileCommands,
    },
    /// Start, inspect, or stop the repository watcher daemon.
    Daemon {
        #[command(subcommand)]
        command: DaemonCommands,
    },
    /// Observe a project build only after explicit project-code consent.
    Resolve {
        /// Select build observation mode. No other resolve mode is available yet.
        #[arg(long, required = true)]
        build: bool,
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Acknowledge that untrusted project code may execute for this invocation.
        #[arg(long)]
        allow_project_code: bool,
        /// Request the exact pinned Rust compiler-precise unit-graph capability.
        #[arg(long)]
        rust_compiler_precise: bool,
        /// Read the release-bound compiler-pack requirement used for this invocation.
        #[arg(
            long,
            value_name = "FILE",
            required_if_eq("rust_compiler_precise", "true"),
            requires = "rust_compiler_precise"
        )]
        compiler_pack_requirement: Option<PathBuf>,
    },
    /// Report worker, toolchain, coverage, and protocol health.
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// List outgoing dependencies from a selector.
    Deps {
        selector: String,
        #[arg(long)]
        transitive: bool,
        #[arg(long, value_name = "PHASE")]
        phase: Vec<String>,
        #[arg(long, value_name = "PROFILE_ID")]
        profile: Vec<String>,
        #[arg(long, value_name = "SESSION_ID")]
        session: Vec<String>,
        #[arg(long, value_name = "ENVIRONMENT")]
        environment: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// List incoming dependencies to a selector.
    Dependents {
        selector: String,
        #[arg(long)]
        transitive: bool,
        #[arg(long, value_name = "PHASE")]
        phase: Vec<String>,
        #[arg(long, value_name = "PROFILE_ID")]
        profile: Vec<String>,
        #[arg(long, value_name = "SESSION_ID")]
        session: Vec<String>,
        #[arg(long, value_name = "ENVIRONMENT")]
        environment: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Explain a deterministic shortest dependency path.
    Why {
        from: String,
        to: String,
        #[arg(long, value_name = "PHASE")]
        phase: Vec<String>,
        #[arg(long, value_name = "PROFILE_ID")]
        profile: Vec<String>,
        #[arg(long, value_name = "SESSION_ID")]
        session: Vec<String>,
        #[arg(long, value_name = "ENVIRONMENT")]
        environment: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Show reverse dependency impact for a selector or Git changed set.
    Impact {
        selector: String,
        /// Read committed and dirty worktree changes since the merge-base with this Git ref.
        #[arg(long, value_name = "GIT_REF")]
        changed: Option<String>,
        /// Limit reverse traversal depth from the selected graph node.
        #[arg(long)]
        depth: Option<usize>,
        /// Traverse edges belonging to one of these exact profile IDs.
        #[arg(long, value_name = "PROFILE_ID")]
        profile: Vec<String>,
        /// Traverse edges whose rendered condition exactly matches one of these values.
        #[arg(long, value_name = "CONDITION")]
        condition: Vec<String>,
        /// Traverse edges in one of these graph phases, including `runtime`.
        #[arg(long, value_name = "PHASE")]
        phase: Vec<String>,
        /// Traverse runtime evidence from one of these imported session IDs.
        #[arg(long, value_name = "SESSION_ID")]
        session: Vec<String>,
        /// Traverse runtime evidence observed in this environment, runtime, or region.
        #[arg(long, value_name = "ENVIRONMENT")]
        environment: Vec<String>,
        /// Stop with an explicit incomplete diagnostic after this many unique nodes.
        #[arg(long, default_value_t = 10_000)]
        max_nodes: usize,
        /// Stop with an explicit incomplete diagnostic after this many unique edges.
        #[arg(long, default_value_t = 50_000)]
        max_edges: usize,
        #[arg(long)]
        json: bool,
    },
    /// Find representative cycles at a graph level.
    Cycles {
        #[arg(long, value_enum, default_value_t = CycleLevelArg::File)]
        level: CycleLevelArg,
        #[arg(long)]
        json: bool,
    },
    /// List unresolved dependency sites.
    Unresolved {
        #[arg(long)]
        json: bool,
    },
    /// Run one bounded read-only query against an immutable completed snapshot.
    Query {
        /// Supply the complete bounded query as one command-line value.
        #[arg(
            long,
            value_name = "QUERY",
            required_unless_present = "file",
            conflicts_with = "file"
        )]
        query: Option<String>,
        /// Read the bounded query from one confined UTF-8 regular file.
        #[arg(
            long,
            value_name = "FILE",
            required_unless_present = "query",
            conflicts_with = "query"
        )]
        file: Option<PathBuf>,
        /// Validate and print the deterministic plan without traversal.
        #[arg(long)]
        explain: bool,
        /// Emit the canonical versioned JSON contract.
        #[arg(long)]
        json: bool,
    },
    /// Validate and match an external runtime trace without changing the store.
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommands,
    },
    /// Name, list, or inspect immutable completed snapshots.
    Snapshot {
        #[command(subcommand)]
        command: SnapshotCommands,
    },
    /// Compare two immutable completed snapshots by name or stable ID.
    Diff {
        from: String,
        to: String,
        #[arg(long)]
        json: bool,
        /// Retain records with one of these node, site, edge, or rename kinds.
        #[arg(long, value_name = "KIND")]
        kind: Vec<String>,
        /// Retain records belonging to one of these exact profile IDs.
        #[arg(long, value_name = "PROFILE_ID")]
        profile: Vec<String>,
        /// Retain edges in one of these phases.
        #[arg(long, value_name = "PHASE")]
        phase: Vec<String>,
        /// Retain sites or edges with one of these resolution statuses.
        #[arg(long, value_name = "STATUS")]
        status: Vec<String>,
    },
    /// Evaluate architecture policy between two immutable completed snapshots.
    Policy {
        from: String,
        to: String,
        #[arg(long, conflicts_with = "github_annotations")]
        json: bool,
        /// Emit GitHub Actions workflow commands for active violations.
        #[arg(long, conflicts_with = "json")]
        github_annotations: bool,
    },
    /// Export the selected scan in a deterministic format.
    Export {
        #[arg(long, value_enum)]
        format: ExportFormatArg,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, value_name = "PHASE")]
        phase: Vec<String>,
        #[arg(long, value_name = "PROFILE_ID")]
        profile: Vec<String>,
        #[arg(long, value_name = "SESSION_ID")]
        session: Vec<String>,
        #[arg(long, value_name = "ENVIRONMENT")]
        environment: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum DaemonCommands {
    /// Run the watcher daemon in the foreground until stopped or interrupted.
    Start {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        json: bool,
    },
    /// Show the last status published by the repository daemon.
    Status {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Ask a foreground repository daemon to stop and wait for cleanup.
    Stop {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ProfileCommands {
    /// Explain the deterministic profile plan for a repository.
    Plan {
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Override the repository-size profile cap while retaining every baseline.
        #[arg(long, value_name = "N", conflicts_with = "profiles_file")]
        profile_budget: Option<u32>,
        /// Replace automatic selection with one strict, bounded versioned JSON file.
        #[arg(long, value_name = "FILE", conflicts_with = "profile_budget")]
        profiles_file: Option<PathBuf>,
        /// Emit the canonical versioned JSON plan and migration diagnostic.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum SnapshotCommands {
    /// Attach an immutable human-readable name to a completed snapshot.
    Create {
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// List named completed snapshots in canonical name order.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show a completed snapshot by name, stable ID, or `current`.
    Show {
        selector: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum RuntimeCommands {
    /// Validate a versioned trace and match its locators to the selected snapshot.
    Validate {
        trace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Atomically union a validated trace into a new immutable snapshot.
    Import {
        trace: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CycleLevelArg {
    Package,
    File,
    Symbol,
    Route,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ExportFormatArg {
    Json,
    Dot,
    Mermaid,
    Graphml,
}

#[derive(Serialize)]
struct CommandEnvelope<'a, T: Serialize> {
    schema_version: &'static str,
    command: &'static str,
    scan_id: String,
    data: &'a T,
}

#[derive(Serialize)]
struct SnapshotCommandEnvelope<'a, T: Serialize> {
    schema_version: &'static str,
    command: &'static str,
    data: &'a T,
}

#[derive(Serialize)]
struct SnapshotView {
    id: String,
    names: Vec<String>,
    status: String,
    source_kind: String,
    source_attempt_id: String,
    scan_id: String,
    build_attempt_id: Option<String>,
    runtime_import_id: Option<String>,
    runtime_session_ids: Vec<String>,
    parent_snapshot_id: Option<String>,
    source_revision: Option<String>,
    profile_ids: Vec<String>,
    created_at: String,
    coverage: CoverageRecord,
}

#[derive(Serialize)]
struct PolicyCommandData<'a> {
    from_snapshot_id: &'a str,
    to_snapshot_id: &'a str,
    result: &'a PolicyResult,
    annotations: &'a [PolicyAnnotation],
}

#[derive(Debug)]
struct QuerySnapshotUnavailable;

impl std::fmt::Display for QuerySnapshotUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "query_snapshot_unavailable: the selected scan has no immutable completed snapshot",
        )
    }
}

impl std::error::Error for QuerySnapshotUnavailable {}

impl From<CompletedSnapshotDetails> for SnapshotView {
    fn from(details: CompletedSnapshotDetails) -> Self {
        let snapshot = details.snapshot;
        Self {
            id: snapshot.id,
            names: details.names,
            status: snapshot.status,
            source_kind: snapshot.source_kind,
            source_attempt_id: snapshot.source_attempt_id,
            scan_id: snapshot.scan_id,
            build_attempt_id: snapshot.build_attempt_id,
            runtime_import_id: snapshot.runtime_import_id,
            runtime_session_ids: snapshot.runtime_session_ids,
            parent_snapshot_id: snapshot.parent_snapshot_id,
            source_revision: snapshot.source_revision,
            profile_ids: snapshot.profile_ids,
            created_at: snapshot.created_at,
            coverage: details.coverage,
        }
    }
}

#[derive(Serialize)]
struct SnapshotCreatedOutput {
    name: String,
    named_at: String,
    snapshot: SnapshotView,
}

#[derive(Serialize)]
struct SnapshotListItem {
    name: String,
    named_at: String,
    #[serde(flatten)]
    snapshot: SnapshotView,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    match run(Cli::parse()).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(error_exit_code(&error))
        }
    }
}

fn error_exit_code(error: &anyhow::Error) -> u8 {
    if let Some(diagnostic) = error.downcast_ref::<QueryDiagnostic>() {
        return if diagnostic.class == QueryFailureClass::Security {
            4
        } else {
            2
        };
    }
    if let Some(error) = error.downcast_ref::<BoundedQueryExecutionError>() {
        return if matches!(
            error.code,
            "query_execution_resource_exhausted"
                | "query_execution_deadline_exceeded"
                | "query_execution_cancelled"
                | "query_plan_not_admitted"
        ) {
            1
        } else {
            3
        };
    }
    let message = format!("{error:#}").to_ascii_lowercase();
    if message.contains("security policy")
        || message.contains("project code execution")
        || message.contains("unsafe explicit profiles file")
    {
        return 4;
    }
    if (message.contains("scan ") && message.contains(" was not found"))
        || (message.contains("completed snapshot") && message.contains(" was not found"))
        || (message.contains("diff ") && message.contains(" filter must"))
        || (message.contains("impact ")
            && (message.contains(" filter must") || message.contains("must be greater")))
        || message.contains("git ref")
        || [
            "selector",
            "snapshot name",
            "no current completed snapshot",
            "has no completed snapshot",
            ".depgraph.toml",
            "config schema_version",
            "does not exist",
            "is not a directory",
            "already exists; use --force",
            "scan id must not be empty",
            "no matching scan is available",
            "daemon status",
            "runtime trace",
            "profile-budget",
            "explicit profiles",
        ]
        .iter()
        .any(|needle| message.contains(needle))
    {
        return 2;
    }
    3
}

async fn run(cli: Cli) -> Result<u8> {
    match cli.command {
        Commands::Init { path, force } => {
            let root = canonical_directory(path)?;
            let path = init_config(&root, force)?;
            println!("initialized {}", path.display());
            Ok(0)
        }
        Commands::Scan {
            path,
            strict,
            json,
            no_cache,
        } => {
            let root = canonical_directory(path)?;
            let config = Config::load(&root)?;
            let store_path = store_path(cli.store, &root)?;
            let _store_writer_lock = acquire_store_writer_lock(&store_path)?;
            let mut store = open_store(&store_path)?;
            let outcome = run_scan_with_cache_mode(
                &mut store,
                root,
                &config,
                strict,
                if no_cache {
                    ScanCacheMode::Disabled
                } else {
                    ScanCacheMode::Enabled
                },
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&outcome)?);
            } else {
                println!("scan: {}", outcome.scan_id);
                println!("status: {}", outcome.status);
                println!(
                    "files: {}/{} analyzed ({} skipped)",
                    outcome.coverage.files_analyzed,
                    outcome.coverage.files_discovered,
                    outcome.coverage.files_skipped
                );
                println!(
                    "sites: {} resolved, {} candidates, {} external, {} unresolved",
                    outcome.coverage.resolved,
                    outcome.coverage.candidates,
                    outcome.coverage.external,
                    outcome.coverage.unresolved
                );
                for diagnostic in &outcome.diagnostics {
                    eprintln!(
                        "{} [{}] {}",
                        diagnostic.severity, diagnostic.code, diagnostic.message
                    );
                }
                if let Some(policy) = &outcome.policy {
                    println!(
                        "policy: {} errors, {} warnings, {} suppressed",
                        policy.summary.errors, policy.summary.warnings, policy.summary.suppressed
                    );
                    for violation in &policy.violations {
                        let state = violation
                            .suppression
                            .as_ref()
                            .map_or("active", |_| "suppressed");
                        println!(
                            "policy {} [{}] {}: {} -> {}",
                            violation.rule_id,
                            state,
                            violation.message,
                            violation.source.locator,
                            violation.target.locator
                        );
                    }
                }
                for event in &outcome.cache_events {
                    println!(
                        "cache {}: {} ({})",
                        event.layer.as_str(),
                        event.outcome,
                        event.reason
                    );
                }
                println!("store: {}", store_path.display());
            }
            Ok(outcome.exit_code)
        }
        Commands::Profiles { command } => match command {
            ProfileCommands::Plan {
                path,
                profile_budget,
                profiles_file,
                json,
            } => {
                let requested_root =
                    std::path::absolute(&path).context("profile planning root is unavailable")?;
                let root = canonical_directory(path)?;
                let config = Config::load(&root)?;
                let mut preview = plan_repository_profiles(&root, &config, profile_budget)?;
                if let Some(path) = profiles_file {
                    let explicit = read_explicit_profile_selection_file(&requested_root, &path)?;
                    validate_explicit_profile_selection_capabilities(&preview.plan, &explicit)?;
                    preview.plan = plan_explicit_profile_selection(preview.plan.input, explicit)?;
                }
                print_profile_plan(&preview, json)?;
                Ok(0)
            }
        },
        Commands::Daemon { command } => match command {
            DaemonCommands::Start { path, strict, json } => {
                let root = canonical_directory(path)?;
                let config = Config::load(&root)?;
                let store_path = store_path(cli.store, &root)?;
                let status_path = daemon_status_path(&store_path);
                let stop_path = daemon_stop_path(&store_path);
                let handle = start_repository_daemon(root, store_path, config, strict)?;
                // Only the process that acquired the daemon lock may clear a
                // stale stop request. A competing start must not consume a
                // request intended for the daemon that already owns the lock.
                remove_control_file(&stop_path)?;
                let mut status = handle.subscribe();
                write_daemon_status(&status_path, &handle.status())?;
                if !json {
                    println!("daemon: started");
                    println!("status: {}", status_path.display());
                }
                let mut stop_poll = tokio::time::interval(std::time::Duration::from_millis(100));
                loop {
                    tokio::select! {
                        signal = tokio::signal::ctrl_c() => {
                            signal.context("failed to listen for daemon shutdown")?;
                            break;
                        }
                        changed = status.changed() => {
                            if changed.is_err() {
                                break;
                            }
                            write_daemon_status(&status_path, &status.borrow().clone())?;
                        }
                        _ = stop_poll.tick() => {
                            if stop_path.try_exists()? {
                                break;
                            }
                        }
                    }
                }
                let stopped = handle.stop().await?;
                write_daemon_status(&status_path, &stopped)?;
                remove_control_file(&stop_path)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&stopped)?);
                } else {
                    println!("daemon: stopped");
                }
                Ok(0)
            }
            DaemonCommands::Status { path, json } => {
                let root = canonical_directory(path)?;
                let store_path = store_path(cli.store, &root)?;
                let status = read_daemon_status(&daemon_status_path(&store_path))?;
                print_daemon_status(&status, json)?;
                Ok(0)
            }
            DaemonCommands::Stop { path, json } => {
                let root = canonical_directory(path)?;
                let store_path = store_path(cli.store, &root)?;
                let status_path = daemon_status_path(&store_path);
                let mut status = read_daemon_status(&status_path)?;
                if status.phase != depgraph_core::DaemonPhase::Stopped {
                    if !daemon_lock_is_held(&store_path)? {
                        anyhow::bail!(
                            "daemon status at {} is stale because no daemon process owns the lifecycle lock",
                            status_path.display()
                        );
                    }
                    write_stop_request(&daemon_stop_path(&store_path))?;
                    status = wait_for_daemon_stop(&status_path, &store_path).await?;
                }
                print_daemon_status(&status, json)?;
                Ok(0)
            }
        },
        Commands::Resolve {
            build,
            path,
            allow_project_code,
            rust_compiler_precise,
            compiler_pack_requirement,
        } => {
            debug_assert!(build, "clap requires --build");
            if rust_compiler_precise {
                require_compiler_precise_consent(build, allow_project_code, rust_compiler_precise)?;
            } else {
                require_build_consent(allow_project_code)?;
            }
            let root = canonical_directory(path)?;
            let store_path = store_path(cli.store, &root)?;
            let compiler_precise_request = if rust_compiler_precise {
                let requirement_path = compiler_pack_requirement
                    .context("--rust-compiler-precise requires --compiler-pack-requirement")?;
                let requirement = read_compiler_pack_requirement(&requirement_path)?;
                Some(create_compiler_precise_unit_graph_request(
                    &root,
                    requirement,
                )?)
            } else {
                None
            };
            let _store_writer_lock = acquire_store_writer_lock(&store_path)?;
            let request = if let Some(request) = compiler_precise_request {
                request
            } else {
                create_build_execution_request(&root)?
            };
            let mut store = open_store(&store_path)?;
            let outcome = execute_build_request_with_cancellation(&request, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await?;
            store.save_build_audit(&serde_json::to_value(&outcome.audit)?)?;
            let mut evidence_status = "audit-only (no completed base scan)";
            let mut build_cache_status = "not stored";
            if let Some(base_scan_id) = store.latest_successful_id()? {
                evidence_status = "not promoted";
                store.start_build_attempt(&base_scan_id, &serde_json::to_value(&outcome.audit)?)?;
                match outcome.audit.outcome {
                    BuildOutcomeKind::Completed => {
                        if outcome.rust_cargo_unit_graph.is_some() {
                            store.finish_build_attempt(
                                &outcome.audit.run_id,
                                "completed",
                                None,
                                false,
                            )?;
                            evidence_status = "validated unit graph (not promoted)";
                        } else {
                            let snapshot = store.load_snapshot(&base_scan_id)?;
                            let ndjson = if let Some(observation) =
                                outcome.rust_observation.as_ref()
                            {
                                rust_build_protocol_ndjson(&snapshot, &outcome.audit, observation)
                                    .context("Rust build observation could not be correlated")
                            } else if let Some(observation) = outcome.web_observation.as_ref() {
                                web_build_protocol_ndjson(&snapshot, &outcome.audit, observation)
                                    .await
                                    .context("Web build observation could not be correlated")
                            } else {
                                Err(anyhow::anyhow!(
                                    "completed build produced no validated observation"
                                ))
                            };
                            let ndjson = match ndjson {
                                Ok(value) => value,
                                Err(error) => {
                                    store.finish_build_attempt(
                                        &outcome.audit.run_id,
                                        "security_failed",
                                        Some("build-observation-correlation-failed"),
                                        false,
                                    )?;
                                    anyhow::bail!(
                                        "security policy violation: build observation could not be correlated: {error:#}"
                                    );
                                }
                            };
                            if let Err(error) = stage_build_evidence(
                                &mut store,
                                &outcome.audit.run_id,
                                Cursor::new(ndjson),
                            ) {
                                store.finish_build_attempt(
                                    &outcome.audit.run_id,
                                    "security_failed",
                                    Some("build-evidence-rejected"),
                                    false,
                                )?;
                                anyhow::bail!(
                                    "security policy violation: build evidence was rejected: {error:#}"
                                );
                            }
                            store.finish_build_attempt(
                                &outcome.audit.run_id,
                                "completed",
                                None,
                                true,
                            )?;
                            evidence_status = "promoted";
                            if let Some(cache_key) = build_cache_key(&outcome.audit) {
                                let snapshot_id = store
                                    .snapshot_id_for_source("build", &outcome.audit.run_id)?
                                    .context(
                                        "promoted build did not expose its completed snapshot",
                                    )?;
                                let cache = store.store_snapshot_cache(
                                    &cache_key,
                                    &snapshot_id,
                                    None,
                                    Some(&outcome.audit.run_id),
                                )?;
                                build_cache_status = if cache.outcome == "stored" {
                                    "stored"
                                } else {
                                    "rejected"
                                };
                            }
                        }
                    }
                    BuildOutcomeKind::Failed => store.finish_build_attempt(
                        &outcome.audit.run_id,
                        "failed",
                        outcome.audit.diagnostic_code.as_deref(),
                        false,
                    )?,
                    BuildOutcomeKind::TimedOut => store.finish_build_attempt(
                        &outcome.audit.run_id,
                        "timed_out",
                        outcome.audit.diagnostic_code.as_deref(),
                        false,
                    )?,
                    BuildOutcomeKind::Cancelled => store.finish_build_attempt(
                        &outcome.audit.run_id,
                        "cancelled",
                        outcome.audit.diagnostic_code.as_deref(),
                        false,
                    )?,
                    BuildOutcomeKind::SecurityFailed => store.finish_build_attempt(
                        &outcome.audit.run_id,
                        "security_failed",
                        outcome.audit.diagnostic_code.as_deref(),
                        false,
                    )?,
                }
            }
            if let Some(unit_graph) = outcome.rust_cargo_unit_graph.as_ref() {
                if evidence_status == "audit-only (no completed base scan)" {
                    evidence_status = "validated unit graph (audit-only; no completed base scan)";
                }
                println!("Cargo units: {}", unit_graph.units.len());
                println!("Cargo unit graph digest: {}", unit_graph.digest);
            }
            println!("build run: {}", outcome.audit.run_id);
            println!("status: {:?}", outcome.audit.outcome);
            println!("project code executed: {}", outcome.project_code_executed);
            println!("build evidence: {evidence_status}");
            println!("build cache: {build_cache_status}");
            println!("network isolation: {:?}", outcome.audit.network_isolation);
            if let Some(diagnostic) = &outcome.audit.isolation_diagnostic {
                eprintln!("warning: {diagnostic}");
            }
            println!("store: {}", store_path.display());
            Ok(match outcome.audit.outcome {
                BuildOutcomeKind::Completed => 0,
                BuildOutcomeKind::SecurityFailed => 4,
                BuildOutcomeKind::Failed
                | BuildOutcomeKind::TimedOut
                | BuildOutcomeKind::Cancelled => 3,
            })
        }
        Commands::Doctor { json } => {
            let root = std::env::current_dir()?;
            let store_path = store_path(cli.store, &root)?;
            let store = open_store(&store_path)?;
            let report = doctor(&store).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("protocol: {}", report.protocol_version);
                println!("graph schema: {}", report.graph_schema_version);
                println!("store schema: {}", report.store_schema_version);
                println!("cache contract: {}", report.cache_contract_version);
                println!(
                    "cache entries: {} syntax, {} semantic, {} build",
                    report.cache_entries.syntax,
                    report.cache_entries.semantic,
                    report.cache_entries.build
                );
                println!(
                    "impact query cache: contract {}, {} entries",
                    report.impact_query_cache_contract_version, report.impact_query_cache_entries
                );
                if let Some(release) = &report.release {
                    println!(
                        "release: {} ({}, schema {}; core {}; schema {})",
                        release.version,
                        release.target,
                        release.schema_version,
                        release.core_integrity,
                        release.schema_integrity
                    );
                    for (artifact, integrity) in &release.runtime_integrity {
                        println!("runtime artifact {artifact}: {integrity}");
                    }
                    for (adapter, requirement) in &release.runtime_requirements {
                        println!("runtime requirement {adapter}: {requirement}");
                    }
                }
                for (toolchain, version) in report.toolchains {
                    let baseline = report
                        .supported_baselines
                        .get(&toolchain)
                        .map(String::as_str)
                        .unwrap_or("best-effort");
                    println!("toolchain {toolchain}: {version} (baseline {baseline})");
                }
                for worker in report.workers {
                    if worker.available {
                        println!(
                            "worker {}: available ({}, {}; {})",
                            worker.adapter,
                            worker.command.unwrap_or_default(),
                            worker
                                .version
                                .unwrap_or_else(|| "unknown version".to_owned()),
                            worker.integrity
                        );
                    } else {
                        println!(
                            "worker {}: unavailable ({})",
                            worker.adapter,
                            worker.error.unwrap_or_default()
                        );
                    }
                }
                if let Some(scan) = report.latest_attempt {
                    println!("latest attempt: {} ({})", scan.scan_id, scan.status);
                    println!(
                        "coverage: {} sites ({} resolved, {} candidates, {} external, {} unresolved), {} skipped, {} unsupported",
                        scan.coverage.dependency_sites,
                        scan.coverage.resolved,
                        scan.coverage.candidates,
                        scan.coverage.external,
                        scan.coverage.unresolved,
                        scan.coverage.files_skipped,
                        scan.coverage.unsupported_syntax
                    );
                    println!(
                        "profile matrix: {} effective profiles ({} matched, {} additional, {} conflicts, {} unobserved)",
                        scan.profile_matrix.entries.len(),
                        scan.profile_matrix
                            .difference_counts
                            .get("matched")
                            .copied()
                            .unwrap_or(0),
                        scan.profile_matrix
                            .difference_counts
                            .get("additional")
                            .copied()
                            .unwrap_or(0),
                        scan.profile_matrix
                            .difference_counts
                            .get("conflict")
                            .copied()
                            .unwrap_or(0),
                        scan.profile_matrix
                            .difference_counts
                            .get("unobserved")
                            .copied()
                            .unwrap_or(0),
                    );
                    for (phase, coverage) in &scan.profile_matrix.phase_coverage {
                        println!(
                            "phase {phase}: {} profiles, {} sites, {} edges, {} evidence ({} resolved, {} candidates, {} external, {} unresolved)",
                            coverage.profile_ids.len(),
                            coverage.sites,
                            coverage.edges,
                            coverage.evidence,
                            coverage.resolved,
                            coverage.candidates,
                            coverage.external,
                            coverage.unresolved,
                        );
                    }
                    for profile in scan.profiles {
                        let profile_coverage = profile
                            .coverage
                            .as_ref()
                            .map(|coverage| {
                                format!(
                                    "{} sites/{} skipped/{} unsupported",
                                    coverage.dependency_sites,
                                    coverage.files_skipped,
                                    coverage.unsupported_syntax
                                )
                            })
                            .unwrap_or_else(|| "unavailable".to_owned());
                        println!(
                            "profile {}: {} target={} features={} coverage={}",
                            profile.id,
                            profile.language,
                            profile.target.unwrap_or_else(|| "unspecified".to_owned()),
                            if profile.features.is_empty() {
                                "none".to_owned()
                            } else {
                                profile.features.join(",")
                            },
                            profile_coverage
                        );
                    }
                    for (package, version) in scan.detected_packages {
                        println!("package {package}: {version}");
                    }
                    for log in scan.adapter_logs.iter().filter(|log| log.truncated) {
                        println!("worker {} stderr: truncated", log.adapter);
                    }
                    for event in scan.cache_events {
                        println!(
                            "cache {}: {} ({})",
                            event.layer.as_str(),
                            event.outcome,
                            event.reason
                        );
                    }
                    println!("project code executed: {}", scan.project_code_executed);
                } else {
                    println!("latest attempt: none");
                }
                for event in report.recent_cache_events {
                    if event.layer == depgraph_store::CacheLayer::Build {
                        println!(
                            "recent cache {}: {} ({})",
                            event.layer.as_str(),
                            event.outcome,
                            event.reason
                        );
                    }
                }
            }
            Ok(0)
        }
        Commands::Deps {
            selector,
            transitive,
            phase,
            profile,
            session,
            environment,
            json,
        } => {
            let filter = GraphQueryFilter::new(phase, profile, session, environment)?;
            let (snapshot, scan_id) = load_snapshot(cli.store, cli.scan_id.as_deref(), false)?;
            let result = traverse_filtered(&snapshot, &selector, transitive, false, &filter)?;
            print_structured("deps", scan_id, &result, json)?;
            if !json {
                print_path_steps(&result.steps);
            }
            Ok(0)
        }
        Commands::Dependents {
            selector,
            transitive,
            phase,
            profile,
            session,
            environment,
            json,
        } => {
            let filter = GraphQueryFilter::new(phase, profile, session, environment)?;
            let (snapshot, scan_id) = load_snapshot(cli.store, cli.scan_id.as_deref(), false)?;
            let result = traverse_filtered(&snapshot, &selector, transitive, true, &filter)?;
            print_structured("dependents", scan_id, &result, json)?;
            if !json {
                print_path_steps(&result.steps);
            }
            Ok(0)
        }
        Commands::Why {
            from,
            to,
            phase,
            profile,
            session,
            environment,
            json,
        } => {
            let filter = GraphQueryFilter::new(phase, profile, session, environment)?;
            let (snapshot, scan_id) = load_snapshot(cli.store, cli.scan_id.as_deref(), false)?;
            let result = why_filtered(&snapshot, &from, &to, &filter)?;
            print_structured("why", scan_id, &result, json)?;
            if !json {
                if result.path_found {
                    println!("{}", result.from.locator);
                    print_why_steps(&result.steps);
                } else {
                    println!(
                        "no dependency path exists from {} to {}",
                        result.from.locator, result.to.locator
                    );
                }
            }
            Ok(0)
        }
        Commands::Impact {
            selector,
            changed,
            depth,
            profile,
            condition,
            phase,
            session,
            environment,
            max_nodes,
            max_edges,
            json,
        } => {
            let filters = ImpactFilters::new(depth, profile, condition, max_nodes, max_edges)?
                .with_runtime_filters(phase, session, environment)?;
            let root = std::env::current_dir()?;
            let store_path = store_path(cli.store, &root)?;
            let mut store = open_store(&store_path)?;
            let scan_id = store.resolve_scan_id(cli.scan_id.as_deref(), false)?;
            let snapshot_id = if changed.is_none() {
                store.snapshot_id_for_scan_selection(&scan_id)?
            } else {
                None
            };
            let cache_key = snapshot_id
                .as_deref()
                .map(|snapshot_id| impact_query_cache_key(snapshot_id, &selector, &filters));
            let cached = match (cache_key.as_deref(), snapshot_id.as_deref()) {
                (Some(cache_key), Some(snapshot_id)) => store
                    .lookup_impact_query_cache(cache_key, snapshot_id)
                    .ok()
                    .flatten()
                    .and_then(|payload| serde_json::from_str::<ImpactResult>(&payload).ok()),
                _ => None,
            };
            let result = if let Some(result) = cached {
                result
            } else {
                let snapshot = store.load_snapshot(&scan_id)?;
                let changed_set = changed
                    .as_deref()
                    .map(|git_ref| read_git_changed_set(Path::new(&snapshot.scan.root), git_ref))
                    .transpose()?;
                let result = impact(&snapshot, &selector, changed_set.as_ref(), filters)?;
                if let (Some(cache_key), Some(snapshot_id)) =
                    (cache_key.as_deref(), snapshot_id.as_deref())
                {
                    let payload = serde_json::to_string(&result)?;
                    // Cache population is best-effort: a successful impact
                    // query must remain usable if the bounded cache cannot be
                    // written, just as scan cache population failures do.
                    let _ = store.store_impact_query_cache(cache_key, snapshot_id, &payload);
                }
                result
            };
            print_structured("impact", scan_id, &result, json)?;
            if !json {
                print_human_impact(&result);
            }
            Ok(0)
        }
        Commands::Cycles { level, json } => {
            let (snapshot, scan_id) = load_snapshot(cli.store, cli.scan_id.as_deref(), false)?;
            let level = match level {
                CycleLevelArg::Package => CycleLevel::Package,
                CycleLevelArg::File => CycleLevel::File,
                CycleLevelArg::Symbol => CycleLevel::Symbol,
                CycleLevelArg::Route => CycleLevel::Route,
            };
            let result = depgraph_core::cycles(&snapshot, level);
            print_structured("cycles", scan_id, &result, json)?;
            if !json {
                if result.is_empty() {
                    println!("no cycles");
                }
                for cycle in result {
                    println!("{}", cycle.node_ids.join(" -> "));
                }
            }
            Ok(0)
        }
        Commands::Unresolved { json } => {
            let (snapshot, scan_id) = load_snapshot(cli.store, cli.scan_id.as_deref(), false)?;
            let result = unresolved(&snapshot);
            print_structured("unresolved", scan_id, &result, json)?;
            if !json {
                for unresolved in result {
                    let effective_profile = unresolved
                        .effective_profile_id
                        .as_deref()
                        .unwrap_or("unavailable");
                    let observed_status = unresolved
                        .correlation_status
                        .as_deref()
                        .unwrap_or("unavailable");
                    let difference_reasons = if unresolved.observed_difference_reasons.is_empty() {
                        "none".to_owned()
                    } else {
                        unresolved.observed_difference_reasons.join(",")
                    };
                    let site = unresolved.site;
                    let span = unresolved.evidence.first().map(|evidence| {
                        format!(
                            "{}:{}:{}-{}:{}",
                            evidence.path,
                            evidence.start_line,
                            evidence.start_column,
                            evidence.end_line,
                            evidence.end_column
                        )
                    });
                    println!(
                        "{} {} at {} profile={} effective_profile={} observed={} differences={} condition={} span={} ({})",
                        site.kind,
                        site.specifier.unwrap_or_default(),
                        site.source,
                        site.profile_id,
                        effective_profile,
                        observed_status,
                        difference_reasons,
                        render_condition(&site.condition),
                        span.unwrap_or_else(|| "unknown".to_owned()),
                        site.reason
                            .unwrap_or_else(|| "no reason provided".to_owned())
                    );
                }
            }
            Ok(0)
        }
        Commands::Query {
            query,
            file,
            explain,
            json,
        } => {
            let repository_root = canonical_directory(std::env::current_dir()?)?;
            let query = match (query, file) {
                (Some(query), None) => query,
                (None, Some(path)) => read_bounded_query_file(&repository_root, &path)?,
                _ => unreachable!("clap requires exactly one bounded query input"),
            };
            // Parse and type-check before store access so malformed, hostile,
            // and credential-shaped input cannot observe repository state.
            let typed = parse_and_type_check_bounded_query(&query)?;
            drop(query);

            let (snapshot, snapshot_id) =
                load_query_snapshot_read_only(cli.store, cli.scan_id.as_deref())?;
            let plan = plan_bounded_query(&typed, &snapshot_id, &snapshot)?;
            if explain {
                print_query_plan(&plan, json)?;
                return Ok(if plan.admitted { 0 } else { 1 });
            }
            if !plan.admitted {
                print_query_plan_rejection(&plan);
                return Ok(1);
            }
            let result =
                execute_bounded_query(&typed, &plan, &snapshot, &CancellationToken::new())?;
            print_query_result(&typed.ast.return_clause.projections, &result, json)?;
            Ok(0)
        }
        Commands::Runtime { command } => match command {
            RuntimeCommands::Validate { trace, json } => {
                let metadata = inspect_runtime_trace_input(&trace)?;
                if !metadata.file_type().is_file() {
                    anyhow::bail!("runtime trace input must be a regular file");
                }
                let input =
                    std::fs::File::open(&trace).context("failed to open runtime trace input")?;
                let trace = read_runtime_trace(input)?;
                let (snapshot, scan_id) =
                    load_snapshot_read_only(cli.store, cli.scan_id.as_deref(), false)?;
                let result = match_runtime_trace(trace, &snapshot)?;
                print_structured("runtime.validate", scan_id, &result, json)?;
                if !json {
                    println!("runtime trace: valid");
                    println!("schema: {}", result.schema_version);
                    println!("session: {}", result.session.id);
                    println!(
                        "profile: {}",
                        result
                            .profile_match
                            .parent_profile_id
                            .as_deref()
                            .unwrap_or("unresolved")
                    );
                    println!(
                        "events: {} ({} resolved, {} external, {} unresolved)",
                        result.summary.events,
                        result.summary.resolved_targets,
                        result.summary.external_targets,
                        result.summary.unresolved_targets
                    );
                    println!("redacted values: {}", result.summary.redacted_values);
                }
                Ok(0)
            }
            RuntimeCommands::Import { trace, json } => {
                let metadata = inspect_runtime_trace_input(&trace)?;
                if !metadata.file_type().is_file() {
                    anyhow::bail!("runtime trace input must be a regular file");
                }
                let input =
                    std::fs::File::open(&trace).context("failed to open runtime trace input")?;
                // Parse and bound untrusted input before acquiring the writer
                // lock or opening a mutable store.
                let trace = read_runtime_trace(input)?;
                let root = std::env::current_dir()?;
                let store_path = store_path(cli.store, &root)?;
                let _store_writer_lock = acquire_store_writer_lock(&store_path)?;
                let mut store = open_store(&store_path)?;
                let base_snapshot_id = if let Some(scan_id) = cli.scan_id.as_deref() {
                    store
                        .snapshot_id_for_scan_selection(scan_id)?
                        .with_context(|| {
                            format!("scan attempt {scan_id} has no completed snapshot")
                        })?
                } else {
                    store
                        .current_snapshot_id()?
                        .context("no current completed snapshot is available")?
                };
                let base = store
                    .completed_snapshot(&base_snapshot_id)?
                    .with_context(|| {
                        format!("completed snapshot {base_snapshot_id} was not found")
                    })?;
                let snapshot = store.load_completed_snapshot(&base_snapshot_id)?;
                let validated = match_runtime_trace(trace, &snapshot)?;
                let delta = runtime_session_delta(validated, &base_snapshot_id, &snapshot)?;
                let result = store.import_runtime_session(&base_snapshot_id, delta)?;
                print_structured("runtime.import", base.scan_id, &result, json)?;
                if !json {
                    println!("runtime session: {}", result.session_id);
                    println!("snapshot: {}", result.snapshot_id);
                    println!("status: {}", result.status);
                    println!("deduplicated: {}", result.deduplicated);
                }
                Ok(0)
            }
        },
        Commands::Snapshot { command } => {
            let root = std::env::current_dir()?;
            let store_path = store_path(cli.store, &root)?;
            let _store_writer_lock = matches!(&command, SnapshotCommands::Create { .. })
                .then(|| acquire_store_writer_lock(&store_path))
                .transpose()?;
            let mut store = open_store(&store_path)?;
            match command {
                SnapshotCommands::Create { name, json } => {
                    let snapshot_id = if let Some(scan_id) = cli.scan_id.as_deref() {
                        store
                            .snapshot_id_for_scan_selection(scan_id)?
                            .with_context(|| {
                                format!("scan attempt {scan_id} has no completed snapshot")
                            })?
                    } else {
                        store
                            .current_snapshot_id()?
                            .context("no current completed snapshot is available")?
                    };
                    let named = store.create_snapshot_name(&name, &snapshot_id)?;
                    let output = SnapshotCreatedOutput {
                        name: named.name,
                        named_at: named.named_at,
                        snapshot: store.completed_snapshot_details(&snapshot_id)?.into(),
                    };
                    if json {
                        print_snapshot_json("snapshot.create", &output)?;
                    } else {
                        println!("created snapshot name: {}", output.name);
                        println!("named at: {}", output.named_at);
                        print_snapshot_view(&output.snapshot);
                    }
                }
                SnapshotCommands::List { json } => {
                    let mut output = Vec::new();
                    for named in store.snapshot_names()? {
                        output.push(SnapshotListItem {
                            name: named.name,
                            named_at: named.named_at,
                            snapshot: store.completed_snapshot_details(&named.snapshot_id)?.into(),
                        });
                    }
                    if json {
                        print_snapshot_json("snapshot.list", &output)?;
                    } else if output.is_empty() {
                        println!("no named snapshots");
                    } else {
                        for item in &output {
                            println!(
                                "{} {} status={} revision={} profiles={} named_at={}",
                                item.name,
                                item.snapshot.id,
                                item.snapshot.status,
                                display_revision(item.snapshot.source_revision.as_deref()),
                                display_list(&item.snapshot.profile_ids),
                                item.named_at,
                            );
                            println!("    {}", coverage_summary(&item.snapshot.coverage));
                        }
                    }
                }
                SnapshotCommands::Show { selector, json } => {
                    let snapshot_id = store.resolve_completed_snapshot_selector(&selector)?;
                    let output: SnapshotView =
                        store.completed_snapshot_details(&snapshot_id)?.into();
                    if json {
                        print_snapshot_json("snapshot.show", &output)?;
                    } else {
                        print_snapshot_view(&output);
                    }
                }
            }
            Ok(0)
        }
        Commands::Diff {
            from,
            to,
            json,
            kind,
            profile,
            phase,
            status,
        } => {
            let filters = DiffFilters::new(kind, profile, phase, status)?;
            let root = std::env::current_dir()?;
            let store_path = store_path(cli.store, &root)?;
            let store = open_store(&store_path)?;
            let from_snapshot_id = store.resolve_completed_snapshot_selector(&from)?;
            let to_snapshot_id = store.resolve_completed_snapshot_selector(&to)?;
            let diff =
                filters.apply(store.diff_completed_snapshots(&from_snapshot_id, &to_snapshot_id)?);
            if json {
                let output = DiffCommandData::new(&diff, &filters);
                print_snapshot_json("diff", &output)?;
            } else if diff.is_empty() {
                print!("{}", render_human_diff(&diff, &filters, None, None));
            } else {
                let from_snapshot = store.load_completed_snapshot(&from_snapshot_id)?;
                let to_snapshot = store.load_completed_snapshot(&to_snapshot_id)?;
                print!(
                    "{}",
                    render_human_diff(&diff, &filters, Some(&from_snapshot), Some(&to_snapshot),)
                );
            }
            Ok(0)
        }
        Commands::Policy {
            from,
            to,
            json,
            github_annotations,
        } => {
            let root = canonical_directory(std::env::current_dir()?)?;
            let config = Config::load(&root)?;
            let store_path = store_path(cli.store, &root)?;
            let store = open_store(&store_path)?;
            let from_snapshot_id = store.resolve_completed_snapshot_selector(&from)?;
            let to_snapshot_id = store.resolve_completed_snapshot_selector(&to)?;
            let from_snapshot = store.load_completed_snapshot(&from_snapshot_id)?;
            let to_snapshot = store.load_completed_snapshot(&to_snapshot_id)?;
            let result = evaluate_policy_diff(
                &from_snapshot_id,
                &from_snapshot,
                &to_snapshot_id,
                &to_snapshot,
                &config.policy,
            )?;
            let annotations = policy_annotations(&result)?;
            if github_annotations {
                print!("{}", render_github_annotations(&annotations));
            } else if json {
                let output = PolicyCommandData {
                    from_snapshot_id: &from_snapshot_id,
                    to_snapshot_id: &to_snapshot_id,
                    result: &result,
                    annotations: &annotations,
                };
                print_snapshot_json("policy", &output)?;
            } else {
                println!(
                    "policy: {} API changes, {} errors, {} warnings, {} suppressed",
                    result.api_changes.len(),
                    result.summary.errors,
                    result.summary.warnings,
                    result.summary.suppressed
                );
                for change in &result.api_changes {
                    let entity = change
                        .after
                        .as_ref()
                        .or(change.before.as_ref())
                        .context("public API change has no entity")?;
                    println!(
                        "API {:?} [{}] {}",
                        change.kind,
                        if change.breaking {
                            "breaking"
                        } else {
                            "compatible"
                        },
                        entity.locator
                    );
                }
                for violation in &result.violations {
                    let state = violation
                        .suppression
                        .as_ref()
                        .map_or("active", |_| "suppressed");
                    println!(
                        "policy {} [{}] {}: {} -> {}",
                        violation.rule_id,
                        state,
                        violation.message,
                        violation.source.locator,
                        violation.target.locator
                    );
                }
            }
            Ok(result.exit_code)
        }
        Commands::Export {
            format,
            output,
            phase,
            profile,
            session,
            environment,
        } => {
            let (snapshot, _) = load_snapshot(cli.store, cli.scan_id.as_deref(), false)?;
            let filter = GraphQueryFilter::new(phase, profile, session, environment)?;
            let format = match format {
                ExportFormatArg::Json => ExportFormat::Json,
                ExportFormatArg::Dot => ExportFormat::Dot,
                ExportFormatArg::Mermaid => ExportFormat::Mermaid,
                ExportFormatArg::Graphml => ExportFormat::Graphml,
            };
            if format == ExportFormat::Graphml {
                if let Some(path) = output {
                    write_file_atomically(&path, |writer| {
                        let mut writer = writer;
                        export_graphml_filtered_to_writer(&snapshot, &filter, &mut writer)
                    })?;
                } else {
                    let stdout = std::io::stdout();
                    let mut writer = stdout.lock();
                    export_graphml_filtered_to_writer(&snapshot, &filter, &mut writer)?;
                    writer
                        .flush()
                        .context("failed to write GraphML to stdout")?;
                }
                return Ok(0);
            }
            let rendered = export_filtered(&snapshot, format, &filter)?;
            if let Some(path) = output {
                std::fs::write(&path, rendered)
                    .with_context(|| format!("failed to write {}", path.display()))?;
            } else {
                print!("{rendered}");
            }
            Ok(0)
        }
    }
}

fn write_file_atomically(
    path: &Path,
    write_contents: impl FnOnce(&mut dyn Write) -> Result<()>,
) -> Result<()> {
    let destination_permissions = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!(
                "refusing to atomically replace symlinked output {}",
                path.display()
            )
        }
        Ok(metadata) if !metadata.is_file() => {
            anyhow::bail!("output path is not a regular file: {}", path.display())
        }
        Ok(metadata) if metadata.permissions().readonly() => {
            anyhow::bail!("output file is read-only: {}", path.display())
        }
        Ok(metadata) => Some(metadata.permissions()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect output {}", path.display()));
        }
    };
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut builder = tempfile::Builder::new();
    builder.prefix(".depgraph-export-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o666));
    }
    let mut temporary = builder.tempfile_in(parent).with_context(|| {
        format!(
            "failed to create temporary output beside {}",
            path.display()
        )
    })?;
    if let Some(permissions) = destination_permissions {
        temporary
            .as_file()
            .set_permissions(permissions)
            .with_context(|| {
                format!(
                    "failed to preserve permissions for temporary output beside {}",
                    path.display()
                )
            })?;
    }
    {
        let mut writer = std::io::BufWriter::new(temporary.as_file_mut());
        write_contents(&mut writer)?;
        writer
            .flush()
            .with_context(|| format!("failed to write {}", path.display()))?;
    }
    temporary
        .persist(path)
        .map(|_| ())
        .map_err(|error| error.error)
        .with_context(|| format!("failed to replace {}", path.display()))
}

const BUILD_CONSENT_REQUIRED: &str = "project code execution permission denied: `resolve --build` may execute untrusted build tools, configuration, plugins, build scripts, and proc macros; rerun this invocation with `--allow-project-code` only after reviewing the target repository";
const COMPILER_PRECISE_CONSENT_REQUIRED: &str = "project code execution permission denied: Rust compiler-precise execution requires the independent `--build`, `--allow-project-code`, and `--rust-compiler-precise` flags on this invocation";

fn require_build_consent(allow_project_code: bool) -> Result<()> {
    if !allow_project_code {
        anyhow::bail!(BUILD_CONSENT_REQUIRED);
    }
    Ok(())
}

fn require_compiler_precise_consent(
    build: bool,
    allow_project_code: bool,
    rust_compiler_precise: bool,
) -> Result<()> {
    if !build || !allow_project_code || !rust_compiler_precise {
        anyhow::bail!(COMPILER_PRECISE_CONSENT_REQUIRED);
    }
    Ok(())
}

fn canonical_directory(path: PathBuf) -> Result<PathBuf> {
    let path = path
        .canonicalize()
        .with_context(|| format!("{} does not exist", path.display()))?;
    if !path.is_dir() {
        anyhow::bail!("{} is not a directory", path.display());
    }
    Ok(path)
}

fn store_path(explicit: Option<PathBuf>, root: &std::path::Path) -> Result<PathBuf> {
    explicit.map(Ok).unwrap_or_else(|| default_store_path(root))
}

fn daemon_status_path(store_path: &Path) -> PathBuf {
    with_path_suffix(store_path, ".daemon-status.json")
}

fn daemon_stop_path(store_path: &Path) -> PathBuf {
    with_path_suffix(store_path, ".daemon-stop")
}

fn daemon_lock_path(store_path: &Path) -> PathBuf {
    with_path_suffix(store_path, ".daemon-lock")
}

fn daemon_lock_is_held(store_path: &Path) -> Result<bool> {
    let path = daemon_lock_path(store_path);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect daemon lock {}", path.display()));
        }
    };
    if !metadata.file_type().is_file() {
        anyhow::bail!("daemon lock path {} is not a regular file", path.display());
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("failed to open daemon lock {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(false),
        Err(std::fs::TryLockError::WouldBlock) => Ok(true),
        Err(std::fs::TryLockError::Error(error)) => {
            Err(error).with_context(|| format!("failed to probe daemon lock {}", path.display()))
        }
    }
}

fn write_daemon_status(path: &Path, status: &DaemonStatus) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create daemon status directory {}",
            parent.display()
        )
    })?;
    let temporary = with_path_suffix(path, &format!(".tmp-{}", std::process::id()));
    remove_control_file(&temporary)?;
    let bytes = serde_json::to_vec_pretty(status)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .with_context(|| format!("failed to create daemon status {}", temporary.display()))?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    // Unix rename atomically replaces the prior status snapshot. Windows
    // requires the destination to be removed first, so readers retry across
    // that platform-specific publication gap.
    #[cfg(windows)]
    remove_control_file(path)?;
    std::fs::rename(&temporary, path).with_context(|| {
        format!(
            "failed to publish daemon status {} as {}",
            temporary.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn with_path_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn read_daemon_status(path: &Path) -> Result<DaemonStatus> {
    for attempt in 0..5 {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && attempt < 4 => {
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("daemon status was not found at {}", path.display()));
            }
        };
        if !metadata.file_type().is_file() {
            anyhow::bail!(
                "daemon status path {} is not a regular file",
                path.display()
            );
        }
        match std::fs::read(path) {
            Ok(raw) => {
                return serde_json::from_slice(&raw)
                    .with_context(|| format!("failed to parse daemon status {}", path.display()));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && attempt < 4 => {
                // The file may have been atomically replaced after metadata was
                // read, or removed briefly by Windows before a replacement.
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read daemon status {}", path.display()));
            }
        }
    }
    unreachable!("the final daemon status read attempt always returns")
}

fn write_stop_request(path: &Path) -> Result<()> {
    if path.try_exists()? {
        return Ok(());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create daemon stop request {}", path.display()))?;
    let requested_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis();
    writeln!(file, "{requested_at}")?;
    file.sync_all()?;
    Ok(())
}

fn remove_control_file(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.is_dir() {
                anyhow::bail!("daemon control path {} is a directory", path.display());
            }
            std::fs::remove_file(path).with_context(|| {
                format!("failed to remove daemon control file {}", path.display())
            })?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect daemon control file {}", path.display())
            });
        }
    }
    Ok(())
}

async fn wait_for_daemon_stop(path: &Path, store_path: &Path) -> Result<DaemonStatus> {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let mut unlocked_checks = 0_u8;
        loop {
            let status = read_daemon_status(path)?;
            if status.phase == depgraph_core::DaemonPhase::Stopped {
                return Ok(status);
            }
            if daemon_lock_is_held(store_path)? {
                unlocked_checks = 0;
            } else {
                unlocked_checks += 1;
                if unlocked_checks >= 10 {
                    anyhow::bail!(
                        "daemon status at {} became stale because the daemon process exited during cleanup",
                        path.display()
                    );
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .context("timed out waiting for daemon process cleanup")?
}

fn print_daemon_status(status: &DaemonStatus, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(status)?);
    } else {
        println!("daemon: {:?}", status.phase);
        println!("root: {}", status.root);
        println!("pending changes: {}", status.pending_change_count);
        if let Some(attempt) = &status.last_completed_attempt {
            println!("last completed: {}", attempt.attempt_id);
        }
        if let Some(attempt) = &status.last_failed_attempt {
            println!("last failed: {}", attempt.attempt_id);
        }
        if let Some(attempt) = &status.last_cancelled_attempt {
            println!("last cancelled: {}", attempt.attempt_id);
        }
        if let Some(error) = &status.last_watcher_error {
            println!("watcher error: {error}");
        }
    }
    Ok(())
}

fn load_snapshot(
    explicit_store: Option<PathBuf>,
    requested_scan_id: Option<&str>,
    latest_attempt: bool,
) -> Result<(depgraph_core::GraphSnapshot, String)> {
    let root = std::env::current_dir()?;
    let store_path = store_path(explicit_store, &root)?;
    let store = open_store(&store_path)?;
    let scan_id = store.resolve_scan_id(requested_scan_id, latest_attempt)?;
    let snapshot = store.load_snapshot(&scan_id)?;
    Ok((snapshot, scan_id))
}

fn load_snapshot_read_only(
    explicit_store: Option<PathBuf>,
    requested_scan_id: Option<&str>,
    latest_attempt: bool,
) -> Result<(depgraph_core::GraphSnapshot, String)> {
    let root = std::env::current_dir()?;
    let store_path = store_path(explicit_store, &root)?;
    let store = open_store_read_only(&store_path)?;
    let scan_id = store.resolve_scan_id(requested_scan_id, latest_attempt)?;
    let snapshot = store.load_snapshot(&scan_id)?;
    Ok((snapshot, scan_id))
}

fn load_query_snapshot_read_only(
    explicit_store: Option<PathBuf>,
    requested_scan_id: Option<&str>,
) -> Result<(depgraph_core::GraphSnapshot, String)> {
    let root = std::env::current_dir()?;
    let store_path = store_path(explicit_store, &root)?;
    let store = open_store_read_only(&store_path)?;
    let snapshot_id = if let Some(scan_id) = requested_scan_id {
        store
            .snapshot_id_for_scan_selection(scan_id)?
            .ok_or(QuerySnapshotUnavailable)?
    } else {
        store
            .current_snapshot_id()?
            .ok_or(QuerySnapshotUnavailable)?
    };
    let snapshot = store.load_completed_snapshot(&snapshot_id)?;
    Ok((snapshot, snapshot_id))
}

fn print_profile_plan(preview: &RepositoryProfilePlanPreview, json: bool) -> Result<()> {
    if json {
        println!("{}", canonical_json(&serde_json::to_value(preview)?));
        return Ok(());
    }
    let plan = &preview.plan;
    println!("{}", profile_selection_human_summary(plan)?);
    println!("contract: {}", plan.contract_version);
    println!(
        "mode: {}",
        canonical_json(&serde_json::to_value(plan.selection_mode)?)
    );
    println!("plan: {}", plan.plan_id);
    println!("input: {}", plan.input_digest);
    println!(
        "repository: {}",
        canonical_json(&serde_json::to_value(&plan.input.repository)?)
    );
    println!(
        "limits: {}",
        canonical_json(&serde_json::to_value(&plan.input.limits)?)
    );
    println!(
        "compatibility: {}",
        canonical_json(&serde_json::to_value(&plan.input.compatibility_ids)?)
    );
    println!(
        "host contexts: {}",
        canonical_json(&serde_json::to_value(&plan.input.host_contexts)?)
    );
    println!(
        "config migration: {}",
        canonical_json(&serde_json::to_value(&preview.config_migration)?)
    );
    for candidate in &plan.candidates {
        println!(
            "candidate {}: {}",
            candidate.profile_id,
            canonical_json(&serde_json::to_value(candidate)?)
        );
    }
    for selected in &plan.selected {
        println!(
            "selected {}: {}",
            selected.profile_id,
            canonical_json(&serde_json::to_value(selected)?)
        );
    }
    for omitted in &plan.omitted {
        println!(
            "omitted {}: {}",
            omitted.profile_id,
            canonical_json(&serde_json::to_value(omitted)?)
        );
    }
    for excluded in &plan.policy_excluded {
        println!(
            "excluded {}: {}",
            excluded.id,
            canonical_json(&serde_json::to_value(excluded)?)
        );
    }
    for discovery in &plan.discovery {
        println!(
            "discovery: {}",
            canonical_json(&serde_json::to_value(discovery)?)
        );
    }
    println!(
        "summary: {}",
        canonical_json(&serde_json::to_value(&plan.summary)?)
    );
    Ok(())
}

fn print_query_plan(plan: &BoundedQueryPlan, json: bool) -> Result<()> {
    if json {
        println!("{}", canonical_json(&serde_json::to_value(plan)?));
        return Ok(());
    }
    println!(
        "query explain: {}",
        if plan.admitted {
            "admitted"
        } else {
            "rejected"
        }
    );
    println!("schema: {}", plan.schema_version);
    println!("contract: {}", plan.contract_version);
    println!("limits: {}", plan.limit_version);
    println!("typed AST: {}", plan.typed_ast_digest);
    println!("snapshot: {}", plan.snapshot_id);
    println!("graph: {}", plan.graph_digest);
    println!("plan: {}", plan.plan_digest);
    println!(
        "redacted typed AST: {}",
        canonical_json(&plan.redacted_typed_ast_shape)
    );
    println!(
        "snapshot statistics: {}",
        canonical_json(&serde_json::to_value(&plan.snapshot_statistics)?)
    );
    for (index, operator) in plan.operators.iter().enumerate() {
        let operator_name = serde_json::to_value(operator.operator)?
            .as_str()
            .context("bounded query operator name is not a string")?
            .to_owned();
        println!(
            "operator {}: {} rows={} visits={} tests={} bytes={} cost={}",
            index + 1,
            operator_name,
            operator.worst_case_rows,
            operator.worst_case_visits,
            operator.worst_case_tests,
            operator.worst_case_serialized_bytes,
            operator.cost,
        );
    }
    println!(
        "cardinality: {}",
        canonical_json(&serde_json::to_value(&plan.cardinality_inputs)?)
    );
    println!(
        "bounds: {}",
        canonical_json(&serde_json::to_value(&plan.bounds)?)
    );
    println!(
        "hard limits: {}",
        canonical_json(&serde_json::to_value(plan.limits)?)
    );
    for reason in &plan.reasons {
        println!(
            "rejected [{}] {} observed={} limit={}; remediation={}",
            reason.code, reason.resource, reason.observed, reason.limit, reason.remediation
        );
    }
    Ok(())
}

fn print_query_plan_rejection(plan: &BoundedQueryPlan) {
    for reason in &plan.reasons {
        eprintln!(
            "error: {}: resource={}; observed={}; limit={}; remediation={}",
            reason.code, reason.resource, reason.observed, reason.limit, reason.remediation
        );
    }
}

fn print_query_result(
    projections: &[TypedProjection],
    result: &BoundedQueryResult,
    json: bool,
) -> Result<()> {
    if json {
        println!("{}", canonical_json(&serde_json::to_value(result)?));
        return Ok(());
    }
    println!("query: complete");
    println!("schema: {}", result.schema_version);
    println!("contract: {}", result.contract_version);
    println!("snapshot: {}", result.snapshot_id);
    println!("graph: {}", result.graph_digest);
    println!("plan: {}", result.plan_digest);
    println!("result: {}", result.result_digest);
    println!("rows: {}", result.rows.len());
    for (row_index, row) in result.rows.iter().enumerate() {
        println!("row {}:", row_index + 1);
        for (projection, value) in projections.iter().zip(row) {
            println!(
                "  {}: {}",
                query_projection_label(projection),
                canonical_json(value)
            );
        }
    }
    println!(
        "metrics: sources={} states={} edges={} sites={} evidence={} output_bytes={} memory_bytes={}",
        result.metrics.source_node_tests,
        result.metrics.traversal_states,
        result.metrics.edge_tests,
        result.metrics.site_tests,
        result.metrics.evidence_tests,
        result.metrics.serialized_output_bytes,
        result.metrics.working_memory_bytes,
    );
    Ok(())
}

fn query_projection_label(projection: &TypedProjection) -> String {
    match projection {
        TypedProjection::Binding(binding) => binding.name.clone(),
        TypedProjection::Field(field) => format!("{}.{}", field.binding, field.field),
    }
}

fn inspect_runtime_trace_input(path: &Path) -> Result<std::fs::Metadata> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata),
        Err(error) => Err(runtime_trace_metadata_error(error)),
    }
}

fn runtime_trace_metadata_error(error: std::io::Error) -> anyhow::Error {
    if error.kind() == std::io::ErrorKind::NotFound {
        anyhow::Error::new(error).context("runtime trace input was not found")
    } else {
        anyhow::Error::new(error).context("failed to inspect runtime trace input")
    }
}

fn print_structured<T: Serialize>(
    command: &'static str,
    scan_id: String,
    data: &T,
    json_output: bool,
) -> Result<()> {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&CommandEnvelope {
                schema_version: "1.0",
                command,
                scan_id,
                data,
            })?
        );
    }
    Ok(())
}

fn print_snapshot_json<T: Serialize>(command: &'static str, data: &T) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&SnapshotCommandEnvelope {
            schema_version: "1.0",
            command,
            data,
        })?
    );
    Ok(())
}

fn print_snapshot_view(snapshot: &SnapshotView) {
    println!("snapshot: {}", snapshot.id);
    println!("names: {}", display_list(&snapshot.names));
    println!("status: {}", snapshot.status);
    println!(
        "source: {} {}",
        snapshot.source_kind, snapshot.source_attempt_id
    );
    println!("scan: {}", snapshot.scan_id);
    if let Some(build_attempt_id) = &snapshot.build_attempt_id {
        println!("build attempt: {build_attempt_id}");
    }
    if let Some(runtime_import_id) = &snapshot.runtime_import_id {
        println!("runtime import: {runtime_import_id}");
    }
    if !snapshot.runtime_session_ids.is_empty() {
        println!(
            "runtime sessions: {}",
            display_list(&snapshot.runtime_session_ids)
        );
    }
    println!(
        "parent: {}",
        snapshot.parent_snapshot_id.as_deref().unwrap_or("none")
    );
    println!(
        "revision: {}",
        display_revision(snapshot.source_revision.as_deref())
    );
    println!("profiles: {}", display_list(&snapshot.profile_ids));
    println!("created at: {}", snapshot.created_at);
    println!("{}", coverage_summary(&snapshot.coverage));
}

fn display_revision(revision: Option<&str>) -> &str {
    revision.unwrap_or("unknown")
}

fn display_list(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        values.join(",")
    }
}

fn coverage_summary(coverage: &CoverageRecord) -> String {
    format!(
        "coverage: {}/{} files analyzed ({} skipped), {} sites ({} resolved, {} candidates, {} external, {} unresolved), {} unsupported; completeness={}; reasons={}; project_code_executed={}",
        coverage.files_analyzed,
        coverage.files_discovered,
        coverage.files_skipped,
        coverage.dependency_sites,
        coverage.resolved,
        coverage.candidates,
        coverage.external,
        coverage.unresolved,
        coverage.unsupported_syntax,
        display_list(&coverage.completeness),
        display_list(&coverage.reasons),
        coverage.project_code_executed,
    )
}

fn print_path_steps(steps: &[depgraph_core::query::PathStep]) {
    for step in steps {
        let edge = &step.edge;
        println!(
            "{} --{} [{}; {}; {}; {}]--> {}",
            edge.source,
            edge.kind,
            edge.phase,
            edge.resolution_status,
            edge.precision,
            edge.profile_id,
            edge.target
        );
        println!("    condition: {}", step.condition_text);
        print_profile_correlation(step, "    ");
        print_evidence(&step.evidence, "    ");
    }
}

fn print_why_steps(steps: &[depgraph_core::query::PathStep]) {
    for step in steps {
        println!(
            "  --{} [{}; {}; {}; {}]--> {}",
            step.edge.kind,
            step.edge.phase,
            step.edge.resolution_status,
            step.edge.precision,
            step.edge.profile_id,
            step.edge.target
        );
        println!("      condition: {}", step.condition_text);
        print_profile_correlation(step, "      ");
        print_evidence(&step.evidence, "      ");
    }
}

fn print_human_impact(result: &ImpactResult) {
    println!(
        "impact focus: {} ({}, id:{})",
        result.root.locator, result.root.kind, result.root.id
    );
    if let Some(changed_set) = &result.changed_set {
        println!(
            "git changed set: ref={} resolved={} merge_base={} head={} paths={} mapped_nodes={}",
            changed_set.requested_ref,
            changed_set.resolved_ref,
            changed_set.merge_base,
            changed_set.head,
            changed_set.changes.len(),
            result.changed_nodes.len()
        );
        for mapping in &result.mappings {
            let path = match (
                mapping.change.old_path.as_deref(),
                mapping.change.new_path.as_deref(),
            ) {
                (Some(old), Some(new)) => format!("{old} -> {new}"),
                (Some(old), None) => old.to_owned(),
                (None, Some(new)) => new.to_owned(),
                (None, None) => "unknown".to_owned(),
            };
            println!(
                "  {} {} sources={} old_nodes={} new_nodes={} correlated_nodes={}",
                mapping.change.status,
                path,
                display_list(&mapping.change.sources),
                display_list(&mapping.old_node_ids),
                display_list(&mapping.new_node_ids),
                display_list(&mapping.correlated_node_ids),
            );
        }
    } else {
        println!("change root: selected node");
    }
    println!(
        "result: impacted={} complete={} impacts={} depth={} profiles={} conditions={}",
        result.root_impacted,
        result.complete,
        result.impacts.len(),
        result
            .filters
            .depth
            .map(|depth| depth.to_string())
            .unwrap_or_else(|| "unbounded".to_owned()),
        display_list(&result.filters.profiles),
        display_list(&result.filters.conditions),
    );
    if !result.root_impacted {
        println!("selected node is not affected by the mapped changed set");
    }
    for impact in &result.impacts {
        println!(
            "{} ({}, id:{}) depth={} changed_node={}",
            impact.node.locator,
            impact.node.kind,
            impact.node.id,
            impact.depth,
            impact.changed_node_id,
        );
        print_why_steps(&impact.dependency_path);
    }
    for diagnostic in &result.diagnostics {
        println!("diagnostic [{}] {}", diagnostic.code, diagnostic.message);
    }
}

fn print_profile_correlation(step: &depgraph_core::query::PathStep, indent: &str) {
    if let (Some(effective_profile), Some(status)) = (
        step.effective_profile_id.as_deref(),
        step.correlation_status.as_deref(),
    ) {
        let differences = if step.observed_difference_reasons.is_empty() {
            "none".to_owned()
        } else {
            step.observed_difference_reasons.join(",")
        };
        println!(
            "{indent}effective profile {effective_profile}: observed={status}; differences={differences}"
        );
        for (phase, coverage) in &step.phase_coverage {
            println!(
                "{indent}phase {phase}: {} sites/{} edges/{} evidence",
                coverage.sites, coverage.edges, coverage.evidence
            );
        }
    }
}

fn print_evidence(evidence: &[depgraph_store::EvidenceRecord], indent: &str) {
    for evidence in evidence {
        println!(
            "{indent}evidence {} {}:{}:{}-{}:{} via {}@{}{}",
            evidence.kind,
            evidence.path,
            evidence.start_line,
            evidence.start_column,
            evidence.end_line,
            evidence.end_column,
            evidence.extractor,
            evidence.extractor_version,
            evidence
                .detail
                .as_deref()
                .map(|detail| format!(" ({detail})"))
                .unwrap_or_default()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        error_exit_code, inspect_runtime_trace_input, require_build_consent,
        require_compiler_precise_consent, runtime_trace_metadata_error, write_file_atomically,
    };

    #[test]
    fn classifies_cli_errors_without_hiding_internal_failures_as_usage() {
        assert_eq!(
            error_exit_code(&anyhow::anyhow!("selector is ambiguous")),
            2
        );
        assert_eq!(
            error_exit_code(&anyhow::anyhow!(
                "policy selector rule source must resolve to exactly one node"
            )),
            2
        );
        assert_eq!(
            error_exit_code(&anyhow::anyhow!("unsupported config schema_version 2")),
            2
        );
        assert_eq!(
            error_exit_code(&anyhow::anyhow!("diff kind filter must not be empty")),
            2
        );
        assert_eq!(
            error_exit_code(&anyhow::anyhow!(
                "impact max-nodes must be greater than zero"
            )),
            2
        );
        assert_eq!(error_exit_code(&anyhow::anyhow!("Git ref is invalid")), 2);
        assert_eq!(
            error_exit_code(&anyhow::anyhow!("security policy violation")),
            4
        );
        assert_eq!(
            error_exit_code(&anyhow::anyhow!("database disk image is malformed")),
            3
        );
        assert_eq!(error_exit_code(&anyhow::anyhow!("build child failed")), 3);
    }

    #[test]
    fn build_consent_is_an_explicit_per_invocation_gate() {
        let error = require_build_consent(false).unwrap_err();
        assert_eq!(error_exit_code(&error), 4);
        assert!(format!("{error:#}").contains("--allow-project-code"));
        require_build_consent(true).expect("the explicit CLI flag grants consent");
    }

    #[test]
    fn compiler_precise_consent_requires_all_three_invocation_flags() {
        for flags in [
            (false, false, false),
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            let error = require_compiler_precise_consent(flags.0, flags.1, flags.2).unwrap_err();
            assert_eq!(error_exit_code(&error), 4);
            let message = error.to_string();
            assert!(message.contains("--build"));
            assert!(message.contains("--allow-project-code"));
            assert!(message.contains("--rust-compiler-precise"));
        }
        require_compiler_precise_consent(true, true, true)
            .expect("all three explicit flags grant compiler-precise consent");
    }

    #[test]
    fn runtime_trace_metadata_distinguishes_missing_input() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.json");
        let error = inspect_runtime_trace_input(&missing).unwrap_err();
        assert!(error.to_string().contains("was not found"));

        let denied = runtime_trace_metadata_error(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "fixture denial",
        ));
        assert!(denied.to_string().contains("failed to inspect"));
        assert!(!denied.to_string().contains("was not found"));
    }

    #[test]
    fn atomic_output_replaces_only_after_the_writer_succeeds() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("graph.graphml");
        std::fs::write(&output, b"previous graph").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o640)).unwrap();
        }

        let error = write_file_atomically(&output, |writer| {
            writer.write_all(b"partial graph")?;
            anyhow::bail!("simulated GraphML failure")
        })
        .unwrap_err();
        assert!(error.to_string().contains("simulated GraphML failure"));
        assert_eq!(std::fs::read(&output).unwrap(), b"previous graph");

        write_file_atomically(&output, |writer| {
            writer.write_all(b"complete graph")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"complete graph");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o640
            );
        }
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
