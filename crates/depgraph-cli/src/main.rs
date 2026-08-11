use std::{
    io::{Cursor, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use depgraph_core::service::{
    BoundedQueryMode, BoundedQueryRequest, CompletedSnapshotView, CyclesRequest,
    DependenciesRequest, DependencyDirection, DepgraphCapability, DepgraphCapabilitySet,
    DepgraphService, DepgraphServiceConfig, DepgraphServiceError, DepgraphServiceLimits,
    DoctorRequest, ExplainPathRequest, ExportFileRequest, GraphExportFormat, GraphExportRequest,
    ImpactRequest, MAX_GRAPH_EXPORT_EDGES, MAX_GRAPH_EXPORT_NODES, PolicyEvaluateRequest,
    ProfilePlanRequest, RepositoryFileError, RepositoryInitRequest, RepositoryOverwritePolicy,
    RepositoryRelativePath, RuntimeValidateRequest, ScanRequest, ServiceSnapshotSelector,
    SnapshotDiffFilters, SnapshotDiffRequest, SnapshotLocator, SnapshotNameCreateRequest,
    SnapshotNameCreateSelector, SnapshotReadRequest, UnresolvedRequest,
};
use depgraph_core::{
    BoundedQueryExecutionError, BoundedQueryPlan, BoundedQueryResult, BuildAudit, BuildOutcomeKind,
    CancellationToken, CycleLevel, DEFAULT_INTERACTIVE_QUERY_MAX_BYTES,
    DEFAULT_INTERACTIVE_QUERY_MAX_ITEMS, DEFAULT_INTERACTIVE_QUERY_MAX_TRAVERSAL, DaemonStatus,
    ExportFormat, GraphQueryFilter, ImpactFilters, ImpactResult, InteractiveQueryPage,
    InteractiveQueryPageRequest, PolicyAnnotation, QueryDiagnostic, QueryFailureClass,
    RepositoryProfilePlanPreview, ScanCacheMode, TraversalPageItem, TypedProjection,
    UnresolvedResult, acquire_store_writer_lock, build_cache_key, compiler_precise_cache_hit_audit,
    compiler_precise_cache_key, compiler_precise_graph_ndjson, create_build_execution_request,
    create_compiler_precise_invocation_request, create_compiler_precise_unit_graph_request,
    default_store_path, execute_build_request_with_cancellation, export_filtered,
    export_graphml_filtered_to_writer, open_store, paginate_interactive_query,
    prepare_build_cache_input, prepare_compiler_precise_cache_input,
    profile_selection_human_summary, read_compiler_pack_requirement, render_condition,
    render_github_annotations, rust_build_protocol_ndjson, snapshot_profile_plan_id,
    stage_build_evidence, traversal_summary, unresolved_summary, validate_build_cache_input,
    validate_build_cache_source, validate_compiler_precise_cache_input,
    validate_compiler_precise_cached_evidence, validate_interactive_query_bounds,
    web_build_protocol_ndjson,
};
use depgraph_mcp_tools::{AgentDaemonStatus, AgentDoctor, AgentRuntimeOutcome, CliAction};
use depgraph_protocol::canonical_json;
use depgraph_store::CoverageRecord;
use serde::Serialize;

mod snapshot_diff;

use snapshot_diff::render_service_human_diff;

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

#[derive(Debug, Clone, Args)]
struct InteractiveOutputArgs {
    /// Return the explicit full result instead of the bounded page contract.
    #[arg(
        long,
        conflicts_with_all = ["max_items", "max_bytes", "cursor"]
    )]
    all: bool,
    /// Return at most this many canonical result items.
    #[arg(long, value_name = "N", conflicts_with = "all")]
    max_items: Option<usize>,
    /// Bound the canonical JSON document size in UTF-8 bytes.
    #[arg(long, value_name = "BYTES", conflicts_with = "all")]
    max_bytes: Option<usize>,
    /// Continue from a cursor returned for the same snapshot and query.
    #[arg(long, value_name = "TOKEN", conflicts_with = "all")]
    cursor: Option<String>,
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
        /// Verify this release-bound compiler-pack requirement for the current host.
        #[arg(long, value_name = "FILE")]
        compiler_pack_requirement: Option<PathBuf>,
        /// Diagnose worker launch policy for this repository root.
        #[arg(long, value_name = "PATH")]
        root: Option<PathBuf>,
        /// Emit the bounded health summary (the default).
        #[arg(long, conflicts_with = "details")]
        summary: bool,
        /// Emit the complete retained attempt payload.
        #[arg(long, conflicts_with = "summary")]
        details: bool,
    },
    /// List outgoing dependencies from a selector.
    Deps {
        selector: String,
        #[arg(long)]
        transitive: bool,
        /// Stop traversal after this many visited dependency edges.
        #[arg(long, value_name = "N", conflicts_with = "all")]
        max_traversal: Option<usize>,
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
        #[command(flatten)]
        output: InteractiveOutputArgs,
    },
    /// List incoming dependencies to a selector.
    Dependents {
        selector: String,
        #[arg(long)]
        transitive: bool,
        /// Stop traversal after this many visited dependency edges.
        #[arg(long, value_name = "N", conflicts_with = "all")]
        max_traversal: Option<usize>,
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
        #[command(flatten)]
        output: InteractiveOutputArgs,
    },
    /// Explain a deterministic shortest dependency path.
    Why {
        from: String,
        to: String,
        /// Stop path exploration after this many visited dependency edges.
        #[arg(long, value_name = "N")]
        max_traversal: Option<usize>,
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
        /// Bound cycle preprocessing and search work.
        #[arg(long, value_name = "N")]
        max_traversal: Option<usize>,
        #[arg(long)]
        json: bool,
    },
    /// List unresolved dependency sites.
    Unresolved {
        /// Include unresolved sites with one of these exact kinds.
        #[arg(long, value_name = "KIND")]
        kind: Vec<String>,
        /// Bound unresolved-site preprocessing and result construction work.
        #[arg(long, value_name = "N")]
        max_traversal: Option<usize>,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        output: InteractiveOutputArgs,
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
        /// Supply the complete runtime trace JSON as one command-line value.
        #[arg(
            long,
            value_name = "TRACE",
            required_unless_present = "file",
            conflicts_with = "file"
        )]
        trace: Option<String>,
        /// Read the runtime trace from one confined repository-relative regular file.
        #[arg(
            long,
            value_name = "FILE",
            required_unless_present = "trace",
            conflicts_with = "trace"
        )]
        file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Atomically union a validated trace into a new immutable snapshot.
    Import {
        /// Read the runtime trace from one confined repository-relative regular file.
        #[arg(
            value_name = "TRACE_FILE",
            required_unless_present = "trace",
            conflicts_with = "trace"
        )]
        trace_file: Option<PathBuf>,
        /// Supply the complete bounded runtime trace JSON inline.
        #[arg(
            long,
            value_name = "TRACE",
            required_unless_present = "trace_file",
            conflicts_with = "trace_file"
        )]
        trace: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

/// Compile-time coverage bridge from the real clap command tree to the MCP catalog.
///
/// The absence of wildcard arms is intentional: adding a CLI leaf command without assigning its
/// catalog action fails compilation. The catalog has a separate const assertion that every
/// `CliAction` is mapped by at least one tool.
#[allow(dead_code)]
fn catalog_action_for_command(command: &Commands) -> CliAction {
    match command {
        Commands::Init { .. } => CliAction::Init,
        Commands::Scan { .. } => CliAction::Scan,
        Commands::Profiles { command } => match command {
            ProfileCommands::Plan { .. } => CliAction::ProfilesPlan,
        },
        Commands::Daemon { command } => match command {
            DaemonCommands::Start { .. } => CliAction::DaemonStart,
            DaemonCommands::Status { .. } => CliAction::DaemonStatus,
            DaemonCommands::Stop { .. } => CliAction::DaemonStop,
        },
        Commands::Resolve { .. } => CliAction::ResolveBuild,
        Commands::Doctor { .. } => CliAction::Doctor,
        Commands::Deps { .. } => CliAction::Deps,
        Commands::Dependents { .. } => CliAction::Dependents,
        Commands::Why { .. } => CliAction::Why,
        Commands::Impact { .. } => CliAction::Impact,
        Commands::Cycles { .. } => CliAction::Cycles,
        Commands::Unresolved { .. } => CliAction::Unresolved,
        Commands::Query { .. } => CliAction::Query,
        Commands::Runtime { command } => match command {
            RuntimeCommands::Validate { .. } => CliAction::RuntimeValidate,
            RuntimeCommands::Import { .. } => CliAction::RuntimeImport,
        },
        Commands::Snapshot { command } => match command {
            SnapshotCommands::Create { .. } => CliAction::SnapshotCreate,
            SnapshotCommands::List { .. } => CliAction::SnapshotList,
            SnapshotCommands::Show { .. } => CliAction::SnapshotShow,
        },
        Commands::Diff { .. } => CliAction::Diff,
        Commands::Policy { .. } => CliAction::Policy,
        Commands::Export { .. } => CliAction::Export,
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CycleLevelArg {
    Package,
    File,
    Symbol,
    Type,
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

#[derive(Serialize)]
struct SnapshotCreatedOutput<'a> {
    name: &'a str,
    named_at: &'a str,
    snapshot: &'a CompletedSnapshotView,
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
    if let Some(service_error) = error.downcast_ref::<DepgraphServiceError>() {
        if matches!(service_error, DepgraphServiceError::QueryRejected) {
            return 1;
        }
        if matches!(
            service_error,
            DepgraphServiceError::BoundedQueryInput { diagnostic }
                if diagnostic.class == QueryFailureClass::Security
        ) {
            return 4;
        }
        if matches!(
            service_error,
            DepgraphServiceError::ProfilePlanSecurity { .. }
        ) {
            return 4;
        }
        if matches!(
            service_error.category(),
            depgraph_core::service::DepgraphServiceErrorCategory::Input
                | depgraph_core::service::DepgraphServiceErrorCategory::NotFound
        ) {
            return 2;
        }
    }
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
        || message.contains("interactive query")
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
            let store_path = store_path(cli.store, &root)?;
            let service = repository_write_service(&root, &store_path)?;
            let initialized = match service.repository_init(
                &RepositoryInitRequest::new(force),
                &CancellationToken::new(),
            ) {
                Ok(initialized) => initialized,
                Err(DepgraphServiceError::RepositoryFile {
                    reason: RepositoryFileError::AlreadyExists,
                }) => anyhow::bail!(".depgraph.toml already exists; use --force to overwrite"),
                Err(error) => return Err(error.into()),
            };
            println!(
                "initialized {}",
                root.join(initialized.output_path().as_str()).display()
            );
            Ok(0)
        }
        Commands::Scan {
            path,
            strict,
            json,
            no_cache,
        } => {
            let root = canonical_directory(path)?;
            let store_path = store_path(cli.store, &root)?;
            let service = store_write_service(&root, &store_path)?;
            let result = service
                .scan(&ScanRequest::new(
                    strict,
                    if no_cache {
                        ScanCacheMode::Disabled
                    } else {
                        ScanCacheMode::Enabled
                    },
                ))
                .await?;
            let outcome = result.outcome();
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
                let store_path = store_path(cli.store, &root)?;
                let service = snapshot_read_service(&root, &store_path)?;
                let profiles_file = profiles_file
                    .map(|path| normalize_cli_repository_file(&requested_root, &root, &path))
                    .transpose()?;
                let preview = service.profile_plan_cancellable(
                    &ProfilePlanRequest {
                        profile_budget,
                        profiles_document: None,
                        profiles_file,
                    },
                    &CancellationToken::new(),
                )?;
                print_profile_plan(&preview, json)?;
                Ok(0)
            }
        },
        Commands::Daemon { command } => match command {
            DaemonCommands::Start { path, strict, json } => {
                let root = canonical_directory(path)?;
                let store_path = store_path(cli.store, &root)?;
                let service = daemon_control_service(&root, &store_path)?;
                let cancellation = CancellationToken::new();
                let signal = tokio::spawn({
                    let cancellation = cancellation.clone();
                    async move {
                        if tokio::signal::ctrl_c().await.is_ok() {
                            cancellation.cancel();
                        }
                    }
                });
                let status_path = {
                    let mut path = service.config().store_path().as_os_str().to_os_string();
                    path.push(".daemon-status.json");
                    PathBuf::from(path)
                };
                let stopped = service
                    .daemon_start_foreground_with_running_cancellable(strict, &cancellation, || {
                        if !json {
                            println!("daemon: started");
                            println!("status: {}", status_path.display());
                        }
                    })
                    .await?;
                signal.abort();
                if json {
                    print_daemon_status(&stopped, true)?;
                } else {
                    println!("daemon: stopped");
                }
                Ok(0)
            }
            DaemonCommands::Status { path, json } => {
                let root = canonical_directory(path)?;
                let store_path = store_path(cli.store, &root)?;
                let service = snapshot_read_service(&root, &store_path)?;
                let status = service.daemon_status_cancellable(&CancellationToken::new())?;
                print_daemon_status(&status, json)?;
                Ok(0)
            }
            DaemonCommands::Stop { path, json } => {
                let root = canonical_directory(path)?;
                let store_path = store_path(cli.store, &root)?;
                let service = daemon_control_service(&root, &store_path)?;
                let status = match service
                    .daemon_stop_cancellable(&CancellationToken::new())
                    .await
                {
                    Ok(status) => status,
                    Err(DepgraphServiceError::Conflict) => {
                        let mut status_path = store_path.as_os_str().to_os_string();
                        status_path.push(".daemon-status.json");
                        anyhow::bail!(
                            "daemon status at {} is stale because no daemon process owns the lifecycle lock",
                            PathBuf::from(status_path).display()
                        );
                    }
                    Err(error) => return Err(error.into()),
                };
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
            let compiler_precise_requirement = if rust_compiler_precise {
                let requirement_path = compiler_pack_requirement
                    .context("--rust-compiler-precise requires --compiler-pack-requirement")?;
                Some(read_compiler_pack_requirement(&requirement_path)?)
            } else {
                None
            };
            let compiler_precise_request = if let Some(requirement) = &compiler_precise_requirement
            {
                Some(create_compiler_precise_unit_graph_request(
                    &root,
                    requirement.clone(),
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
            let base_scan_id = store.latest_successful_id()?;
            let mut cache_input = None;
            let mut cache_key = None;
            let mut compiler_cache_input = None;
            let mut compiler_cache_key = None;
            let mut cache_lookup_status = "unavailable".to_owned();
            let mut cache_lookup_reason = "no-completed-base-scan".to_owned();
            if rust_compiler_precise {
                if let Some(base_scan_id) = base_scan_id.as_deref()
                    && let Some(base_snapshot_id) =
                        store.snapshot_id_for_source("scan", base_scan_id)?
                {
                    let base = store.load_snapshot(&base_snapshot_id)?;
                    if let Some(profile_plan_id) = snapshot_profile_plan_id(&base)? {
                        match prepare_compiler_precise_cache_input(
                            &request,
                            &base_snapshot_id,
                            &profile_plan_id,
                        ) {
                            Ok(input) => {
                                let key = compiler_precise_cache_key(&input);
                                let lookup = store.lookup_compiler_precise_cache(&key)?;
                                cache_lookup_status = lookup.result.outcome.clone();
                                cache_lookup_reason = lookup.result.reason.clone();
                                if lookup.result.outcome == "hit" {
                                    let evidence = lookup
                                        .payload
                                        .as_ref()
                                        .and_then(|payload| payload.get("evidence"))
                                        .cloned()
                                        .and_then(|value| {
                                            serde_json::from_value::<
                                                depgraph_core::CompilerPreciseCachedEvidence,
                                            >(value)
                                            .ok()
                                        });
                                    let cached_audit = lookup.audit.as_ref().and_then(|audit| {
                                        serde_json::from_value::<BuildAudit>(audit.clone()).ok()
                                    });
                                    let confirmed = prepare_compiler_precise_cache_input(
                                        &request,
                                        &base_snapshot_id,
                                        &profile_plan_id,
                                    )
                                    .map(|confirmed| compiler_precise_cache_key(&confirmed));
                                    if confirmed.as_ref().ok() == Some(&key)
                                        && evidence.as_ref().is_some_and(|evidence| {
                                            validate_compiler_precise_cached_evidence(
                                                evidence, &input, &key,
                                            )
                                            .is_ok()
                                        })
                                        && cached_audit.as_ref().is_some_and(|audit| {
                                            matches!(audit.outcome, BuildOutcomeKind::Completed)
                                                && audit.source_root_digest
                                                    == input.source_root_digest
                                                && audit.validated_output_digest.as_deref()
                                                    == evidence.as_ref().map(|evidence| {
                                                        evidence.validated_output_digest.as_str()
                                                    })
                                        })
                                    {
                                        let audit = compiler_precise_cache_hit_audit(
                                            cached_audit.as_ref().context(
                                                "validated compiler cache audit is missing",
                                            )?,
                                        );
                                        let audit_value = serde_json::to_value(&audit)?;
                                        let published = store
                                            .promote_validated_compiler_precise_cache_hit_with_precommit(
                                                &lookup,
                                                base_scan_id,
                                                &audit_value,
                                                || {
                                                    validate_compiler_precise_cache_input(
                                                        &input,
                                                        &request,
                                                        &profile_plan_id,
                                                    )
                                                },
                                            )
                                            .is_ok();
                                        if published {
                                            let evidence = evidence.context(
                                                "validated compiler cache evidence is missing",
                                            )?;
                                            println!(
                                                "Rust compiler invocations: {}",
                                                evidence.invocation_ledger.entries.len()
                                            );
                                            println!(
                                                "Rust compiler invocation ledger digest: {}",
                                                evidence.invocation_ledger.digest
                                            );
                                            let body_count = evidence
                                                .mir_ledger
                                                .entries
                                                .iter()
                                                .map(|entry| entry.bodies.len())
                                                .sum::<usize>();
                                            println!("Rust typed MIR bodies: {body_count}");
                                            println!(
                                                "Rust typed MIR ledger digest: {}",
                                                evidence.mir_ledger.digest
                                            );
                                            println!(
                                                "Cargo units: {}",
                                                evidence.unit_graph.units.len()
                                            );
                                            println!(
                                                "Cargo unit graph digest: {}",
                                                evidence.unit_graph.digest
                                            );
                                            println!("build run: {}", audit.run_id);
                                            println!("status: {:?}", audit.outcome);
                                            println!("project code executed: false");
                                            println!(
                                                "build evidence: reused compiler-precise graph"
                                            );
                                            println!("build cache lookup: hit (validated)");
                                            println!("build cache: hit");
                                            println!(
                                                "network isolation: {:?}",
                                                audit.network_isolation
                                            );
                                            if let Some(diagnostic) = &audit.isolation_diagnostic {
                                                eprintln!("warning: {diagnostic}");
                                            }
                                            println!("store: {}", store_path.display());
                                            return Ok(0);
                                        }
                                    }
                                    cache_lookup_status = "reject".to_owned();
                                    cache_lookup_reason = "corrupt".to_owned();
                                }
                                compiler_cache_input = Some(input);
                                compiler_cache_key = Some(key);
                            }
                            Err(_) => {
                                cache_lookup_status = "reject".to_owned();
                                cache_lookup_reason = "unsafe-input".to_owned();
                            }
                        }
                    } else {
                        cache_lookup_status = "reject".to_owned();
                        cache_lookup_reason = "unsafe-input".to_owned();
                    }
                }
            } else if let Some(base_scan_id) = base_scan_id.as_deref()
                && let Some(base_snapshot_id) = store.build_cache_base_snapshot_id(base_scan_id)?
                && let Some(input) = prepare_build_cache_input(&request, &base_snapshot_id).await?
            {
                let key = build_cache_key(&input);
                let lookup = store.lookup_build_cache(&key)?;
                cache_lookup_status = lookup.result.outcome.clone();
                cache_lookup_reason = lookup.result.reason.clone();
                if lookup.result.outcome == "hit" {
                    let confirmed = prepare_build_cache_input(&request, &base_snapshot_id)
                        .await?
                        .map(|input| build_cache_key(&input));
                    let cached_audit = lookup
                        .audit
                        .as_ref()
                        .and_then(|audit| serde_json::from_value::<BuildAudit>(audit.clone()).ok());
                    if confirmed.as_ref() == Some(&key)
                        && cached_audit.as_ref().is_some_and(|audit| {
                            matches!(audit.outcome, BuildOutcomeKind::Completed)
                                && validate_build_cache_input(&input, audit)
                        })
                    {
                        let published = store
                            .publish_validated_build_cache_hit_with_precommit(&lookup, || {
                                validate_build_cache_source(&input, &root)
                            })
                            .is_ok();
                        if published {
                            let audit =
                                cached_audit.context("validated build cache audit is missing")?;
                            println!("build run: {}", audit.run_id);
                            println!("status: {:?}", audit.outcome);
                            println!("project code executed: false");
                            println!("build evidence: reused");
                            println!("build cache lookup: hit (validated)");
                            println!("build cache: hit");
                            println!("network isolation: {:?}", audit.network_isolation);
                            if let Some(diagnostic) = &audit.isolation_diagnostic {
                                eprintln!("warning: {diagnostic}");
                            }
                            println!("store: {}", store_path.display());
                            return Ok(0);
                        }
                    }
                    cache_lookup_status = "reject".to_owned();
                    cache_lookup_reason = "input-changed-before-publication".to_owned();
                }
                cache_input = Some(input);
                cache_key = Some(key);
            }
            let cancellation = CancellationToken::new();
            let signal_token = cancellation.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                signal_token.cancel();
            });
            let mut outcome =
                execute_build_request_with_cancellation(&request, cancellation.cancelled()).await?;
            if rust_compiler_precise && matches!(outcome.audit.outcome, BuildOutcomeKind::Completed)
            {
                let unit_graph = outcome
                    .rust_cargo_unit_graph
                    .clone()
                    .context("compiler-precise unit graph stage produced no validated graph")?;
                let invocation_request = create_compiler_precise_invocation_request(
                    &root,
                    compiler_precise_requirement
                        .context("compiler-precise pack requirement is unavailable")?,
                    unit_graph,
                    outcome.audit.source_root_digest.clone(),
                )?;
                outcome = execute_build_request_with_cancellation(
                    &invocation_request,
                    cancellation.cancelled(),
                )
                .await?;
            }
            let audit_value = serde_json::to_value(&outcome.audit)?;
            store.save_build_audit(&audit_value)?;
            let mut evidence_status = "audit-only (no completed base scan)";
            let mut build_cache_status = "not stored";
            if let Some(base_scan_id) = base_scan_id {
                evidence_status = "not promoted";
                let build_attempt_required = requires_build_attempt(
                    &outcome.audit.outcome,
                    outcome.rust_compiler_mir_ledger.is_some(),
                    outcome.rust_compiler_invocation_ledger.is_some(),
                    outcome.rust_cargo_unit_graph.is_some(),
                );
                if build_attempt_required {
                    if let Some(input) = compiler_cache_input.as_ref() {
                        store.start_build_attempt_at_base_snapshot(
                            &base_scan_id,
                            &input.base_snapshot_id,
                            &audit_value,
                        )?;
                    } else {
                        store.start_build_attempt(&base_scan_id, &audit_value)?;
                    }
                    if cache_input.is_some()
                        && matches!(cache_lookup_status.as_str(), "miss" | "reject")
                    {
                        store.record_cache_event(
                            None,
                            Some(&outcome.audit.run_id),
                            depgraph_store::CacheLayer::Build,
                            cache_key.as_ref().map(|key| key.key.as_str()),
                            &cache_lookup_status,
                            &cache_lookup_reason,
                        )?;
                    }
                    if rust_compiler_precise
                        && matches!(cache_lookup_status.as_str(), "miss" | "reject")
                    {
                        store.record_cache_event(
                            None,
                            Some(&outcome.audit.run_id),
                            depgraph_store::CacheLayer::CompilerPrecise,
                            compiler_cache_key.as_ref().map(|key| key.key.as_str()),
                            &cache_lookup_status,
                            &cache_lookup_reason,
                        )?;
                    }
                    if let Some(input) = cache_input.as_mut() {
                        let attempt_base_snapshot_id = store
                            .build_attempt(&outcome.audit.run_id)?
                            .and_then(|attempt| attempt.base_snapshot_id)
                            .context("build attempt has no completed base snapshot")?;
                        if input.base_snapshot_id != attempt_base_snapshot_id {
                            input.base_snapshot_id = attempt_base_snapshot_id;
                            cache_key = Some(build_cache_key(input));
                        }
                    }
                }
                match outcome.audit.outcome {
                    BuildOutcomeKind::Completed => {
                        if let Some(mir) = outcome.rust_compiler_mir_ledger.as_ref() {
                            let snapshot = if let Some(input) = compiler_cache_input.as_ref() {
                                store.load_snapshot(&input.base_snapshot_id)?
                            } else {
                                store.load_snapshot(&base_scan_id)?
                            };
                            let ndjson = outcome
                                .compiler_pack_attestation
                                .as_ref()
                                .context(
                                    "completed compiler-precise attempt has no pack attestation",
                                )
                                .and_then(|pack| {
                                    compiler_precise_graph_ndjson(
                                        &snapshot,
                                        &outcome.audit,
                                        pack,
                                        outcome.rust_cargo_unit_graph.as_ref().context(
                                            "completed compiler-precise attempt has no unit graph",
                                        )?,
                                        outcome
                                            .rust_compiler_invocation_ledger
                                            .as_ref()
                                            .context(
                                                "completed compiler-precise attempt has no invocation ledger",
                                            )?,
                                        mir,
                                    )
                                });
                            let ndjson = match ndjson {
                                Ok(value) => value,
                                Err(error) => {
                                    store.finish_build_attempt(
                                        &outcome.audit.run_id,
                                        "security_failed",
                                        Some("compiler-precise-graph-correlation-failed"),
                                        false,
                                    )?;
                                    anyhow::bail!(
                                        "security policy violation: compiler-precise graph could not be correlated: {error:#}"
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
                                    Some("compiler-precise-evidence-rejected"),
                                    false,
                                )?;
                                anyhow::bail!(
                                    "security policy violation: compiler-precise evidence was rejected: {error:#}"
                                );
                            }
                            store.finish_build_attempt(
                                &outcome.audit.run_id,
                                "completed",
                                None,
                                true,
                            )?;
                            evidence_status = "promoted compiler-precise graph";
                            if let (Some(input), Some(key)) =
                                (compiler_cache_input.as_ref(), compiler_cache_key.as_ref())
                            {
                                let pack = outcome.compiler_pack_attestation.as_ref().context(
                                    "completed compiler-precise cache result has no pack",
                                )?;
                                let unit_graph = outcome
                                    .rust_cargo_unit_graph
                                    .as_ref()
                                    .context("completed compiler cache result has no unit graph")?;
                                let invocations =
                                    outcome.rust_compiler_invocation_ledger.as_ref().context(
                                        "completed compiler cache result has no invocation ledger",
                                    )?;
                                let validated_output_digest =
                                    outcome.audit.validated_output_digest.as_deref().context(
                                        "completed compiler cache result has no output digest",
                                    )?;
                                let cache_evidence = depgraph_core::CompilerPreciseCachedEvidence {
                                    schema_version:
                                        depgraph_core::COMPILER_PRECISE_CACHE_ENTRY_SCHEMA_VERSION
                                            .to_owned(),
                                    cache_contract_version:
                                        depgraph_core::COMPILER_PRECISE_CACHE_CONTRACT_VERSION
                                            .to_owned(),
                                    effective_input_identity: key.key.clone(),
                                    base_snapshot_id: input.base_snapshot_id.clone(),
                                    compiler_pack_attestation: pack.clone(),
                                    unit_graph: unit_graph.clone(),
                                    invocation_ledger: invocations.clone(),
                                    mir_ledger: mir.clone(),
                                    validated_output_digest: validated_output_digest.to_owned(),
                                };
                                let admitted = outcome.audit.source_root_digest
                                    == input.source_root_digest
                                    && pack == &input.compiler_pack_attestation
                                    && validate_compiler_precise_cached_evidence(
                                        &cache_evidence,
                                        input,
                                        key,
                                    )
                                    .is_ok()
                                    && validate_compiler_precise_cache_input(
                                        input,
                                        &request,
                                        &input.profile_selection_plan_id,
                                    )
                                    .is_ok();
                                if admitted {
                                    match store.store_compiler_precise_cache(
                                        key,
                                        &outcome.audit.run_id,
                                        &serde_json::to_value(&cache_evidence)?,
                                    ) {
                                        Ok(cache) if cache.outcome == "stored" => {
                                            build_cache_status = "stored";
                                        }
                                        Ok(_) => build_cache_status = "not stored",
                                        Err(error) => {
                                            eprintln!(
                                                "warning: compiler-precise cache was not stored: {error:#}"
                                            );
                                            build_cache_status = "not stored";
                                        }
                                    }
                                } else {
                                    store.record_cache_event(
                                        None,
                                        Some(&outcome.audit.run_id),
                                        depgraph_store::CacheLayer::CompilerPrecise,
                                        Some(&key.key),
                                        "reject",
                                        "input-changed",
                                    )?;
                                    build_cache_status = "not stored";
                                }
                            }
                        } else if outcome.rust_compiler_invocation_ledger.is_some() {
                            evidence_status = "validated compiler invocation ledger (not promoted)";
                        } else if outcome.rust_cargo_unit_graph.is_some() {
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
                            if let (Some(cache_input), Some(cache_key)) =
                                (cache_input.as_ref(), cache_key.as_ref())
                            {
                                if !validate_build_cache_input(cache_input, &outcome.audit) {
                                    store.record_cache_event(
                                        None,
                                        Some(&outcome.audit.run_id),
                                        depgraph_store::CacheLayer::Build,
                                        Some(&cache_key.key),
                                        "reject",
                                        "input-changed-during-build",
                                    )?;
                                    build_cache_status = "rejected";
                                } else {
                                    let snapshot_id = store
                                        .snapshot_id_for_source("build", &outcome.audit.run_id)?
                                        .context(
                                            "promoted build did not expose its completed snapshot",
                                        )?;
                                    let cache = store.store_snapshot_cache(
                                        cache_key,
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
            if let Some(ledger) = outcome.rust_compiler_invocation_ledger.as_ref() {
                if evidence_status == "audit-only (no completed base scan)" {
                    evidence_status =
                        "validated compiler invocation ledger (audit-only; no completed base scan)";
                }
                println!("Rust compiler invocations: {}", ledger.entries.len());
                println!("Rust compiler invocation ledger digest: {}", ledger.digest);
            }
            if let Some(ledger) = outcome.rust_compiler_mir_ledger.as_ref() {
                if evidence_status == "audit-only (no completed base scan)" {
                    evidence_status =
                        "validated typed MIR DTO (audit-only; no completed base scan)";
                }
                let body_count = ledger
                    .entries
                    .iter()
                    .map(|entry| entry.bodies.len())
                    .sum::<usize>();
                println!("Rust typed MIR bodies: {body_count}");
                println!("Rust typed MIR ledger digest: {}", ledger.digest);
            }
            if let Some(unit_graph) = outcome.rust_cargo_unit_graph.as_ref() {
                if evidence_status == "audit-only (no completed base scan)"
                    && outcome.rust_compiler_invocation_ledger.is_none()
                {
                    evidence_status = "validated unit graph (audit-only; no completed base scan)";
                }
                println!("Cargo units: {}", unit_graph.units.len());
                println!("Cargo unit graph digest: {}", unit_graph.digest);
            }
            println!("build run: {}", outcome.audit.run_id);
            println!("status: {:?}", outcome.audit.outcome);
            println!("project code executed: {}", outcome.project_code_executed);
            println!("build evidence: {evidence_status}");
            println!("build cache lookup: {cache_lookup_status} ({cache_lookup_reason})");
            println!("build cache: {build_cache_status}");
            println!("network isolation: {:?}", outcome.audit.network_isolation);
            if let Some(diagnostic) = &outcome.audit.diagnostic_code {
                println!("diagnostic: {diagnostic}");
            }
            if let Some(failure) = &outcome.audit.compiler_failure {
                println!("compiler Cargo unit: {}", failure.unit_id);
                println!(
                    "compiler Cargo unit context: kind={}, mode={}, platform={}",
                    failure.unit_kind, failure.mode, failure.cargo_platform
                );
            }
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
        Commands::Doctor {
            json,
            compiler_pack_requirement,
            root,
            summary: _,
            details,
        } => {
            let invocation_root = std::env::current_dir()?;
            let diagnostic_root = root.map(canonical_directory).transpose()?;
            let store_path = store_path(
                cli.store,
                diagnostic_root.as_deref().unwrap_or(&invocation_root),
            )?;
            let service_root = diagnostic_root.as_deref().unwrap_or(&invocation_root);
            let service = snapshot_read_service(service_root, &store_path)?;
            let result = service.doctor_cancellable(
                &DoctorRequest {
                    details,
                    use_service_root: diagnostic_root.is_some(),
                    compiler_pack_requirement,
                },
                &CancellationToken::new(),
            )?;
            let result = AgentDoctor::from(result);
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                print_agent_doctor_human(&serde_json::to_value(result)?, details);
            }
            Ok(0)
        }
        Commands::Deps {
            selector,
            transitive,
            max_traversal,
            phase,
            profile,
            session,
            environment,
            json,
            output,
        } => {
            let filter = GraphQueryFilter::new(phase, profile, session, environment)?;
            let (service, mut snapshot) =
                graph_snapshot_request(cli.store, cli.scan_id.as_deref())?;
            let request = DependenciesRequest::try_new(
                selector,
                DependencyDirection::Outgoing,
                transitive,
                filter,
                if output.all {
                    depgraph_core::MAX_INTERACTIVE_QUERY_TRAVERSAL
                } else {
                    max_traversal.unwrap_or(DEFAULT_INTERACTIVE_QUERY_MAX_TRAVERSAL)
                },
            )?;
            let result =
                service.dependencies(&mut snapshot, &request, &CancellationToken::new())?;
            if output.all {
                print_structured(
                    "deps",
                    result.scan_id().to_owned(),
                    result.traversal(),
                    json,
                )?;
                if !json {
                    print_path_steps(&result.traversal().steps);
                }
            } else {
                let page = interactive_dependencies_page(&result, "deps", &request, &output)?;
                print_interactive_page(&page, json)?;
                if !json {
                    for item in &page.items {
                        print_path_steps(std::slice::from_ref(&item.step));
                    }
                }
            }
            Ok(0)
        }
        Commands::Dependents {
            selector,
            transitive,
            max_traversal,
            phase,
            profile,
            session,
            environment,
            json,
            output,
        } => {
            let filter = GraphQueryFilter::new(phase, profile, session, environment)?;
            let (service, mut snapshot) =
                graph_snapshot_request(cli.store, cli.scan_id.as_deref())?;
            let request = DependenciesRequest::try_new(
                selector,
                DependencyDirection::Incoming,
                transitive,
                filter,
                if output.all {
                    depgraph_core::MAX_INTERACTIVE_QUERY_TRAVERSAL
                } else {
                    max_traversal.unwrap_or(DEFAULT_INTERACTIVE_QUERY_MAX_TRAVERSAL)
                },
            )?;
            let result =
                service.dependencies(&mut snapshot, &request, &CancellationToken::new())?;
            if output.all {
                print_structured(
                    "dependents",
                    result.scan_id().to_owned(),
                    result.traversal(),
                    json,
                )?;
                if !json {
                    print_path_steps(&result.traversal().steps);
                }
            } else {
                let page = interactive_dependencies_page(&result, "dependents", &request, &output)?;
                print_interactive_page(&page, json)?;
                if !json {
                    for item in &page.items {
                        print_path_steps(std::slice::from_ref(&item.step));
                    }
                }
            }
            Ok(0)
        }
        Commands::Why {
            from,
            to,
            max_traversal,
            phase,
            profile,
            session,
            environment,
            json,
        } => {
            let filter = GraphQueryFilter::new(phase, profile, session, environment)?;
            let (service, mut snapshot) =
                graph_snapshot_request(cli.store, cli.scan_id.as_deref())?;
            let result = service.explain_path(
                &mut snapshot,
                &ExplainPathRequest::try_new(
                    from,
                    to,
                    filter,
                    max_traversal.unwrap_or(DEFAULT_INTERACTIVE_QUERY_MAX_TRAVERSAL),
                )?,
                &CancellationToken::new(),
            )?;
            print_structured("why", result.scan_id().to_owned(), result.path(), json)?;
            if !json {
                if result.path().path_found {
                    println!("{}", result.path().from.locator);
                    print_why_steps(&result.path().steps);
                } else {
                    println!(
                        "no dependency path exists from {} to {}",
                        result.path().from.locator,
                        result.path().to.locator
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
            let (service, mut snapshot) =
                graph_snapshot_request(cli.store, cli.scan_id.as_deref())?;
            let result = service.impact(
                &mut snapshot,
                &ImpactRequest::try_new(selector, changed, filters)?,
                &CancellationToken::new(),
            )?;
            print_structured("impact", result.scan_id().to_owned(), result.impact(), json)?;
            if !json {
                print_human_impact(result.impact());
            }
            Ok(0)
        }
        Commands::Cycles {
            level,
            max_traversal,
            json,
        } => {
            let level = match level {
                CycleLevelArg::Package => CycleLevel::Package,
                CycleLevelArg::File => CycleLevel::File,
                CycleLevelArg::Symbol => CycleLevel::Symbol,
                CycleLevelArg::Type => CycleLevel::Type,
                CycleLevelArg::Route => CycleLevel::Route,
            };
            let (service, mut snapshot) =
                graph_snapshot_request(cli.store, cli.scan_id.as_deref())?;
            let result = service.cycles(
                &mut snapshot,
                &CyclesRequest::try_new(
                    level,
                    max_traversal.unwrap_or(DEFAULT_INTERACTIVE_QUERY_MAX_TRAVERSAL),
                )?,
                &CancellationToken::new(),
            )?;
            print_structured(
                "cycles",
                result.scan_id().to_owned(),
                &result.cycles(),
                json,
            )?;
            if !json {
                if result.cycles().is_empty() {
                    println!("no cycles");
                }
                for cycle in result.cycles() {
                    println!("{}", cycle.node_ids.join(" -> "));
                }
            }
            Ok(0)
        }
        Commands::Unresolved {
            kind,
            max_traversal,
            json,
            output,
        } => {
            let (service, mut snapshot) =
                graph_snapshot_request(cli.store, cli.scan_id.as_deref())?;
            let request = UnresolvedRequest::try_new(
                kind,
                max_traversal.unwrap_or(DEFAULT_INTERACTIVE_QUERY_MAX_TRAVERSAL),
            )?;
            let result = service.unresolved(&mut snapshot, &request, &CancellationToken::new())?;
            if output.all {
                print_structured(
                    "unresolved",
                    result.scan_id().to_owned(),
                    &result.items(),
                    json,
                )?;
                if !json {
                    print_unresolved_items(result.items());
                }
            } else {
                let snapshot_id = result.snapshot_id().as_str();
                let scan_id = result.scan_id();
                let max_items = output
                    .max_items
                    .unwrap_or(DEFAULT_INTERACTIVE_QUERY_MAX_ITEMS);
                let max_bytes = output
                    .max_bytes
                    .unwrap_or(DEFAULT_INTERACTIVE_QUERY_MAX_BYTES);
                validate_interactive_query_bounds(max_items, max_bytes, None)?;
                let context = serde_json::json!({
                    "query":"unresolved",
                    "kinds": request.kinds(),
                    "max_traversal": request.max_traversal(),
                });
                let page = paginate_interactive_query(
                    result.items(),
                    unresolved_summary(result.items()),
                    InteractiveQueryPageRequest {
                        command: "unresolved",
                        scan_id,
                        snapshot_id,
                        context: &context,
                        cursor: output.cursor.as_deref(),
                        max_items,
                        max_bytes,
                        traversal_complete: true,
                        traversed_items: result.items().len().try_into().unwrap_or(u64::MAX),
                        root: None,
                        diagnostics: Vec::new(),
                    },
                )?;
                print_interactive_page(&page, json)?;
                if !json {
                    print_unresolved_items(&page.items);
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
            let store_path = store_path(cli.store, &repository_root)?;
            let service = snapshot_read_service(&repository_root, &store_path)?;
            let query_file = file
                .map(|path| repository_relative_cli_input(&path))
                .transpose()?;
            let request = BoundedQueryRequest {
                query,
                query_file,
                snapshot: cli_snapshot_selector(cli.scan_id),
                mode: if explain {
                    BoundedQueryMode::Explain
                } else {
                    BoundedQueryMode::Execute
                },
            };
            let found = match service.bounded_query(&request, &CancellationToken::new()) {
                Ok(found) => found,
                Err(DepgraphServiceError::NotFound) => return Err(QuerySnapshotUnavailable.into()),
                Err(error) => return Err(error.into()),
            };
            let plan = found.plan();
            if explain {
                print_query_plan(plan, json)?;
                return Ok(if plan.admitted { 0 } else { 1 });
            }
            let result = found
                .result()
                .ok_or_else(|| anyhow::anyhow!("bounded query execution result is unavailable"))?;
            print_query_result(found.projections(), result, json)?;
            Ok(0)
        }
        Commands::Runtime { command } => match command {
            RuntimeCommands::Validate { trace, file, json } => {
                let repository_root = canonical_directory(std::env::current_dir()?)?;
                let store_path = store_path(cli.store, &repository_root)?;
                let service = snapshot_read_service(&repository_root, &store_path)?;
                let request = RuntimeValidateRequest {
                    trace,
                    trace_file: file
                        .map(|path| repository_relative_cli_input(&path))
                        .transpose()?,
                    snapshot: cli_snapshot_selector(cli.scan_id),
                };
                let found = service.runtime_validate(&request, &CancellationToken::new())?;
                let result = found.trace();
                print_structured("runtime.validate", found.scan_id().to_owned(), result, json)?;
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
            RuntimeCommands::Import {
                trace_file,
                trace,
                json,
            } => {
                let root = canonical_directory(std::env::current_dir()?)?;
                let store_path = store_path(cli.store, &root)?;
                let service = store_write_service(&root, &store_path)?;
                let request = RuntimeValidateRequest {
                    trace,
                    trace_file: trace_file
                        .map(|path| repository_relative_cli_input(&path))
                        .transpose()?,
                    snapshot: cli_snapshot_selector(cli.scan_id),
                };
                let imported = service.runtime_import(&request, &CancellationToken::new())?;
                let result = AgentRuntimeOutcome::try_from(&imported)
                    .map_err(|_| anyhow::anyhow!("runtime import result is invalid"))?;
                print_structured(
                    "runtime.import",
                    imported.scan_id().to_owned(),
                    &result,
                    json,
                )?;
                if !json {
                    println!("runtime session: {}", result.session_id().as_str());
                    println!("snapshot: {}", result.snapshot_id().as_str());
                    println!(
                        "status: {}",
                        match result.status() {
                            depgraph_mcp_tools::AgentRuntimeStatus::Completed => "completed",
                            depgraph_mcp_tools::AgentRuntimeStatus::Partial => "partial",
                        }
                    );
                    println!("deduplicated: {}", result.deduplicated());
                }
                Ok(0)
            }
        },
        Commands::Snapshot { command } => {
            let root = std::env::current_dir()?;
            let store_path = std::path::absolute(store_path(cli.store, &root)?)?;
            match command {
                SnapshotCommands::Create { name, json } => {
                    let service = store_write_service(&root, &store_path)?;
                    let request = if let Some(scan_id) = cli.scan_id {
                        SnapshotNameCreateRequest::for_scan(name, scan_id)
                    } else {
                        SnapshotNameCreateRequest::new(name, SnapshotLocator::Current)
                    };
                    let named =
                        match service.snapshot_name_create(&request, &CancellationToken::new()) {
                            Ok(named) => named,
                            Err(DepgraphServiceError::Conflict) => {
                                return Err(anyhow::anyhow!(
                                    "snapshot name {} already exists",
                                    request.name()
                                ));
                            }
                            Err(DepgraphServiceError::InvalidInput) => {
                                return Err(anyhow::anyhow!(
                                    "snapshot name {} is invalid",
                                    request.name()
                                ));
                            }
                            Err(DepgraphServiceError::NotFound) => {
                                let message = match request.selector() {
                                    SnapshotNameCreateSelector::CompletedForScan(scan_id) => {
                                        format!("scan {scan_id} has no completed snapshot")
                                    }
                                    SnapshotNameCreateSelector::Completed(
                                        SnapshotLocator::Current,
                                    ) => "no current completed snapshot is available".to_owned(),
                                    SnapshotNameCreateSelector::Completed(selector) => {
                                        format!("completed snapshot {selector:?} was not found")
                                    }
                                };
                                return Err(anyhow::anyhow!(message));
                            }
                            Err(error) => return Err(error.into()),
                        };
                    let output = SnapshotCreatedOutput {
                        name: named.name(),
                        named_at: named.named_at(),
                        snapshot: named.snapshot(),
                    };
                    if json {
                        print_snapshot_json("snapshot.create", &output)?;
                    } else {
                        println!("created snapshot name: {}", output.name);
                        println!("named at: {}", output.named_at);
                        print_completed_snapshot_view(output.snapshot);
                    }
                }
                SnapshotCommands::List { json } => {
                    let service = snapshot_read_service(&root, &store_path)?;
                    let output = service.list_completed_snapshots()?;
                    if json {
                        print_snapshot_json("snapshot.list", &output)?;
                    } else if output.is_empty() {
                        println!("no named snapshots");
                    } else {
                        for item in &output {
                            println!(
                                "{} {} status={} revision={} profiles={} named_at={}",
                                item.name(),
                                item.snapshot().id(),
                                item.snapshot().status(),
                                display_revision(item.snapshot().source_revision()),
                                display_list(item.snapshot().profile_ids()),
                                item.named_at(),
                            );
                            println!("    {}", coverage_summary(item.snapshot().coverage()));
                        }
                    }
                }
                SnapshotCommands::Show { selector, json } => {
                    let service = snapshot_read_service(&root, &store_path)?;
                    let selector = SnapshotLocator::parse(&selector)?;
                    let output = service.show_completed_snapshot(&selector)?;
                    if json {
                        print_snapshot_json("snapshot.show", &output)?;
                    } else {
                        print_completed_snapshot_view(&output);
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
            let filters = snapshot_diff::DiffFilters::new(kind, profile, phase, status)?;
            let filters = SnapshotDiffFilters::try_new(
                filters.kind,
                filters.profile,
                filters.phase,
                filters.status,
            )?;
            let root = std::env::current_dir()?;
            let store_path = store_path(cli.store, &root)?;
            let service = snapshot_read_service(&root, &store_path)?;
            let request = SnapshotDiffRequest::new(
                SnapshotLocator::parse(&from)?,
                SnapshotLocator::parse(&to)?,
                filters,
            );
            let diff = service
                .snapshot_diff(&request, &CancellationToken::new())
                .context("snapshot selector resolution failed")?;
            if json {
                print_snapshot_json("diff", &diff)?;
            } else {
                print!("{}", render_service_human_diff(&diff));
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
            let store_path = store_path(cli.store, &root)?;
            let service = snapshot_read_service(&root, &store_path)?;
            let request = PolicyEvaluateRequest::new(
                SnapshotLocator::parse(&from)?,
                SnapshotLocator::parse(&to)?,
            );
            let output = service
                .policy_evaluate(&request, &CancellationToken::new())
                .context("snapshot selector resolution failed")?;
            let result = &output.result;
            if github_annotations {
                let annotations = output
                    .annotations
                    .iter()
                    .map(|annotation| PolicyAnnotation {
                        violation_id: annotation.violation_id.clone(),
                        rule_id: annotation.rule_id.clone(),
                        level: annotation.level,
                        path: annotation.path.clone(),
                        start_line: annotation.start_line,
                        start_column: annotation.start_column,
                        end_line: annotation.end_line,
                        end_column: annotation.end_column,
                        title: annotation.title.clone(),
                        message: annotation.message.clone(),
                    })
                    .collect::<Vec<_>>();
                print!("{}", render_github_annotations(&annotations));
            } else if json {
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
            let filter = GraphQueryFilter::new(phase, profile, session, environment)?;
            let format = match format {
                ExportFormatArg::Json => ExportFormat::Json,
                ExportFormatArg::Dot => ExportFormat::Dot,
                ExportFormatArg::Mermaid => ExportFormat::Mermaid,
                ExportFormatArg::Graphml => ExportFormat::Graphml,
            };
            {
                let root = canonical_directory(std::env::current_dir()?)?;
                let store_path = store_path(cli.store.clone(), &root)?;
                let service = if output.is_some() {
                    repository_write_service(&root, &store_path)?
                } else {
                    snapshot_read_service(&root, &store_path)?
                };
                let snapshot = if let Some(scan_id) = cli.scan_id.as_deref() {
                    match service
                        .start_snapshot_request_for_scan(scan_id, &CancellationToken::new())
                    {
                        Ok(pinned) => Some(SnapshotLocator::StableId(
                            pinned.snapshot_id().as_str().to_owned(),
                        )),
                        // Explicit failed or partial scans remain inspectable through the legacy
                        // CLI-only projection. Agent-facing reads never enter this path.
                        Err(DepgraphServiceError::Integrity | DepgraphServiceError::NotFound) => {
                            None
                        }
                        Err(error) => return Err(error.into()),
                    }
                } else {
                    Some(SnapshotLocator::Current)
                };
                if let Some(snapshot) = snapshot {
                    let service_format = match format {
                        ExportFormat::Json => GraphExportFormat::Json,
                        ExportFormat::Dot => GraphExportFormat::Dot,
                        ExportFormat::Mermaid => GraphExportFormat::Mermaid,
                        ExportFormat::Graphml => GraphExportFormat::Graphml,
                    };
                    let request = GraphExportRequest::try_new(
                        snapshot,
                        service_format,
                        None,
                        filter.clone(),
                        MAX_GRAPH_EXPORT_NODES,
                        MAX_GRAPH_EXPORT_EDGES,
                    )?;
                    if let Some(output) = output.as_ref() {
                        let output_path = normalize_cli_repository_output(&root, output)?;
                        service.export_file(
                            &ExportFileRequest::raw_compatible(
                                request,
                                output_path,
                                RepositoryOverwritePolicy::Overwrite,
                            ),
                            &CancellationToken::new(),
                        )?;
                    } else {
                        let rendered = service.graph_export(&request, &CancellationToken::new())?;
                        print!("{}", rendered.content);
                    }
                    return Ok(0);
                }
            }
            let (snapshot, _) = load_snapshot(cli.store.clone(), cli.scan_id.as_deref(), false)?;
            let service_format = match format {
                ExportFormat::Json => GraphExportFormat::Json,
                ExportFormat::Dot => GraphExportFormat::Dot,
                ExportFormat::Mermaid => GraphExportFormat::Mermaid,
                ExportFormat::Graphml => GraphExportFormat::Graphml,
            };
            if format == ExportFormat::Graphml {
                if let Some(path) = output.as_ref() {
                    let root = canonical_directory(std::env::current_dir()?)?;
                    let store_path = store_path(cli.store.clone(), &root)?;
                    let service = repository_write_service(&root, &store_path)?;
                    let output_path = normalize_cli_repository_output(&root, path)?;
                    let mut rendered = Vec::new();
                    export_graphml_filtered_to_writer(&snapshot, &filter, &mut rendered)?;
                    service.export_rendered_file(
                        &output_path,
                        RepositoryOverwritePolicy::Overwrite,
                        service_format,
                        &rendered,
                        &CancellationToken::new(),
                    )?;
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
            if let Some(path) = output.as_ref() {
                let root = canonical_directory(std::env::current_dir()?)?;
                let store_path = store_path(cli.store, &root)?;
                let service = repository_write_service(&root, &store_path)?;
                let output_path = normalize_cli_repository_output(&root, path)?;
                service.export_rendered_file(
                    &output_path,
                    RepositoryOverwritePolicy::Overwrite,
                    service_format,
                    rendered.as_bytes(),
                    &CancellationToken::new(),
                )?;
            } else {
                print!("{rendered}");
            }
            Ok(0)
        }
    }
}

#[cfg(test)]
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

fn requires_build_attempt(
    outcome: &BuildOutcomeKind,
    has_compiler_mir_ledger: bool,
    has_compiler_invocation_ledger: bool,
    has_cargo_unit_graph: bool,
) -> bool {
    !matches!(outcome, BuildOutcomeKind::Completed)
        || has_compiler_mir_ledger
        || (!has_compiler_invocation_ledger && !has_cargo_unit_graph)
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

fn normalize_cli_repository_file(
    requested_root: &Path,
    canonical_root: &Path,
    supplied: &Path,
) -> std::result::Result<RepositoryRelativePath, DepgraphServiceError> {
    let candidate = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        requested_root.join(supplied)
    };
    let relative = candidate
        .strip_prefix(requested_root)
        .or_else(|_| candidate.strip_prefix(canonical_root))
        .map_err(|_| unsafe_profiles_file("path is outside repository"))?;
    let mut normalized = Vec::new();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(unsafe_profiles_file("path is not repository-relative"));
        };
        normalized.push(
            component
                .to_str()
                .ok_or_else(|| unsafe_profiles_file("path is not valid UTF-8"))?,
        );
    }
    RepositoryRelativePath::parse(normalized.join("/"))
        .map_err(|_| unsafe_profiles_file("path is not repository-relative"))
}

fn repository_relative_cli_input(
    supplied: &Path,
) -> std::result::Result<RepositoryRelativePath, DepgraphServiceError> {
    let supplied = supplied
        .to_str()
        .ok_or(DepgraphServiceError::InvalidInput)?;
    RepositoryRelativePath::parse(supplied)
}

fn normalize_cli_repository_output(
    _canonical_root: &Path,
    supplied: &Path,
) -> std::result::Result<RepositoryRelativePath, DepgraphServiceError> {
    repository_relative_cli_input(supplied)
}

fn cli_snapshot_selector(scan_id: Option<String>) -> ServiceSnapshotSelector {
    scan_id.map_or_else(
        ServiceSnapshotSelector::current,
        ServiceSnapshotSelector::ScanId,
    )
}

fn unsafe_profiles_file(reason: &'static str) -> DepgraphServiceError {
    DepgraphServiceError::profile_plan_security(anyhow::anyhow!(
        "unsafe explicit profiles file: {reason}"
    ))
}

fn store_path(explicit: Option<PathBuf>, root: &std::path::Path) -> Result<PathBuf> {
    explicit.map(Ok).unwrap_or_else(|| default_store_path(root))
}

fn print_daemon_status(status: &DaemonStatus, json: bool) -> Result<()> {
    let status = AgentDaemonStatus::try_from(status.clone())
        .map_err(|_| anyhow::anyhow!("daemon status violates the public contract"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        let status = serde_json::to_value(status)?;
        println!("daemon: {}", status["phase"].as_str().unwrap_or("unknown"));
        println!(
            "pending changes: {}",
            status["pending_change_count"].as_u64().unwrap_or(0)
        );
        for (label, field) in [
            ("last completed", "last_completed_attempt"),
            ("last failed", "last_failed_attempt"),
            ("last cancelled", "last_cancelled_attempt"),
        ] {
            if let Some(attempt_id) = status[field]["attempt_id"].as_str() {
                println!("{label}: {attempt_id}");
            }
        }
    }
    Ok(())
}

fn print_agent_doctor_human(report: &serde_json::Value, details: bool) {
    let kind = report["report_kind"].as_str().unwrap_or("doctor");
    println!("doctor report: {kind}");
    if let Some(protocol) = report["protocol_version"].as_str() {
        println!("protocol: {protocol}");
    }
    if let Some(latest) = report["latest_attempt"].as_object() {
        let status = latest["status"].as_str().unwrap_or("unknown");
        println!("latest attempt: {status}");
    } else {
        println!("latest attempt: none");
    }
    if details {
        println!("details: redacted agent-safe projection");
    }
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

fn graph_snapshot_request(
    explicit_store: Option<PathBuf>,
    requested_scan_id: Option<&str>,
) -> Result<(DepgraphService, SnapshotReadRequest)> {
    let root = std::env::current_dir()?;
    let store_path = store_path(explicit_store, &root)?;
    let service = snapshot_read_service(&root, &store_path)?;
    let cancellation = CancellationToken::new();
    let request = match requested_scan_id {
        Some(scan_id) => service.start_snapshot_request_for_scan(scan_id, &cancellation)?,
        None => service
            .start_snapshot_request_at_cancellable(&SnapshotLocator::Current, &cancellation)?,
    };
    Ok((service, request))
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
        "toolchain guidance: {}",
        canonical_json(&serde_json::to_value(&preview.toolchain_guidance)?)
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

#[allow(dead_code)]
fn print_compiler_pack_health_human(report: &depgraph_core::CompilerPackAvailabilityHealth) {
    println!(
        "compiler pack: {} (host={}; policy={})",
        report.status,
        report.host_target.as_deref().unwrap_or("unsupported"),
        report.fallback_policy
    );
    println!("compiler pack diagnostic: {}", report.diagnostic);
    println!("compiler pack action: {}", report.remediation);
}

#[allow(dead_code)]
fn print_doctor_summary_human(report: &depgraph_core::DoctorSummaryReport) {
    println!("doctor report: {}", report.report_kind);
    println!(
        "diagnostic root: {} ({})",
        report.diagnostic_root.path, report.diagnostic_root.source
    );
    println!("protocol: {}", report.protocol_version);
    println!("graph schema: {}", report.graph_schema_version);
    println!("store schema: {}", report.store_schema_version);
    println!(
        "cache entries: {} syntax, {} semantic, {} build, {} compiler-precise",
        report.cache_entries.syntax,
        report.cache_entries.semantic,
        report.cache_entries.build,
        report.cache_entries.compiler_precise,
    );
    print_compiler_pack_health_human(&report.compiler_pack);
    for (toolchain, version) in &report.toolchains {
        let baseline = report
            .supported_baselines
            .get(toolchain)
            .map(String::as_str)
            .unwrap_or("best-effort");
        println!("toolchain {toolchain}: {version} (baseline {baseline})");
        if let Some(remediation) = report.toolchain_remediation.get(toolchain) {
            println!("toolchain {toolchain} remediation: {remediation}");
        }
    }
    for worker in &report.workers {
        if worker.available {
            println!(
                "worker {} artifact: available ({}, {}; protocol={}; {})",
                worker.adapter,
                worker.command.as_deref().unwrap_or_default(),
                worker.version.as_deref().unwrap_or("unknown version"),
                worker.protocol.as_deref().unwrap_or("unknown"),
                worker.integrity
            );
        } else {
            println!(
                "worker {} artifact: unavailable ({})",
                worker.adapter,
                worker.error.as_deref().unwrap_or_default()
            );
        }
        if worker.root_launch_allowed {
            println!("worker {} root launch: allowed", worker.adapter);
        } else {
            println!(
                "worker {} root launch: blocked ({})",
                worker.adapter,
                worker.root_launch_error.as_deref().unwrap_or_default()
            );
        }
    }
    if let Some(scan) = &report.latest_attempt {
        println!(
            "latest attempt: {} ({}) root={}",
            scan.scan_id, scan.status, scan.root
        );
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
        let languages = scan
            .profiles_by_language
            .iter()
            .map(|(language, count)| format!("{language}={count}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "profiles: {} ({languages}); package instances: {}",
            scan.profile_count, scan.package_instance_count
        );
        println!(
            "diagnostics: {} total, {} groups shown, {} groups omitted, {} diagnostics omitted",
            scan.diagnostics.total,
            scan.diagnostics.groups.len(),
            scan.diagnostics.omitted_groups,
            scan.diagnostics.omitted_diagnostics
        );
        for group in &scan.diagnostics.groups {
            println!(
                "  {} {} adapter={}: {}",
                group.severity,
                group.code,
                group.adapter.as_deref().unwrap_or("none"),
                group.count
            );
        }
        for sample in &scan.diagnostics.samples {
            println!(
                "  sample {} {} path={}: {}",
                sample.code,
                sample.id,
                sample.path.as_deref().unwrap_or("none"),
                sample.message
            );
        }
        for coverage in &scan.file_coverage {
            println!(
                "files {}: {} total, {} skipped; sites discovered={} emitted={} skipped={}",
                coverage.adapter,
                coverage.files,
                coverage.skipped_files,
                coverage.discovered_sites,
                coverage.emitted_sites,
                coverage.skipped_sites
            );
        }
        for log in &scan.adapter_logs {
            if log.truncated {
                println!(
                    "worker {} stderr: {} bytes (truncated)",
                    log.adapter, log.stderr_bytes
                );
            }
        }
        println!("project code executed: {}", scan.project_code_executed);
    } else {
        println!("latest attempt: none");
    }
    println!("details: {}", report.detail_command);
}

#[allow(clippy::too_many_arguments)]
fn interactive_dependencies_page(
    execution: &depgraph_core::service::DependenciesResult,
    command: &'static str,
    request: &DependenciesRequest,
    output: &InteractiveOutputArgs,
) -> Result<InteractiveQueryPage<TraversalPageItem>> {
    let max_items = output
        .max_items
        .unwrap_or(DEFAULT_INTERACTIVE_QUERY_MAX_ITEMS);
    let max_bytes = output
        .max_bytes
        .unwrap_or(DEFAULT_INTERACTIVE_QUERY_MAX_BYTES);
    let max_traversal = request.max_traversal();
    validate_interactive_query_bounds(max_items, max_bytes, Some(max_traversal))?;
    let context = serde_json::json!({
        "selector": request.selector(),
        "transitive": request.transitive(),
        "reverse": request.direction().is_incoming(),
        "filter": request.filter(),
        "max_traversal": max_traversal,
    });
    paginate_interactive_query(
        execution.items(),
        traversal_summary(execution.traversal()),
        InteractiveQueryPageRequest {
            command,
            scan_id: execution.scan_id(),
            snapshot_id: execution.snapshot_id().as_str(),
            context: &context,
            cursor: output.cursor.as_deref(),
            max_items,
            max_bytes,
            traversal_complete: execution.complete(),
            traversed_items: execution.traversed_edges(),
            root: Some(&execution.traversal().root),
            diagnostics: execution.diagnostics().to_vec(),
        },
    )
}

fn print_interactive_page<T: Serialize>(
    page: &InteractiveQueryPage<T>,
    json_output: bool,
) -> Result<()> {
    if json_output {
        println!("{}", canonical_json(&serde_json::to_value(page)?));
        return Ok(());
    }
    println!(
        "{}: returned {}/{} items; complete={}; traversed={}; output_bytes={}",
        page.command,
        page.returned_items,
        page.total_items,
        page.complete,
        page.traversed_items,
        page.serialized_output_bytes
    );
    for (label, summary) in [
        ("status", &page.summary.by_status),
        ("phase", &page.summary.by_phase),
        ("profile", &page.summary.by_profile),
        ("kind", &page.summary.by_kind),
        ("reason", &page.summary.by_reason),
    ] {
        if summary.groups.is_empty() && summary.omitted_groups == 0 {
            continue;
        }
        let groups = summary
            .groups
            .iter()
            .map(|group| format!("{}={}", group.key, group.count))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "summary {label}: {groups}; omitted_groups={} omitted_items={}",
            summary.omitted_groups, summary.omitted_items
        );
    }
    for diagnostic in &page.diagnostics {
        println!(
            "diagnostic {}: {}; remediation={}",
            diagnostic.code, diagnostic.message, diagnostic.remediation
        );
    }
    if let Some(cursor) = &page.next_cursor {
        println!("next cursor: {cursor}");
    }
    Ok(())
}

fn print_unresolved_items(items: &[UnresolvedResult]) {
    for unresolved in items {
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
        let site = &unresolved.site;
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
            site.specifier.as_deref().unwrap_or_default(),
            site.source,
            site.profile_id,
            effective_profile,
            observed_status,
            difference_reasons,
            render_condition(&site.condition),
            span.unwrap_or_else(|| "unknown".to_owned()),
            site.reason.as_deref().unwrap_or("no reason provided")
        );
    }
}

#[cfg(test)]
fn inspect_runtime_trace_input(path: &Path) -> Result<std::fs::Metadata> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata),
        Err(error) => Err(runtime_trace_metadata_error(error)),
    }
}

#[cfg(test)]
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

fn print_completed_snapshot_view(snapshot: &CompletedSnapshotView) {
    println!("snapshot: {}", snapshot.id());
    println!("names: {}", display_list(snapshot.names()));
    println!("status: {}", snapshot.status());
    println!(
        "source: {} {}",
        snapshot.source_kind(),
        snapshot.source_attempt_id()
    );
    println!("scan: {}", snapshot.scan_id());
    if let Some(build_attempt_id) = snapshot.build_attempt_id() {
        println!("build attempt: {build_attempt_id}");
    }
    if let Some(runtime_import_id) = snapshot.runtime_import_id() {
        println!("runtime import: {runtime_import_id}");
    }
    if !snapshot.runtime_session_ids().is_empty() {
        println!(
            "runtime sessions: {}",
            display_list(snapshot.runtime_session_ids())
        );
    }
    println!(
        "parent: {}",
        snapshot.parent_snapshot_id().unwrap_or("none")
    );
    println!("revision: {}", display_revision(snapshot.source_revision()));
    println!("profiles: {}", display_list(snapshot.profile_ids()));
    println!("created at: {}", snapshot.created_at());
    println!("{}", coverage_summary(snapshot.coverage()));
}

fn snapshot_read_service(root: &Path, store_path: &Path) -> Result<DepgraphService> {
    let store_path = std::path::absolute(store_path).context("store path is unavailable")?;
    let config = DepgraphServiceConfig::new(
        root,
        &store_path,
        DepgraphCapabilitySet::read_only(),
        DepgraphServiceLimits::default(),
    )?;
    Ok(DepgraphService::new(config))
}

fn store_write_service(root: &Path, store_path: &Path) -> Result<DepgraphService> {
    let store_path = std::path::absolute(store_path).context("store path is unavailable")?;
    let config = DepgraphServiceConfig::new(
        root,
        &store_path,
        DepgraphCapabilitySet::try_new([DepgraphCapability::Read, DepgraphCapability::StoreWrite])?,
        DepgraphServiceLimits::default(),
    )?;
    Ok(DepgraphService::new(config))
}

fn daemon_control_service(root: &Path, store_path: &Path) -> Result<DepgraphService> {
    let store_path = std::path::absolute(store_path).context("store path is unavailable")?;
    let config = DepgraphServiceConfig::new(
        root,
        &store_path,
        DepgraphCapabilitySet::try_new([
            DepgraphCapability::Read,
            DepgraphCapability::StoreWrite,
            DepgraphCapability::DaemonControl,
        ])?,
        DepgraphServiceLimits::default(),
    )?;
    Ok(DepgraphService::new(config))
}

fn repository_write_service(root: &Path, store_path: &Path) -> Result<DepgraphService> {
    let store_path = std::path::absolute(store_path).context("store path is unavailable")?;
    let config = DepgraphServiceConfig::new(
        root,
        &store_path,
        DepgraphCapabilitySet::try_new([
            DepgraphCapability::Read,
            DepgraphCapability::RepositoryWrite,
        ])?,
        DepgraphServiceLimits::default(),
    )?;
    Ok(DepgraphService::new(config))
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
        require_compiler_precise_consent, requires_build_attempt, runtime_trace_metadata_error,
        write_file_atomically,
    };
    use depgraph_core::BuildOutcomeKind;

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
        assert_eq!(
            error_exit_code(&anyhow::anyhow!(
                "interactive query cursor does not match this snapshot and query"
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
    fn completed_compiler_promotion_opens_only_the_required_delta_attempt() {
        assert!(requires_build_attempt(
            &BuildOutcomeKind::Completed,
            true,
            true,
            true
        ));
        assert!(!requires_build_attempt(
            &BuildOutcomeKind::Completed,
            false,
            true,
            true
        ));
        assert!(!requires_build_attempt(
            &BuildOutcomeKind::Completed,
            false,
            false,
            true
        ));
        assert!(requires_build_attempt(
            &BuildOutcomeKind::Completed,
            false,
            false,
            false
        ));
        for outcome in [
            BuildOutcomeKind::Failed,
            BuildOutcomeKind::TimedOut,
            BuildOutcomeKind::Cancelled,
            BuildOutcomeKind::SecurityFailed,
        ] {
            assert!(requires_build_attempt(&outcome, false, false, false));
        }
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
