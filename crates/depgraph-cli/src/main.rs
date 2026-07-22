use std::{io::Cursor, path::PathBuf, process::ExitCode};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use depgraph_core::{
    BuildOutcomeKind, Config, CycleLevel, ExportFormat, create_build_execution_request,
    default_store_path, doctor, execute_build_request_with_cancellation, export, init_config,
    open_store, render_condition, run_scan, rust_build_protocol_ndjson, stage_build_evidence,
    traverse, unresolved, web_build_protocol_ndjson, why,
};
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
        #[arg(long)]
        json: bool,
    },
    /// List incoming dependencies to a selector.
    Dependents {
        selector: String,
        #[arg(long)]
        transitive: bool,
        #[arg(long)]
        json: bool,
    },
    /// Explain a deterministic shortest dependency path.
    Why {
        from: String,
        to: String,
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
    /// Export the selected scan in a deterministic format.
    Export {
        #[arg(long, value_enum)]
        format: ExportFormatArg,
        #[arg(short, long)]
        output: Option<PathBuf>,
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
    parent_snapshot_id: Option<String>,
    source_revision: Option<String>,
    profile_ids: Vec<String>,
    created_at: String,
    coverage: CoverageRecord,
}

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
    let message = format!("{error:#}").to_ascii_lowercase();
    if message.contains("security policy") || message.contains("project code execution") {
        return 4;
    }
    if (message.contains("scan ") && message.contains(" was not found"))
        || (message.contains("completed snapshot") && message.contains(" was not found"))
        || (message.contains("diff ") && message.contains(" filter must"))
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
        Commands::Scan { path, strict, json } => {
            let root = canonical_directory(path)?;
            let config = Config::load(&root)?;
            let store_path = store_path(cli.store, &root)?;
            let mut store = open_store(&store_path)?;
            let outcome = run_scan(&mut store, root, &config, strict).await?;
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
                println!("store: {}", store_path.display());
            }
            Ok(outcome.exit_code)
        }
        Commands::Resolve {
            build,
            path,
            allow_project_code,
        } => {
            debug_assert!(build, "clap requires --build");
            require_build_consent(allow_project_code)?;
            let root = canonical_directory(path)?;
            let request = create_build_execution_request(&root)?;
            let store_path = store_path(cli.store, &root)?;
            let mut store = open_store(&store_path)?;
            let outcome = execute_build_request_with_cancellation(&request, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await?;
            store.save_build_audit(&serde_json::to_value(&outcome.audit)?)?;
            let mut evidence_status = "audit-only (no completed base scan)";
            if let Some(base_scan_id) = store.latest_successful_id()? {
                evidence_status = "not promoted";
                store.start_build_attempt(&base_scan_id, &serde_json::to_value(&outcome.audit)?)?;
                match outcome.audit.outcome {
                    BuildOutcomeKind::Completed => {
                        let snapshot = store.load_snapshot(&base_scan_id)?;
                        let ndjson = if let Some(observation) = outcome.rust_observation.as_ref() {
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
            println!("build run: {}", outcome.audit.run_id);
            println!("status: {:?}", outcome.audit.outcome);
            println!("project code executed: {}", outcome.project_code_executed);
            println!("build evidence: {evidence_status}");
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
                    println!("project code executed: {}", scan.project_code_executed);
                } else {
                    println!("latest attempt: none");
                }
            }
            Ok(0)
        }
        Commands::Deps {
            selector,
            transitive,
            json,
        } => {
            let (snapshot, scan_id) = load_snapshot(cli.store, cli.scan_id.as_deref(), false)?;
            let result = traverse(&snapshot, &selector, transitive, false)?;
            print_structured("deps", scan_id, &result, json)?;
            if !json {
                print_path_steps(&result.steps);
            }
            Ok(0)
        }
        Commands::Dependents {
            selector,
            transitive,
            json,
        } => {
            let (snapshot, scan_id) = load_snapshot(cli.store, cli.scan_id.as_deref(), false)?;
            let result = traverse(&snapshot, &selector, transitive, true)?;
            print_structured("dependents", scan_id, &result, json)?;
            if !json {
                print_path_steps(&result.steps);
            }
            Ok(0)
        }
        Commands::Why { from, to, json } => {
            let (snapshot, scan_id) = load_snapshot(cli.store, cli.scan_id.as_deref(), false)?;
            let result = why(&snapshot, &from, &to)?;
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
        Commands::Snapshot { command } => {
            let root = std::env::current_dir()?;
            let store_path = store_path(cli.store, &root)?;
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
        Commands::Export { format, output } => {
            let (snapshot, _) = load_snapshot(cli.store, cli.scan_id.as_deref(), false)?;
            let format = match format {
                ExportFormatArg::Json => ExportFormat::Json,
                ExportFormatArg::Dot => ExportFormat::Dot,
                ExportFormatArg::Mermaid => ExportFormat::Mermaid,
            };
            let rendered = export(&snapshot, format)?;
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

const BUILD_CONSENT_REQUIRED: &str = "project code execution permission denied: `resolve --build` may execute untrusted build tools, configuration, plugins, build scripts, and proc macros; rerun this invocation with `--allow-project-code` only after reviewing the target repository";

fn require_build_consent(allow_project_code: bool) -> Result<()> {
    if !allow_project_code {
        anyhow::bail!(BUILD_CONSENT_REQUIRED);
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
    use super::{error_exit_code, require_build_consent};

    #[test]
    fn classifies_cli_errors_without_hiding_internal_failures_as_usage() {
        assert_eq!(
            error_exit_code(&anyhow::anyhow!("selector is ambiguous")),
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
}
