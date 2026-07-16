use std::{path::PathBuf, process::ExitCode};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use depgraph_core::{
    Config, CycleLevel, ExportFormat, default_store_path, doctor, export, init_config, open_store,
    render_condition, run_scan, traverse, unresolved, why,
};
use serde::Serialize;

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
    /// Export the selected scan in a deterministic format.
    Export {
        #[arg(long, value_enum)]
        format: ExportFormatArg,
        #[arg(short, long)]
        output: Option<PathBuf>,
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
        || [
            "selector",
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
                        "{} {} at {} profile={} condition={} span={} ({})",
                        site.kind,
                        site.specifier.unwrap_or_default(),
                        site.source,
                        site.profile_id,
                        render_condition(&site.condition),
                        span.unwrap_or_else(|| "unknown".to_owned()),
                        site.reason
                            .unwrap_or_else(|| "no reason provided".to_owned())
                    );
                }
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

fn print_path_steps(steps: &[depgraph_core::query::PathStep]) {
    for step in steps {
        let edge = &step.edge;
        println!(
            "{} --{} [{}; {}; {}]--> {}",
            edge.source,
            edge.kind,
            edge.resolution_status,
            edge.precision,
            edge.profile_id,
            edge.target
        );
        println!("    condition: {}", step.condition_text);
        print_evidence(&step.evidence, "    ");
    }
}

fn print_why_steps(steps: &[depgraph_core::query::PathStep]) {
    for step in steps {
        println!(
            "  --{} [{}; {}; {}]--> {}",
            step.edge.kind,
            step.edge.resolution_status,
            step.edge.precision,
            step.edge.profile_id,
            step.edge.target
        );
        println!("      condition: {}", step.condition_text);
        print_evidence(&step.evidence, "      ");
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
    use super::error_exit_code;

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
            error_exit_code(&anyhow::anyhow!("security policy violation")),
            4
        );
        assert_eq!(
            error_exit_code(&anyhow::anyhow!("database disk image is malformed")),
            3
        );
    }
}
