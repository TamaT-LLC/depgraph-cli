use anyhow::{Context, Result};
use clap::Parser;
use depgraph_rust_worker::{
    ADAPTER_VERSION, RUST_ANALYZER_CRATE_VERSION, RUST_ANALYZER_REVISION,
    RUST_ANALYZER_SALSA_VERSION, build_events, scan,
};
use std::{
    io::{BufWriter, Write},
    path::PathBuf,
};

#[derive(Debug, Parser)]
#[command(name = "depgraph-rust-worker", disable_version_flag = true)]
struct Args {
    #[arg(long)]
    root: PathBuf,
    #[arg(long)]
    scan_id: String,
    #[arg(long)]
    inventory_file: Option<PathBuf>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("depgraph-rust-worker: {error:#}");
        std::process::exit(3);
    }
}

fn run() -> Result<()> {
    let raw_args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if raw_args.len() == 1 && matches!(raw_args[0].to_str(), Some("--version" | "-V")) {
        println!(
            "depgraph-rust-worker {ADAPTER_VERSION} (protocol 1.0; rust-analyzer {RUST_ANALYZER_CRATE_VERSION}; rust-analyzer-revision {RUST_ANALYZER_REVISION}; salsa {RUST_ANALYZER_SALSA_VERSION})"
        );
        return Ok(());
    }
    let args = Args::try_parse().map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if args.scan_id.trim().is_empty() {
        anyhow::bail!("--scan-id requires a non-empty identifier");
    }

    let result = match args.inventory_file {
        Some(inventory_file) => {
            depgraph_rust_worker::scan_with_inventory_file(&args.root, &inventory_file)?
        }
        None => scan(&args.root)?,
    };
    let events = build_events(&args.scan_id, &result)?;
    let stdout = std::io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    for event in events {
        serde_json::to_writer(&mut writer, &event).context("serialize protocol event")?;
        writer.write_all(b"\n").context("write protocol event")?;
    }
    writer.flush().context("flush protocol output")
}
