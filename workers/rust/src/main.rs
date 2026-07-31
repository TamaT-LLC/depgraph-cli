use anyhow::{Context, Result};
use clap::Parser;
use depgraph_rust_worker::{
    ADAPTER_VERSION, RUST_ANALYZER_CRATE_VERSION, RUST_ANALYZER_REVISION,
    RUST_ANALYZER_SALSA_VERSION, build_events, scan,
};
use std::{
    io::{BufWriter, Write},
    path::PathBuf,
    time::Instant,
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
    let protocol_build_started = Instant::now();
    let events = build_events(&args.scan_id, &result)?;
    let protocol_build_ms = elapsed_ms(protocol_build_started);
    let protocol_event_count = events.len() as u64;
    let stdout = std::io::stdout();
    let mut writer = CountingWriter::new(BufWriter::new(stdout.lock()));
    let protocol_write_started = Instant::now();
    for event in events {
        serde_json::to_writer(&mut writer, &event).context("serialize protocol event")?;
        writer.write_all(b"\n").context("write protocol event")?;
    }
    writer.flush().context("flush protocol output")?;
    let protocol_write_ms = elapsed_ms(protocol_write_started);
    let protocol_bytes = writer.bytes_written();
    if scan_profile_enabled() {
        emit_performance(
            &result,
            protocol_build_ms,
            protocol_event_count,
            protocol_write_ms,
            protocol_bytes,
        );
    }
    Ok(())
}

fn emit_performance(
    result: &depgraph_rust_worker::ScanResult,
    protocol_build_ms: u64,
    protocol_event_count: u64,
    protocol_write_ms: u64,
    protocol_bytes: u64,
) {
    for metric in &result.performance {
        eprintln!(
            "depgraph-progress phase={} status=completed duration_ms={} items={} bytes={}",
            metric.phase, metric.duration_ms, metric.items, metric.bytes
        );
    }
    eprintln!(
        "depgraph-progress phase=rust_protocol_build status=completed duration_ms={protocol_build_ms} items={protocol_event_count} bytes=0"
    );
    eprintln!(
        "depgraph-progress phase=rust_protocol_write status=completed duration_ms={protocol_write_ms} items={protocol_event_count} bytes={protocol_bytes}"
    );
}

fn scan_profile_enabled() -> bool {
    std::env::var("DEPGRAPH_SCAN_PROFILE").as_deref() == Ok("1")
}

struct CountingWriter<W> {
    inner: W,
    bytes_written: u64,
}

impl<W> CountingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            bytes_written: 0,
        }
    }

    fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.bytes_written = self
            .bytes_written
            .saturating_add(written.try_into().unwrap_or(u64::MAX));
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}
