use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use depgraph_rust_worker::{
    ADAPTER_VERSION, HirMode, RUST_ANALYZER_CRATE_VERSION, RUST_ANALYZER_REVISION,
    RUST_ANALYZER_SALSA_VERSION, ScanPhaseMetric, scan_with_options_for_emit, write_events,
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
    /// `syntax-only` skips the rust-analyzer HIR backend; the core requests it
    /// only to retry a full analysis that exceeded the worker memory budget.
    #[arg(long, value_enum, default_value_t = HirModeArg::Full)]
    hir_mode: HirModeArg,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum HirModeArg {
    Full,
    SyntaxOnly,
}

impl From<HirModeArg> for HirMode {
    fn from(value: HirModeArg) -> Self {
        match value {
            HirModeArg::Full => Self::Full,
            HirModeArg::SyntaxOnly => Self::SyntaxOnly,
        }
    }
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

    let mut result = scan_with_options_for_emit(
        &args.root,
        args.inventory_file.as_deref(),
        args.hir_mode.into(),
    )?;
    let performance = std::mem::take(&mut result.performance);
    let stdout = std::io::stdout();
    let mut writer = CountingWriter::new(BufWriter::new(stdout.lock()));
    // Events are built and written one at a time from the owned scan result,
    // so the result and a second copy of it as events are never both resident.
    #[cfg(debug_assertions)]
    let mut validator = depgraph_protocol::ProtocolValidator::new();
    let protocol_write_started = Instant::now();
    let protocol_event_count = write_events(&args.scan_id, result, |event| {
        #[cfg(debug_assertions)]
        validator
            .push(event.clone())
            .context("Rust worker generated an invalid protocol event")?;
        serde_json::to_writer(&mut writer, event).context("serialize protocol event")?;
        writer.write_all(b"\n").context("write protocol event")?;
        Ok(())
    })?;
    #[cfg(debug_assertions)]
    validator
        .finish()
        .context("Rust worker generated an incomplete protocol stream")?;
    writer.flush().context("flush protocol output")?;
    let protocol_write_ms = elapsed_ms(protocol_write_started);
    let protocol_bytes = writer.bytes_written();
    if scan_profile_enabled() {
        emit_performance(
            &performance,
            protocol_event_count,
            protocol_write_ms,
            protocol_bytes,
        );
    }
    Ok(())
}

fn emit_performance(
    performance: &[ScanPhaseMetric],
    protocol_event_count: u64,
    protocol_write_ms: u64,
    protocol_bytes: u64,
) {
    for metric in performance {
        eprintln!(
            "depgraph-progress phase={} status=completed duration_ms={} items={} bytes={}",
            metric.phase, metric.duration_ms, metric.items, metric.bytes
        );
    }
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
