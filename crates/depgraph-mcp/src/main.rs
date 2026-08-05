use std::{
    borrow::Cow,
    io::{self, Write as _},
    path::PathBuf,
    process::ExitCode,
    sync::{Arc, Mutex},
};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, ValueEnum};
use depgraph_core::{
    DepgraphCapability, DepgraphCapabilitySet, DepgraphService, DepgraphServiceConfig,
    DepgraphServiceLimits, VerifiedCompilerPack, read_compiler_pack_requirement,
    verify_compiler_pack,
};
use depgraph_mcp::runtime::{AuditLogger, RuntimeConfig, RuntimeController};
use depgraph_mcp_tools::ToolCatalog;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
    model::{
        Implementation, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo,
        Tool, ToolsCapability,
    },
    service::{RequestContext, RxJsonRpcMessage, TxJsonRpcMessage},
    transport::Transport,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex as AsyncMutex,
};
use tracing_subscriber::fmt::MakeWriter as _;

const MAX_INBOUND_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_STDERR_RECORD_BYTES: usize = 1024;
const MAX_STDERR_TOTAL_BYTES: usize = 16 * 1024;
const STARTUP_ERROR: &str = "depgraph-mcp: invalid startup configuration\n";
const INBOUND_ERROR: &str = "depgraph-mcp: inbound message rejected\n";

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CapabilityArg {
    #[value(name = "read")]
    Read,
    #[value(name = "store-write")]
    StoreWrite,
    #[value(name = "repository-write")]
    RepositoryWrite,
    #[value(name = "daemon-control")]
    DaemonControl,
    #[value(name = "project-exec")]
    ProjectExec,
}

impl From<CapabilityArg> for DepgraphCapability {
    fn from(value: CapabilityArg) -> Self {
        match value {
            CapabilityArg::Read => Self::Read,
            CapabilityArg::StoreWrite => Self::StoreWrite,
            CapabilityArg::RepositoryWrite => Self::RepositoryWrite,
            CapabilityArg::DaemonControl => Self::DaemonControl,
            CapabilityArg::ProjectExec => Self::ProjectExec,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for tracing::level_filters::LevelFilter {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Error => Self::ERROR,
            LogLevel::Warn => Self::WARN,
            LogLevel::Info => Self::INFO,
            LogLevel::Debug => Self::DEBUG,
            LogLevel::Trace => Self::TRACE,
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "depgraph-mcp", about = "depgraph MCP server over stdio")]
struct Args {
    /// Existing repository directory to analyze.
    #[arg(long)]
    root: PathBuf,

    /// Absolute fixed path to the depgraph store file.
    #[arg(long)]
    store: PathBuf,

    /// Explicitly granted service capabilities. Repeat for every capability.
    #[arg(long, required = true)]
    capability: Vec<CapabilityArg>,

    /// Regular, non-symlink compiler-pack requirement JSON file (at most 1 MiB).
    #[arg(long)]
    compiler_pack_requirement: PathBuf,

    /// Bounded stderr log severity.
    #[arg(long, value_enum, default_value_t = LogLevel::Warn)]
    log_level: LogLevel,
}

struct DepgraphMcpServer {
    // Retained as immutable server state so tool handlers share one validated setup and runtime.
    service: DepgraphService,
    compiler_pack: VerifiedCompilerPack,
    runtime: RuntimeController,
    audit: AuditLogger,
    tools: Arc<[Tool]>,
}

impl ServerHandler for DepgraphMcpServer {
    fn get_info(&self) -> ServerInfo {
        let _ = (
            &self.service,
            &self.compiler_pack,
            &self.runtime,
            &self.audit,
        );
        let mut tools = ToolsCapability::default();
        tools.list_changed = Some(false);
        let mut capabilities = ServerCapabilities::default();
        capabilities.tools = Some(tools);
        ServerInfo::new(capabilities).with_server_info(
            Implementation::new("depgraph-mcp", env!("CARGO_PKG_VERSION"))
                .with_description("depgraph MCP server"),
        )
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, McpError>> + '_ {
        std::future::ready(Ok(ListToolsResult::with_all_items(self.tools.to_vec())))
    }
}

#[derive(Clone)]
struct BoundedStderr {
    written: Arc<Mutex<usize>>,
}

impl BoundedStderr {
    fn new() -> Self {
        Self {
            written: Arc::new(Mutex::new(0)),
        }
    }

    fn write_message(&self, message: &str) {
        let mut writer = self.make_writer();
        let _ = writer.write_all(message.as_bytes());
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BoundedStderr {
    type Writer = BoundedStderrWriter;

    fn make_writer(&'a self) -> Self::Writer {
        BoundedStderrWriter {
            written: Arc::clone(&self.written),
            record_remaining: MAX_STDERR_RECORD_BYTES,
        }
    }
}

struct BoundedStderrWriter {
    written: Arc<Mutex<usize>>,
    record_remaining: usize,
}

fn bounded_write_len(total_written: usize, record_remaining: usize, input_len: usize) -> usize {
    input_len
        .min(record_remaining)
        .min(MAX_STDERR_TOTAL_BYTES.saturating_sub(total_written))
}

impl io::Write for BoundedStderrWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let allowed = {
            let mut written = self.written.lock().expect("stderr bound mutex poisoned");
            let allowed = bounded_write_len(*written, self.record_remaining, buffer.len());
            if allowed != 0 {
                io::stderr().lock().write_all(&buffer[..allowed])?;
                *written += allowed;
                self.record_remaining -= allowed;
            }
            allowed
        };
        // Logging must never turn an exhausted diagnostic budget into a failure path.
        Ok(if allowed == buffer.len() {
            allowed
        } else {
            buffer.len()
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct TransportState {
    inbound_rejected: std::sync::atomic::AtomicBool,
    eof: std::sync::atomic::AtomicBool,
}

struct BoundedStdioTransport<R, W> {
    reader: R,
    writer: Arc<AsyncMutex<W>>,
    frame: Vec<u8>,
    pending: Vec<u8>,
    pending_offset: usize,
    state: Arc<TransportState>,
}

impl<R, W> BoundedStdioTransport<R, W> {
    fn new(reader: R, writer: W, state: Arc<TransportState>) -> Self {
        Self {
            reader,
            writer: Arc::new(AsyncMutex::new(writer)),
            frame: Vec::with_capacity(8192),
            pending: Vec::with_capacity(8192),
            pending_offset: 0,
            state,
        }
    }
}

impl<R, W> Transport<RoleServer> for BoundedStdioTransport<R, W>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin + 'static,
{
    type Error = io::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let writer = Arc::clone(&self.writer);
        async move {
            let encoded = serde_json::to_vec(&item).map_err(io::Error::other)?;
            let mut writer = writer.lock().await;
            writer.write_all(&encoded).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await
        }
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        loop {
            if self.pending_offset == self.pending.len() {
                self.pending.clear();
                self.pending_offset = 0;
                let mut chunk = [0_u8; 8192];
                let read = match self.reader.read(&mut chunk).await {
                    Ok(read) => read,
                    Err(_) => return None,
                };
                if read == 0 {
                    if self.frame.len() > MAX_INBOUND_MESSAGE_BYTES {
                        self.state
                            .inbound_rejected
                            .store(true, std::sync::atomic::Ordering::Release);
                        return None;
                    }
                    self.state
                        .eof
                        .store(true, std::sync::atomic::Ordering::Release);
                    return None;
                }
                self.pending.extend_from_slice(&chunk[..read]);
            }

            let byte = self.pending[self.pending_offset];
            self.pending_offset += 1;
            if byte == b'\n' {
                let frame = std::mem::take(&mut self.frame);
                let frame = frame.strip_suffix(b"\r").unwrap_or(&frame);
                if frame.is_empty() {
                    continue;
                }
                match serde_json::from_slice(frame) {
                    Ok(message) => return Some(message),
                    // Unparseable peer input is intentionally ignored without logging it.
                    Err(_) => continue,
                }
            }
            let may_be_crlf_terminator =
                self.frame.len() == MAX_INBOUND_MESSAGE_BYTES && byte == b'\r';
            if self.frame.len() >= MAX_INBOUND_MESSAGE_BYTES && !may_be_crlf_terminator {
                self.state
                    .inbound_rejected
                    .store(true, std::sync::atomic::Ordering::Release);
                return None;
            }
            self.frame.push(byte);
        }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.writer.lock().await.shutdown().await
    }
}

fn build_server(args: &Args) -> Result<DepgraphMcpServer> {
    let capabilities =
        DepgraphCapabilitySet::try_new(args.capability.iter().copied().map(Into::into))
            .context("invalid capability set")?;
    let compiler_pack_requirement = read_compiler_pack_requirement(&args.compiler_pack_requirement)
        .context("invalid compiler pack requirement")?;
    let compiler_pack = verify_compiler_pack(&compiler_pack_requirement)
        .context("compiler pack verification failed")?;
    let catalog = ToolCatalog::for_capabilities(&capabilities)
        .map_err(anyhow::Error::msg)
        .context("invalid tool catalog")?;
    let tools = catalog
        .tools()
        .iter()
        .map(|definition| {
            let mut tool = Tool::default();
            tool.name = Cow::Owned(definition.name().to_owned());
            tool.description = Some(Cow::Owned(definition.description().to_owned()));
            tool.input_schema = Arc::new(definition.input_schema().clone());
            tool.output_schema = Some(Arc::new(definition.output_schema().clone()));
            tool
        })
        .collect::<Vec<_>>()
        .into();
    let config = DepgraphServiceConfig::new(
        &args.root,
        &args.store,
        capabilities,
        DepgraphServiceLimits::default(),
    )
    .context("invalid server configuration")?;

    let runtime = RuntimeController::new(RuntimeConfig::default())
        .context("invalid MCP runtime configuration")?;
    Ok(DepgraphMcpServer {
        service: DepgraphService::new(config),
        compiler_pack,
        runtime,
        audit: AuditLogger::default(),
        tools,
    })
}

async fn run(args: Args) -> Result<()> {
    let server = build_server(&args)?;
    let state = Arc::new(TransportState::default());
    let transport =
        BoundedStdioTransport::new(tokio::io::stdin(), tokio::io::stdout(), Arc::clone(&state));
    let running = match server.serve(transport).await {
        Ok(running) => running,
        Err(_)
            if state
                .inbound_rejected
                .load(std::sync::atomic::Ordering::Acquire) =>
        {
            bail!("inbound message rejected")
        }
        Err(_) if state.eof.load(std::sync::atomic::Ordering::Acquire) => return Ok(()),
        Err(_) => bail!("MCP stdio initialization failed"),
    };
    match running.waiting().await {
        Ok(_)
            if state
                .inbound_rejected
                .load(std::sync::atomic::Ordering::Acquire) =>
        {
            bail!("inbound message rejected")
        }
        Ok(_) => Ok(()),
        Err(_)
            if state
                .inbound_rejected
                .load(std::sync::atomic::Ordering::Acquire) =>
        {
            bail!("inbound message rejected")
        }
        Err(_) => bail!("MCP server task failed"),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let stderr = BoundedStderr::new();
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(_) => {
            stderr.write_message(STARTUP_ERROR);
            return ExitCode::FAILURE;
        }
    };
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::level_filters::LevelFilter::OFF.into())
        .parse_lossy(format!(
            "depgraph_mcp={}",
            tracing::level_filters::LevelFilter::from(args.log_level)
        ));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(stderr.clone())
        .without_time()
        .init();

    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if error.to_string() == "inbound message rejected" => {
            stderr.write_message(INBOUND_ERROR);
            ExitCode::FAILURE
        }
        Err(_) => {
            stderr.write_message(STARTUP_ERROR);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_stderr_limits_each_record_and_total_output() {
        assert_eq!(
            bounded_write_len(0, MAX_STDERR_RECORD_BYTES, usize::MAX),
            MAX_STDERR_RECORD_BYTES
        );
        assert_eq!(bounded_write_len(MAX_STDERR_TOTAL_BYTES - 2, 10, 99), 2);
        assert_eq!(bounded_write_len(MAX_STDERR_TOTAL_BYTES, 10, 99), 0);
    }
}
