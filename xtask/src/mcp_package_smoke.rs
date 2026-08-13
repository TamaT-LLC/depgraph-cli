use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use depgraph_core::{
    CompilerPackBuildComponent, CompilerPackBuildSpec, CompilerPackRequirement, DepgraphCapability,
    DepgraphCapabilitySet, build_compiler_pack, compiler_pack_host_target, verify_compiler_pack,
};
use depgraph_mcp_tools::{
    AgentContext, AgentDependenciesResponse, OperationId, PortableTerminalOutputContract,
    SuccessEnvelope, ToolCatalog,
};
use depgraph_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

pub const MCP_PACKAGE_SMOKE_SCHEMA_VERSION: &str = "mcp-package-smoke-v1";
pub const SUBMIT_DEADLINE_MS: u64 = 2_000;
pub const EOF_DEADLINE_MS: u64 = 5_000;
const RESPONSE_DEADLINE: Duration = Duration::from_secs(10);
const OPERATION_DEADLINE: Duration = Duration::from_secs(60);
const TOOL_CONTRACT_VERSION: &str = depgraph_mcp_tools::MCP_TOOLS_CONTRACT_VERSION;
const OPERATION_CONTRACT_VERSION: &str = depgraph_operation::OPERATION_CONTRACT_VERSION;
const TOOL_SCHEMA_PATH: &str = "schemas/depgraph-mcp-tools-v1.schema.json";
const DOCUMENTATION_PATH: &str = "docs/50_test/mcp-agent-host-operations.md";
const DOCUMENTATION_MARKER_PREFIX: &str = "<!-- depgraph-mcp-package-smoke:";
const DOCUMENTED_ROOT: &str = "/absolute/path/to/repository";
const DOCUMENTED_STORE: &str = "/absolute/path/to/state/depgraph.sqlite";
const DOCUMENTED_REQUIREMENT: &str = "/absolute/path/to/compiler-pack-requirement.json";
const PROTOCOL_REVISIONS: &[&str] = &["2025-11-25", "2026-07-28"];
const READ_CAPABILITIES: &[DepgraphCapability] = &[DepgraphCapability::Read];
const STORE_WRITE_CAPABILITIES: &[DepgraphCapability] =
    &[DepgraphCapability::Read, DepgraphCapability::StoreWrite];
const CAPABILITY_PROFILES: &[(&str, &[DepgraphCapability])] = &[
    ("read", READ_CAPABILITIES),
    ("store-write", STORE_WRITE_CAPABILITIES),
    (
        "repository-write",
        &[
            DepgraphCapability::Read,
            DepgraphCapability::RepositoryWrite,
        ],
    ),
    (
        "daemon-control",
        &[
            DepgraphCapability::Read,
            DepgraphCapability::StoreWrite,
            DepgraphCapability::DaemonControl,
        ],
    ),
    (
        "project-exec",
        &[
            DepgraphCapability::Read,
            DepgraphCapability::StoreWrite,
            DepgraphCapability::ProjectExec,
        ],
    ),
    (
        "full",
        &[
            DepgraphCapability::Read,
            DepgraphCapability::StoreWrite,
            DepgraphCapability::RepositoryWrite,
            DepgraphCapability::DaemonControl,
            DepgraphCapability::ProjectExec,
        ],
    ),
];

#[derive(Clone, Debug)]
struct DocumentedLaunchProfile {
    executable_relative: PathBuf,
    arguments: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpPackageSmokeReport {
    pub schema_version: String,
    pub target: String,
    pub archive_sha256: String,
    pub release_version: String,
    pub protocol_revisions: Vec<String>,
    pub tool_contract_version: String,
    pub operation_contract_version: String,
    pub tool_schema_sha256: String,
    pub initialization_sha256: BTreeMap<String, String>,
    pub profile_catalog_sha256: BTreeMap<String, String>,
    pub discovery_sha256: String,
    pub context_result_sha256: String,
    pub dependencies_result_sha256: String,
    pub fixture_result_sha256: String,
    pub safe_scan_submit_deadline_ms: u64,
    pub safe_scan_submit_elapsed_ms: u64,
    pub safe_scan_recovered_after_eof: bool,
    pub safe_scan_terminal_status: String,
    pub safe_scan_project_code_executed: bool,
    pub operation_cancel_denied_code: String,
    pub eof_deadline_ms: u64,
    pub stdin_eof_clean_exit: bool,
    pub stdout_json_rpc_only: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct McpPackageSmokeIdentity {
    protocol_revisions: Vec<String>,
    tool_contract_version: String,
    operation_contract_version: String,
    tool_schema_sha256: String,
    initialization_sha256: BTreeMap<String, String>,
    profile_catalog_sha256: BTreeMap<String, String>,
    discovery_sha256: String,
    context_result_sha256: String,
    dependencies_result_sha256: String,
    fixture_result_sha256: String,
    safe_scan_submit_deadline_ms: u64,
    safe_scan_recovered_after_eof: bool,
    safe_scan_terminal_status: String,
    safe_scan_project_code_executed: bool,
    operation_cancel_denied_code: String,
    eof_deadline_ms: u64,
    stdin_eof_clean_exit: bool,
    stdout_json_rpc_only: bool,
}

impl McpPackageSmokeReport {
    #[must_use]
    pub fn cross_target_identity(&self) -> McpPackageSmokeIdentity {
        McpPackageSmokeIdentity {
            protocol_revisions: self.protocol_revisions.clone(),
            tool_contract_version: self.tool_contract_version.clone(),
            operation_contract_version: self.operation_contract_version.clone(),
            tool_schema_sha256: self.tool_schema_sha256.clone(),
            initialization_sha256: self.initialization_sha256.clone(),
            profile_catalog_sha256: self.profile_catalog_sha256.clone(),
            discovery_sha256: self.discovery_sha256.clone(),
            context_result_sha256: self.context_result_sha256.clone(),
            dependencies_result_sha256: self.dependencies_result_sha256.clone(),
            fixture_result_sha256: self.fixture_result_sha256.clone(),
            safe_scan_submit_deadline_ms: self.safe_scan_submit_deadline_ms,
            safe_scan_recovered_after_eof: self.safe_scan_recovered_after_eof,
            safe_scan_terminal_status: self.safe_scan_terminal_status.clone(),
            safe_scan_project_code_executed: self.safe_scan_project_code_executed,
            operation_cancel_denied_code: self.operation_cancel_denied_code.clone(),
            eof_deadline_ms: self.eof_deadline_ms,
            stdin_eof_clean_exit: self.stdin_eof_clean_exit,
            stdout_json_rpc_only: self.stdout_json_rpc_only,
        }
    }
}

pub fn verify_documentation(workspace: &Path, release_version: &str) -> Result<()> {
    documented_launch_profiles(workspace, release_version).map(drop)
}

fn documented_launch_profiles(
    workspace: &Path,
    release_version: &str,
) -> Result<BTreeMap<String, DocumentedLaunchProfile>> {
    let readme = fs::read_to_string(workspace.join("README.md"))?;
    let runbook = fs::read_to_string(workspace.join(DOCUMENTATION_PATH))?;
    let marker_count = readme.matches(DOCUMENTATION_MARKER_PREFIX).count()
        + runbook.matches(DOCUMENTATION_MARKER_PREFIX).count();
    if marker_count != CAPABILITY_PROFILES.len() + 1 {
        bail!(
            "packaged MCP documentation must contain one command and exactly six profile markers"
        );
    }

    let expected_executable =
        format!("/absolute/path/to/depgraph-{release_version}-TARGET_TRIPLE/bin/depgraph-mcp");
    let expected_command = [
        format!("{expected_executable} \\"),
        format!("  --root {DOCUMENTED_ROOT} \\"),
        format!("  --store {DOCUMENTED_STORE} \\"),
        "  --capability read \\".to_owned(),
        format!("  --compiler-pack-requirement {DOCUMENTED_REQUIREMENT} \\"),
        "  --log-level warn".to_owned(),
    ]
    .join("\n");
    let command = marked_code_block(&readme, "command", "sh")?;
    let (command_executable, command_arguments) = documented_shell_command(command)?;
    let command_executable_relative =
        documented_executable_relative(&command_executable, release_version)?;
    if command != expected_command {
        bail!("README packaged MCP command example differs from the read-only launch contract");
    }

    let mut profiles = BTreeMap::new();
    for (name, capabilities) in CAPABILITY_PROFILES.iter().copied() {
        let document = if name == "read" { &readme } else { &runbook };
        let block = marked_code_block(document, name, "json")?;
        let actual: Value = serde_json::from_str(block)
            .with_context(|| format!("packaged MCP {name} documentation is not valid JSON"))?;
        let arguments = expected_documented_arguments(capabilities);
        let expected = json!({
            "mcpServers": {
                "depgraph": {
                    "command": expected_executable.clone(),
                    "args": arguments
                }
            }
        });
        if actual != expected {
            bail!("packaged MCP {name} documentation differs from its exact capability profile");
        }
        let executable = actual["mcpServers"]["depgraph"]["command"]
            .as_str()
            .context("packaged MCP documentation has no command")?;
        let executable_relative = documented_executable_relative(executable, release_version)?;
        let arguments = actual["mcpServers"]["depgraph"]["args"]
            .as_array()
            .context("packaged MCP documentation has no argument array")?
            .iter()
            .map(|argument| {
                argument
                    .as_str()
                    .map(ToOwned::to_owned)
                    .context("packaged MCP documentation contains a non-string argument")
            })
            .collect::<Result<Vec<_>>>()?;
        if name == "read"
            && (executable_relative != command_executable_relative
                || arguments != command_arguments)
        {
            bail!("README packaged MCP command and Agent host entry differ");
        }
        let launch_profile = if name == "read" {
            DocumentedLaunchProfile {
                executable_relative: command_executable_relative.clone(),
                arguments: command_arguments.clone(),
            }
        } else {
            DocumentedLaunchProfile {
                executable_relative,
                arguments,
            }
        };
        if profiles.insert(name.to_owned(), launch_profile).is_some() {
            bail!("packaged MCP documentation contains duplicate profile {name}");
        }
    }
    Ok(profiles)
}

fn documented_shell_command(command: &str) -> Result<(String, Vec<String>)> {
    let lines = command.lines().collect::<Vec<_>>();
    if lines.len() < 2 {
        bail!("README packaged MCP command has no arguments");
    }
    let executable = lines[0]
        .trim()
        .strip_suffix(" \\")
        .context("README packaged MCP command has a malformed executable continuation")?;
    if executable.is_empty()
        || !executable
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        bail!("README packaged MCP executable is not a shell-safe path token");
    }
    let mut arguments = Vec::new();
    for (index, line) in lines.iter().enumerate().skip(1) {
        let line = line.trim();
        let line = if index + 1 == lines.len() {
            line
        } else {
            line.strip_suffix(" \\")
                .context("README packaged MCP command has a malformed continuation")?
        };
        arguments.extend(line.split_ascii_whitespace().map(ToOwned::to_owned));
    }
    Ok((executable.to_owned(), arguments))
}

fn documented_executable_relative(executable: &str, release_version: &str) -> Result<PathBuf> {
    let archive_prefix = format!("/absolute/path/to/depgraph-{release_version}-TARGET_TRIPLE/");
    let relative = executable
        .strip_prefix(&archive_prefix)
        .context("packaged MCP command is outside the documented release directory")?;
    if relative != "bin/depgraph-mcp" {
        bail!("packaged MCP command does not name the packaged native server");
    }
    Ok(PathBuf::from(relative))
}

fn marked_code_block<'a>(document: &'a str, name: &str, language: &str) -> Result<&'a str> {
    let marker = format!("{DOCUMENTATION_MARKER_PREFIX}{name} -->");
    if document.matches(&marker).count() != 1 {
        bail!("packaged MCP documentation marker {name} must appear exactly once");
    }
    let opening = format!("{marker}\n```{language}\n");
    let (_, after) = document.split_once(&opening).with_context(|| {
        format!("packaged MCP documentation marker {name} has no {language} fence")
    })?;
    let (block, _) = after.split_once("\n```\n").with_context(|| {
        format!("packaged MCP documentation marker {name} has no closing fence")
    })?;
    Ok(block)
}

fn expected_documented_arguments(capabilities: &[DepgraphCapability]) -> Vec<String> {
    let mut arguments = vec![
        "--root".to_owned(),
        DOCUMENTED_ROOT.to_owned(),
        "--store".to_owned(),
        DOCUMENTED_STORE.to_owned(),
    ];
    for capability in capabilities {
        arguments.push("--capability".to_owned());
        arguments.push(capability_cli_name(*capability).to_owned());
    }
    arguments.extend([
        "--compiler-pack-requirement".to_owned(),
        DOCUMENTED_REQUIREMENT.to_owned(),
        "--log-level".to_owned(),
        "warn".to_owned(),
    ]);
    arguments
}

pub fn verify(
    workspace: &Path,
    extracted: &Path,
    target: &str,
    archive_sha256: &str,
    release_version: &str,
) -> Result<McpPackageSmokeReport> {
    let host = compiler_pack_host_target().context("MCP smoke host target is unsupported")?;
    if target != host {
        bail!("packaged MCP smoke target {target} does not match native host {host}");
    }
    if !lowercase_sha256(archive_sha256) {
        bail!("packaged MCP smoke received a malformed archive digest");
    }
    let documented_profiles = documented_launch_profiles(workspace, release_version)?;

    let temporary = tempfile::tempdir()?;
    let requirement = create_compiler_pack_requirement(temporary.path(), release_version)?;
    let read_root = temporary.path().join("read-fixture/repository");
    let read_store = temporary.path().join("read-fixture/graph.sqlite");
    prepare_read_fixture(&read_root, &read_store)?;

    let mut initialization_sha256 = BTreeMap::new();
    let mut profile_catalog_sha256 = BTreeMap::new();

    let mut legacy = PackagedMcp::start(
        extracted,
        &read_root,
        &read_store,
        &requirement,
        documented_profiles
            .get("read")
            .context("packaged MCP documentation has no read profile")?,
    )?;
    let legacy_initialize = legacy.initialize(1, PROTOCOL_REVISIONS[0], false)?;
    initialization_sha256.insert(
        PROTOCOL_REVISIONS[0].to_owned(),
        canonical_sha256(&legacy_initialize["result"]),
    );
    let ping = legacy.request(json!({
        "jsonrpc":"2.0", "id":2, "method":"ping", "params":{}
    }))?;
    if ping != json!({"jsonrpc":"2.0", "id":2, "result":{}}) {
        bail!("legacy packaged MCP ping response is incompatible");
    }
    let legacy_tools = legacy.tools_list(3)?;
    let legacy_catalog_sha256 = verify_tools_list(&legacy_tools, READ_CAPABILITIES)?;
    legacy.finish()?;

    let mut context_projection = None;
    let mut dependencies_result = None;
    for (index, (profile_name, capabilities)) in CAPABILITY_PROFILES.iter().copied().enumerate() {
        let mut mcp = PackagedMcp::start(
            extracted,
            &read_root,
            &read_store,
            &requirement,
            documented_profiles.get(profile_name).with_context(|| {
                format!("packaged MCP documentation has no {profile_name} profile")
            })?,
        )?;
        let initialize = mcp.initialize(10 + (index as u64 * 10), PROTOCOL_REVISIONS[1], false)?;
        if profile_name == "read" {
            initialization_sha256.insert(
                PROTOCOL_REVISIONS[1].to_owned(),
                canonical_sha256(&initialize["result"]),
            );
        }
        let tools = mcp.tools_list(11 + (index as u64 * 10))?;
        let catalog_sha256 = verify_tools_list(&tools, capabilities)?;
        if profile_name == "read" && catalog_sha256 != legacy_catalog_sha256 {
            bail!("legacy and modern packaged MCP discovery catalogs differ");
        }
        profile_catalog_sha256.insert(profile_name.to_owned(), catalog_sha256);

        if profile_name == "read" {
            let context = mcp.call_tool(
                12,
                "get_context",
                json!({
                    "contract_version":TOOL_CONTRACT_VERSION,
                    "repository_id":"repository"
                }),
            )?;
            let context_structured = successful_structured_tool_result(&context, "get_context")?;
            serde_json::from_value::<SuccessEnvelope<AgentContext>>(context_structured.clone())
                .context("packaged get_context result violates its closed contract")?;
            context_projection = Some(stable_context_projection(&context_structured)?);

            let dependencies = mcp.call_tool(
                13,
                "graph_dependencies_list",
                json!({
                    "contract_version":TOOL_CONTRACT_VERSION,
                    "repository_id":"repository",
                    "snapshot":"current",
                    "selector":"path:src/source.ts",
                    "transitive":false,
                    "limit":100
                }),
            )?;
            let dependencies_structured =
                successful_structured_tool_result(&dependencies, "graph_dependencies_list")?;
            serde_json::from_value::<SuccessEnvelope<AgentDependenciesResponse>>(
                dependencies_structured.clone(),
            )
            .context("packaged dependencies result violates its closed contract")?;
            verify_dependencies_fixture(&dependencies_structured)?;
            dependencies_result = Some(dependencies_structured);
        }
        mcp.finish()?;
    }

    let context_projection = context_projection.context("read profile did not run get_context")?;
    let dependencies_result =
        dependencies_result.context("read profile did not run graph_dependencies_list")?;
    let context_result_sha256 = canonical_sha256(&context_projection);
    let dependencies_result_sha256 = canonical_sha256(&dependencies_result);
    let fixture_result_sha256 = canonical_sha256(&json!({
        "context_result_sha256":context_result_sha256,
        "dependencies_result_sha256":dependencies_result_sha256
    }));
    let discovery_sha256 = canonical_sha256(&json!({
        "initialization_sha256":initialization_sha256,
        "profile_catalog_sha256":profile_catalog_sha256
    }));

    let durable = verify_durable_scan(
        extracted,
        temporary.path(),
        &requirement,
        &documented_profiles,
    )?;
    let tool_schema_sha256 = sha256_file(&extracted.join(TOOL_SCHEMA_PATH))?;
    let report = McpPackageSmokeReport {
        schema_version: MCP_PACKAGE_SMOKE_SCHEMA_VERSION.to_owned(),
        target: target.to_owned(),
        archive_sha256: archive_sha256.to_owned(),
        release_version: release_version.to_owned(),
        protocol_revisions: PROTOCOL_REVISIONS
            .iter()
            .map(|revision| (*revision).to_owned())
            .collect(),
        tool_contract_version: TOOL_CONTRACT_VERSION.to_owned(),
        operation_contract_version: OPERATION_CONTRACT_VERSION.to_owned(),
        tool_schema_sha256,
        initialization_sha256,
        profile_catalog_sha256,
        discovery_sha256,
        context_result_sha256,
        dependencies_result_sha256,
        fixture_result_sha256,
        safe_scan_submit_deadline_ms: SUBMIT_DEADLINE_MS,
        safe_scan_submit_elapsed_ms: durable.submit_elapsed_ms,
        safe_scan_recovered_after_eof: true,
        safe_scan_terminal_status: "completed".to_owned(),
        safe_scan_project_code_executed: false,
        operation_cancel_denied_code: "CAPABILITY_DENIED".to_owned(),
        eof_deadline_ms: EOF_DEADLINE_MS,
        stdin_eof_clean_exit: true,
        stdout_json_rpc_only: true,
    };
    validate(&report, target, archive_sha256, release_version)?;
    Ok(report)
}

pub fn validate(
    report: &McpPackageSmokeReport,
    target: &str,
    archive_sha256: &str,
    release_version: &str,
) -> Result<()> {
    let expected_protocols = PROTOCOL_REVISIONS
        .iter()
        .map(|revision| (*revision).to_owned())
        .collect::<Vec<_>>();
    if report.schema_version != MCP_PACKAGE_SMOKE_SCHEMA_VERSION
        || report.target != target
        || report.archive_sha256 != archive_sha256
        || !lowercase_sha256(&report.archive_sha256)
        || report.release_version != release_version
        || report.protocol_revisions != expected_protocols
        || report.tool_contract_version != TOOL_CONTRACT_VERSION
        || report.operation_contract_version != OPERATION_CONTRACT_VERSION
        || !lowercase_sha256(&report.tool_schema_sha256)
        || report.safe_scan_submit_deadline_ms != SUBMIT_DEADLINE_MS
        || report.safe_scan_submit_elapsed_ms >= SUBMIT_DEADLINE_MS
        || !report.safe_scan_recovered_after_eof
        || report.safe_scan_terminal_status != "completed"
        || report.safe_scan_project_code_executed
        || report.operation_cancel_denied_code != "CAPABILITY_DENIED"
        || report.eof_deadline_ms != EOF_DEADLINE_MS
        || !report.stdin_eof_clean_exit
        || !report.stdout_json_rpc_only
    {
        bail!("packaged MCP smoke report is incompatible for {target}");
    }
    if report
        .initialization_sha256
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != PROTOCOL_REVISIONS
        || report
            .initialization_sha256
            .values()
            .any(|digest| !lowercase_sha256(digest))
    {
        bail!("packaged MCP initialization digest closure is incompatible");
    }
    let expected_catalogs = expected_profile_catalog_sha256()?;
    if report.profile_catalog_sha256 != expected_catalogs {
        bail!("packaged MCP profile catalog digest closure differs from the compiled catalog");
    }
    for digest in [
        report.discovery_sha256.as_str(),
        report.context_result_sha256.as_str(),
        report.dependencies_result_sha256.as_str(),
        report.fixture_result_sha256.as_str(),
    ] {
        if !lowercase_sha256(digest) {
            bail!("packaged MCP smoke report contains a malformed digest");
        }
    }
    let expected_discovery = canonical_sha256(&json!({
        "initialization_sha256":report.initialization_sha256,
        "profile_catalog_sha256":report.profile_catalog_sha256
    }));
    if report.discovery_sha256 != expected_discovery {
        bail!("packaged MCP discovery digest is not bound to its protocol/profile evidence");
    }
    let expected_fixture = canonical_sha256(&json!({
        "context_result_sha256":report.context_result_sha256,
        "dependencies_result_sha256":report.dependencies_result_sha256
    }));
    if report.fixture_result_sha256 != expected_fixture {
        bail!("packaged MCP fixture digest is not bound to its context/dependencies evidence");
    }
    Ok(())
}

pub fn expected_profile_catalog_sha256() -> Result<BTreeMap<String, String>> {
    CAPABILITY_PROFILES
        .iter()
        .map(|(name, profile_capabilities)| {
            let capabilities =
                DepgraphCapabilitySet::try_new(profile_capabilities.iter().copied())?;
            let catalog =
                ToolCatalog::for_capabilities(&capabilities).map_err(anyhow::Error::msg)?;
            let tools = catalog
                .tools()
                .iter()
                .map(expected_tool_value)
                .collect::<Vec<_>>();
            Ok(((*name).to_owned(), canonical_sha256(&Value::Array(tools))))
        })
        .collect()
}

struct DurableScanEvidence {
    submit_elapsed_ms: u64,
}

fn verify_durable_scan(
    extracted: &Path,
    temporary: &Path,
    requirement: &Path,
    documented_profiles: &BTreeMap<String, DocumentedLaunchProfile>,
) -> Result<DurableScanEvidence> {
    let root = temporary.join("operation-fixture/repository");
    let store = temporary.join("operation-fixture/graph.sqlite");
    fs::create_dir_all(&root)?;
    let source_path = root.join("README.md");
    let source_bytes = b"packaged MCP durable scan fixture\n";
    fs::write(&source_path, source_bytes)?;

    let mut submit = PackagedMcp::start(
        extracted,
        &root,
        &store,
        requirement,
        documented_profiles
            .get("store-write")
            .context("packaged MCP documentation has no store-write profile")?,
    )?;
    submit.initialize(100, PROTOCOL_REVISIONS[1], true)?;
    let started = Instant::now();
    let accepted = submit.request(json!({
        "jsonrpc":"2.0",
        "id":101,
        "method":"tools/call",
        "params":{"name":"scan_submit","arguments":{
            "contract_version":TOOL_CONTRACT_VERSION,
            "repository_id":"repository",
            "idempotency_key":"mcp-package-smoke-safe-scan-v1",
            "strict":false,
            "no_cache":false
        }}
    }))?;
    let elapsed = started.elapsed();
    let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    if elapsed_ms >= SUBMIT_DEADLINE_MS {
        bail!("packaged MCP safe scan submit exceeded {SUBMIT_DEADLINE_MS}ms: {elapsed_ms}ms");
    }
    let task_id = accepted["result"]["taskId"]
        .as_str()
        .context("packaged MCP Tasks submit returned no taskId")?;
    let operation_id = OperationId::parse(task_id)
        .map_err(anyhow::Error::msg)
        .context("packaged MCP Tasks submit returned an invalid operation ID")?;
    submit.finish()?;

    let mut reconnected = PackagedMcp::start(
        extracted,
        &root,
        &store,
        requirement,
        documented_profiles
            .get("store-write")
            .context("packaged MCP documentation has no store-write profile")?,
    )?;
    reconnected.initialize(110, PROTOCOL_REVISIONS[1], true)?;
    let deadline = Instant::now() + OPERATION_DEADLINE;
    let terminal = loop {
        let response = reconnected.request(json!({
            "jsonrpc":"2.0",
            "id":111,
            "method":"tasks/get",
            "params":{"taskId":operation_id.as_str()}
        }))?;
        let status = response["result"]["status"]
            .as_str()
            .context("packaged MCP Tasks status is missing")?;
        match status {
            "completed" => break response,
            "failed" | "cancelled" => {
                bail!("packaged MCP durable safe scan reached terminal status {status}")
            }
            _ if Instant::now() >= deadline => {
                bail!(
                    "packaged MCP durable safe scan did not complete within {OPERATION_DEADLINE:?}"
                )
            }
            _ => std::thread::sleep(Duration::from_millis(25)),
        }
    };
    let terminal_structured = &terminal["result"]["result"]["structuredContent"];
    if terminal_structured["result"]["status"] != "completed"
        || terminal_structured["result"]["project_code_executed"] != false
    {
        bail!("packaged MCP Tasks terminal result lost the safe scan contract");
    }

    let operation_result = reconnected.call_tool(
        112,
        "operation_result",
        json!({
            "contract_version":TOOL_CONTRACT_VERSION,
            "repository_id":"repository",
            "operation_id":operation_id.as_str()
        }),
    )?;
    let operation_structured =
        successful_structured_tool_result(&operation_result, "operation_result")?;
    PortableTerminalOutputContract::ScanSubmit
        .deserialize(operation_structured.clone())
        .context("packaged MCP operation result violates its portable terminal contract")?;
    if &operation_structured != terminal_structured {
        bail!("packaged MCP Tasks and portable operation result differ after reconnect");
    }
    reconnected.finish()?;

    let mut read_only = PackagedMcp::start(
        extracted,
        &root,
        &store,
        requirement,
        documented_profiles
            .get("read")
            .context("packaged MCP documentation has no read profile")?,
    )?;
    read_only.initialize(120, PROTOCOL_REVISIONS[1], false)?;
    let denied = read_only.call_tool(
        121,
        "operation_cancel",
        json!({
            "contract_version":TOOL_CONTRACT_VERSION,
            "repository_id":"repository",
            "operation_id":operation_id.as_str()
        }),
    )?;
    let denied_structured = structured_tool_result(&denied, "operation_cancel")?;
    if denied["isError"] != true || denied_structured["error"]["code"] != "CAPABILITY_DENIED" {
        bail!("packaged MCP read profile did not deny operation_cancel");
    }
    read_only.finish()?;

    if fs::read(&source_path)? != source_bytes {
        bail!("packaged MCP durable safe scan mutated its source fixture");
    }
    Ok(DurableScanEvidence {
        submit_elapsed_ms: elapsed_ms,
    })
}

fn prepare_read_fixture(root: &Path, store_path: &Path) -> Result<()> {
    fs::create_dir_all(root.join("src"))?;
    fs::write(
        root.join("src/source.ts"),
        "import { target } from './target.js';\nexport const source = target;\n",
    )?;
    fs::write(root.join("src/target.ts"), "export const target = 1;\n")?;

    let mut store = Store::open(store_path)?;
    let scan_id = "mcp-package-smoke-read-fixture";
    store.start_scan_with_revision(scan_id, root, false, Some("fixture-revision-v1"))?;
    let coverage = json!({
        "profiles":1,
        "files_discovered":2,
        "files_analyzed":2,
        "files_skipped":0,
        "dependency_sites":0,
        "resolved":0,
        "candidates":0,
        "external":0,
        "unresolved":0,
        "unsupported_syntax":0,
        "project_code_executed":false,
        "completeness":["syntax-complete"],
        "reasons":[]
    });
    let common = |event: &str, seq: u64| {
        json!({
            "event":event,
            "protocol_version":"1.0",
            "scan_id":scan_id,
            "adapter":"fixture",
            "adapter_version":"1.0",
            "seq":seq
        })
    };
    let mut started = common("scan_started", 1);
    started["root"] = json!(root);
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    store.ingest_event(&started)?;
    let mut profile = common("profile_declared", 2);
    profile["profile"] = json!({
        "id":"release:mcp-smoke",
        "language":"fixture",
        "features":[],
        "environment":{},
        "properties":{"contract":"mcp-package-smoke-fixture-v1"}
    });
    store.ingest_event(&profile)?;
    for (seq, id, path, name) in [
        (3, "node:mcp-source", "src/source.ts", "source"),
        (4, "node:mcp-target", "src/target.ts", "target"),
    ] {
        let mut node = common("node_upsert", seq);
        node["node"] = json!({
            "id":id,
            "kind":"file",
            "locator":format!("file:{path}"),
            "display_name":name,
            "properties":{"path":path}
        });
        store.ingest_event(&node)?;
    }
    let mut edge = common("edge_upsert", 5);
    edge["edge"] = json!({
        "id":"edge:mcp-source-target",
        "source":"node:mcp-source",
        "target":"node:mcp-target",
        "kind":"imports",
        "phase":"semantic",
        "environment":"host",
        "profile_id":"release:mcp-smoke",
        "resolution_status":"resolved",
        "precision":"exact",
        "condition":{"op":"all", "conditions":[]},
        "generated":false,
        "evidence":[{
            "kind":"semantic",
            "extractor":"mcp-package-smoke",
            "extractor_version":"1.0",
            "path":"src/source.ts",
            "start_line":1,
            "start_column":1,
            "end_line":1,
            "end_column":39,
            "detail":"fixed release fixture import",
            "properties":{}
        }]
    });
    store.ingest_event(&edge)?;
    for (seq, path) in [(6, "src/source.ts"), (7, "src/target.ts")] {
        let mut file = common("file_completed", seq);
        file["path"] = json!(path);
        file["discovered_sites"] = json!(0);
        file["emitted_sites"] = json!(0);
        file["skipped_sites"] = json!(0);
        file["skipped"] = json!(false);
        store.ingest_event(&file)?;
    }
    let mut profile_completed = common("profile_completed", 8);
    profile_completed["profile_id"] = json!("release:mcp-smoke");
    profile_completed["coverage"] = coverage.clone();
    store.ingest_event(&profile_completed)?;
    let mut completed = common("scan_completed", 9);
    completed["coverage"] = coverage;
    store.ingest_event(&completed)?;
    store.finish_scan(scan_id, "completed", None, true)?;
    Ok(())
}

fn stable_context_projection(structured: &Value) -> Result<Value> {
    let result = structured["result"]
        .as_object()
        .context("packaged get_context result has no result object")?;
    let snapshot = result["snapshot"]
        .as_object()
        .context("packaged get_context result has no snapshot object")?;
    let details = snapshot["details"]
        .as_object()
        .context("packaged get_context fixture has no completed snapshot")?;
    if snapshot["available"] != true
        || structured["snapshot_id"] != details["snapshot_id"]
        || details["profile_ids"] != json!(["release:mcp-smoke"])
    {
        bail!("packaged get_context fixture identity is incompatible");
    }
    Ok(json!({
        "contract_version":structured["contract_version"],
        "repository_id":structured["repository_id"],
        "snapshot_id":structured["snapshot_id"],
        "enabled_capabilities":result["enabled_capabilities"],
        "snapshot":{
            "available":snapshot["available"],
            "snapshot_id":details["snapshot_id"],
            "status":details["status"],
            "source_kind":details["source_kind"],
            "source_revision":details["source_revision"],
            "profile_ids":details["profile_ids"],
            "coverage":details["coverage"]
        }
    }))
}

fn verify_dependencies_fixture(structured: &Value) -> Result<()> {
    let result = &structured["result"];
    let items = result["edges"]["items"]
        .as_array()
        .context("packaged dependencies fixture has no edge page")?;
    if structured["repository_id"] != "repository"
        || result["root"]["id"] != "node:mcp-source"
        || result["direction"] != "outgoing"
        || result["transitive"] != false
        || result["traversal_complete"] != true
        || items.len() != 1
        || items[0]["id"] != "edge:mcp-source-target"
        || items[0]["source_id"] != "node:mcp-source"
        || items[0]["target_id"] != "node:mcp-target"
    {
        bail!("packaged dependencies fixture result is incompatible");
    }
    Ok(())
}

fn verify_tools_list(tools: &[Value], capabilities: &[DepgraphCapability]) -> Result<String> {
    let capabilities = DepgraphCapabilitySet::try_new(capabilities.iter().copied())?;
    let catalog = ToolCatalog::for_capabilities(&capabilities).map_err(anyhow::Error::msg)?;
    let expected = catalog
        .tools()
        .iter()
        .map(expected_tool_value)
        .collect::<Vec<_>>();
    if tools != expected {
        bail!("packaged MCP tools/list differs from its compiled capability profile");
    }
    Ok(canonical_sha256(&Value::Array(tools.to_vec())))
}

fn expected_tool_value(tool: &depgraph_mcp_tools::ToolDefinition) -> Value {
    json!({
        "name":tool.name(),
        "description":tool.description(),
        "inputSchema":tool.input_schema(),
        "outputSchema":tool.output_schema()
    })
}

fn successful_structured_tool_result(result: &Value, tool: &str) -> Result<Value> {
    if result["isError"] != false {
        bail!("packaged MCP {tool} returned a tool error");
    }
    structured_tool_result(result, tool)
}

fn structured_tool_result(result: &Value, tool: &str) -> Result<Value> {
    let structured = result["structuredContent"].clone();
    if !structured.is_object() {
        bail!("packaged MCP {tool} omitted structuredContent");
    }
    let content = result["content"]
        .as_array()
        .context("packaged MCP tool result has no content array")?;
    if content.len() != 1 || content[0]["type"] != "text" {
        bail!("packaged MCP {tool} did not return one canonical text mirror");
    }
    let mirrored: Value = serde_json::from_str(
        content[0]["text"]
            .as_str()
            .context("packaged MCP tool text mirror is missing")?,
    )?;
    if mirrored != structured {
        bail!("packaged MCP {tool} text and structured results differ");
    }
    Ok(structured)
}

struct PackagedMcp {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<std::io::Result<Vec<u8>>>,
    stdout_reader: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
    stderr_reader: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
    consumed_stdout: Vec<u8>,
    finished: bool,
}

impl PackagedMcp {
    fn start(
        extracted: &Path,
        root: &Path,
        store: &Path,
        requirement: &Path,
        documented_profile: &DocumentedLaunchProfile,
    ) -> Result<Self> {
        let mut executable = extracted.join(&documented_profile.executable_relative);
        if cfg!(windows) {
            executable.set_extension("exe");
        }
        let mut command = Command::new(&executable);
        command
            .current_dir(extracted)
            .args(render_documented_arguments(
                documented_profile,
                root,
                store,
                requirement,
            ))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for variable in [
            "DEPGRAPH_RUST_WORKER",
            "DEPGRAPH_GO_WORKER",
            "DEPGRAPH_WEB_WORKER",
        ] {
            command.env_remove(variable);
        }
        let mut child = command.spawn().with_context(|| {
            format!(
                "failed to start packaged MCP server {}",
                executable.display()
            )
        })?;
        let stdin = child
            .stdin
            .take()
            .context("packaged MCP stdin is unavailable")?;
        let stdout = child
            .stdout
            .take()
            .context("packaged MCP stdout is unavailable")?;
        let stderr = child
            .stderr
            .take()
            .context("packaged MCP stderr is unavailable")?;
        let (sender, lines) = mpsc::channel();
        let stdout_reader = std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut captured = Vec::new();
            loop {
                let mut line = Vec::new();
                let bytes = reader.read_until(b'\n', &mut line)?;
                if bytes == 0 {
                    break;
                }
                captured.extend_from_slice(&line);
                if sender.send(Ok(line)).is_err() {
                    break;
                }
            }
            Ok(captured)
        });
        let stderr_reader = std::thread::spawn(move || {
            let mut reader = stderr;
            let mut captured = Vec::new();
            reader.read_to_end(&mut captured)?;
            Ok(captured)
        });
        Ok(Self {
            child,
            stdin: Some(stdin),
            lines,
            stdout_reader: Some(stdout_reader),
            stderr_reader: Some(stderr_reader),
            consumed_stdout: Vec::new(),
            finished: false,
        })
    }

    fn initialize(&mut self, id: u64, protocol: &str, tasks: bool) -> Result<Value> {
        let capabilities = if tasks {
            json!({"extensions":{"io.modelcontextprotocol/tasks":{}}})
        } else {
            json!({})
        };
        let response = self.request(json!({
            "jsonrpc":"2.0",
            "id":id,
            "method":"initialize",
            "params":{
                "protocolVersion":protocol,
                "capabilities":capabilities,
                "clientInfo":{"name":"depgraph-release-smoke", "version":"1"}
            }
        }))?;
        if response["result"]["protocolVersion"] != protocol
            || response["result"]["serverInfo"]["name"] != "depgraph-mcp"
            || !response["result"]["serverInfo"]["version"].is_string()
            || !response["result"]["capabilities"]["tools"].is_object()
        {
            bail!("packaged MCP initialize response is incompatible with {protocol}");
        }
        Ok(response)
    }

    fn tools_list(&mut self, id: u64) -> Result<Vec<Value>> {
        let response = self.request(json!({
            "jsonrpc":"2.0", "id":id, "method":"tools/list", "params":{}
        }))?;
        response["result"]["tools"]
            .as_array()
            .cloned()
            .context("packaged MCP tools/list response has no tools")
    }

    fn call_tool(&mut self, id: u64, name: &str, arguments: Value) -> Result<Value> {
        let response = self.request(json!({
            "jsonrpc":"2.0",
            "id":id,
            "method":"tools/call",
            "params":{"name":name, "arguments":arguments}
        }))?;
        if !response["result"].is_object() {
            bail!("packaged MCP {name} call returned no tool result");
        }
        Ok(response["result"].clone())
    }

    fn request(&mut self, request: Value) -> Result<Value> {
        let expected_id = request["id"].clone();
        let mut bytes = serde_json::to_vec(&request)?;
        bytes.push(b'\n');
        let stdin = self
            .stdin
            .as_mut()
            .context("packaged MCP stdin is closed")?;
        stdin.write_all(&bytes)?;
        stdin.flush()?;
        let line = self
            .lines
            .recv_timeout(RESPONSE_DEADLINE)
            .context("packaged MCP response deadline exceeded")??;
        self.consumed_stdout.extend_from_slice(&line);
        if !line.ends_with(b"\n") || line == b"\n" {
            bail!("packaged MCP stdout contains a non-message byte sequence");
        }
        let response: Value = serde_json::from_slice(&line)
            .context("packaged MCP stdout contains non-JSON-RPC bytes")?;
        if response["jsonrpc"] != "2.0" || response["id"] != expected_id {
            bail!("packaged MCP response does not match its request ID");
        }
        Ok(response)
    }

    fn finish(mut self) -> Result<()> {
        drop(self.stdin.take());
        let deadline = Instant::now() + Duration::from_millis(EOF_DEADLINE_MS);
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                bail!("packaged MCP server did not exit after stdin EOF");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let stdout = self
            .stdout_reader
            .take()
            .context("packaged MCP stdout reader is missing")?
            .join()
            .map_err(|_| anyhow::anyhow!("packaged MCP stdout reader panicked"))??;
        let stderr = self
            .stderr_reader
            .take()
            .context("packaged MCP stderr reader is missing")?
            .join()
            .map_err(|_| anyhow::anyhow!("packaged MCP stderr reader panicked"))??;
        if !status.success() {
            bail!(
                "packaged MCP server failed after EOF: {}",
                String::from_utf8_lossy(&stderr)
            );
        }
        if !stderr.is_empty() {
            bail!(
                "packaged MCP server wrote stderr during smoke: {}",
                String::from_utf8_lossy(&stderr)
            );
        }
        if stdout != self.consumed_stdout || self.lines.try_iter().next().is_some() {
            bail!("packaged MCP stdout contains an unexpected message or non-message bytes");
        }
        self.finished = true;
        Ok(())
    }
}

fn render_documented_arguments(
    profile: &DocumentedLaunchProfile,
    root: &Path,
    store: &Path,
    requirement: &Path,
) -> Vec<OsString> {
    profile
        .arguments
        .iter()
        .map(|argument| match argument.as_str() {
            DOCUMENTED_ROOT => root.as_os_str().to_owned(),
            DOCUMENTED_STORE => store.as_os_str().to_owned(),
            DOCUMENTED_REQUIREMENT => requirement.as_os_str().to_owned(),
            _ => OsString::from(argument),
        })
        .collect()
}

impl Drop for PackagedMcp {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        drop(self.stdin.take());
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.stdout_reader.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }
}

fn create_compiler_pack_requirement(directory: &Path, release_version: &str) -> Result<PathBuf> {
    let source = directory.join("compiler-pack-source");
    let pack = directory.join("compiler-pack");
    fs::create_dir(&source)?;
    let component = |name: &str, files: Vec<String>| CompilerPackBuildComponent {
        name: name.to_owned(),
        archive_sha256: "0".repeat(64),
        source: format!(
            "https://static.rust-lang.org/dist/2026-07-17/{name}-nightly-mcp-smoke.tar.xz"
        ),
        files,
    };
    let host = compiler_pack_host_target()
        .context("packaged MCP smoke compiler-pack host is unsupported")?
        .to_owned();
    let spec = CompilerPackBuildSpec {
        host: host.clone(),
        target: host.clone(),
        release_checksum_reference: format!(
            "release-checksums:v{release_version}/mcp-smoke-compiler-pack-{host}"
        ),
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
            fs::create_dir_all(path.parent().context("compiler-pack file has no parent")?)?;
            fs::write(path, format!("mcp-smoke:{}", component.name))?;
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
        fs::create_dir_all(
            path.parent()
                .context("compiler-pack support file has no parent")?,
        )?;
        fs::write(path, b"mcp-package-smoke-fixture")?;
    }
    for relative in [
        spec.cargo_path.as_str(),
        spec.rustc_path.as_str(),
        spec.wrapper_path.as_str(),
        spec.query_path.as_str(),
    ] {
        make_executable(&source.join(relative))?;
    }
    let verified = build_compiler_pack(&source, &pack, &spec)?;
    let requirement = CompilerPackRequirement {
        root: pack,
        expected_manifest_sha256: verified.attestation.manifest_sha256,
        release_checksum_reference: spec.release_checksum_reference,
        host: spec.host,
        target: spec.target,
    };
    verify_compiler_pack(&requirement)?;
    let path = directory.join("mcp-smoke-compiler-pack-requirement.json");
    fs::write(&path, serde_json::to_vec(&requirement)?)?;
    Ok(path)
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

fn capability_cli_name(capability: DepgraphCapability) -> &'static str {
    match capability {
        DepgraphCapability::Read => "read",
        DepgraphCapability::StoreWrite => "store-write",
        DepgraphCapability::RepositoryWrite => "repository-write",
        DepgraphCapability::DaemonControl => "daemon-control",
        DepgraphCapability::ProjectExec => "project-exec",
    }
}

fn canonical_sha256(value: &Value) -> String {
    hex::encode(Sha256::digest(
        depgraph_protocol::canonical_json(value).as_bytes(),
    ))
}

fn sha256_file(path: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(fs::read(path).with_context(
        || format!("failed to read {}", path.display()),
    )?)))
}

fn lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_host_documentation_profiles_are_exact_and_read_only_by_default() -> Result<()> {
        verify_documentation(&crate::workspace_root(), crate::VERSION)
    }

    #[test]
    fn agent_host_documentation_rejects_privileged_default_and_duplicate_markers() -> Result<()> {
        let workspace = crate::workspace_root();
        let temporary = tempfile::tempdir()?;
        fs::create_dir_all(temporary.path().join("docs/50_test"))?;
        let readme = fs::read_to_string(workspace.join("README.md"))?;
        let runbook = fs::read_to_string(workspace.join(DOCUMENTATION_PATH))?;
        fs::write(
            temporary.path().join("README.md"),
            readme.replacen(
                "\"--capability\", \"read\",",
                "\"--capability\", \"store-write\",",
                1,
            ),
        )?;
        fs::write(temporary.path().join(DOCUMENTATION_PATH), &runbook)?;
        assert!(verify_documentation(temporary.path(), crate::VERSION).is_err());

        fs::write(temporary.path().join("README.md"), &readme)?;
        fs::write(
            temporary.path().join(DOCUMENTATION_PATH),
            format!(
                "{runbook}\n<!-- depgraph-mcp-package-smoke:store-write -->\n```json\n{{}}\n```\n"
            ),
        )?;
        assert!(verify_documentation(temporary.path(), crate::VERSION).is_err());
        Ok(())
    }

    #[test]
    fn documented_shell_command_rejects_executable_metacharacters() {
        let unsafe_command = concat!(
            "/absolute/path/to/depgraph-0.4.0-<target>/bin/depgraph-mcp \\\n",
            "  --capability read"
        );
        let error = documented_shell_command(unsafe_command).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("executable is not a shell-safe path token")
        );
    }

    #[test]
    fn profile_catalog_digests_are_closed_and_sorted() -> Result<()> {
        let digests = expected_profile_catalog_sha256()?;
        assert_eq!(
            digests.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "daemon-control",
                "full",
                "project-exec",
                "read",
                "repository-write",
                "store-write"
            ]
        );
        assert!(digests.values().all(|digest| lowercase_sha256(digest)));
        Ok(())
    }

    #[test]
    fn report_validation_rejects_timing_digest_and_recovery_drift() -> Result<()> {
        let initialization_sha256 = BTreeMap::from([
            ("2025-11-25".to_owned(), "1".repeat(64)),
            ("2026-07-28".to_owned(), "2".repeat(64)),
        ]);
        let profile_catalog_sha256 = expected_profile_catalog_sha256()?;
        let discovery_sha256 = canonical_sha256(&json!({
            "initialization_sha256":initialization_sha256,
            "profile_catalog_sha256":profile_catalog_sha256
        }));
        let report = McpPackageSmokeReport {
            schema_version: MCP_PACKAGE_SMOKE_SCHEMA_VERSION.to_owned(),
            target: "x86_64-unknown-linux-gnu".to_owned(),
            archive_sha256: "a".repeat(64),
            release_version: "0.4.0".to_owned(),
            protocol_revisions: PROTOCOL_REVISIONS
                .iter()
                .map(|revision| (*revision).to_owned())
                .collect(),
            tool_contract_version: TOOL_CONTRACT_VERSION.to_owned(),
            operation_contract_version: OPERATION_CONTRACT_VERSION.to_owned(),
            tool_schema_sha256: "3".repeat(64),
            initialization_sha256,
            profile_catalog_sha256,
            discovery_sha256,
            context_result_sha256: "4".repeat(64),
            dependencies_result_sha256: "5".repeat(64),
            fixture_result_sha256: canonical_sha256(&json!({
                "context_result_sha256":"4".repeat(64),
                "dependencies_result_sha256":"5".repeat(64)
            })),
            safe_scan_submit_deadline_ms: SUBMIT_DEADLINE_MS,
            safe_scan_submit_elapsed_ms: SUBMIT_DEADLINE_MS - 1,
            safe_scan_recovered_after_eof: true,
            safe_scan_terminal_status: "completed".to_owned(),
            safe_scan_project_code_executed: false,
            operation_cancel_denied_code: "CAPABILITY_DENIED".to_owned(),
            eof_deadline_ms: EOF_DEADLINE_MS,
            stdin_eof_clean_exit: true,
            stdout_json_rpc_only: true,
        };
        let validate_report = |report: &McpPackageSmokeReport| {
            validate(report, "x86_64-unknown-linux-gnu", &"a".repeat(64), "0.4.0")
        };
        validate_report(&report)?;

        let mut timing = report.clone();
        timing.safe_scan_submit_elapsed_ms += 1;
        assert!(validate_report(&timing).is_err());
        let mut catalog = report.clone();
        catalog
            .profile_catalog_sha256
            .insert("read".to_owned(), "f".repeat(64));
        assert!(validate_report(&catalog).is_err());
        let mut fixture = report.clone();
        fixture.fixture_result_sha256 = "f".repeat(64);
        assert!(validate_report(&fixture).is_err());
        let mut recovery = report.clone();
        recovery.safe_scan_recovered_after_eof = false;
        assert!(validate_report(&recovery).is_err());

        let identity = report.cross_target_identity();
        let mut another_target = report.clone();
        another_target.target = "aarch64-apple-darwin".to_owned();
        another_target.archive_sha256 = "b".repeat(64);
        another_target.safe_scan_submit_elapsed_ms = 1;
        assert_eq!(identity, another_target.cross_target_identity());
        another_target.context_result_sha256 = "7".repeat(64);
        assert_ne!(identity, another_target.cross_target_identity());

        let mut unknown_field = serde_json::to_value(&report)?;
        unknown_field["unattested"] = json!(true);
        assert!(serde_json::from_value::<McpPackageSmokeReport>(unknown_field).is_err());
        let mut target_binding = report;
        target_binding.target = "aarch64-unknown-linux-gnu".to_owned();
        assert!(validate_report(&target_binding).is_err());
        Ok(())
    }
}
