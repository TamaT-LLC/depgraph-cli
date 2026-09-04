use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufRead as _, BufReader, Read as _, Write as _},
    path::{Component, Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use depgraph_core::{
    DepgraphCapabilitySet, DepgraphServiceConfig, DepgraphServiceLimits, compiler_pack_host_target,
    read_compiler_pack_requirement, verify_compiler_pack,
};
use depgraph_mcp_tools::{
    AgentContext, AgentHostCapabilityProfile, AgentHostFormat, MCP_PROTOCOL_REVISION, MCP_SDK_NAME,
    MCP_SDK_VERSION, MCP_TOOLS_CONTRACT_VERSION, SuccessEnvelope, ToolCatalog,
    agent_host_launch_arguments, render_agent_host_configuration,
};
use depgraph_store::Store;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 1024;
const MAX_RELEASE_EVIDENCE_BYTES: u64 = 1024 * 1024;
const MAX_RELEASE_ARCHIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_RELEASE_ARCHIVE_ENTRIES: usize = 250_000;
const MAX_RELEASE_ARCHIVE_EXPANDED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_PUBLIC_RELEASE_ASSET_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const RELEASE_POST_PUBLISH_EVIDENCE_SCHEMA_VERSION: &str = "release-post-publish-evidence-v1";
const OFFICIAL_RELEASE_REPOSITORY: &str = "TamaT-LLC/depgraph-cli";
const FULL_CI_JOB_NAMES: &[&str] = &[
    "benchmark",
    "compiler-precise-hostile",
    "go",
    "integration (macos-15, aarch64-apple-darwin)",
    "integration (ubuntu-24.04, x86_64-unknown-linux-gnu, -C linker-features=-lld)",
    "rust",
    "web",
    "windows-smoke",
];
const RELEASE_TARGETS: &[(&str, &str)] = &[
    ("aarch64-apple-darwin", "tar.gz"),
    ("aarch64-unknown-linux-gnu", "tar.gz"),
    ("x86_64-apple-darwin", "tar.gz"),
    ("x86_64-pc-windows-msvc", "zip"),
    ("x86_64-unknown-linux-gnu", "tar.gz"),
];
const INITIALIZE_RESPONSE_DEADLINE: Duration = Duration::from_secs(30);
const RESPONSE_DEADLINE: Duration = Duration::from_secs(10);
const EOF_DEADLINE: Duration = Duration::from_secs(5);
const MCP_TOOL_SCHEMA_BYTES: &[u8] =
    include_bytes!("../../../schemas/depgraph-mcp-tools-v1.schema.json");

fn probe_response_deadline(method: Option<&str>) -> Duration {
    if method == Some("initialize") {
        INITIALIZE_RESPONSE_DEADLINE
    } else {
        RESPONSE_DEADLINE
    }
}

pub struct AgentConfigRequest<'a> {
    pub root: &'a Path,
    pub store: &'a Path,
    pub release_archive: &'a Path,
    pub release_checksum: &'a Path,
    pub release_evidence: &'a Path,
    pub trusted_release_evidence_sha256: &'a str,
    pub release_manifest: &'a Path,
    pub compiler_pack_requirement: &'a Path,
    pub format: AgentHostFormat,
    pub profile: AgentHostCapabilityProfile,
    pub acknowledge_privileged_effects: bool,
    pub acknowledge_project_exec_human_confirmation: bool,
}

pub struct AgentConfigOutput {
    pub configuration: String,
    pub release_version: String,
    pub target: String,
    pub archive_sha256: String,
    pub release_tag: String,
    pub release_evidence_sha256: String,
    pub canonical_root: PathBuf,
    pub canonical_store: PathBuf,
    pub current_snapshot_id: String,
    pub tool_count: usize,
}

#[derive(Debug, Deserialize)]
struct ReleaseManifestProjection {
    release_version: String,
    protocol_version: String,
    schema_version: String,
    target: String,
    core: Artifact,
    mcp_server: McpServerArtifact,
    operation_runner: OperationRunnerArtifact,
    mcp_tool_schema: VersionedArtifact,
    workers: Vec<WorkerArtifact>,
}

#[derive(Debug, Deserialize)]
struct Artifact {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct VersionedArtifact {
    contract_version: String,
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct McpServerArtifact {
    version: String,
    path: String,
    sha256: String,
    sdk_name: String,
    sdk_version: String,
    protocol_revision: String,
    tool_contract_version: String,
    operation_contract_version: String,
}

#[derive(Debug, Deserialize)]
struct OperationRunnerArtifact {
    version: String,
    operation_contract_version: String,
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct WorkerArtifact {
    adapter: String,
    version: String,
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseAssetEvidence {
    name: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseCandidateEvidence {
    commit: String,
    tree: String,
    tag_object: String,
    tag_signature_verification: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FullCiJobEvidence {
    name: String,
    conclusion: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FullCiRunEvidence {
    run_id: u64,
    url: String,
    head_sha: String,
    head_branch: String,
    jobs: Vec<FullCiJobEvidence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseWorkflowEvidence {
    run_id: u64,
    url: String,
    head_sha: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseAggregateEvidence {
    release_verification_sha256: String,
    compiler_pack_verification_sha256: String,
    benchmark_report_sha256: String,
    cache_hit_benchmark_report_sha256: String,
    stable_release_gate_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasePostPublishEvidence {
    schema_version: String,
    repository: String,
    release_version: String,
    tag: String,
    decision: String,
    candidate: ReleaseCandidateEvidence,
    full_ci: FullCiRunEvidence,
    release_workflow: ReleaseWorkflowEvidence,
    workflow_public_asset_identity: bool,
    public_download_reverified: bool,
    asset_set_sha256: String,
    assets: Vec<ReleaseAssetEvidence>,
    aggregates: ReleaseAggregateEvidence,
}

struct LocalReleaseAsset {
    name: String,
    bytes: u64,
    sha256: String,
}

struct VerifiedArchiveBinding {
    archive: LocalReleaseAsset,
    checksum: LocalReleaseAsset,
}

struct VerifiedReleaseTrust {
    tag: String,
    evidence_sha256: String,
}

pub(crate) struct VerifiedAgentPackage {
    release_root: PathBuf,
    core: PathBuf,
    mcp: PathBuf,
    requirement_path: PathBuf,
    release_version: String,
    target: String,
    archive_sha256: String,
    release_tag: String,
    release_evidence_sha256: String,
}

impl VerifiedAgentPackage {
    pub(crate) fn core(&self) -> &Path {
        &self.core
    }
}

pub fn generate(request: &AgentConfigRequest<'_>) -> Result<AgentConfigOutput> {
    let executable = std::env::current_exe()
        .context("Agent host preflight cannot locate the running depgraph executable")?;
    generate_for_executable(request, &executable)
}

fn generate_for_executable(
    request: &AgentConfigRequest<'_>,
    current_executable: &Path,
) -> Result<AgentConfigOutput> {
    let package = verify_package_for_executable(request, current_executable)?;
    generate_with_verified_package(request, package)
}

pub(crate) fn verify_package_for_executable(
    request: &AgentConfigRequest<'_>,
    current_executable: &Path,
) -> Result<VerifiedAgentPackage> {
    validate_acknowledgements(request)?;
    let manifest_path = verified_regular_file(
        request.release_manifest,
        MAX_MANIFEST_BYTES,
        "release manifest",
    )?;
    let release_root = manifest_path
        .parent()
        .context("Agent host preflight release manifest has no parent")?;
    let root_metadata = fs::symlink_metadata(release_root)
        .context("Agent host preflight release root is unavailable")?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        security_bail("release root must be a real directory")?;
    }
    let release_root = release_root
        .canonicalize()
        .context("Agent host preflight cannot canonicalize the release root")?;
    if manifest_path != release_root.join("release-manifest.json") {
        security_bail("release manifest is not at the release root")?;
    }

    let manifest_bytes = fs::read(&manifest_path)?;
    let manifest: ReleaseManifestProjection = serde_json::from_slice(&manifest_bytes)
        .context("Agent host preflight release manifest is invalid")?;
    validate_manifest_identity(&manifest)?;
    let expected_package_name =
        format!("depgraph-{}-{}", manifest.release_version, manifest.target);
    if release_root.file_name().and_then(|name| name.to_str()) != Some(&expected_package_name) {
        security_bail("extracted release directory name does not match manifest version/target")?;
    }

    let archive = verify_archive_binding(
        request.release_archive,
        request.release_checksum,
        &expected_package_name,
        &manifest.target,
        &manifest_bytes,
    )?;
    let requirement_path = verified_regular_file(
        request.compiler_pack_requirement,
        1024 * 1024,
        "compiler-pack requirement",
    )?;
    let requirement_asset = local_release_asset(&requirement_path)?;
    let release_trust = verify_release_evidence(
        request.release_evidence,
        request.trusted_release_evidence_sha256,
        &manifest.release_version,
        &manifest.target,
        [&archive.archive, &archive.checksum, &requirement_asset],
    )?;
    let current_executable = current_executable
        .canonicalize()
        .context("Agent host preflight cannot canonicalize the running executable")?;
    let expected_core_path = format!("bin/{}", executable_name("depgraph"));
    if manifest.core.path != expected_core_path {
        security_bail("release manifest core path is incompatible")?;
    }
    let core = verify_release_artifact(&release_root, &manifest.core, "depgraph core")?;
    if core != current_executable {
        security_bail("running depgraph executable is not the manifest-attested package core")?;
    }
    require_executable(&core, "depgraph core")?;

    let mcp = verify_mcp_closure(&release_root, &manifest)?;
    if !request.compiler_pack_requirement.is_absolute() {
        security_bail("compiler-pack requirement path must be absolute")?;
    }
    let requirement = read_compiler_pack_requirement(&requirement_path)
        .context("Agent host preflight compiler-pack requirement is invalid")?;
    validate_compiler_pack_release_binding(
        &requirement.release_checksum_reference,
        &manifest.release_version,
        &manifest.target,
    )?;
    let compiler_pack = verify_compiler_pack(&requirement)
        .context("Agent host preflight compiler-pack verification failed")?;
    if compiler_pack.attestation.host != manifest.target
        || compiler_pack.attestation.target != manifest.target
    {
        security_bail("compiler-pack host/target differs from the release manifest")?;
    }

    Ok(VerifiedAgentPackage {
        release_root,
        core,
        mcp,
        requirement_path,
        release_version: manifest.release_version,
        target: manifest.target,
        archive_sha256: archive.archive.sha256,
        release_tag: release_trust.tag,
        release_evidence_sha256: release_trust.evidence_sha256,
    })
}

pub(crate) fn validated_binding(request: &AgentConfigRequest<'_>) -> Result<DepgraphServiceConfig> {
    validate_acknowledgements(request)?;

    let capabilities =
        DepgraphCapabilitySet::try_new(request.profile.capabilities().iter().copied())
            .context("Agent host preflight capability closure is invalid")?;
    let config = DepgraphServiceConfig::new(
        request.root,
        request.store,
        capabilities.clone(),
        DepgraphServiceLimits::default(),
    )
    .context("Agent host preflight root/Store binding is invalid")?;
    if config.store_path().starts_with(config.canonical_root()) {
        security_bail("private Agent Store must be outside the repository root")?;
    }
    Ok(config)
}

pub(crate) fn generate_with_verified_package(
    request: &AgentConfigRequest<'_>,
    package: VerifiedAgentPackage,
) -> Result<AgentConfigOutput> {
    let config = validated_binding(request)?;
    let root_seal = config.repository_root_seal();
    if !root_seal.matches_live_root() {
        security_bail("repository root seal changed during preflight")?;
    }
    let current_snapshot_id = verify_store_binding(&config, &package.core)?;

    let mcp_string = utf8_path(&package.mcp, "MCP executable")?;
    let root_string = utf8_path(config.canonical_root(), "repository root")?;
    let store_string = utf8_path(config.store_path(), "Store")?;
    let requirement_string = utf8_path(&package.requirement_path, "compiler-pack requirement")?;
    let arguments = agent_host_launch_arguments(
        request.profile,
        root_string,
        store_string,
        requirement_string,
    );
    let tool_count = probe_connection(
        &package.release_root,
        &package.mcp,
        &arguments,
        request.profile,
        config.logical_repository_id(),
        &current_snapshot_id,
    )?;
    if !root_seal.matches_live_root() {
        security_bail("repository root seal changed before configuration generation")?;
    }
    let configuration = render_agent_host_configuration(
        request.format,
        request.profile,
        mcp_string,
        root_string,
        store_string,
        requirement_string,
    )
    .map_err(anyhow::Error::msg)
    .context("Agent host configuration rendering failed")?;
    Ok(AgentConfigOutput {
        configuration,
        release_version: package.release_version,
        target: package.target,
        archive_sha256: package.archive_sha256,
        release_tag: package.release_tag,
        release_evidence_sha256: package.release_evidence_sha256,
        canonical_root: config.canonical_root().to_path_buf(),
        canonical_store: config.store_path().to_path_buf(),
        current_snapshot_id,
        tool_count,
    })
}

fn validate_acknowledgements(request: &AgentConfigRequest<'_>) -> Result<()> {
    if request.profile.is_privileged() && !request.acknowledge_privileged_effects {
        bail!(
            "profile {} has privileged effects ({}); pass --acknowledge-privileged-effects after review",
            request.profile.as_str(),
            request.profile.effect_summary()
        );
    }
    if request.profile.permits_project_execution()
        && !request.acknowledge_project_exec_human_confirmation
    {
        bail!(
            "profile {} permits project code execution; pass --acknowledge-project-exec-human-confirmation only when the Agent host requires an independent human decision for each resolve-build request",
            request.profile.as_str()
        );
    }
    if request.acknowledge_project_exec_human_confirmation
        && !request.profile.permits_project_execution()
    {
        bail!(
            "--acknowledge-project-exec-human-confirmation is only valid for project-exec or full"
        );
    }
    Ok(())
}

fn validate_manifest_identity(manifest: &ReleaseManifestProjection) -> Result<()> {
    let host = compiler_pack_host_target()
        .context("Agent host preflight does not support this native host target")?;
    if manifest.release_version != env!("CARGO_PKG_VERSION")
        || manifest.protocol_version != "1.0"
        || manifest.schema_version != "1.0"
        || manifest.target != host
    {
        security_bail("release manifest version/protocol/target is incompatible")?;
    }
    Ok(())
}

fn validate_compiler_pack_release_binding(
    checksum_reference: &str,
    release_version: &str,
    target: &str,
) -> Result<()> {
    let expected = format!("release-checksums:v{release_version}/compiler-pack-{target}");
    if checksum_reference != expected {
        security_bail("compiler-pack requirement belongs to a different product release")?;
    }
    Ok(())
}

fn verify_mcp_closure(
    release_root: &Path,
    manifest: &ReleaseManifestProjection,
) -> Result<PathBuf> {
    let expected_mcp = format!("bin/{}", executable_name("depgraph-mcp"));
    if manifest.mcp_server.version != env!("CARGO_PKG_VERSION")
        || manifest.mcp_server.path != expected_mcp
        || manifest.mcp_server.sdk_name != MCP_SDK_NAME
        || manifest.mcp_server.sdk_version != MCP_SDK_VERSION
        || manifest.mcp_server.protocol_revision != MCP_PROTOCOL_REVISION
        || manifest.mcp_server.tool_contract_version != MCP_TOOLS_CONTRACT_VERSION
        || manifest.mcp_server.operation_contract_version
            != depgraph_operation::OPERATION_CONTRACT_VERSION
    {
        security_bail("release manifest MCP compatibility unit is incompatible")?;
    }
    let mcp = verify_release_artifact(
        release_root,
        &Artifact {
            path: manifest.mcp_server.path.clone(),
            sha256: manifest.mcp_server.sha256.clone(),
        },
        "MCP server",
    )?;
    require_executable(&mcp, "MCP server")?;

    let expected_runner = format!("libexec/{}", executable_name("depgraph-operation-runner"));
    if manifest.operation_runner.version != env!("CARGO_PKG_VERSION")
        || manifest.operation_runner.operation_contract_version
            != depgraph_operation::OPERATION_CONTRACT_VERSION
        || manifest.operation_runner.path != expected_runner
    {
        security_bail("release manifest operation-runner compatibility unit is incompatible")?;
    }
    let runner = verify_release_artifact(
        release_root,
        &Artifact {
            path: manifest.operation_runner.path.clone(),
            sha256: manifest.operation_runner.sha256.clone(),
        },
        "operation runner",
    )?;
    require_executable(&runner, "operation runner")?;

    if manifest.mcp_tool_schema.contract_version != MCP_TOOLS_CONTRACT_VERSION
        || manifest.mcp_tool_schema.path != "schemas/depgraph-mcp-tools-v1.schema.json"
    {
        security_bail("release manifest MCP tool schema identity is incompatible")?;
    }
    let schema = verify_release_artifact(
        release_root,
        &Artifact {
            path: manifest.mcp_tool_schema.path.clone(),
            sha256: manifest.mcp_tool_schema.sha256.clone(),
        },
        "MCP tool schema",
    )?;
    if fs::read(schema)? != MCP_TOOL_SCHEMA_BYTES {
        security_bail("packaged MCP tool schema differs from the compiled contract")?;
    }

    let mut workers = BTreeMap::new();
    for worker in &manifest.workers {
        if workers.insert(worker.adapter.as_str(), worker).is_some() {
            security_bail("release manifest contains a duplicate worker adapter")?;
        }
    }
    if workers.len() != 3 {
        security_bail("release manifest worker closure is incomplete or unknown")?;
    }
    for (adapter, basename, executable) in [
        ("rust", "depgraph-rust-worker", true),
        ("go", "depgraph-go-worker", true),
        ("web", "depgraph-web-worker.mjs", false),
    ] {
        let worker = workers.get(adapter).with_context(|| {
            format!("Agent host preflight release manifest has no {adapter} worker")
        })?;
        let expected_path = if executable {
            format!("libexec/{}", executable_name(basename))
        } else {
            format!("libexec/{basename}")
        };
        if worker.version != env!("CARGO_PKG_VERSION") || worker.path != expected_path {
            security_bail("release manifest worker version/path is incompatible")?;
        }
        let path = verify_release_artifact(
            release_root,
            &Artifact {
                path: worker.path.clone(),
                sha256: worker.sha256.clone(),
            },
            "worker",
        )?;
        if executable {
            require_executable(&path, "worker")?;
        }
    }
    Ok(mcp)
}

fn verify_store_binding(config: &DepgraphServiceConfig, core: &Path) -> Result<String> {
    match current_snapshot_if_valid(config) {
        Ok(Some(snapshot_id)) => Ok(snapshot_id),
        Ok(None) => bail!(
            "no current completed snapshot is available from the private Store; {}",
            safe_scan_remediation(core, config.canonical_root(), config.store_path())?
        ),
        Err(error) => bail!(
            "no current completed snapshot is available from the private Store: {error:#}; {}",
            safe_scan_remediation(core, config.canonical_root(), config.store_path())?
        ),
    }
}

pub(crate) fn current_snapshot_if_valid(config: &DepgraphServiceConfig) -> Result<Option<String>> {
    match fs::symlink_metadata(config.store_path()) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            security_bail("private Agent Store must be a regular non-symlink file")?;
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("Agent host preflight cannot inspect the Store"),
    }
    let store = Store::open_read_only(config.store_path())?;
    let Some(current_snapshot_id) = store.current_snapshot_id()? else {
        return Ok(None);
    };
    let details = store.completed_snapshot_details(&current_snapshot_id)?;
    let scan = store
        .scan(&details.snapshot.scan_id)?
        .context("Agent host preflight current snapshot has no source scan")?;
    let stored_root = PathBuf::from(&scan.root)
        .canonicalize()
        .context("Agent host preflight current snapshot source root is unavailable")?;
    if stored_root != config.canonical_root() {
        security_bail("private Store current snapshot belongs to a different repository root")?;
    }
    Ok(Some(current_snapshot_id))
}

fn safe_scan_remediation(core: &Path, root: &Path, store: &Path) -> Result<String> {
    let argv = [
        utf8_path(core, "depgraph core")?.to_owned(),
        "scan".to_owned(),
        utf8_path(root, "repository root")?.to_owned(),
        "--store".to_owned(),
        utf8_path(store, "Store")?.to_owned(),
        "--json".to_owned(),
    ];
    Ok(format!(
        "prepare one safe snapshot as a separate Store-write operation with argv {} and rerun agent-config",
        serde_json::to_string(&argv)?
    ))
}

fn verify_archive_binding(
    archive: &Path,
    checksum: &Path,
    package_name: &str,
    target: &str,
    extracted_manifest: &[u8],
) -> Result<VerifiedArchiveBinding> {
    let expected_extension = if target.ends_with("windows-msvc") {
        ".zip"
    } else {
        ".tar.gz"
    };
    let expected_archive_name = format!("{package_name}{expected_extension}");
    if archive.file_name().and_then(|name| name.to_str()) != Some(&expected_archive_name) {
        security_bail("release archive filename does not match manifest version/target")?;
    }
    let archive = verified_regular_file(archive, MAX_RELEASE_ARCHIVE_BYTES, "release archive")?;
    let expected_checksum_name = format!("{expected_archive_name}.sha256");
    if checksum.file_name().and_then(|name| name.to_str()) != Some(&expected_checksum_name) {
        security_bail("release checksum filename does not match the selected archive")?;
    }
    let checksum = verified_regular_file(checksum, MAX_CHECKSUM_BYTES, "release checksum")?;
    let archive_sha256 = sha256_file(&archive)?;
    let expected_sidecar = format!("{archive_sha256}  {expected_archive_name}\n");
    if fs::read(&checksum)? != expected_sidecar.as_bytes() {
        security_bail("release checksum sidecar does not attest the selected archive")?;
    }
    let archived_manifest = if expected_extension == ".zip" {
        manifest_from_zip(&archive, package_name)?
    } else {
        manifest_from_tar_gz(&archive, package_name)?
    };
    if archived_manifest != extracted_manifest {
        security_bail("extracted release manifest differs from the checksum-verified archive")?;
    }
    Ok(VerifiedArchiveBinding {
        archive: LocalReleaseAsset {
            name: expected_archive_name,
            bytes: fs::metadata(&archive)?.len(),
            sha256: archive_sha256,
        },
        checksum: local_release_asset(&checksum)?,
    })
}

fn local_release_asset(path: &Path) -> Result<LocalReleaseAsset> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("Agent host preflight release asset filename is not valid UTF-8")?
        .to_owned();
    Ok(LocalReleaseAsset {
        name,
        bytes: fs::metadata(path)?.len(),
        sha256: sha256_file(path)?,
    })
}

fn verify_release_evidence(
    evidence_path: &Path,
    trusted_evidence_sha256: &str,
    release_version: &str,
    target: &str,
    local_assets: [&LocalReleaseAsset; 3],
) -> Result<VerifiedReleaseTrust> {
    if !valid_sha256(trusted_evidence_sha256) {
        security_bail("trusted release-evidence digest is malformed")?;
    }
    let evidence_path = verified_regular_file(
        evidence_path,
        MAX_RELEASE_EVIDENCE_BYTES,
        "release post-publish evidence",
    )?;
    let evidence_sha256 = sha256_file(&evidence_path)?;
    if evidence_sha256 != trusted_evidence_sha256 {
        security_bail(
            "release post-publish evidence does not match the independently obtained digest",
        )?;
    }
    let evidence: ReleasePostPublishEvidence =
        serde_json::from_slice(&fs::read(&evidence_path)?)
            .context("Agent host preflight release evidence violates its closed schema")?;
    let expected_evidence_name = format!("release-post-publish-evidence-{}.json", evidence.tag);
    if evidence_path.file_name().and_then(|name| name.to_str())
        != Some(expected_evidence_name.as_str())
        || evidence.schema_version != RELEASE_POST_PUBLISH_EVIDENCE_SCHEMA_VERSION
        || evidence.repository != OFFICIAL_RELEASE_REPOSITORY
        || evidence.release_version != release_version
        || !supported_release_tag(&evidence.tag, release_version)
        || evidence.decision != "allow"
        || !evidence.workflow_public_asset_identity
        || !evidence.public_download_reverified
        || !matches!(
            evidence.candidate.tag_signature_verification.as_str(),
            "valid" | "unknown_key" | "unverified_email"
        )
        || !lowercase_git_sha(&evidence.candidate.commit)
        || !lowercase_git_sha(&evidence.candidate.tree)
        || !lowercase_git_sha(&evidence.candidate.tag_object)
        || evidence.release_workflow.run_id == 0
        || evidence.release_workflow.url
            != canonical_actions_run_url(evidence.release_workflow.run_id)
        || evidence.release_workflow.head_sha != evidence.candidate.commit
        || evidence.full_ci.run_id == 0
        || evidence.full_ci.url != canonical_actions_run_url(evidence.full_ci.run_id)
        || evidence.full_ci.head_sha != evidence.candidate.commit
        || evidence.full_ci.head_branch != "main"
    {
        security_bail("release evidence is not an allowed official post-publish record")?;
    }

    let actual_jobs = evidence
        .full_ci
        .jobs
        .iter()
        .map(|job| job.name.as_str())
        .collect::<Vec<_>>();
    if actual_jobs != FULL_CI_JOB_NAMES
        || evidence
            .full_ci
            .jobs
            .iter()
            .any(|job| job.conclusion != "success")
    {
        security_bail("release evidence does not contain the exact all-green Full CI closure")?;
    }

    let expected_names = expected_release_asset_names(release_version);
    let mut assets = BTreeMap::new();
    for asset in &evidence.assets {
        if !expected_names.contains(&asset.name)
            || asset.bytes == 0
            || asset.bytes > MAX_PUBLIC_RELEASE_ASSET_BYTES
            || !valid_sha256(&asset.sha256)
            || assets.insert(asset.name.clone(), asset).is_some()
        {
            security_bail("release evidence contains an invalid or duplicate asset")?;
        }
    }
    if assets.len() != expected_names.len()
        || assets.keys().cloned().collect::<BTreeSet<_>>() != expected_names
        || evidence
            .assets
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
        || release_asset_set_sha256(&evidence.assets) != evidence.asset_set_sha256
    {
        security_bail("release evidence asset set is incomplete, reordered, or unbound")?;
    }
    for local in local_assets {
        let published = assets
            .get(&local.name)
            .with_context(|| format!("official release evidence has no {}", local.name))?;
        if published.bytes != local.bytes || published.sha256 != local.sha256 {
            security_bail("local release input differs from the official public asset identity")?;
        }
    }

    for (name, aggregate) in [
        (
            "release-verification.json",
            evidence.aggregates.release_verification_sha256.as_str(),
        ),
        (
            "compiler-pack-verification.json",
            evidence
                .aggregates
                .compiler_pack_verification_sha256
                .as_str(),
        ),
        (
            "benchmark-report.json",
            evidence.aggregates.benchmark_report_sha256.as_str(),
        ),
        (
            "cache-hit-benchmark-report.json",
            evidence
                .aggregates
                .cache_hit_benchmark_report_sha256
                .as_str(),
        ),
        (
            "stable-release-gate.json",
            evidence.aggregates.stable_release_gate_sha256.as_str(),
        ),
    ] {
        if assets.get(name).map(|asset| asset.sha256.as_str()) != Some(aggregate) {
            security_bail("release evidence aggregate digest is not bound to its public asset")?;
        }
    }

    let requirement_name =
        format!("depgraph-compiler-pack-{release_version}-{target}.requirement.json");
    if local_assets[2].name != requirement_name {
        security_bail("compiler-pack requirement is not the official target asset")?;
    }
    Ok(VerifiedReleaseTrust {
        tag: evidence.tag,
        evidence_sha256,
    })
}

fn expected_release_asset_names(release_version: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::from([
        "benchmark-report.json".to_owned(),
        "cache-hit-benchmark-report.json".to_owned(),
        "compiler-pack-verification.json".to_owned(),
        "compiler-precise-hostile-e2e.json".to_owned(),
        "release-verification.json".to_owned(),
        "stable-release-gate.json".to_owned(),
    ]);
    for (target, extension) in RELEASE_TARGETS {
        for name in [
            format!("depgraph-{release_version}-{target}.{extension}"),
            format!("depgraph-{release_version}-{target}.{extension}.sha256"),
            format!("depgraph-{release_version}-{target}.query-smoke.json"),
            format!("depgraph-{release_version}-{target}.cross-language-smoke.json"),
            format!("depgraph-{release_version}-{target}.mcp-smoke.json"),
            format!("depgraph-compiler-pack-{release_version}-{target}.{extension}"),
            format!("depgraph-compiler-pack-{release_version}-{target}.{extension}.sha256"),
            format!("depgraph-compiler-pack-{release_version}-{target}.requirement.json"),
            format!("depgraph-compiler-pack-{release_version}-{target}.smoke.json"),
        ] {
            names.insert(name);
        }
    }
    names
}

fn release_asset_set_sha256(assets: &[ReleaseAssetEvidence]) -> String {
    let mut digest = Sha256::new();
    for asset in assets {
        digest.update(asset.name.as_bytes());
        digest.update([0]);
        digest.update(asset.bytes.to_string().as_bytes());
        digest.update([0]);
        digest.update(asset.sha256.as_bytes());
        digest.update([b'\n']);
    }
    hex::encode(digest.finalize())
}

fn supported_release_tag(tag: &str, release_version: &str) -> bool {
    let stable = format!("v{release_version}");
    if tag == stable {
        return true;
    }
    tag.strip_prefix(&format!("{stable}-rc."))
        .is_some_and(|candidate| {
            !candidate.is_empty()
                && !candidate.starts_with('0')
                && candidate.bytes().all(|byte| byte.is_ascii_digit())
                && candidate.parse::<u64>().is_ok_and(|number| number > 0)
        })
}

fn lowercase_git_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_actions_run_url(run_id: u64) -> String {
    format!("https://github.com/{OFFICIAL_RELEASE_REPOSITORY}/actions/runs/{run_id}")
}

fn manifest_from_tar_gz(archive: &Path, package_name: &str) -> Result<Vec<u8>> {
    let expected = PathBuf::from(package_name).join("release-manifest.json");
    let decoder = flate2::read::GzDecoder::new(File::open(archive)?);
    let mut archive = tar::Archive::new(decoder);
    let mut manifest = None;
    let mut entries = 0_usize;
    let mut expanded_bytes = 0_u64;
    for entry in archive
        .entries()
        .context("Agent host preflight cannot read release archive")?
    {
        let mut entry = entry?;
        entries = entries
            .checked_add(1)
            .context("Agent host preflight release archive entry count overflow")?;
        expanded_bytes = expanded_bytes
            .checked_add(entry.size())
            .context("Agent host preflight release archive size overflow")?;
        if entries > MAX_RELEASE_ARCHIVE_ENTRIES
            || expanded_bytes > MAX_RELEASE_ARCHIVE_EXPANDED_BYTES
        {
            security_bail("release archive exceeds the bounded entry/expanded-size closure")?;
        }
        let path = entry.path()?.into_owned();
        if path != expected {
            continue;
        }
        if manifest.is_some() || !entry.header().entry_type().is_file() {
            security_bail("release archive contains an invalid duplicate manifest entry")?;
        }
        if entry.size() > MAX_MANIFEST_BYTES {
            security_bail("release archive manifest exceeds the size limit")?;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        manifest = Some(bytes);
    }
    manifest.context("Agent host preflight release archive has no manifest")
}

fn manifest_from_zip(archive: &Path, package_name: &str) -> Result<Vec<u8>> {
    let expected = format!("{package_name}/release-manifest.json");
    let mut archive = zip::ZipArchive::new(File::open(archive)?)
        .context("Agent host preflight cannot read release zip")?;
    if archive.len() > MAX_RELEASE_ARCHIVE_ENTRIES {
        security_bail("release zip exceeds the bounded entry closure")?;
    }
    let mut index = None;
    let mut expanded_bytes = 0_u64;
    for candidate in 0..archive.len() {
        let entry = archive.by_index(candidate)?;
        expanded_bytes = expanded_bytes
            .checked_add(entry.size())
            .context("Agent host preflight release zip size overflow")?;
        if expanded_bytes > MAX_RELEASE_ARCHIVE_EXPANDED_BYTES {
            security_bail("release zip exceeds the bounded expanded-size closure")?;
        }
        if entry.name() == expected && index.replace(candidate).is_some() {
            security_bail("release zip contains a duplicate manifest entry")?;
        }
    }
    let index = index.context("Agent host preflight release zip has no manifest")?;
    let mut entry = archive.by_index(index)?;
    if !entry.is_file() || entry.size() > MAX_MANIFEST_BYTES {
        security_bail("release zip manifest entry is invalid")?;
    }
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn verify_release_artifact(
    release_root: &Path,
    artifact: &Artifact,
    description: &str,
) -> Result<PathBuf> {
    if !valid_sha256(&artifact.sha256) {
        security_bail("release manifest contains a malformed artifact digest")?;
    }
    let declared = Path::new(&artifact.path);
    if declared.is_absolute()
        || declared
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        security_bail("release manifest contains an unsafe artifact path")?;
    }
    let mut candidate = release_root.to_path_buf();
    for component in declared.components() {
        let Component::Normal(component) = component else {
            unreachable!();
        };
        candidate.push(component);
        if fs::symlink_metadata(&candidate).is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            security_bail("release artifact path contains a symlink")?;
        }
    }
    let candidate = candidate
        .canonicalize()
        .with_context(|| format!("Agent host preflight {description} is missing"))?;
    if !candidate.starts_with(release_root) || !candidate.is_file() {
        security_bail("release artifact escapes its package root or is not a file")?;
    }
    if sha256_file(&candidate)? != artifact.sha256 {
        security_bail("release artifact checksum mismatch")?;
    }
    Ok(candidate)
}

fn verified_regular_file(path: &Path, maximum_bytes: u64, description: &str) -> Result<PathBuf> {
    if !path.is_absolute() {
        security_bail("preflight input file paths must be absolute")?;
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("Agent host preflight {description} is unavailable"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        security_bail("preflight input must be a bounded regular non-symlink file")?;
    }
    path.canonicalize()
        .with_context(|| format!("Agent host preflight cannot canonicalize {description}"))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut input = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(unix)]
fn require_executable(path: &Path, description: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    if fs::metadata(path)?.permissions().mode() & 0o111 == 0 {
        security_bail(&format!("packaged {description} is not executable"))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_executable(path: &Path, description: &str) -> Result<()> {
    if !path.is_file() {
        security_bail(&format!("packaged {description} is not executable"))?;
    }
    Ok(())
}

fn executable_name(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}

fn utf8_path<'a>(path: &'a Path, description: &str) -> Result<&'a str> {
    path.to_str()
        .with_context(|| format!("Agent host preflight {description} is not valid UTF-8"))
}

fn security_bail(message: &str) -> Result<()> {
    bail!("Agent host preflight security policy violation: {message}")
}

fn probe_connection(
    release_root: &Path,
    executable: &Path,
    arguments: &[String],
    profile: AgentHostCapabilityProfile,
    repository_id: &str,
    current_snapshot_id: &str,
) -> Result<usize> {
    let mut probe = Probe::start(release_root, executable, arguments)?;
    let initialize = probe.request(json!({
        "jsonrpc":"2.0",
        "id":1,
        "method":"initialize",
        "params":{
            "protocolVersion":MCP_PROTOCOL_REVISION,
            "capabilities":{},
            "clientInfo":{"name":"depgraph-agent-config", "version":env!("CARGO_PKG_VERSION")}
        }
    }))?;
    if initialize["result"]["protocolVersion"] != MCP_PROTOCOL_REVISION
        || initialize["result"]["serverInfo"]["name"] != "depgraph-mcp"
        || initialize["result"]["serverInfo"]["version"] != env!("CARGO_PKG_VERSION")
        || !initialize["result"]["capabilities"]["tools"].is_object()
    {
        security_bail("MCP initialize response differs from the release contract")?;
    }
    let tools = probe.request(json!({
        "jsonrpc":"2.0", "id":2, "method":"tools/list", "params":{}
    }))?;
    let actual_tools = tools["result"]["tools"]
        .as_array()
        .context("Agent host connection probe tools/list has no tool array")?;
    let capabilities = DepgraphCapabilitySet::try_new(profile.capabilities().iter().copied())?;
    let expected_tools = ToolCatalog::for_capabilities(&capabilities)
        .map_err(anyhow::Error::msg)?
        .tools()
        .iter()
        .map(|tool| {
            json!({
                "name":tool.name(),
                "description":tool.description(),
                "inputSchema":tool.input_schema(),
                "outputSchema":tool.output_schema()
            })
        })
        .collect::<Vec<_>>();
    if actual_tools != &expected_tools {
        security_bail("MCP tools/list differs from the selected capability profile")?;
    }
    let context = probe.request(json!({
        "jsonrpc":"2.0",
        "id":3,
        "method":"tools/call",
        "params":{"name":"get_context", "arguments":{
            "contract_version":MCP_TOOLS_CONTRACT_VERSION,
            "repository_id":repository_id
        }}
    }))?;
    let result = &context["result"];
    if result["isError"] != false {
        security_bail("MCP get_context returned an error during connection probe")?;
    }
    let structured = result["structuredContent"].clone();
    serde_json::from_value::<SuccessEnvelope<AgentContext>>(structured.clone())
        .context("Agent host connection probe get_context violates its closed contract")?;
    if structured["repository_id"] != repository_id
        || structured["snapshot_id"] != current_snapshot_id
        || structured["result"]["snapshot"]["available"] != true
    {
        security_bail("MCP get_context does not match the preflight root/Store binding")?;
    }
    probe.finish()?;
    Ok(actual_tools.len())
}

struct Probe {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<std::io::Result<Vec<u8>>>,
    stdout_reader: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
    stderr_reader: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
    consumed_stdout: Vec<u8>,
    finished: bool,
}

impl Probe {
    fn start(release_root: &Path, executable: &Path, arguments: &[String]) -> Result<Self> {
        let package_path =
            std::env::join_paths([release_root.join("bin"), release_root.join("libexec")])?;
        let mut command = Command::new(executable);
        command
            .current_dir(release_root)
            .args(arguments)
            .env_clear()
            .env("PATH", package_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        for variable in ["SystemRoot", "WINDIR"] {
            if let Some(value) = std::env::var_os(variable) {
                command.env(variable, value);
            }
        }
        let mut child = command.spawn().context(
            "Agent host connection probe could not start the manifest-attested MCP server",
        )?;
        let stdin = child
            .stdin
            .take()
            .context("MCP probe stdin is unavailable")?;
        let stdout = child
            .stdout
            .take()
            .context("MCP probe stdout is unavailable")?;
        let stderr = child
            .stderr
            .take()
            .context("MCP probe stderr is unavailable")?;
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
            let mut captured = Vec::new();
            let mut reader = stderr;
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

    fn request(&mut self, request: Value) -> Result<Value> {
        let deadline = probe_response_deadline(request["method"].as_str());
        self.request_with_deadline(request, deadline)
    }

    fn request_with_deadline(&mut self, request: Value, deadline: Duration) -> Result<Value> {
        let expected_id = request["id"].clone();
        let method = request["method"].as_str().unwrap_or("unknown");
        let mut bytes = serde_json::to_vec(&request)?;
        bytes.push(b'\n');
        let stdin = self.stdin.as_mut().context("MCP probe stdin is closed")?;
        stdin.write_all(&bytes)?;
        stdin.flush()?;
        let line = self.lines.recv_timeout(deadline).with_context(|| {
            format!(
                "Agent host connection probe {method} response deadline exceeded after {}s",
                deadline.as_secs()
            )
        })??;
        self.consumed_stdout.extend_from_slice(&line);
        if !line.ends_with(b"\n") || line == b"\n" {
            security_bail("MCP probe stdout contains a non-message byte sequence")?;
        }
        let response: Value = serde_json::from_slice(&line)
            .context("MCP probe stdout contains non-JSON-RPC bytes")?;
        if response["jsonrpc"] != "2.0" || response["id"] != expected_id {
            security_bail("MCP probe response does not match its request ID")?;
        }
        Ok(response)
    }

    fn finish(mut self) -> Result<()> {
        drop(self.stdin.take());
        let deadline = Instant::now() + EOF_DEADLINE;
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                bail!("Agent host connection probe server did not exit after stdin EOF");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let stdout = self
            .stdout_reader
            .take()
            .context("MCP probe stdout reader is missing")?
            .join()
            .map_err(|_| anyhow::anyhow!("MCP probe stdout reader panicked"))??;
        let stderr = self
            .stderr_reader
            .take()
            .context("MCP probe stderr reader is missing")?
            .join()
            .map_err(|_| anyhow::anyhow!("MCP probe stderr reader panicked"))??;
        if !status.success() || !stderr.is_empty() {
            bail!("Agent host connection probe server failed or wrote stderr");
        }
        if stdout != self.consumed_stdout || self.lines.try_iter().next().is_some() {
            security_bail("MCP probe stdout contains unexpected extra output")?;
        }
        self.finished = true;
        Ok(())
    }
}

impl Drop for Probe {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_probe_allows_cold_initialize_but_keeps_follow_up_requests_bounded() {
        assert_eq!(INITIALIZE_RESPONSE_DEADLINE, Duration::from_secs(30));
        assert_eq!(RESPONSE_DEADLINE, Duration::from_secs(10));
        assert!(INITIALIZE_RESPONSE_DEADLINE > RESPONSE_DEADLINE);
        assert_eq!(
            probe_response_deadline(Some("initialize")),
            INITIALIZE_RESPONSE_DEADLINE
        );
        assert_eq!(
            probe_response_deadline(Some("tools/list")),
            RESPONSE_DEADLINE
        );
        assert_eq!(probe_response_deadline(None), RESPONSE_DEADLINE);
    }

    fn release_evidence_fixture(
        directory: &Path,
        local_assets: &[LocalReleaseAsset; 3],
    ) -> Result<(PathBuf, String)> {
        let version = env!("CARGO_PKG_VERSION");
        let tag = format!("v{version}-rc.1");
        let local = local_assets
            .iter()
            .map(|asset| (asset.name.as_str(), asset))
            .collect::<BTreeMap<_, _>>();
        let assets = expected_release_asset_names(version)
            .into_iter()
            .map(|name| match local.get(name.as_str()) {
                Some(asset) => ReleaseAssetEvidence {
                    name,
                    bytes: asset.bytes,
                    sha256: asset.sha256.clone(),
                },
                None => ReleaseAssetEvidence {
                    bytes: u64::try_from(name.len()).unwrap_or(u64::MAX),
                    sha256: hex::encode(Sha256::digest(name.as_bytes())),
                    name,
                },
            })
            .collect::<Vec<_>>();
        let digest = |name: &str| {
            assets
                .iter()
                .find(|asset| asset.name == name)
                .map(|asset| asset.sha256.clone())
                .with_context(|| format!("test release evidence has no {name}"))
        };
        let commit = "a".repeat(40);
        let evidence = json!({
            "schema_version":RELEASE_POST_PUBLISH_EVIDENCE_SCHEMA_VERSION,
            "repository":OFFICIAL_RELEASE_REPOSITORY,
            "release_version":version,
            "tag":tag,
            "decision":"allow",
            "candidate":{
                "commit":&commit,
                "tree":"b".repeat(40),
                "tag_object":"c".repeat(40),
                "tag_signature_verification":"valid"
            },
            "full_ci":{
                "run_id":1,
                "url":canonical_actions_run_url(1),
                "head_sha":&commit,
                "head_branch":"main",
                "jobs":FULL_CI_JOB_NAMES.iter().map(|name| json!({
                    "name":name,
                    "conclusion":"success"
                })).collect::<Vec<_>>()
            },
            "release_workflow":{
                "run_id":2,
                "url":canonical_actions_run_url(2),
                "head_sha":&commit
            },
            "workflow_public_asset_identity":true,
            "public_download_reverified":true,
            "asset_set_sha256":release_asset_set_sha256(&assets),
            "assets":assets,
            "aggregates":{
                "release_verification_sha256":digest("release-verification.json")?,
                "compiler_pack_verification_sha256":digest("compiler-pack-verification.json")?,
                "benchmark_report_sha256":digest("benchmark-report.json")?,
                "cache_hit_benchmark_report_sha256":digest("cache-hit-benchmark-report.json")?,
                "stable_release_gate_sha256":digest("stable-release-gate.json")?
            }
        });
        let path = directory.join(format!("release-post-publish-evidence-{tag}.json"));
        let mut bytes = serde_json::to_vec_pretty(&evidence)?;
        bytes.push(b'\n');
        fs::write(&path, bytes)?;
        Ok((path.clone(), sha256_file(&path)?))
    }

    #[test]
    fn privileged_profiles_require_effect_and_project_execution_acknowledgements() {
        let root = Path::new("/root");
        let request = |profile, effects, project_exec| AgentConfigRequest {
            root,
            store: Path::new("/store"),
            release_archive: Path::new("/archive"),
            release_checksum: Path::new("/checksum"),
            release_evidence: Path::new("/evidence"),
            trusted_release_evidence_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            release_manifest: Path::new("/manifest"),
            compiler_pack_requirement: Path::new("/requirement"),
            format: AgentHostFormat::Codex,
            profile,
            acknowledge_privileged_effects: effects,
            acknowledge_project_exec_human_confirmation: project_exec,
        };
        assert!(
            validate_acknowledgements(&request(AgentHostCapabilityProfile::Read, false, false))
                .is_ok()
        );
        assert!(
            validate_acknowledgements(&request(
                AgentHostCapabilityProfile::StoreWrite,
                false,
                false
            ))
            .is_err()
        );
        assert!(
            validate_acknowledgements(&request(
                AgentHostCapabilityProfile::StoreWrite,
                true,
                false
            ))
            .is_ok()
        );
        assert!(
            validate_acknowledgements(&request(AgentHostCapabilityProfile::Read, false, true))
                .is_err()
        );
        assert!(
            validate_acknowledgements(&request(
                AgentHostCapabilityProfile::ProjectExec,
                true,
                false
            ))
            .is_err()
        );
        assert!(
            validate_acknowledgements(&request(
                AgentHostCapabilityProfile::ProjectExec,
                true,
                true
            ))
            .is_ok()
        );
    }

    #[test]
    fn safe_scan_remediation_is_an_unambiguous_argv_array() {
        let remediation = safe_scan_remediation(
            Path::new("/release/bin/depgraph"),
            Path::new("/root with spaces"),
            Path::new("/state/store.sqlite"),
        )
        .unwrap();
        assert!(remediation.contains(r#"["/release/bin/depgraph","scan","/root with spaces","--store","/state/store.sqlite","--json"]"#));
        assert!(remediation.contains("separate Store-write operation"));
    }

    #[test]
    fn artifact_paths_and_digests_fail_closed_before_file_access() {
        let temporary = tempfile::tempdir().unwrap();
        for path in ["../outside", "/absolute", "nested/../outside"] {
            let artifact = Artifact {
                path: path.to_owned(),
                sha256: "0".repeat(64),
            };
            assert!(verify_release_artifact(temporary.path(), &artifact, "fixture").is_err());
        }
        let malformed = Artifact {
            path: "missing".to_owned(),
            sha256: "A".repeat(64),
        };
        assert!(verify_release_artifact(temporary.path(), &malformed, "fixture").is_err());
    }

    #[test]
    fn compiler_pack_requirement_is_bound_to_the_product_release_and_target() {
        let reference = "release-checksums:v0.5.0/compiler-pack-aarch64-apple-darwin";
        assert!(
            validate_compiler_pack_release_binding(reference, "0.5.0", "aarch64-apple-darwin")
                .is_ok()
        );
        assert!(
            validate_compiler_pack_release_binding(reference, "0.4.0", "aarch64-apple-darwin")
                .is_err()
        );
        assert!(
            validate_compiler_pack_release_binding(reference, "0.5.0", "x86_64-apple-darwin")
                .is_err()
        );
    }

    #[test]
    fn public_release_evidence_is_the_independent_artifact_trust_root() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let version = env!("CARGO_PKG_VERSION");
        let target = "aarch64-apple-darwin";
        let paths = [
            temporary
                .path()
                .join(format!("depgraph-{version}-{target}.tar.gz")),
            temporary
                .path()
                .join(format!("depgraph-{version}-{target}.tar.gz.sha256")),
            temporary.path().join(format!(
                "depgraph-compiler-pack-{version}-{target}.requirement.json"
            )),
        ];
        for (index, path) in paths.iter().enumerate() {
            fs::write(path, format!("official public asset fixture {index}"))?;
        }
        let local_assets = [
            local_release_asset(&paths[0])?,
            local_release_asset(&paths[1])?,
            local_release_asset(&paths[2])?,
        ];
        assert_eq!(expected_release_asset_names(version).len(), 51);
        let (evidence, trusted_digest) = release_evidence_fixture(temporary.path(), &local_assets)?;
        let verified = verify_release_evidence(
            &evidence,
            &trusted_digest,
            version,
            target,
            [&local_assets[0], &local_assets[1], &local_assets[2]],
        )?;
        assert_eq!(verified.tag, format!("v{version}-rc.1"));
        assert_eq!(verified.evidence_sha256, trusted_digest);

        assert!(
            verify_release_evidence(
                &evidence,
                &"0".repeat(64),
                version,
                target,
                [&local_assets[0], &local_assets[1], &local_assets[2]],
            )
            .is_err()
        );

        let mut forged: Value = serde_json::from_slice(&fs::read(&evidence)?)?;
        forged["repository"] = json!("attacker/depgraph-cli");
        let mut forged_bytes = serde_json::to_vec_pretty(&forged)?;
        forged_bytes.push(b'\n');
        fs::write(&evidence, forged_bytes)?;
        let forged_digest = sha256_file(&evidence)?;
        assert!(
            verify_release_evidence(
                &evidence,
                &forged_digest,
                version,
                target,
                [&local_assets[0], &local_assets[1], &local_assets[2]],
            )
            .is_err()
        );

        let (evidence, trusted_digest) = release_evidence_fixture(temporary.path(), &local_assets)?;
        let changed_requirement = LocalReleaseAsset {
            name: local_assets[2].name.clone(),
            bytes: local_assets[2].bytes,
            sha256: "f".repeat(64),
        };
        assert!(
            verify_release_evidence(
                &evidence,
                &trusted_digest,
                version,
                target,
                [&local_assets[0], &local_assets[1], &changed_requirement],
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn archive_binding_requires_the_exact_sidecar_and_manifest_bytes() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let package_name = "depgraph-0.5.0-aarch64-apple-darwin";
        let archive_path = temporary.path().join(format!("{package_name}.tar.gz"));
        let manifest_bytes = b"{\"release_version\":\"0.5.0\"}";
        let encoder = flate2::write::GzEncoder::new(
            File::create(&archive_path)?,
            flate2::Compression::default(),
        );
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(manifest_bytes.len())?);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(
            &mut header,
            format!("{package_name}/release-manifest.json"),
            manifest_bytes.as_slice(),
        )?;
        archive.into_inner()?.finish()?;

        let digest = sha256_file(&archive_path)?;
        let checksum_path = temporary
            .path()
            .join(format!("{package_name}.tar.gz.sha256"));
        fs::write(&checksum_path, format!("{digest}  {package_name}.tar.gz\n"))?;
        let verified = verify_archive_binding(
            &archive_path,
            &checksum_path,
            package_name,
            "aarch64-apple-darwin",
            manifest_bytes,
        )?;
        assert_eq!(verified.archive.sha256, digest);
        assert!(
            verify_archive_binding(
                &archive_path,
                &checksum_path,
                package_name,
                "aarch64-apple-darwin",
                b"different manifest"
            )
            .is_err()
        );
        fs::write(
            &checksum_path,
            format!("{}  {package_name}.tar.gz\n", "0".repeat(64)),
        )?;
        assert!(
            verify_archive_binding(
                &archive_path,
                &checksum_path,
                package_name,
                "aarch64-apple-darwin",
                manifest_bytes
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn missing_store_returns_safe_scan_remediation_without_creating_state() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("repository");
        let state = temporary.path().join("private-state");
        fs::create_dir(&root)?;
        fs::create_dir(&state)?;
        let store = state.join("graph.sqlite");
        let capabilities =
            DepgraphCapabilitySet::try_new([depgraph_core::DepgraphCapability::Read])?;
        let config = DepgraphServiceConfig::new(
            &root,
            &store,
            capabilities,
            DepgraphServiceLimits::default(),
        )?;
        let core = temporary.path().join("release/bin/depgraph");
        let error = verify_store_binding(&config, &core)
            .expect_err("a missing Store must require a separate safe scan");
        let rendered = error.to_string();
        assert!(rendered.contains("no current completed snapshot"));
        assert!(rendered.contains("\"scan\""));
        assert!(rendered.contains("separate Store-write operation"));
        assert!(!store.exists());
        assert!(!PathBuf::from(format!("{}.operations.sqlite", store.display())).exists());
        Ok(())
    }
}
