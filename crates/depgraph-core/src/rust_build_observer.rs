use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use depgraph_protocol::{
    CommonFields, CompletenessLevel, Condition, Coverage, DependencySite, DependencySiteEvent,
    EdgeUpsert, Evidence, EvidenceKind, GraphEdge, GraphNode, NodeUpsert, Phase, Precision,
    Profile, ProfileCompleted, ProfileDeclared, ProtocolEvent, ResolutionStatus, ScanCompleted,
    ScanStarted, build_edge_stable_id, build_site_stable_id, stable_id_from_value,
};
use depgraph_store::{GraphSnapshot, NodeRecord, SiteRecord};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::build::{BuildAudit, BuildOutcomeKind};

pub const RUST_BUILD_OBSERVER: &str = "rust-cargo-build-observer";
pub const RUST_BUILD_OBSERVER_VERSION: &str = "1.0.0";
pub const RUST_BUILD_OBSERVATION_SCHEMA: &str = "rust-cargo-build-observation-v1";
pub const RUST_BUILD_CAPABILITY: &str = "cargo-json-build-script-proc-macro-v1";

const MAX_CARGO_MESSAGES: usize = 250_000;
const MAX_OBSERVED_ITEMS: usize = 250_000;
const MAX_SAFE_STRING: usize = 4_096;
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RustBuildObservation {
    pub schema_version: String,
    pub observer: String,
    pub observer_version: String,
    pub capability: String,
    pub build_finished: bool,
    pub build_scripts: Vec<RustObservedBuildScript>,
    pub proc_macros: Vec<RustObservedProcMacro>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RustObservedBuildScript {
    pub package_key: String,
    pub package_name: String,
    pub package_version: Option<String>,
    pub source_path: String,
    pub out_dir_logical_path: String,
    pub out_dir_artifacts: Vec<RustObservedArtifact>,
    pub cfgs: Vec<RustObservedCfg>,
    pub environment_keys: Vec<String>,
    pub redacted_environment_key_count: usize,
    pub linked_libraries: Vec<RustObservedLinkedLibrary>,
    pub linked_paths: Vec<RustObservedLinkPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RustObservedProcMacro {
    pub package_key: String,
    pub package_name: String,
    pub package_version: Option<String>,
    pub source_path: String,
    pub binaries: Vec<RustObservedArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RustObservedArtifact {
    pub logical_path: String,
    pub digest: String,
    pub byte_len: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustObservedCfg {
    pub key: String,
    pub value_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustObservedLinkedLibrary {
    pub kind: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustObservedLinkPath {
    pub kind: String,
    pub scope: String,
}

#[derive(Debug, Clone)]
struct CargoTarget {
    package_id: String,
    package_name: String,
    package_version: Option<String>,
    source_path: String,
    package_key: String,
    filenames: Vec<PathBuf>,
}

#[derive(Debug)]
struct RawBuildScript {
    package_id: String,
    out_dir: PathBuf,
    cfgs: Vec<RustObservedCfg>,
    environment_keys: Vec<String>,
    redacted_environment_key_count: usize,
    linked_libraries: Vec<RustObservedLinkedLibrary>,
    linked_paths: Vec<(String, PathBuf)>,
}

fn sha256(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(bytes.as_ref()))
}

fn safe_string(value: &Value, field: &str) -> Result<String> {
    let value = value
        .as_str()
        .filter(|value| !value.is_empty() && value.len() <= MAX_SAFE_STRING)
        .with_context(|| format!("Cargo build observation {field} must be a bounded string"))?;
    if value.chars().any(char::is_control) {
        bail!("Cargo build observation {field} contains control characters");
    }
    Ok(value.to_owned())
}

fn safe_strings(value: Option<&Value>, field: &str) -> Result<Vec<String>> {
    let values = value
        .and_then(Value::as_array)
        .with_context(|| format!("Cargo build observation {field} must be an array"))?;
    if values.len() > MAX_OBSERVED_ITEMS {
        bail!("Cargo build observation {field} exceeds its item limit");
    }
    let mut result = values
        .iter()
        .map(|value| safe_string(value, field))
        .collect::<Result<Vec<_>>>()?;
    result.sort();
    result.dedup();
    Ok(result)
}

fn relative_path(root: &Path, value: &Path, field: &str) -> Result<String> {
    let canonical_root = root
        .canonicalize()
        .with_context(|| format!("Cargo build observation {field} root is unavailable"))?;
    let canonical = value
        .canonicalize()
        .with_context(|| format!("Cargo build observation {field} is unavailable"))?;
    let relative = canonical
        .strip_prefix(&canonical_root)
        .with_context(|| format!("Cargo build observation {field} escapes its supervised root"))?;
    let portable = relative.to_string_lossy().replace('\\', "/");
    if portable.is_empty()
        || portable.starts_with('/')
        || portable
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        bail!("Cargo build observation {field} is not a canonical relative path");
    }
    Ok(portable)
}

fn package_identity(
    package_id: &str,
    target_name: &str,
    source_path: &str,
) -> (String, Option<String>, String) {
    let fragment = package_id.rsplit_once('#').map(|(_, fragment)| fragment);
    let (name, version) = match fragment.and_then(|fragment| fragment.rsplit_once('@')) {
        Some((name, version)) if !name.is_empty() && !version.is_empty() => {
            (name.to_owned(), Some(version.to_owned()))
        }
        _ => {
            let version = fragment
                .filter(|fragment| {
                    !fragment.is_empty()
                        && fragment
                            .chars()
                            .next()
                            .is_some_and(|value| value.is_ascii_digit())
                })
                .map(str::to_owned);
            (target_name.to_owned(), version)
        }
    };
    let key = format!(
        "{name}@{}#{source_path}",
        version.as_deref().unwrap_or("unknown")
    );
    (name, version, key)
}

fn parse_target(
    message: &Map<String, Value>,
    workspace_root: &Path,
) -> Result<(CargoTarget, BTreeSet<String>)> {
    let package_id = safe_string(
        message
            .get("package_id")
            .context("compiler-artifact package_id is missing")?,
        "compiler-artifact.package_id",
    )?;
    let target = message
        .get("target")
        .and_then(Value::as_object)
        .context("compiler-artifact target is missing")?;
    let target_name = safe_string(
        target
            .get("name")
            .context("compiler-artifact target.name is missing")?,
        "compiler-artifact.target.name",
    )?;
    let source = safe_string(
        target
            .get("src_path")
            .context("compiler-artifact target.src_path is missing")?,
        "compiler-artifact.target.src_path",
    )?;
    let source_path = relative_path(workspace_root, Path::new(&source), "target source path")?;
    let kinds = safe_strings(target.get("kind"), "compiler-artifact.target.kind")?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let filenames = message
        .get("filenames")
        .and_then(Value::as_array)
        .context("compiler-artifact filenames are missing")?;
    if filenames.len() > MAX_OBSERVED_ITEMS {
        bail!("compiler-artifact filenames exceed their item limit");
    }
    let filenames = filenames
        .iter()
        .map(|value| safe_string(value, "compiler-artifact.filenames[]").map(PathBuf::from))
        .collect::<Result<Vec<_>>>()?;
    let (package_name, package_version, package_key) =
        package_identity(&package_id, &target_name, &source_path);
    Ok((
        CargoTarget {
            package_id,
            package_name,
            package_version,
            source_path,
            package_key,
            filenames,
        },
        kinds,
    ))
}

fn is_secret_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "API_KEY",
        "PRIVATE_KEY",
        "CREDENTIAL",
        "AUTH",
        "COOKIE",
        "SESSION",
    ]
    .iter()
    .any(|part| upper.contains(part))
}

fn parse_environment(value: Option<&Value>) -> Result<(Vec<String>, usize)> {
    let entries = value
        .and_then(Value::as_array)
        .context("build-script-executed env must be an array")?;
    if entries.len() > MAX_OBSERVED_ITEMS {
        bail!("build-script-executed env exceeds its item limit");
    }
    let mut keys = BTreeSet::new();
    let mut redacted = 0;
    for entry in entries {
        let pair = entry
            .as_array()
            .filter(|pair| pair.len() == 2)
            .context("build-script-executed env entry must contain a key and value")?;
        let key = safe_string(&pair[0], "build-script-executed.env.key")?;
        let raw_value = pair[1]
            .as_str()
            .filter(|value| value.len() <= MAX_SAFE_STRING)
            .context("build-script-executed env value must be a bounded string")?;
        if raw_value.chars().any(char::is_control) {
            bail!("build-script-executed env value contains control characters");
        }
        if !key
            .chars()
            .all(|character| character == '_' || character.is_ascii_alphanumeric())
        {
            bail!("build-script-executed env key is invalid");
        }
        if is_secret_key(&key) {
            redacted += 1;
        } else {
            keys.insert(key);
        }
    }
    Ok((keys.into_iter().collect(), redacted))
}

fn parse_cfg(value: &str) -> Result<RustObservedCfg> {
    let (key, raw_value) = value
        .split_once('=')
        .map_or((value, None), |(key, value)| (key, Some(value)));
    if key.is_empty()
        || key.len() > 256
        || !key.chars().enumerate().all(|(index, value)| {
            value == '_' || value.is_ascii_alphanumeric() && (index > 0 || !value.is_ascii_digit())
        })
    {
        bail!("build-script-executed cfg key is invalid");
    }
    let value_digest = raw_value
        .map(|raw| {
            let parsed: String = serde_json::from_str(raw)
                .context("build-script-executed cfg value must be a JSON string")?;
            if parsed.len() > MAX_SAFE_STRING || parsed.chars().any(char::is_control) {
                bail!("build-script-executed cfg value is unsafe");
            }
            Ok(sha256(parsed))
        })
        .transpose()?;
    Ok(RustObservedCfg {
        key: key.to_owned(),
        value_digest,
    })
}

fn parse_linked_library(value: &str) -> Result<RustObservedLinkedLibrary> {
    const KINDS: [&str; 3] = ["dylib", "static", "framework"];
    let (kind, name) = if let Some((kind, name)) = value.split_once('=')
        && KINDS.contains(&kind)
        && !name.is_empty()
    {
        (kind, name)
    } else {
        ("default", value)
    };
    if name.is_empty()
        || name.contains(['/', '\\'])
        || name.chars().any(|character| character.is_whitespace())
    {
        bail!("build-script-executed linked library name is invalid");
    }
    Ok(RustObservedLinkedLibrary {
        kind: kind.to_owned(),
        name: name.to_owned(),
    })
}

fn parse_linked_path(value: &str) -> (String, PathBuf) {
    const KINDS: [&str; 5] = ["dependency", "crate", "native", "framework", "all"];
    if let Some((kind, path)) = value.split_once('=')
        && KINDS.contains(&kind)
        && !path.is_empty()
    {
        return (kind.to_owned(), PathBuf::from(path));
    }
    ("all".to_owned(), PathBuf::from(value))
}

fn parse_build_script(message: &Map<String, Value>) -> Result<RawBuildScript> {
    let package_id = safe_string(
        message
            .get("package_id")
            .context("build-script-executed package_id is missing")?,
        "build-script-executed.package_id",
    )?;
    let out_dir = PathBuf::from(safe_string(
        message
            .get("out_dir")
            .context("build-script-executed out_dir is missing")?,
        "build-script-executed.out_dir",
    )?);
    let cfgs = safe_strings(message.get("cfgs"), "build-script-executed.cfgs")?
        .into_iter()
        .map(|value| parse_cfg(&value))
        .collect::<Result<BTreeSet<_>>>()?
        .into_iter()
        .collect();
    let (environment_keys, redacted_environment_key_count) = parse_environment(message.get("env"))?;
    let linked_libraries = safe_strings(
        message.get("linked_libs"),
        "build-script-executed.linked_libs",
    )?
    .into_iter()
    .map(|value| parse_linked_library(&value))
    .collect::<Result<BTreeSet<_>>>()?
    .into_iter()
    .collect();
    let linked_paths = safe_strings(
        message.get("linked_paths"),
        "build-script-executed.linked_paths",
    )?
    .into_iter()
    .map(|value| parse_linked_path(&value))
    .collect();
    Ok(RawBuildScript {
        package_id,
        out_dir,
        cfgs,
        environment_keys,
        redacted_environment_key_count,
        linked_libraries,
        linked_paths,
    })
}

fn observed_file(path: &Path, logical_path: String) -> Result<RustObservedArtifact> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_ARTIFACT_BYTES
    {
        bail!("Cargo build observation contains an unsafe or oversized artifact");
    }
    let bytes = fs::read(path)?;
    Ok(RustObservedArtifact {
        logical_path,
        digest: sha256(&bytes),
        byte_len: metadata.len(),
    })
}

fn observe_out_dir(
    out_dir: &Path,
    output_root: &Path,
    package_key: &str,
) -> Result<(String, Vec<RustObservedArtifact>)> {
    let _ = relative_path(output_root, out_dir, "build-script OUT_DIR")?;
    if !out_dir.is_dir() {
        bail!("build-script OUT_DIR is not a directory");
    }
    let package_digest = &sha256(package_key)[..24];
    let logical_root = format!("rust-build/{package_digest}/out");
    let mut entries = WalkDir::new(out_dir)
        .follow_links(false)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path().to_path_buf());
    if entries.len() > MAX_OBSERVED_ITEMS {
        bail!("build-script OUT_DIR exceeds its item limit");
    }
    let mut artifacts = Vec::new();
    let mut total_bytes = 0_u64;
    for entry in entries {
        if entry.path() == out_dir {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
            bail!("build-script OUT_DIR contains an unsafe entry");
        }
        if metadata.is_file() {
            total_bytes = total_bytes.saturating_add(metadata.len());
            if total_bytes > MAX_ARTIFACT_BYTES {
                bail!("build-script OUT_DIR exceeds its byte limit");
            }
            let relative = relative_path(out_dir, entry.path(), "OUT_DIR artifact")?;
            artifacts.push(observed_file(
                entry.path(),
                format!("{logical_root}/{relative}"),
            )?);
        }
    }
    artifacts.sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
    Ok((logical_root, artifacts))
}

fn observe_proc_macro_binaries(
    target: &CargoTarget,
    output_root: &Path,
) -> Result<Vec<RustObservedArtifact>> {
    let package_digest = &sha256(&target.package_key)[..24];
    let mut candidates = target
        .filenames
        .iter()
        .filter(|path| {
            path.extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| {
                    matches!(
                        extension.to_ascii_lowercase().as_str(),
                        "dll" | "dylib" | "so"
                    )
                })
        })
        .map(|path| {
            let relative = relative_path(output_root, path, "proc-macro binary")?;
            Ok((relative, path))
        })
        .collect::<Result<Vec<_>>>()?;
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    if candidates.is_empty() {
        bail!("proc-macro compiler artifact did not contain a dynamic library");
    }
    candidates
        .into_iter()
        .enumerate()
        .map(|(index, (_, path))| {
            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or("bin");
            observed_file(
                path,
                format!("rust-build/{package_digest}/proc-macro/{index}.{extension}"),
            )
        })
        .collect()
}

pub(crate) fn collect_rust_build_observation(
    stdout: &[u8],
    workspace_root: &Path,
    output_root: &Path,
) -> Result<RustBuildObservation> {
    let text = std::str::from_utf8(stdout).context("Cargo JSON output is not UTF-8")?;
    let mut custom_build_targets = BTreeMap::<String, CargoTarget>::new();
    let mut proc_macro_targets = Vec::<CargoTarget>::new();
    let mut build_scripts = Vec::<RawBuildScript>::new();
    let mut build_finished = None;
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_CARGO_MESSAGES {
            bail!("Cargo JSON output exceeds its message limit");
        }
        if line.is_empty() {
            continue;
        }
        let value: Value =
            serde_json::from_str(line).context("Cargo output contains a non-JSON line")?;
        let message = value
            .as_object()
            .context("Cargo JSON message must be an object")?;
        let reason = safe_string(
            message
                .get("reason")
                .context("Cargo JSON reason is missing")?,
            "reason",
        )?;
        match reason.as_str() {
            "compiler-artifact" => {
                let (target, kinds) = parse_target(message, workspace_root)?;
                if kinds.contains("custom-build") {
                    if custom_build_targets
                        .insert(target.package_id.clone(), target)
                        .is_some()
                    {
                        bail!("Cargo output contains duplicate custom-build artifacts");
                    }
                } else if kinds.contains("proc-macro") {
                    proc_macro_targets.push(target);
                }
            }
            "build-script-executed" => build_scripts.push(parse_build_script(message)?),
            "build-finished" => {
                let success = message
                    .get("success")
                    .and_then(Value::as_bool)
                    .context("build-finished success is missing")?;
                if build_finished.replace(success).is_some() {
                    bail!("Cargo output contains duplicate build-finished messages");
                }
            }
            "compiler-message" | "text-line" => {}
            _ => {}
        }
    }
    if build_finished != Some(true) {
        bail!("Cargo JSON output did not complete successfully");
    }
    if build_scripts.len() > MAX_OBSERVED_ITEMS || proc_macro_targets.len() > MAX_OBSERVED_ITEMS {
        bail!("Cargo build observation exceeds its item limit");
    }

    let canonical_output = output_root
        .canonicalize()
        .context("supervised Cargo output root is unavailable")?;
    let mut observed_scripts = Vec::new();
    for raw in build_scripts {
        let target = custom_build_targets
            .get(&raw.package_id)
            .context("build-script-executed message has no matching custom-build artifact")?;
        let (out_dir_logical_path, out_dir_artifacts) =
            observe_out_dir(&raw.out_dir, &canonical_output, &target.package_key)?;
        let canonical_out_dir = raw.out_dir.canonicalize()?;
        let linked_paths = raw
            .linked_paths
            .into_iter()
            .map(|(kind, path)| {
                let scope = path
                    .canonicalize()
                    .ok()
                    .map(|canonical| {
                        if canonical.starts_with(&canonical_out_dir) {
                            "out-dir"
                        } else if canonical.starts_with(&canonical_output) {
                            "cargo-output"
                        } else {
                            "external"
                        }
                    })
                    .unwrap_or("external");
                RustObservedLinkPath {
                    kind,
                    scope: scope.to_owned(),
                }
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        observed_scripts.push(RustObservedBuildScript {
            package_key: target.package_key.clone(),
            package_name: target.package_name.clone(),
            package_version: target.package_version.clone(),
            source_path: target.source_path.clone(),
            out_dir_logical_path,
            out_dir_artifacts,
            cfgs: raw.cfgs,
            environment_keys: raw.environment_keys,
            redacted_environment_key_count: raw.redacted_environment_key_count,
            linked_libraries: raw.linked_libraries,
            linked_paths,
        });
    }
    observed_scripts.sort_by(|left, right| left.package_key.cmp(&right.package_key));

    let mut observed_macros = proc_macro_targets
        .into_iter()
        .map(|target| {
            let binaries = observe_proc_macro_binaries(&target, &canonical_output)?;
            Ok(RustObservedProcMacro {
                package_key: target.package_key,
                package_name: target.package_name,
                package_version: target.package_version,
                source_path: target.source_path,
                binaries,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    observed_macros.sort_by(|left, right| left.package_key.cmp(&right.package_key));

    Ok(RustBuildObservation {
        schema_version: RUST_BUILD_OBSERVATION_SCHEMA.to_owned(),
        observer: RUST_BUILD_OBSERVER.to_owned(),
        observer_version: RUST_BUILD_OBSERVER_VERSION.to_owned(),
        capability: RUST_BUILD_CAPABILITY.to_owned(),
        build_finished: true,
        build_scripts: observed_scripts,
        proc_macros: observed_macros,
    })
}

fn observation_digest(observation: &RustBuildObservation) -> Result<String> {
    Ok(sha256(serde_json::to_vec(observation)?))
}

fn audit_output_digest(audit: &BuildAudit) -> Result<&str> {
    if audit.outcome != BuildOutcomeKind::Completed {
        bail!("Rust build evidence requires a completed supervisor audit");
    }
    audit
        .validated_output_digest
        .as_deref()
        .context("completed Rust build audit has no validated output digest")
}

fn build_properties(
    audit: &BuildAudit,
    logical_path: &str,
    artifact_digest: &str,
) -> Map<String, Value> {
    Map::from_iter([
        ("build_run_id".to_owned(), json!(audit.run_id)),
        ("profile_id".to_owned(), json!(audit.profile_id)),
        (
            "command_plan_digest".to_owned(),
            json!(audit.command_plan_digest),
        ),
        (
            "toolchain_executable_digest".to_owned(),
            json!(audit.toolchain_executable_digest),
        ),
        (
            "environment_key_set_digest".to_owned(),
            json!(audit.environment_key_set_digest),
        ),
        (
            "validated_output_digest".to_owned(),
            json!(audit.validated_output_digest),
        ),
        ("logical_artifact_path".to_owned(), json!(logical_path)),
        ("artifact_digest".to_owned(), json!(artifact_digest)),
    ])
}

fn build_evidence(
    audit: &BuildAudit,
    logical_path: &str,
    artifact_digest: &str,
    source: Option<&depgraph_store::EvidenceRecord>,
) -> Evidence {
    Evidence {
        kind: EvidenceKind::Build,
        extractor: audit.adapter.clone(),
        extractor_version: audit.adapter_version.clone(),
        path: source
            .map(|value| value.path.clone())
            .or_else(|| Some(logical_path.to_owned())),
        start_line: source.and_then(|value| value.start_line.try_into().ok()),
        start_column: source.and_then(|value| value.start_column.try_into().ok()),
        end_line: source.and_then(|value| value.end_line.try_into().ok()),
        end_column: source.and_then(|value| value.end_column.try_into().ok()),
        detail: Some("supervised Cargo build observation".to_owned()),
        properties: build_properties(audit, logical_path, artifact_digest)
            .into_iter()
            .collect(),
    }
}

fn generated_node(
    kind: &str,
    identity: Value,
    display_name: String,
    mut properties: Map<String, Value>,
    audit: &BuildAudit,
    logical_path: &str,
    artifact_digest: &str,
) -> GraphNode {
    let id = stable_id_from_value(kind, &identity);
    properties.insert("build_generated".to_owned(), Value::Bool(true));
    properties.insert("build_identity".to_owned(), identity);
    let mut provenance = build_properties(audit, logical_path, artifact_digest);
    provenance.insert("observer".to_owned(), json!(audit.adapter));
    provenance.insert("observer_version".to_owned(), json!(audit.adapter_version));
    properties.insert("build_provenance".to_owned(), Value::Object(provenance));
    GraphNode {
        id: id.clone(),
        kind: kind.to_owned(),
        locator: format!("build://{}/{logical_path}#{id}", audit.adapter),
        display_name: Some(display_name),
        properties: properties.into_iter().collect(),
    }
}

fn base_node(node: &NodeRecord) -> Result<GraphNode> {
    Ok(GraphNode {
        id: node.id.clone(),
        kind: node.kind.clone(),
        locator: node.locator.clone(),
        display_name: Some(node.display_name.clone()),
        properties: node
            .properties
            .as_object()
            .cloned()
            .context("base node properties must be an object")?
            .into_iter()
            .collect(),
    })
}

fn add_node(nodes: &mut BTreeMap<String, GraphNode>, node: GraphNode) -> Result<()> {
    if let Some(previous) = nodes.get(&node.id)
        && previous != &node
    {
        bail!("Rust build graph contains a conflicting node {}", node.id);
    }
    nodes.insert(node.id.clone(), node);
    Ok(())
}

struct RelationInput<'a> {
    source: &'a str,
    target: &'a str,
    kind: &'a str,
    specifier: &'a str,
    condition: Condition,
    evidence: Evidence,
}

fn add_relation(
    sites: &mut BTreeMap<String, DependencySite>,
    edges: &mut BTreeMap<String, GraphEdge>,
    audit: &BuildAudit,
    input: RelationInput<'_>,
) -> Result<()> {
    let mut site = DependencySite {
        id: "pending".to_owned(),
        source: input.source.to_owned(),
        kind: input.kind.to_owned(),
        specifier: input.specifier.to_owned(),
        resolution_status: ResolutionStatus::Resolved,
        target_ids: vec![input.target.to_owned()],
        profile_id: audit.profile_id.clone(),
        condition: input.condition.canonicalize(),
        precision: Precision::Observed,
        reason: None,
        evidence: vec![input.evidence.clone()],
    };
    site.id = build_site_stable_id(&site)?;
    let mut edge = GraphEdge {
        id: "pending".to_owned(),
        source: input.source.to_owned(),
        target: input.target.to_owned(),
        kind: input.kind.to_owned(),
        site_id: Some(site.id.clone()),
        phase: Phase::Build,
        environment: Some("build".to_owned()),
        profile_id: audit.profile_id.clone(),
        condition: site.condition.clone(),
        resolution_status: ResolutionStatus::Resolved,
        precision: Precision::Observed,
        generated: true,
        evidence: vec![input.evidence],
    };
    edge.id = build_edge_stable_id(&edge)?;
    if let Some(previous) = sites.get(&site.id)
        && previous != &site
    {
        bail!("Rust build graph contains a conflicting site {}", site.id);
    }
    if let Some(previous) = edges.get(&edge.id)
        && previous != &edge
    {
        bail!("Rust build graph contains a conflicting edge {}", edge.id);
    }
    sites.insert(site.id.clone(), site);
    edges.insert(edge.id.clone(), edge);
    Ok(())
}

fn package_for_source<'a>(
    snapshot: &'a GraphSnapshot,
    source_path: &str,
) -> Option<&'a NodeRecord> {
    snapshot
        .nodes
        .iter()
        .filter(|node| node.kind == "package_instance")
        .filter_map(|node| {
            let manifest = node.properties.get("manifest_path")?.as_str()?;
            let directory = manifest.strip_suffix("/Cargo.toml").unwrap_or("");
            let owns = directory.is_empty()
                || source_path == directory
                || source_path.starts_with(&format!("{directory}/"));
            owns.then_some((directory.len(), node))
        })
        .max_by_key(|(length, _)| *length)
        .map(|(_, node)| node)
}

fn source_node_for_path<'a>(snapshot: &'a GraphSnapshot, path: &str) -> Option<&'a NodeRecord> {
    snapshot
        .nodes
        .iter()
        .find(|node| node.kind == "file" && node.display_name == path)
}

fn site_source_evidence<'a>(
    snapshot: &'a GraphSnapshot,
    site: &SiteRecord,
) -> Option<&'a depgraph_store::EvidenceRecord> {
    snapshot
        .evidence
        .iter()
        .filter(|evidence| evidence.owner_type == "site" && evidence.owner_id == site.id)
        .min_by_key(|evidence| evidence.ordinal)
}

fn node_package_name(node: &NodeRecord) -> Option<&str> {
    node.properties.get("package").and_then(Value::as_str)
}

pub fn rust_build_protocol_events(
    snapshot: &GraphSnapshot,
    audit: &BuildAudit,
    observation: &RustBuildObservation,
) -> Result<Vec<ProtocolEvent>> {
    if observation.schema_version != RUST_BUILD_OBSERVATION_SCHEMA
        || observation.observer != RUST_BUILD_OBSERVER
        || observation.observer_version != RUST_BUILD_OBSERVER_VERSION
        || observation.capability != RUST_BUILD_CAPABILITY
        || !observation.build_finished
        || audit.adapter != RUST_BUILD_OBSERVER
        || audit.adapter_version != RUST_BUILD_OBSERVER_VERSION
    {
        bail!("Rust build observation contract is invalid");
    }
    let validated_output_digest = audit_output_digest(audit)?.to_owned();
    let observed_digest = observation_digest(observation)?;
    let observation_path = format!(".depgraph/rust-build/{observed_digest}.json");
    let common_observation = || build_evidence(audit, &observation_path, &observed_digest, None);
    let mut nodes = BTreeMap::<String, GraphNode>::new();
    let mut sites = BTreeMap::<String, DependencySite>::new();
    let mut edges = BTreeMap::<String, GraphEdge>::new();
    let mut out_dirs_by_package = BTreeMap::<String, GraphNode>::new();
    let mut macro_binaries_by_package = BTreeMap::<String, Vec<GraphNode>>::new();

    for script in &observation.build_scripts {
        let package = package_for_source(snapshot, &script.source_path).with_context(|| {
            format!(
                "observed build script {} has no safe package",
                script.source_path
            )
        })?;
        let source = source_node_for_path(snapshot, &script.source_path).unwrap_or(package);
        add_node(&mut nodes, base_node(package)?)?;
        add_node(&mut nodes, base_node(source)?)?;
        let run = generated_node(
            "build_script_run",
            json!({
                "observer": RUST_BUILD_OBSERVER,
                "package_key": script.package_key,
                "source_path": script.source_path,
                "profile_id": audit.profile_id,
                "validated_output_digest": validated_output_digest,
            }),
            format!("build.rs ({})", script.package_name),
            Map::from_iter([
                ("ecosystem".to_owned(), json!("cargo")),
                ("package_name".to_owned(), json!(script.package_name)),
                ("package_version".to_owned(), json!(script.package_version)),
                ("source_path".to_owned(), json!(script.source_path)),
                (
                    "environment_keys".to_owned(),
                    json!(script.environment_keys),
                ),
                (
                    "redacted_environment_key_count".to_owned(),
                    json!(script.redacted_environment_key_count),
                ),
            ]),
            audit,
            &observation_path,
            &observed_digest,
        );
        add_node(&mut nodes, run.clone())?;
        add_relation(
            &mut sites,
            &mut edges,
            audit,
            RelationInput {
                source: &source.id,
                target: &run.id,
                kind: "executes_build_script",
                specifier: &script.source_path,
                condition: Condition::default(),
                evidence: common_observation(),
            },
        )?;
        let out_dir = generated_node(
            "build_output_directory",
            json!({
                "observer": RUST_BUILD_OBSERVER,
                "package_key": script.package_key,
                "profile_id": audit.profile_id,
                "validated_output_digest": validated_output_digest,
            }),
            format!("OUT_DIR ({})", script.package_name),
            Map::from_iter([
                ("ecosystem".to_owned(), json!("cargo")),
                ("package_name".to_owned(), json!(script.package_name)),
                (
                    "artifact_count".to_owned(),
                    json!(script.out_dir_artifacts.len()),
                ),
                (
                    "logical_path".to_owned(),
                    json!(script.out_dir_logical_path),
                ),
            ]),
            audit,
            &observation_path,
            &observed_digest,
        );
        add_node(&mut nodes, out_dir.clone())?;
        add_relation(
            &mut sites,
            &mut edges,
            audit,
            RelationInput {
                source: &run.id,
                target: &out_dir.id,
                kind: "generates_out_dir",
                specifier: "OUT_DIR",
                condition: Condition::default(),
                evidence: common_observation(),
            },
        )?;
        out_dirs_by_package.insert(package.id.clone(), out_dir.clone());

        for artifact in &script.out_dir_artifacts {
            let node = generated_node(
                "file",
                json!({
                    "observer": RUST_BUILD_OBSERVER,
                    "package_key": script.package_key,
                    "logical_path": artifact.logical_path,
                    "artifact_digest": artifact.digest,
                    "profile_id": audit.profile_id,
                }),
                artifact.logical_path.clone(),
                Map::from_iter([
                    ("ecosystem".to_owned(), json!("cargo")),
                    ("generated".to_owned(), Value::Bool(true)),
                    ("artifact_role".to_owned(), json!("out-dir")),
                    ("logical_path".to_owned(), json!(artifact.logical_path)),
                    ("artifact_digest".to_owned(), json!(artifact.digest)),
                    ("byte_len".to_owned(), json!(artifact.byte_len)),
                ]),
                audit,
                &artifact.logical_path,
                &artifact.digest,
            );
            add_node(&mut nodes, node.clone())?;
            add_relation(
                &mut sites,
                &mut edges,
                audit,
                RelationInput {
                    source: &out_dir.id,
                    target: &node.id,
                    kind: "contains_generated_artifact",
                    specifier: &artifact.logical_path,
                    condition: Condition::default(),
                    evidence: build_evidence(audit, &artifact.logical_path, &artifact.digest, None),
                },
            )?;
        }
        for cfg in &script.cfgs {
            let node = generated_node(
                "build_configuration",
                json!({
                    "observer": RUST_BUILD_OBSERVER,
                    "package_key": script.package_key,
                    "cfg_key": cfg.key,
                    "cfg_value_digest": cfg.value_digest,
                    "profile_id": audit.profile_id,
                    "validated_output_digest": validated_output_digest,
                }),
                cfg.key.clone(),
                Map::from_iter([
                    ("ecosystem".to_owned(), json!("cargo")),
                    ("configuration_kind".to_owned(), json!("rustc-cfg")),
                    ("cfg_key".to_owned(), json!(cfg.key)),
                    ("cfg_value_digest".to_owned(), json!(cfg.value_digest)),
                    ("cfg_value_persisted".to_owned(), Value::Bool(false)),
                ]),
                audit,
                &observation_path,
                &observed_digest,
            );
            add_node(&mut nodes, node.clone())?;
            add_relation(
                &mut sites,
                &mut edges,
                audit,
                RelationInput {
                    source: &run.id,
                    target: &node.id,
                    kind: "enables_cfg",
                    specifier: &cfg.key,
                    condition: Condition::default(),
                    evidence: common_observation(),
                },
            )?;
        }
        for key in &script.environment_keys {
            let node = generated_node(
                "build_environment",
                json!({
                    "observer": RUST_BUILD_OBSERVER,
                    "package_key": script.package_key,
                    "key": key,
                    "profile_id": audit.profile_id,
                    "validated_output_digest": validated_output_digest,
                }),
                key.clone(),
                Map::from_iter([
                    ("ecosystem".to_owned(), json!("cargo")),
                    ("environment_key".to_owned(), json!(key)),
                    ("value_persisted".to_owned(), Value::Bool(false)),
                ]),
                audit,
                &observation_path,
                &observed_digest,
            );
            add_node(&mut nodes, node.clone())?;
            add_relation(
                &mut sites,
                &mut edges,
                audit,
                RelationInput {
                    source: &run.id,
                    target: &node.id,
                    kind: "defines_build_environment",
                    specifier: key,
                    condition: Condition::default(),
                    evidence: common_observation(),
                },
            )?;
        }
        for library in &script.linked_libraries {
            let node = generated_node(
                "native_library",
                json!({
                    "observer": RUST_BUILD_OBSERVER,
                    "package_key": script.package_key,
                    "link_kind": library.kind,
                    "name": library.name,
                    "profile_id": audit.profile_id,
                    "validated_output_digest": validated_output_digest,
                }),
                library.name.clone(),
                Map::from_iter([
                    ("ecosystem".to_owned(), json!("native")),
                    ("link_kind".to_owned(), json!(library.kind)),
                    ("library_name".to_owned(), json!(library.name)),
                    ("location".to_owned(), json!("observed-link-directive")),
                ]),
                audit,
                &observation_path,
                &observed_digest,
            );
            add_node(&mut nodes, node.clone())?;
            add_relation(
                &mut sites,
                &mut edges,
                audit,
                RelationInput {
                    source: &run.id,
                    target: &node.id,
                    kind: "links_native_library",
                    specifier: &format!("{}={}", library.kind, library.name),
                    condition: Condition::default(),
                    evidence: common_observation(),
                },
            )?;
        }
        for linked_path in &script.linked_paths {
            let node = generated_node(
                "native_search_path",
                json!({
                    "observer": RUST_BUILD_OBSERVER,
                    "package_key": script.package_key,
                    "kind": linked_path.kind,
                    "scope": linked_path.scope,
                    "profile_id": audit.profile_id,
                    "validated_output_digest": validated_output_digest,
                }),
                format!("{} {} search path", linked_path.scope, linked_path.kind),
                Map::from_iter([
                    ("ecosystem".to_owned(), json!("native")),
                    ("search_kind".to_owned(), json!(linked_path.kind)),
                    ("path_scope".to_owned(), json!(linked_path.scope)),
                    ("absolute_path_persisted".to_owned(), Value::Bool(false)),
                ]),
                audit,
                &observation_path,
                &observed_digest,
            );
            add_node(&mut nodes, node.clone())?;
            add_relation(
                &mut sites,
                &mut edges,
                audit,
                RelationInput {
                    source: &run.id,
                    target: &node.id,
                    kind: "adds_native_search_path",
                    specifier: &format!("{}:{}", linked_path.kind, linked_path.scope),
                    condition: Condition::default(),
                    evidence: common_observation(),
                },
            )?;
        }
    }

    for observed in &observation.proc_macros {
        let package = package_for_source(snapshot, &observed.source_path).with_context(|| {
            format!(
                "observed proc macro {} has no safe package",
                observed.source_path
            )
        })?;
        add_node(&mut nodes, base_node(package)?)?;
        let mut binaries = Vec::new();
        for artifact in &observed.binaries {
            let node = generated_node(
                "proc_macro_binary",
                json!({
                    "observer": RUST_BUILD_OBSERVER,
                    "package_key": observed.package_key,
                    "logical_path": artifact.logical_path,
                    "artifact_digest": artifact.digest,
                    "profile_id": audit.profile_id,
                }),
                format!("proc macro {}", observed.package_name),
                Map::from_iter([
                    ("ecosystem".to_owned(), json!("cargo")),
                    ("package_name".to_owned(), json!(observed.package_name)),
                    (
                        "package_version".to_owned(),
                        json!(observed.package_version),
                    ),
                    ("source_path".to_owned(), json!(observed.source_path)),
                    ("logical_path".to_owned(), json!(artifact.logical_path)),
                    ("artifact_digest".to_owned(), json!(artifact.digest)),
                    ("byte_len".to_owned(), json!(artifact.byte_len)),
                ]),
                audit,
                &artifact.logical_path,
                &artifact.digest,
            );
            add_node(&mut nodes, node.clone())?;
            add_relation(
                &mut sites,
                &mut edges,
                audit,
                RelationInput {
                    source: &package.id,
                    target: &node.id,
                    kind: "compiles_proc_macro",
                    specifier: &observed.package_name,
                    condition: Condition::default(),
                    evidence: build_evidence(audit, &artifact.logical_path, &artifact.digest, None),
                },
            )?;
            binaries.push(node);
        }
        macro_binaries_by_package.insert(package.id.clone(), binaries);
    }

    let package_nodes_by_name = snapshot
        .nodes
        .iter()
        .filter(|node| node.kind == "package_instance")
        .filter_map(|node| Some((node.properties.get("name")?.as_str()?.to_owned(), node)))
        .collect::<BTreeMap<_, _>>();
    for site in &snapshot.sites {
        if site.specifier.as_deref() == Some("OUT_DIR") {
            let Some(source) = snapshot.nodes.iter().find(|node| node.id == site.source) else {
                continue;
            };
            let Some(package_name) = node_package_name(source) else {
                continue;
            };
            let Some(package) = package_nodes_by_name.get(package_name) else {
                continue;
            };
            let Some(out_dir) = out_dirs_by_package.get(&package.id) else {
                continue;
            };
            add_node(&mut nodes, base_node(source)?)?;
            let condition: Condition = serde_json::from_value(site.condition.clone())?;
            add_relation(
                &mut sites,
                &mut edges,
                audit,
                RelationInput {
                    source: &source.id,
                    target: &out_dir.id,
                    kind: "reads_build_output",
                    specifier: "OUT_DIR",
                    condition,
                    evidence: build_evidence(
                        audit,
                        &observation_path,
                        &observed_digest,
                        site_source_evidence(snapshot, site),
                    ),
                },
            )?;
        }
        if site.kind != "proc_macro_expansion" {
            continue;
        }
        let Some(source) = snapshot.nodes.iter().find(|node| node.id == site.source) else {
            continue;
        };
        let Some(source_package_name) = node_package_name(source) else {
            continue;
        };
        let Some(source_package) = package_nodes_by_name.get(source_package_name) else {
            continue;
        };
        let mut candidates = snapshot
            .edges
            .iter()
            .filter(|edge| {
                edge.source == source_package.id
                    && matches!(edge.kind.as_str(), "depends_on" | "build_depends_on")
            })
            .filter_map(|edge| macro_binaries_by_package.get(&edge.target))
            .flatten()
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| left.id.cmp(&right.id));
        candidates.dedup_by(|left, right| left.id == right.id);
        if candidates.len() != 1 {
            continue;
        }
        add_node(&mut nodes, base_node(source)?)?;
        let condition: Condition = serde_json::from_value(site.condition.clone())?;
        add_relation(
            &mut sites,
            &mut edges,
            audit,
            RelationInput {
                source: &source.id,
                target: &candidates[0].id,
                kind: "expands_with_proc_macro",
                specifier: site.specifier.as_deref().unwrap_or("proc-macro"),
                condition,
                evidence: build_evidence(
                    audit,
                    &observation_path,
                    &observed_digest,
                    site_source_evidence(snapshot, site),
                ),
            },
        )?;
    }

    let profile = Profile {
        id: audit.profile_id.clone(),
        language: "rust".to_owned(),
        toolchain: audit.toolchain_version.clone().map(Value::String),
        command: Some(audit.command_arguments.join(" ")),
        target: audit.target.clone(),
        features: vec![RUST_BUILD_CAPABILITY.to_owned()],
        environment: BTreeMap::from([("mode".to_owned(), json!("build"))]),
        source_revision: None,
        properties: BTreeMap::from([
            ("observer".to_owned(), json!(RUST_BUILD_OBSERVER)),
            (
                "observer_version".to_owned(),
                json!(RUST_BUILD_OBSERVER_VERSION),
            ),
            ("project_code_executed".to_owned(), Value::Bool(true)),
            (
                "build_scripts_executed".to_owned(),
                json!(!observation.build_scripts.is_empty()),
            ),
            (
                "proc_macros_executed".to_owned(),
                json!(!observation.proc_macros.is_empty()),
            ),
        ]),
    };
    let coverage = Coverage {
        profiles: 1,
        files_discovered: 0,
        files_analyzed: 0,
        files_skipped: 0,
        dependency_sites: sites.len().try_into().unwrap_or(u64::MAX),
        resolved: sites.len().try_into().unwrap_or(u64::MAX),
        candidates: 0,
        external: 0,
        unresolved: 0,
        unsupported_syntax: 0,
        project_code_executed: true,
        completeness: vec![CompletenessLevel::BuildObserved],
        reasons: Vec::new(),
    };
    let mut seq = 0_u64;
    let mut next_common = || {
        seq += 1;
        CommonFields {
            protocol_version: "1.0".to_owned(),
            scan_id: audit.run_id.clone(),
            adapter: audit.adapter.clone(),
            adapter_version: audit.adapter_version.clone(),
            seq,
        }
    };
    let mut events = vec![ProtocolEvent::ScanStarted(ScanStarted {
        common: next_common(),
        root: ".".to_owned(),
        project_code_executed: true,
        safe_mode: false,
    })];
    events.push(ProtocolEvent::ProfileDeclared(ProfileDeclared {
        common: next_common(),
        profile,
    }));
    for node in nodes.into_values() {
        events.push(ProtocolEvent::NodeUpsert(NodeUpsert {
            common: next_common(),
            node,
        }));
    }
    for site in sites.into_values() {
        events.push(ProtocolEvent::DependencySite(DependencySiteEvent {
            common: next_common(),
            site,
        }));
    }
    for edge in edges.into_values() {
        events.push(ProtocolEvent::EdgeUpsert(EdgeUpsert {
            common: next_common(),
            edge,
        }));
    }
    events.push(ProtocolEvent::ProfileCompleted(ProfileCompleted {
        common: next_common(),
        profile_id: audit.profile_id.clone(),
        coverage: coverage.clone(),
    }));
    events.push(ProtocolEvent::ScanCompleted(ScanCompleted {
        common: next_common(),
        coverage,
    }));
    Ok(events)
}

pub fn rust_build_protocol_ndjson(
    snapshot: &GraphSnapshot,
    audit: &BuildAudit,
    observation: &RustBuildObservation,
) -> Result<Vec<u8>> {
    let events = rust_build_protocol_events(snapshot, audit, observation)?;
    let mut output = Vec::new();
    for event in events {
        serde_json::to_writer(&mut output, &event)?;
        output.push(b'\n');
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use depgraph_store::{
        CoverageRecord, EdgeRecord, EvidenceRecord, GraphSnapshot, NodeRecord, ScanRecord,
        SiteRecord,
    };
    use serde_json::json;

    use super::*;
    use crate::build::NetworkIsolation;

    fn cargo_message_fixture(workspace: &Path, output: &Path) -> Result<(Vec<u8>, String, String)> {
        let build_source = workspace.join("build.rs");
        let macro_source = workspace.join("macro/src/lib.rs");
        fs::create_dir_all(macro_source.parent().context("macro source parent")?)?;
        fs::write(&build_source, "fn main() {}\n")?;
        fs::write(&macro_source, "extern crate proc_macro;\n")?;

        let out_dir = output.join("cargo-target/debug/build/app-fixture/out");
        fs::create_dir_all(out_dir.join("nested"))?;
        fs::write(
            out_dir.join("generated.rs"),
            "pub const GENERATED: bool = true;\n",
        )?;
        fs::write(out_dir.join("nested/data.bin"), b"observed-bytes")?;
        let extension = if cfg!(windows) {
            "dll"
        } else if cfg!(target_os = "macos") {
            "dylib"
        } else {
            "so"
        };
        let macro_binary = output.join(format!("cargo-target/debug/libfixture_macro.{extension}"));
        fs::create_dir_all(macro_binary.parent().context("macro binary parent")?)?;
        fs::write(&macro_binary, b"proc-macro-binary")?;

        let app_id = format!("path+file://{}#app@0.1.0", workspace.display());
        let macro_id = format!("path+file://{}#fixture-macro@0.1.0", workspace.display());
        let messages = [
            json!({
                "reason": "compiler-artifact",
                "package_id": app_id,
                "target": {
                    "name": "build-script-build",
                    "kind": ["custom-build"],
                    "src_path": build_source,
                },
                "filenames": [output.join("cargo-target/debug/build/app-fixture/build-script-build")],
            }),
            json!({
                "reason": "compiler-artifact",
                "package_id": macro_id,
                "target": {
                    "name": "fixture_macro",
                    "kind": ["proc-macro"],
                    "src_path": macro_source,
                },
                "filenames": [macro_binary],
            }),
            json!({
                "reason": "build-script-executed",
                "package_id": app_id,
                "linked_libs": ["dylib=observed_native"],
                "linked_paths": [
                    format!("native={}", out_dir.display()),
                    format!("framework={}", workspace.display()),
                ],
                "cfgs": ["mode=\"release\"", "observed_cfg"],
                "env": [
                    ["OBSERVED_ENV", "hidden-env-value"],
                    ["API_TOKEN", "super-secret-token"],
                ],
                "out_dir": out_dir,
            }),
            json!({"reason": "build-finished", "success": true}),
        ];
        let stdout = messages
            .into_iter()
            .map(|message| serde_json::to_string(&message))
            .collect::<std::result::Result<Vec<_>, _>>()?
            .join("\n")
            .into_bytes();
        Ok((
            stdout,
            workspace.to_string_lossy().into_owned(),
            output.to_string_lossy().into_owned(),
        ))
    }

    #[test]
    fn cargo_json_observation_is_deterministic_and_redacts_untrusted_values() -> Result<()> {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        let output = root.path().join("output");
        fs::create_dir_all(&workspace)?;
        fs::create_dir_all(&output)?;
        let (stdout, workspace_path, output_path) = cargo_message_fixture(&workspace, &output)?;

        let first = collect_rust_build_observation(&stdout, &workspace, &output)?;
        let second = collect_rust_build_observation(&stdout, &workspace, &output)?;
        assert_eq!(first, second);
        assert_eq!(first.build_scripts.len(), 1);
        assert_eq!(first.proc_macros.len(), 1);
        assert_eq!(first.build_scripts[0].out_dir_artifacts.len(), 2);
        assert_eq!(first.build_scripts[0].environment_keys, ["OBSERVED_ENV"]);
        assert_eq!(first.build_scripts[0].redacted_environment_key_count, 1);
        assert_eq!(first.build_scripts[0].linked_libraries[0].kind, "dylib");
        assert_eq!(
            first.build_scripts[0].linked_libraries[0].name,
            "observed_native"
        );
        let valued_cfg = first.build_scripts[0]
            .cfgs
            .iter()
            .find(|cfg| cfg.key == "mode")
            .context("valued cfg")?;
        assert_eq!(
            valued_cfg.value_digest.as_deref(),
            Some(sha256("release").as_str())
        );

        let serialized = serde_json::to_string(&first)?;
        for secret in [
            "hidden-env-value",
            "super-secret-token",
            "API_TOKEN",
            "release",
            &workspace_path,
            &output_path,
            "depgraph-build-",
        ] {
            assert!(!serialized.contains(secret), "leaked {secret}");
        }
        Ok(())
    }

    #[test]
    fn cargo_json_observation_rejects_incomplete_or_path_like_link_evidence() -> Result<()> {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        let output = root.path().join("output");
        fs::create_dir_all(&workspace)?;
        fs::create_dir_all(&output)?;
        let (stdout, _, _) = cargo_message_fixture(&workspace, &output)?;

        let mut lines = std::str::from_utf8(&stdout)?.lines().collect::<Vec<_>>();
        lines.pop();
        let error =
            collect_rust_build_observation(lines.join("\n").as_bytes(), &workspace, &output)
                .unwrap_err();
        assert!(error.to_string().contains("did not complete"));

        let mut messages = std::str::from_utf8(&stdout)?
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        messages[2]["linked_libs"] = json!(["dylib=/private/native"]);
        let tampered = messages
            .into_iter()
            .map(|message| serde_json::to_string(&message))
            .collect::<std::result::Result<Vec<_>, _>>()?
            .join("\n");
        let error =
            collect_rust_build_observation(tampered.as_bytes(), &workspace, &output).unwrap_err();
        assert!(error.to_string().contains("linked library name"));
        Ok(())
    }

    fn base_node(id: &str, kind: &str, display_name: &str, properties: Value) -> NodeRecord {
        NodeRecord {
            id: id.to_owned(),
            kind: kind.to_owned(),
            locator: format!("safe://{display_name}"),
            display_name: display_name.to_owned(),
            properties,
        }
    }

    fn source_evidence(site_id: &str, path: &str) -> EvidenceRecord {
        EvidenceRecord {
            owner_type: "site".to_owned(),
            owner_id: site_id.to_owned(),
            ordinal: 0,
            kind: "source".to_owned(),
            extractor: "rust-safe".to_owned(),
            extractor_version: "1.0.0".to_owned(),
            path: path.to_owned(),
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 8,
            detail: None,
            properties: json!({}),
        }
    }

    fn safe_snapshot() -> GraphSnapshot {
        let condition = json!({"op":"all","conditions":[]});
        GraphSnapshot {
            scan: ScanRecord {
                id: "safe-scan".to_owned(),
                root: "/safe/root".to_owned(),
                status: "completed".to_owned(),
                strict: false,
                started_at: "2026-07-22T00:00:00.000Z".to_owned(),
                completed_at: Some("2026-07-22T00:00:01.000Z".to_owned()),
                project_code_executed: false,
                error: None,
            },
            profiles: Vec::new(),
            nodes: vec![
                base_node(
                    "package:app",
                    "package_instance",
                    "app",
                    json!({
                        "ecosystem":"cargo", "name":"app", "version":"0.1.0",
                        "manifest_path":"Cargo.toml", "safe_marker":"preserved"
                    }),
                ),
                base_node(
                    "package:macro",
                    "package_instance",
                    "fixture-macro",
                    json!({
                        "ecosystem":"cargo", "name":"fixture-macro", "version":"0.1.0",
                        "manifest_path":"macro/Cargo.toml"
                    }),
                ),
                base_node(
                    "file:build",
                    "file",
                    "build.rs",
                    json!({"path":"build.rs", "package":"app"}),
                ),
                base_node(
                    "file:app",
                    "file",
                    "src/lib.rs",
                    json!({"path":"src/lib.rs", "package":"app"}),
                ),
            ],
            sites: vec![
                SiteRecord {
                    id: "site:out-dir".to_owned(),
                    source: "file:app".to_owned(),
                    kind: "environment".to_owned(),
                    specifier: Some("OUT_DIR".to_owned()),
                    profile_id: "rust:safe".to_owned(),
                    resolution_status: "unresolved".to_owned(),
                    precision: "syntax".to_owned(),
                    condition: condition.clone(),
                    target_ids: Vec::new(),
                    reason: Some("build-output-not-executed".to_owned()),
                },
                SiteRecord {
                    id: "site:proc-macro".to_owned(),
                    source: "file:app".to_owned(),
                    kind: "proc_macro_expansion".to_owned(),
                    specifier: Some("Observed".to_owned()),
                    profile_id: "rust:safe".to_owned(),
                    resolution_status: "unresolved".to_owned(),
                    precision: "syntax".to_owned(),
                    condition: condition.clone(),
                    target_ids: Vec::new(),
                    reason: Some("proc-macro-not-executed".to_owned()),
                },
            ],
            edges: vec![EdgeRecord {
                id: "edge:app-macro".to_owned(),
                site_id: None,
                source: "package:app".to_owned(),
                target: "package:macro".to_owned(),
                kind: "depends_on".to_owned(),
                phase: "source".to_owned(),
                environment: "host".to_owned(),
                profile_id: "rust:safe".to_owned(),
                resolution_status: "resolved".to_owned(),
                precision: "exact".to_owned(),
                condition,
                generated: false,
            }],
            evidence: vec![
                source_evidence("site:out-dir", "src/lib.rs"),
                source_evidence("site:proc-macro", "src/lib.rs"),
            ],
            diagnostics: Vec::new(),
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: CoverageRecord {
                project_code_executed: false,
                ..CoverageRecord::default()
            },
        }
    }

    fn completed_audit() -> BuildAudit {
        BuildAudit {
            schema_version: "1.0".to_owned(),
            run_id: "build-run".to_owned(),
            adapter: RUST_BUILD_OBSERVER.to_owned(),
            adapter_version: RUST_BUILD_OBSERVER_VERSION.to_owned(),
            profile_id: "rust:build".to_owned(),
            command_program: "cargo".to_owned(),
            command_arguments: vec!["build".to_owned(), "--offline".to_owned()],
            command_plan_digest: "a".repeat(64),
            logical_cwd: ".".to_owned(),
            source_root_digest: "b".repeat(64),
            toolchain_executable_digest: "c".repeat(64),
            toolchain_version: Some("cargo 1.93.0".to_owned()),
            target: None,
            environment_keys: vec!["PATH".to_owned()],
            environment_key_set_digest: "d".repeat(64),
            redacted_secret_key_count: 0,
            timeout_seconds: 900,
            stdout_limit_bytes: 1024,
            stderr_limit_bytes: 1024,
            network_policy: "deny".to_owned(),
            network_isolation: NetworkIsolation::BestEffort,
            isolation_diagnostic: Some("fixture".to_owned()),
            started_at: "2026-07-22T00:00:00.000Z".to_owned(),
            finished_at: "2026-07-22T00:00:01.000Z".to_owned(),
            duration_millis: 1_000,
            outcome: BuildOutcomeKind::Completed,
            exit_code: Some(0),
            stdout_truncated: false,
            stderr_truncated: false,
            validated_output_digest: Some("e".repeat(64)),
            diagnostic_code: None,
        }
    }

    fn complete_observation() -> RustBuildObservation {
        RustBuildObservation {
            schema_version: RUST_BUILD_OBSERVATION_SCHEMA.to_owned(),
            observer: RUST_BUILD_OBSERVER.to_owned(),
            observer_version: RUST_BUILD_OBSERVER_VERSION.to_owned(),
            capability: RUST_BUILD_CAPABILITY.to_owned(),
            build_finished: true,
            build_scripts: vec![RustObservedBuildScript {
                package_key: "app@0.1.0#build.rs".to_owned(),
                package_name: "app".to_owned(),
                package_version: Some("0.1.0".to_owned()),
                source_path: "build.rs".to_owned(),
                out_dir_logical_path: "rust-build/app/out".to_owned(),
                out_dir_artifacts: vec![RustObservedArtifact {
                    logical_path: "rust-build/app/out/generated.rs".to_owned(),
                    digest: "f".repeat(64),
                    byte_len: 32,
                }],
                cfgs: vec![RustObservedCfg {
                    key: "observed_cfg".to_owned(),
                    value_digest: None,
                }],
                environment_keys: vec!["OBSERVED_ENV".to_owned()],
                redacted_environment_key_count: 1,
                linked_libraries: vec![RustObservedLinkedLibrary {
                    kind: "dylib".to_owned(),
                    name: "observed_native".to_owned(),
                }],
                linked_paths: vec![RustObservedLinkPath {
                    kind: "native".to_owned(),
                    scope: "out-dir".to_owned(),
                }],
            }],
            proc_macros: vec![RustObservedProcMacro {
                package_key: "fixture-macro@0.1.0#macro/src/lib.rs".to_owned(),
                package_name: "fixture-macro".to_owned(),
                package_version: Some("0.1.0".to_owned()),
                source_path: "macro/src/lib.rs".to_owned(),
                binaries: vec![RustObservedArtifact {
                    logical_path: "rust-build/macro/proc-macro/0.dylib".to_owned(),
                    digest: "1".repeat(64),
                    byte_len: 64,
                }],
            }],
        }
    }

    #[test]
    fn build_protocol_correlates_observed_evidence_without_overwriting_safe_nodes() -> Result<()> {
        let snapshot = safe_snapshot();
        let audit = completed_audit();
        let observation = complete_observation();
        let ndjson = rust_build_protocol_ndjson(&snapshot, &audit, &observation)?;
        assert_eq!(
            ndjson,
            rust_build_protocol_ndjson(&snapshot, &audit, &observation)?
        );
        depgraph_protocol::validate_build_ndjson(Cursor::new(&ndjson))?;

        let serialized = std::str::from_utf8(&ndjson)?;
        for expected in [
            "build_script_run",
            "proc_macro_binary",
            "native_library",
            "reads_build_output",
            "expands_with_proc_macro",
            "safe_marker",
            "build-observed",
        ] {
            assert!(serialized.contains(expected), "missing {expected}");
        }
        assert!(!serialized.contains("super-secret-token"));
        assert!(!serialized.contains("/safe/root"));
        Ok(())
    }
}
