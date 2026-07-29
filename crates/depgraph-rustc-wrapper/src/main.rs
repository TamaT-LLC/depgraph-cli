use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
    process::{Command, ExitCode},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const RECORD_SCHEMA_VERSION: &str = "depgraph-rust-compiler-invocation-record-v1";
const EXPECTED_GRAPH_SCHEMA_VERSION: &str = "depgraph-rust-cargo-unit-graph-v1";
const MAX_ARGUMENTS: usize = 16_384;
const MAX_ARGUMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_EXPECTED_GRAPH_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 4_096;

const ENV_ATTEMPT_DIGEST: &str = "DEPGRAPH_COMPILER_ATTEMPT_DIGEST";
const ENV_EXPECTED_GRAPH: &str = "DEPGRAPH_COMPILER_EXPECTED_UNIT_GRAPH";
const ENV_EXPECTED_RUSTC: &str = "DEPGRAPH_COMPILER_EXPECTED_RUSTC";
const ENV_EXPECTED_RUSTC_SHA256: &str = "DEPGRAPH_COMPILER_EXPECTED_RUSTC_SHA256";
const ENV_EXPECTED_RUSTC_VERBOSE_SHA256: &str = "DEPGRAPH_COMPILER_EXPECTED_RUSTC_VERBOSE_SHA256";
const ENV_LEDGER_DIR: &str = "DEPGRAPH_COMPILER_LEDGER_DIR";
const ENV_OUTPUT_ROOT: &str = "DEPGRAPH_COMPILER_OUTPUT_ROOT";
const ENV_PACK_ROOT: &str = "DEPGRAPH_COMPILER_PACK_ROOT";
const ENV_WORKSPACE_ROOT: &str = "DEPGRAPH_COMPILER_WORKSPACE_ROOT";
const ENV_WRAPPER_ACTIVE: &str = "DEPGRAPH_COMPILER_WRAPPER_ACTIVE";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectedGraph {
    schema_version: String,
    digest: String,
    units: Vec<ExpectedUnit>,
    roots: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectedUnit {
    unit_id: String,
    package_id: String,
    target: ExpectedTarget,
    profile: ExpectedProfile,
    platform: Option<String>,
    mode: String,
    features: Vec<String>,
    is_std: bool,
    dependencies: Vec<ExpectedDependency>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectedTarget {
    kind: Vec<String>,
    crate_types: Vec<String>,
    name: String,
    src_path: String,
    edition: String,
    doc: bool,
    doctest: bool,
    test: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectedProfile {
    name: String,
    opt_level: String,
    lto: String,
    codegen_units: Option<u64>,
    debuginfo: Option<u64>,
    split_debuginfo: Option<String>,
    debug_assertions: bool,
    overflow_checks: bool,
    rpath: bool,
    incremental: bool,
    panic: String,
    strip: ExpectedStrip,
    codegen_backend: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExpectedStrip {
    Deferred(String),
    Resolved(String),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectedDependency {
    unit_id: String,
    extern_crate_name: String,
    public: bool,
    noprelude: bool,
    nounused: bool,
}

#[derive(Debug, Serialize)]
struct StartRecord {
    schema_version: &'static str,
    record_kind: &'static str,
    invocation_id: String,
    attempt_digest: String,
    unit_id: String,
    crate_name: String,
    crate_types: Vec<String>,
    source_path: String,
    source_sha256: String,
    profile_digest: String,
    edition: String,
    target: Option<String>,
    mode: String,
    features: Vec<String>,
    canonical_argv: Vec<String>,
    argv_digest: String,
    rustc_sha256: String,
    rustc_verbose_sha256: String,
}

#[derive(Debug, Serialize)]
struct TerminalRecord {
    schema_version: &'static str,
    record_kind: &'static str,
    invocation_id: String,
    attempt_digest: String,
    start_record_sha256: String,
    status: &'static str,
    exit_code: Option<i32>,
}

#[derive(Debug)]
struct Invocation {
    crate_name: String,
    crate_types: Vec<String>,
    source_path: String,
    source_sha256: String,
    edition: String,
    target: Option<String>,
    mode: String,
    features: Vec<String>,
    canonical_argv: Vec<String>,
}

#[derive(Debug)]
struct Roots {
    workspace: PathBuf,
    cargo_home: PathBuf,
    output: PathBuf,
    pack: PathBuf,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(u8::try_from(code.clamp(0, 255)).unwrap_or(1)),
        Err(error) => {
            eprintln!("depgraph-rustc-wrapper: {error:#}");
            ExitCode::from(86)
        }
    }
}

fn run() -> Result<i32> {
    if env::var_os(ENV_WRAPPER_ACTIVE).is_some() {
        bail!("nested compiler wrapper invocation is forbidden");
    }
    let raw_args = env::args_os().skip(1).collect::<Vec<_>>();
    if raw_args.len() < 2
        || raw_args.len() > MAX_ARGUMENTS
        || raw_args
            .iter()
            .try_fold(0_usize, |total, value| {
                total.checked_add(value.as_encoded_bytes().len())
            })
            .is_none_or(|total| total > MAX_ARGUMENT_BYTES)
    {
        bail!("rustc invocation argument bounds are invalid");
    }
    let actual_rustc = canonical_regular_file(Path::new(&raw_args[0]), "actual rustc")?;
    let expected_rustc = canonical_regular_file(
        &required_absolute_path(ENV_EXPECTED_RUSTC)?,
        "expected rustc",
    )?;
    if actual_rustc != expected_rustc {
        bail!("actual rustc path does not match the attested compiler");
    }
    let expected_rustc_sha256 = required_digest(ENV_EXPECTED_RUSTC_SHA256)?;
    let rustc_sha256 = digest_file(&actual_rustc)?;
    if rustc_sha256 != expected_rustc_sha256 {
        bail!("actual rustc digest does not match the attested compiler");
    }
    let verbose = Command::new(&actual_rustc)
        .arg("-vV")
        .env_clear()
        .output()
        .context("failed to probe actual rustc identity")?;
    if !verbose.status.success() || verbose.stdout.len() > 64 * 1024 {
        bail!("actual rustc verbose identity is unavailable");
    }
    let rustc_verbose_sha256 = digest_bytes(&verbose.stdout);
    if rustc_verbose_sha256 != required_digest(ENV_EXPECTED_RUSTC_VERBOSE_SHA256)? {
        bail!("actual rustc verbose identity does not match the attested compiler");
    }

    let roots = Roots {
        workspace: canonical_directory(
            &required_absolute_path(ENV_WORKSPACE_ROOT)?,
            "workspace root",
        )?,
        cargo_home: canonical_directory(&required_absolute_path("CARGO_HOME")?, "Cargo home")?,
        output: canonical_directory(&required_absolute_path(ENV_OUTPUT_ROOT)?, "output root")?,
        pack: canonical_directory(
            &required_absolute_path(ENV_PACK_ROOT)?,
            "compiler pack root",
        )?,
    };
    let ledger_dir = confined_directory(
        &required_absolute_path(ENV_LEDGER_DIR)?,
        &roots.output,
        "ledger",
    )?;
    let expected_graph_path = confined_regular_file(
        &required_absolute_path(ENV_EXPECTED_GRAPH)?,
        &roots.output,
        "expected unit graph",
    )?;
    let expected_graph = read_expected_graph(&expected_graph_path)?;
    let attempt_digest = required_digest(ENV_ATTEMPT_DIGEST)?;
    let invocation = parse_invocation(&raw_args[1..], &roots)?;
    let (unit_id, profile_digest) = match_unit(&invocation, &expected_graph)?;
    let argv_digest = digest_json(&invocation.canonical_argv)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes the Unix epoch")?
        .as_nanos();
    let invocation_id = digest_bytes(
        format!(
            "{attempt_digest}\0{unit_id}\0{}\0{nonce}",
            std::process::id()
        )
        .as_bytes(),
    );
    let start = StartRecord {
        schema_version: RECORD_SCHEMA_VERSION,
        record_kind: "start",
        invocation_id: invocation_id.clone(),
        attempt_digest: attempt_digest.clone(),
        unit_id,
        crate_name: invocation.crate_name,
        crate_types: invocation.crate_types,
        source_path: invocation.source_path,
        source_sha256: invocation.source_sha256,
        profile_digest,
        edition: invocation.edition,
        target: invocation.target,
        mode: invocation.mode,
        features: invocation.features,
        canonical_argv: invocation.canonical_argv,
        argv_digest,
        rustc_sha256,
        rustc_verbose_sha256,
    };
    let start_bytes = canonical_json_bytes(&start)?;
    write_new_record(
        &ledger_dir.join(format!("start-{invocation_id}.json")),
        &start_bytes,
    )?;

    let status = Command::new(&actual_rustc)
        .args(&raw_args[1..])
        .env(ENV_WRAPPER_ACTIVE, "1")
        .status()
        .context("failed to start attested rustc")?;
    let terminal = TerminalRecord {
        schema_version: RECORD_SCHEMA_VERSION,
        record_kind: "terminal",
        invocation_id: invocation_id.clone(),
        attempt_digest,
        start_record_sha256: digest_bytes(&start_bytes),
        status: if status.success() {
            "completed"
        } else {
            "failed"
        },
        exit_code: status.code(),
    };
    write_new_record(
        &ledger_dir.join(format!("terminal-{invocation_id}.json")),
        &canonical_json_bytes(&terminal)?,
    )?;
    Ok(status.code().unwrap_or(1))
}

fn parse_invocation(args: &[OsString], roots: &Roots) -> Result<Invocation> {
    let mut crate_name = None;
    let mut crate_types = BTreeSet::new();
    let mut source = None;
    let mut edition = None;
    let mut target = None;
    let mut features = BTreeSet::new();
    let mut test = false;
    let mut canonical_argv = Vec::with_capacity(args.len());
    let mut index = 0;
    while index < args.len() {
        let value = args[index]
            .to_str()
            .context("rustc invocation contains non-UTF-8 arguments")?;
        validate_text(value)?;
        reject_secret_shaped_text(value)?;
        if value.contains('@') {
            bail!("rustc response files are forbidden");
        }
        let (key, inline) = split_option(value);
        let consumes = matches!(
            key,
            "--crate-name"
                | "--crate-type"
                | "--edition"
                | "--target"
                | "--out-dir"
                | "--extern"
                | "--emit"
                | "--cfg"
                | "--check-cfg"
                | "--sysroot"
                | "--remap-path-prefix"
                | "-L"
                | "-C"
                | "-A"
                | "-W"
                | "-D"
                | "-F"
        );
        let option_value = if inline.is_some() {
            inline
        } else if consumes {
            index += 1;
            Some(
                args.get(index)
                    .context("rustc option is missing its value")?
                    .to_str()
                    .context("rustc invocation contains non-UTF-8 arguments")?,
            )
        } else {
            None
        };
        match key {
            "--crate-name" => crate_name = Some(required_option_value(option_value)?.to_owned()),
            "--crate-type" => {
                for crate_type in required_option_value(option_value)?.split(',') {
                    validate_identity(crate_type)?;
                    crate_types.insert(crate_type.to_owned());
                }
            }
            "--edition" => edition = Some(required_option_value(option_value)?.to_owned()),
            "--target" => target = Some(required_option_value(option_value)?.to_owned()),
            "--cfg" => {
                let cfg = required_option_value(option_value)?;
                if let Some(feature) = cfg
                    .strip_prefix("feature=\"")
                    .and_then(|v| v.strip_suffix('"'))
                {
                    validate_text(feature)?;
                    features.insert(feature.to_owned());
                }
            }
            "--test" => test = true,
            _ if !value.starts_with('-') => {
                if source.is_some() {
                    bail!("rustc invocation contains more than one source input");
                }
                source = Some(value.to_owned());
            }
            _ => {}
        }
        canonical_argv.push(canonicalize_argument(value, key, option_value, roots)?);
        if inline.is_none() && consumes {
            let raw_value = option_value.context("rustc option is missing its value")?;
            validate_text(raw_value)?;
            reject_secret_shaped_text(raw_value)?;
            if raw_value.contains('@') {
                bail!("rustc response files are forbidden");
            }
            canonical_argv.push(canonicalize_option_value(key, raw_value, roots)?);
        }
        index += 1;
    }
    let crate_name = crate_name.context("rustc invocation omitted --crate-name")?;
    validate_identity(&crate_name)?;
    let edition = edition.context("rustc invocation omitted --edition")?;
    validate_identity(&edition)?;
    let source = source.context("rustc invocation omitted its source input")?;
    let source = normalize_existing_file(&source, roots, true)?;
    let source_sha256 = if let Some(relative) = source.strip_prefix("repo://") {
        digest_file(&roots.workspace.join(relative))?
    } else if let Some(relative) = source.strip_prefix("cargo-home://") {
        digest_file(&roots.cargo_home.join(relative))?
    } else {
        bail!("rustc source is outside the staged source roots");
    };
    if crate_types.is_empty() {
        crate_types.insert("bin".to_owned());
    }
    Ok(Invocation {
        crate_name,
        crate_types: crate_types.into_iter().collect(),
        source_path: source,
        source_sha256,
        edition,
        target,
        mode: if test { "test" } else { "build" }.to_owned(),
        features: features.into_iter().collect(),
        canonical_argv,
    })
}

fn match_unit(invocation: &Invocation, graph: &ExpectedGraph) -> Result<(String, String)> {
    let mut matches = graph
        .units
        .iter()
        .filter(|unit| {
            let expected_name = unit.target.name.replace('-', "_");
            let mut expected_types = unit.target.crate_types.clone();
            expected_types.sort();
            expected_types.dedup();
            expected_name == invocation.crate_name
                && expected_types == invocation.crate_types
                && unit.target.src_path == invocation.source_path
                && unit.target.edition == invocation.edition
                && unit.features == invocation.features
                && unit.mode == invocation.mode
                && unit.platform == invocation.target
        })
        .map(|unit| {
            Ok((
                unit.unit_id.clone(),
                digest_json(&unit.profile)
                    .context("failed to digest admitted Cargo unit profile")?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    matches.sort();
    matches.dedup();
    if matches.len() != 1 {
        bail!("rustc invocation does not match exactly one admitted Cargo unit");
    }
    Ok(matches.remove(0))
}

fn canonicalize_argument(
    raw: &str,
    key: &str,
    inline: Option<&str>,
    roots: &Roots,
) -> Result<String> {
    if let Some(value) = inline {
        let normalized = canonicalize_option_value(key, value, roots)?;
        return Ok(format!("{key}={normalized}"));
    }
    if !raw.starts_with('-') {
        return normalize_existing_file(raw, roots, true);
    }
    canonicalize_embedded_paths(raw, roots)
}

fn canonicalize_option_value(key: &str, value: &str, roots: &Roots) -> Result<String> {
    match key {
        "--out-dir" | "--sysroot" => normalize_path(value, roots, false),
        "--extern" => {
            let (name, path) = value
                .split_once('=')
                .context("--extern must name a confined artifact")?;
            validate_identity(name)?;
            Ok(format!("{name}={}", normalize_path(path, roots, false)?))
        }
        "-L" => {
            let (kind, path) = value.split_once('=').unwrap_or(("", value));
            let path = normalize_path(path, roots, false)?;
            Ok(if kind.is_empty() {
                path
            } else {
                format!("{kind}={path}")
            })
        }
        "-C" => {
            if let Some((name, path)) = value.split_once('=')
                && matches!(
                    name,
                    "incremental" | "profile-generate" | "profile-use" | "symbol-mangling-version"
                )
                && (name != "symbol-mangling-version" || Path::new(path).is_absolute())
            {
                return Ok(format!("{name}={}", normalize_path(path, roots, false)?));
            }
            canonicalize_embedded_paths(value, roots)
        }
        "--remap-path-prefix" => {
            let (from, to) = value
                .split_once('=')
                .context("--remap-path-prefix must contain a mapping")?;
            Ok(format!("{}={to}", normalize_path(from, roots, false)?))
        }
        _ => canonicalize_embedded_paths(value, roots),
    }
}

fn normalize_existing_file(value: &str, roots: &Roots, workspace_only: bool) -> Result<String> {
    let path = if Path::new(value).is_absolute() {
        PathBuf::from(value)
    } else {
        roots.workspace.join(value)
    };
    let path = canonical_regular_file(&path, "rustc input")?;
    let normalized = normalize_canonical_path(&path, roots)?;
    if workspace_only
        && !(normalized.starts_with("repo://") || normalized.starts_with("cargo-home://"))
    {
        bail!("rustc source input escapes the staged source roots");
    }
    Ok(normalized)
}

fn normalize_path(value: &str, roots: &Roots, must_exist: bool) -> Result<String> {
    let path = Path::new(value);
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        bail!("rustc path contains parent traversal");
    }
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        roots.workspace.join(path)
    };
    let canonical = if must_exist {
        path.canonicalize().context("rustc path is unavailable")?
    } else {
        canonicalize_with_existing_parent(&path)?
    };
    normalize_canonical_path(&canonical, roots)
}

fn normalize_canonical_path(path: &Path, roots: &Roots) -> Result<String> {
    for (label, root) in [
        ("repo:", &roots.workspace),
        ("cargo-home:", &roots.cargo_home),
        ("output", &roots.output),
        ("pack", &roots.pack),
    ] {
        if let Ok(relative) = path.strip_prefix(root) {
            let rendered = slash_path(relative)?;
            return Ok(if rendered.is_empty() {
                label.to_owned()
            } else if label.ends_with(':') {
                format!("{label}//{rendered}")
            } else {
                format!("{label}/{rendered}")
            });
        }
    }
    bail!("rustc path escapes the staged workspace, output, and compiler pack")
}

fn canonicalize_with_existing_parent(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return path.canonicalize().context("rustc path is unavailable");
    }
    let parent = path
        .parent()
        .context("rustc path has no parent")?
        .canonicalize()
        .context("rustc path parent is unavailable")?;
    let name = path.file_name().context("rustc path has no file name")?;
    Ok(parent.join(name))
}

fn canonicalize_embedded_paths(value: &str, roots: &Roots) -> Result<String> {
    reject_secret_shaped_text(value)?;
    let mut output = String::with_capacity(value.len());
    let mut start = 0;
    for (index, delimiter) in value
        .char_indices()
        .filter(|(_, character)| matches!(character, '=' | ',' | ';' | ' ' | '\t'))
    {
        output.push_str(&canonicalize_embedded_path_fragment(
            &value[start..index],
            roots,
        )?);
        output.push(delimiter);
        start = index + delimiter.len_utf8();
    }
    output.push_str(&canonicalize_embedded_path_fragment(
        &value[start..],
        roots,
    )?);
    Ok(output)
}

fn canonicalize_embedded_path_fragment(fragment: &str, roots: &Roots) -> Result<String> {
    let path = Path::new(fragment);
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        bail!("rustc argument contains parent traversal");
    }
    if path.is_absolute() {
        normalize_path(fragment, roots, false)
    } else if is_portable_windows_absolute(fragment)
        || fragment.starts_with("\\\\")
        || fragment.contains("://")
    {
        bail!("rustc argument contains a portable absolute path or URI")
    } else {
        Ok(fragment.to_owned())
    }
}

fn is_portable_windows_absolute(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

fn reject_secret_shaped_text(value: &str) -> Result<()> {
    let lower = value.to_ascii_lowercase();
    let non_logical_url = lower.replace("repo://", "").replace("cargo-home://", "");
    if [
        "authorization:",
        "bearer ",
        "password=",
        "passwd=",
        "client_secret=",
        "private_key=",
        "secret_key=",
        "api_key=",
        "access_token=",
        "-----begin ",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
        || value
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .any(|token| {
                (token.starts_with("ghp_") && token.len() >= 20)
                    || (token.starts_with("github_pat_") && token.len() >= 24)
                    || (token.starts_with("AKIA") && token.len() == 20)
            })
        || value
            .split(|character: char| character.is_ascii_whitespace() || character == ',')
            .any(|token| token.starts_with("sk-") && token.len() >= 20)
        || non_logical_url
            .split_once("://")
            .is_some_and(|(_, remainder)| {
                remainder
                    .split(['/', '?', '#'])
                    .next()
                    .is_some_and(|authority| authority.contains('@'))
            })
    {
        bail!("rustc invocation contains secret-shaped text");
    }
    Ok(())
}

fn split_option(value: &str) -> (&str, Option<&str>) {
    if let Some((key, value)) = value.split_once('=')
        && key.starts_with('-')
    {
        (key, Some(value))
    } else {
        (value, None)
    }
}

fn required_option_value(value: Option<&str>) -> Result<&str> {
    value.context("rustc option is missing its value")
}

fn validate_logical_source_path(value: &str) -> Result<()> {
    let relative = value
        .strip_prefix("repo://")
        .or_else(|| value.strip_prefix("cargo-home://"))
        .context("expected unit source path is not staged-source-relative")?;
    if relative.is_empty()
        || Path::new(relative).is_absolute()
        || Path::new(relative)
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        bail!("expected unit source path is not confined");
    }
    Ok(())
}

fn validate_sorted_unique(values: &[String], allow_empty: bool) -> Result<()> {
    if (!allow_empty && values.is_empty()) || !values.windows(2).all(|window| window[0] < window[1])
    {
        bail!("expected unit graph collection is not canonical");
    }
    for value in values {
        validate_text(value)?;
    }
    Ok(())
}

fn validate_expected_unit(unit: &ExpectedUnit) -> Result<()> {
    validate_text(&unit.package_id)?;
    validate_text(&unit.unit_id)?;
    validate_text(&unit.target.name)?;
    validate_text(&unit.target.edition)?;
    validate_text(&unit.mode)?;
    validate_logical_source_path(&unit.target.src_path)?;
    validate_sorted_unique(&unit.target.kind, false)?;
    validate_sorted_unique(&unit.target.crate_types, false)?;
    validate_sorted_unique(&unit.features, true)?;
    if let Some(platform) = &unit.platform {
        validate_text(platform)?;
    }
    if !matches!(unit.mode.as_str(), "build" | "test" | "run-custom-build") {
        bail!("expected unit graph mode is unsupported");
    }
    for dependency in &unit.dependencies {
        validate_text(&dependency.unit_id)?;
        validate_text(&dependency.extern_crate_name)?;
    }
    Ok(())
}

fn read_expected_graph(path: &Path) -> Result<ExpectedGraph> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_EXPECTED_GRAPH_BYTES
    {
        bail!("expected unit graph is not a bounded regular file");
    }
    let graph: ExpectedGraph =
        serde_json::from_slice(&fs::read(path)?).context("expected unit graph is invalid")?;
    if graph.schema_version != EXPECTED_GRAPH_SCHEMA_VERSION
        || graph.units.is_empty()
        || graph.units.len() > 100_000
        || graph.roots.is_empty()
        || graph.roots.len() > graph.units.len()
    {
        bail!("expected unit graph identity or bounds are invalid");
    }
    required_hex_digest(&graph.digest)?;
    if graph.digest != digest_bytes(&serde_json::to_vec(&(&graph.units, &graph.roots))?) {
        bail!("expected unit graph digest is invalid");
    }
    let unit_ids = graph
        .units
        .iter()
        .map(|unit| unit.unit_id.as_str())
        .collect::<BTreeSet<_>>();
    if unit_ids.len() != graph.units.len()
        || !graph
            .units
            .windows(2)
            .all(|window| window[0].unit_id < window[1].unit_id)
        || !graph.roots.windows(2).all(|window| window[0] < window[1])
        || graph
            .roots
            .iter()
            .any(|root| !unit_ids.contains(root.as_str()))
    {
        bail!("expected unit graph unit identity is invalid");
    }
    for unit in &graph.units {
        validate_expected_unit(unit)?;
        let _ = (
            unit.target.doc,
            unit.target.doctest,
            unit.target.test,
            &unit.profile,
            unit.is_std,
        );
    }
    Ok(graph)
}

fn required_absolute_path(key: &str) -> Result<PathBuf> {
    let value = env::var_os(key).with_context(|| format!("{key} is unavailable"))?;
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        bail!("{key} must be an absolute path");
    }
    Ok(path)
}

fn required_digest(key: &str) -> Result<String> {
    let value = env::var(key).with_context(|| format!("{key} is unavailable"))?;
    required_hex_digest(&value)?;
    Ok(value)
}

fn required_hex_digest(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("compiler invocation digest is invalid");
    }
    Ok(())
}

fn canonical_regular_file(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("{label} is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{label} is not a regular file");
    }
    path.canonicalize()
        .with_context(|| format!("{label} is unavailable"))
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("{label} is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("{label} is not a directory");
    }
    path.canonicalize()
        .with_context(|| format!("{label} is unavailable"))
}

fn confined_directory(path: &Path, root: &Path, label: &str) -> Result<PathBuf> {
    let path = canonical_directory(path, label)?;
    if !path.starts_with(root) || path == root {
        bail!("{label} escapes its run-owned root");
    }
    Ok(path)
}

fn confined_regular_file(path: &Path, root: &Path, label: &str) -> Result<PathBuf> {
    let path = canonical_regular_file(path, label)?;
    if !path.starts_with(root) || path == root {
        bail!("{label} escapes its run-owned root");
    }
    Ok(path)
}

fn validate_text(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(|character| character.is_control())
    {
        bail!("rustc invocation contains invalid text");
    }
    Ok(())
}

fn validate_identity(value: &str) -> Result<()> {
    validate_text(value)?;
    if value
        .chars()
        .any(|character| !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-')))
    {
        bail!("rustc invocation identity is invalid");
    }
    Ok(())
}

fn slash_path(path: &Path) -> Result<String> {
    let mut output = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => output.push(
                value
                    .to_str()
                    .context("rustc path contains non-UTF-8 text")?,
            ),
            Component::CurDir => {}
            _ => bail!("rustc path is not canonical"),
        }
    }
    Ok(output.join("/"))
}

fn digest_file(path: &Path) -> Result<String> {
    Ok(digest_bytes(&fs::read(path)?))
}

fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn digest_json(value: &impl Serialize) -> Result<String> {
    Ok(digest_bytes(&canonical_json_bytes(value)?))
}

fn canonical_json_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(value)?;
    sort_json(&mut value);
    Ok(serde_json::to_vec(&value)?)
}

fn sort_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                sort_json(value);
            }
        }
        serde_json::Value::Object(object) => {
            let mut entries = std::mem::take(object).into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            for (key, mut value) in entries {
                sort_json(&mut value);
                object.insert(key, value);
            }
        }
        _ => {}
    }
}

fn write_new_record(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("compiler invocation record already exists or cannot be created")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_split_preserves_non_options() {
        assert_eq!(
            split_option("--crate-name=fixture"),
            ("--crate-name", Some("fixture"))
        );
        assert_eq!(split_option("src/lib.rs"), ("src/lib.rs", None));
    }

    #[test]
    fn canonical_paths_reject_escape() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let workspace = temporary.path().join("workspace");
        let output = temporary.path().join("output");
        let pack = temporary.path().join("pack");
        for path in [&workspace, &output, &pack] {
            fs::create_dir(path)?;
        }
        let roots = Roots {
            workspace: workspace.canonicalize()?,
            cargo_home: workspace.canonicalize()?,
            output: output.canonicalize()?,
            pack: pack.canonicalize()?,
        };
        let escaped = temporary.path().join("escaped");
        fs::write(&escaped, b"escape")?;
        assert!(normalize_path(escaped.to_str().unwrap(), &roots, true).is_err());
        fs::create_dir(pack.join("bin"))?;
        let pack_argument = format!("linker={}", pack.join("bin/rust-lld").display());
        assert_eq!(
            canonicalize_embedded_paths(&pack_argument, &roots)?,
            "linker=pack/bin/rust-lld"
        );
        assert!(
            canonicalize_embedded_paths(&format!("emit={}", escaped.display()), &roots).is_err()
        );
        assert!(canonicalize_embedded_paths("linker=C:\\toolchain\\link.exe", &roots).is_err());
        assert!(canonicalize_embedded_paths("source=file:///tmp/fixture.rs", &roots).is_err());
        assert!(reject_secret_shaped_text("api_key=fixture-secret").is_err());
        assert!(reject_secret_shaped_text("tokenizers").is_ok());
        Ok(())
    }
}
