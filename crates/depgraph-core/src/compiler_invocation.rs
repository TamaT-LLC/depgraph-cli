use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::compiler_precise::{RustCargoUnit, RustCargoUnitGraph};

pub const COMPILER_PRECISE_INVOCATION_ADAPTER: &str = "rust-compiler-invocation-ledger";
pub const COMPILER_PRECISE_INVOCATION_ADAPTER_VERSION: &str = "1.0.0";
pub const COMPILER_INVOCATION_RECORD_SCHEMA_VERSION: &str =
    "depgraph-rust-compiler-invocation-record-v1";
pub const COMPILER_INVOCATION_LEDGER_SCHEMA_VERSION: &str =
    "depgraph-rust-compiler-invocation-ledger-v1";
pub const COMPILER_INVOCATION_RECORD_SCHEMA_PATH: &str =
    "schemas/depgraph-rust-compiler-precise-v1.schema.json";
pub const COMPILER_INVOCATION_RECORD_SCHEMA: &str =
    include_str!("../../../schemas/depgraph-rust-compiler-precise-v1.schema.json");
pub const COMPILER_INVOCATION_LEDGER_SCHEMA_PATH: &str =
    "schemas/depgraph-rust-compiler-invocation-ledger-v1.schema.json";
pub const COMPILER_INVOCATION_LEDGER_SCHEMA: &str =
    include_str!("../../../schemas/depgraph-rust-compiler-invocation-ledger-v1.schema.json");

const MAX_LEDGER_FILES: usize = 200_000;
const MAX_LEDGER_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_LEDGER_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ARGUMENTS: usize = 16_384;
const MAX_TEXT_BYTES: usize = 4_096;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustCompilerInvocationLedger {
    pub schema_version: String,
    pub digest: String,
    pub attempt_digest: String,
    pub unit_graph_digest: String,
    pub entries: Vec<RustCompilerInvocation>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustCompilerInvocation {
    pub unit_id: String,
    pub invocation_id: String,
    pub invocation_digest: String,
    pub crate_name: String,
    pub crate_types: Vec<String>,
    pub source_path: String,
    pub source_sha256: String,
    pub profile_digest: String,
    pub edition: String,
    pub target: Option<String>,
    pub mode: String,
    pub features: Vec<String>,
    pub canonical_argv: Vec<String>,
    pub argv_digest: String,
    pub rustc_sha256: String,
    pub rustc_verbose_sha256: String,
    pub terminal_status: String,
    pub exit_code: i32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartRecord {
    schema_version: String,
    record_kind: String,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalRecord {
    schema_version: String,
    record_kind: String,
    invocation_id: String,
    attempt_digest: String,
    start_record_sha256: String,
    status: String,
    exit_code: Option<i32>,
}

#[derive(Serialize)]
struct LedgerIdentity<'a> {
    attempt_digest: &'a str,
    unit_graph_digest: &'a str,
    entries: &'a [RustCompilerInvocation],
}

#[derive(Serialize)]
struct InvocationIdentity<'a> {
    unit_id: &'a str,
    invocation_id: &'a str,
    crate_name: &'a str,
    crate_types: &'a [String],
    source_path: &'a str,
    source_sha256: &'a str,
    profile_digest: &'a str,
    edition: &'a str,
    target: &'a Option<String>,
    mode: &'a str,
    features: &'a [String],
    canonical_argv: &'a [String],
    argv_digest: &'a str,
    rustc_sha256: &'a str,
    rustc_verbose_sha256: &'a str,
    terminal_status: &'a str,
    exit_code: i32,
}

pub fn compiler_invocation_entry_digest(entry: &RustCompilerInvocation) -> Result<String> {
    digest_json(&InvocationIdentity {
        unit_id: &entry.unit_id,
        invocation_id: &entry.invocation_id,
        crate_name: &entry.crate_name,
        crate_types: &entry.crate_types,
        source_path: &entry.source_path,
        source_sha256: &entry.source_sha256,
        profile_digest: &entry.profile_digest,
        edition: &entry.edition,
        target: &entry.target,
        mode: &entry.mode,
        features: &entry.features,
        canonical_argv: &entry.canonical_argv,
        argv_digest: &entry.argv_digest,
        rustc_sha256: &entry.rustc_sha256,
        rustc_verbose_sha256: &entry.rustc_verbose_sha256,
        terminal_status: &entry.terminal_status,
        exit_code: entry.exit_code,
    })
}

pub fn compiler_invocation_ledger_digest(
    attempt_digest: &str,
    unit_graph_digest: &str,
    entries: &[RustCompilerInvocation],
) -> Result<String> {
    digest_json(&LedgerIdentity {
        attempt_digest,
        unit_graph_digest,
        entries,
    })
}

pub fn compiler_invocation_attempt_digest(
    source_root_digest: &str,
    command_plan_digest: &str,
    compiler_pack_manifest_sha256: &str,
    unit_graph_digest: &str,
) -> Result<String> {
    for digest in [
        source_root_digest,
        command_plan_digest,
        compiler_pack_manifest_sha256,
        unit_graph_digest,
    ] {
        validate_digest(digest)?;
    }
    digest_json(&(
        "depgraph-rust-compiler-attempt-v1",
        source_root_digest,
        command_plan_digest,
        compiler_pack_manifest_sha256,
        unit_graph_digest,
    ))
}

pub fn validate_compiler_invocation_unit_graph(graph: &RustCargoUnitGraph) -> Result<()> {
    validate_graph_identity(graph)?;
    if graph.schema_version != crate::compiler_precise::COMPILER_PRECISE_UNIT_GRAPH_SCHEMA_VERSION
        || graph.units.is_empty()
        || graph.units.len() > 100_000
        || graph.roots.is_empty()
        || graph.roots.len() > graph.units.len()
    {
        bail!("compiler invocation Cargo unit graph identity or bounds are invalid");
    }
    let mut unit_ids = BTreeSet::new();
    let mut previous = None;
    for unit in &graph.units {
        validate_text("compiler invocation Cargo unit", &unit.unit_id)?;
        if previous.is_some_and(|previous| previous >= unit.unit_id.as_str())
            || !unit_ids.insert(unit.unit_id.as_str())
        {
            bail!("compiler invocation Cargo units are not strictly sorted and unique");
        }
        previous = Some(unit.unit_id.as_str());
        validate_source_path(&unit.target.src_path)?;
        if unit.package_id.contains("file://")
            || Path::new(&unit.package_id).is_absolute()
            || contains_parent_traversal(&unit.package_id)
        {
            bail!("compiler invocation Cargo package identity contains an unconfined path");
        }
    }
    if !graph.roots.windows(2).all(|window| window[0] < window[1])
        || graph
            .roots
            .iter()
            .any(|root| !unit_ids.contains(root.as_str()))
    {
        bail!("compiler invocation Cargo roots are not canonical or conserved");
    }
    Ok(())
}

/// Revalidates the complete in-memory invocation ledger before it crosses the
/// atomic graph-promotion boundary. The directory validator performs the
/// filesystem/source checks while the supervised workspace still exists; this
/// check repeats every canonical identity and conservation invariant on the
/// retained DTO so post-validation mutation cannot produce a partial delta.
pub fn validate_compiler_invocation_ledger_identity(
    ledger: &RustCompilerInvocationLedger,
    graph: &RustCargoUnitGraph,
) -> Result<()> {
    validate_compiler_invocation_unit_graph(graph)?;
    validate_digest(&ledger.attempt_digest)?;
    if ledger.schema_version != COMPILER_INVOCATION_LEDGER_SCHEMA_VERSION
        || ledger.unit_graph_digest != graph.digest
    {
        bail!("compiler invocation ledger identity is invalid");
    }
    let admitted = graph
        .units
        .iter()
        .filter(|unit| unit.mode != "run-custom-build")
        .map(|unit| (unit.unit_id.as_str(), unit))
        .collect::<BTreeMap<_, _>>();
    if ledger.entries.len() != admitted.len()
        || !ledger
            .entries
            .windows(2)
            .all(|window| window[0].unit_id < window[1].unit_id)
    {
        bail!("compiler invocation ledger does not conserve admitted Cargo units");
    }
    let mut invocation_ids = BTreeSet::new();
    for entry in &ledger.entries {
        let unit = admitted
            .get(entry.unit_id.as_str())
            .context("compiler invocation references an unadmitted Cargo unit")?;
        let expected_name = unit.target.name.replace('-', "_");
        let mut expected_types = unit.target.crate_types.clone();
        expected_types.sort();
        expected_types.dedup();
        if entry.crate_name != expected_name
            || entry.crate_types != expected_types
            || entry.source_path != unit.target.src_path
            || entry.profile_digest != digest_json(&unit.profile)?
            || entry.edition != unit.target.edition
            || entry.features != unit.features
            || entry.mode != unit.mode
            || entry.target != unit.platform
            || entry.terminal_status != "completed"
            || entry.exit_code != 0
            || !invocation_ids.insert(entry.invocation_id.as_str())
        {
            bail!("compiler invocation ledger entry is incomplete or mismatched");
        }
        for digest in [
            &entry.invocation_id,
            &entry.source_sha256,
            &entry.profile_digest,
            &entry.argv_digest,
            &entry.rustc_sha256,
            &entry.rustc_verbose_sha256,
        ] {
            validate_digest(digest)?;
        }
        validate_source_path(&entry.source_path)?;
        validate_sorted_unique_identities("compiler invocation crate types", &entry.crate_types)?;
        validate_sorted_unique_text("compiler invocation features", &entry.features)?;
        if entry.canonical_argv.is_empty()
            || entry.canonical_argv.len() > MAX_ARGUMENTS
            || entry.argv_digest != digest_json(&entry.canonical_argv)?
        {
            bail!("compiler invocation argv identity is invalid");
        }
        for argument in &entry.canonical_argv {
            validate_text("compiler invocation argument", argument)?;
            if contains_unconfined_path_fragment(argument)
                || contains_parent_traversal(argument)
                || argument.contains('@')
            {
                bail!("compiler invocation argv contains a path escape or response file");
            }
        }
        let expected_digest = compiler_invocation_entry_digest(entry)?;
        if entry.invocation_digest != expected_digest {
            bail!("compiler invocation canonical identity is invalid");
        }
    }
    if admitted
        .keys()
        .copied()
        .ne(ledger.entries.iter().map(|entry| entry.unit_id.as_str()))
    {
        bail!("compiler invocation ledger unit coverage is incomplete");
    }
    let expected_digest = compiler_invocation_ledger_digest(
        &ledger.attempt_digest,
        &ledger.unit_graph_digest,
        &ledger.entries,
    )?;
    if ledger.digest != expected_digest {
        bail!("compiler invocation ledger digest is invalid");
    }
    Ok(())
}

pub fn validate_compiler_invocation_ledger(
    ledger_directory: &Path,
    workspace: &Path,
    cargo_home: &Path,
    graph: &RustCargoUnitGraph,
    attempt_digest: &str,
    rustc_sha256: &str,
    rustc_verbose_sha256: &str,
) -> Result<RustCompilerInvocationLedger> {
    validate_digest(attempt_digest)?;
    validate_digest(rustc_sha256)?;
    validate_digest(rustc_verbose_sha256)?;
    validate_compiler_invocation_unit_graph(graph)?;
    let workspace = workspace
        .canonicalize()
        .context("staged compiler workspace is unavailable")?;
    if !workspace.is_dir() {
        bail!("staged compiler workspace is not a directory");
    }
    let cargo_home = cargo_home
        .canonicalize()
        .context("staged compiler Cargo home is unavailable")?;
    if !cargo_home.is_dir()
        || cargo_home.starts_with(&workspace)
        || workspace.starts_with(&cargo_home)
    {
        bail!("staged compiler Cargo home is invalid or overlaps the workspace");
    }
    let ledger_metadata = fs::symlink_metadata(ledger_directory)
        .context("compiler invocation ledger directory is unavailable")?;
    if ledger_metadata.file_type().is_symlink() || !ledger_metadata.is_dir() {
        bail!("compiler invocation ledger is not a regular directory");
    }
    let ledger_directory = ledger_directory
        .canonicalize()
        .context("compiler invocation ledger directory is unavailable")?;

    let mut starts = BTreeMap::<String, (StartRecord, Vec<u8>)>::new();
    let mut terminals = BTreeMap::<String, TerminalRecord>::new();
    let mut file_count = 0_usize;
    let mut byte_count = 0_u64;
    for entry in fs::read_dir(&ledger_directory)? {
        let entry = entry?;
        file_count = file_count
            .checked_add(1)
            .context("compiler invocation ledger file count overflowed")?;
        if file_count > MAX_LEDGER_FILES {
            bail!("compiler invocation ledger exceeds its file count limit");
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_LEDGER_FILE_BYTES
        {
            bail!("compiler invocation ledger contains a non-regular or oversized record");
        }
        byte_count = byte_count
            .checked_add(metadata.len())
            .context("compiler invocation ledger byte count overflowed")?;
        if byte_count > MAX_LEDGER_BYTES {
            bail!("compiler invocation ledger exceeds its byte limit");
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("compiler invocation record name is not UTF-8"))?;
        let bytes = fs::read(entry.path())?;
        if let Some(invocation_id) = record_file_id(&name, "start-") {
            let record: StartRecord = serde_json::from_slice(&bytes)
                .context("compiler invocation start record is invalid")?;
            validate_start_record(
                &record,
                invocation_id,
                attempt_digest,
                rustc_sha256,
                rustc_verbose_sha256,
            )?;
            if starts
                .insert(invocation_id.to_owned(), (record, bytes))
                .is_some()
            {
                bail!("compiler invocation ledger contains duplicate start records");
            }
        } else if let Some(invocation_id) = record_file_id(&name, "terminal-") {
            let record: TerminalRecord = serde_json::from_slice(&bytes)
                .context("compiler invocation terminal record is invalid")?;
            validate_terminal_record(&record, invocation_id, attempt_digest)?;
            if terminals.insert(invocation_id.to_owned(), record).is_some() {
                bail!("compiler invocation ledger contains duplicate terminal records");
            }
        } else {
            bail!("compiler invocation ledger contains an unknown record");
        }
    }

    let admitted = graph
        .units
        .iter()
        .filter(|unit| unit.mode != "run-custom-build")
        .map(|unit| (unit.unit_id.as_str(), unit))
        .collect::<BTreeMap<_, _>>();
    if starts.len() != admitted.len()
        || terminals.len() != admitted.len()
        || starts.keys().collect::<Vec<_>>() != terminals.keys().collect::<Vec<_>>()
    {
        bail!("compiler invocation ledger has missing, extra, or partial terminal records");
    }

    let mut matched_units = BTreeSet::new();
    let mut entries = Vec::with_capacity(starts.len());
    for (invocation_id, (start, start_bytes)) in starts {
        let terminal = terminals
            .remove(&invocation_id)
            .context("compiler invocation terminal record is missing")?;
        if terminal.start_record_sha256 != digest_bytes(&start_bytes)
            || terminal.status != "completed"
            || terminal.exit_code != Some(0)
        {
            bail!("compiler invocation terminal record is partial, failed, or mismatched");
        }
        let unit = admitted
            .get(start.unit_id.as_str())
            .context("compiler invocation references an unadmitted Cargo unit")?;
        if !matched_units.insert(start.unit_id.clone()) {
            bail!("compiler invocation ledger contains a duplicate Cargo unit");
        }
        validate_invocation_against_unit(&start, unit, &workspace, &cargo_home)?;
        let mut entry = RustCompilerInvocation {
            unit_id: start.unit_id,
            invocation_id: start.invocation_id,
            invocation_digest: String::new(),
            crate_name: start.crate_name,
            crate_types: start.crate_types,
            source_path: start.source_path,
            source_sha256: start.source_sha256,
            profile_digest: start.profile_digest,
            edition: start.edition,
            target: start.target,
            mode: start.mode,
            features: start.features,
            canonical_argv: start.canonical_argv,
            argv_digest: start.argv_digest,
            rustc_sha256: start.rustc_sha256,
            rustc_verbose_sha256: start.rustc_verbose_sha256,
            terminal_status: terminal.status,
            exit_code: 0,
        };
        entry.invocation_digest = compiler_invocation_entry_digest(&entry)?;
        entries.push(entry);
    }
    if matched_units.len() != admitted.len() {
        bail!("compiler invocation ledger does not conserve admitted Cargo units");
    }
    entries.sort_by(|left, right| left.unit_id.cmp(&right.unit_id));
    let digest = compiler_invocation_ledger_digest(attempt_digest, &graph.digest, &entries)?;
    Ok(RustCompilerInvocationLedger {
        schema_version: COMPILER_INVOCATION_LEDGER_SCHEMA_VERSION.to_owned(),
        digest,
        attempt_digest: attempt_digest.to_owned(),
        unit_graph_digest: graph.digest.clone(),
        entries,
    })
}

fn validate_start_record(
    record: &StartRecord,
    file_id: &str,
    attempt_digest: &str,
    rustc_sha256: &str,
    rustc_verbose_sha256: &str,
) -> Result<()> {
    if record.schema_version != COMPILER_INVOCATION_RECORD_SCHEMA_VERSION
        || record.record_kind != "start"
        || record.invocation_id != file_id
        || record.attempt_digest != attempt_digest
        || record.rustc_sha256 != rustc_sha256
        || record.rustc_verbose_sha256 != rustc_verbose_sha256
    {
        bail!("compiler invocation start record identity is invalid");
    }
    validate_digest(&record.invocation_id)?;
    validate_digest(&record.source_sha256)?;
    validate_digest(&record.profile_digest)?;
    validate_digest(&record.argv_digest)?;
    if record.argv_digest != digest_json(&record.canonical_argv)? {
        bail!("compiler invocation argv digest is invalid");
    }
    validate_text("compiler invocation unit", &record.unit_id)?;
    validate_identity("compiler invocation crate", &record.crate_name)?;
    validate_sorted_unique_identities("compiler invocation crate types", &record.crate_types)?;
    validate_source_path(&record.source_path)?;
    validate_identity("compiler invocation edition", &record.edition)?;
    if let Some(target) = &record.target {
        validate_identity("compiler invocation target", target)?;
    }
    if !matches!(record.mode.as_str(), "build" | "test") {
        bail!("compiler invocation mode is unsupported");
    }
    validate_sorted_unique_text("compiler invocation features", &record.features)?;
    if record.canonical_argv.is_empty() || record.canonical_argv.len() > MAX_ARGUMENTS {
        bail!("compiler invocation argv count is outside its bounds");
    }
    for argument in &record.canonical_argv {
        validate_text("compiler invocation argument", argument)?;
        if contains_unconfined_path_fragment(argument)
            || contains_parent_traversal(argument)
            || argument.contains('@')
        {
            bail!("compiler invocation argv contains a path escape or response file");
        }
    }
    Ok(())
}

fn contains_parent_traversal(value: &str) -> bool {
    value == ".."
        || value.starts_with("../")
        || value.ends_with("/..")
        || value.contains("/../")
        || value.starts_with("..\\")
        || value.ends_with("\\..")
        || value.contains("\\..\\")
}

fn contains_unconfined_path_fragment(value: &str) -> bool {
    value
        .split(|character: char| {
            matches!(character, '=' | ',' | ';') || character.is_ascii_whitespace()
        })
        .map(|fragment| fragment.trim_matches(['"', '\'']))
        .filter(|fragment| !fragment.is_empty())
        .any(|fragment| {
            let path = Path::new(fragment);
            path.is_absolute()
                || is_portable_windows_absolute(fragment)
                || fragment.starts_with("\\\\")
                || (fragment.contains("://")
                    && !fragment.starts_with("repo://")
                    && !fragment.starts_with("cargo-home://"))
        })
}

fn is_portable_windows_absolute(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

fn secret_shaped_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let non_logical_url = lower.replace("repo://", "").replace("cargo-home://", "");
    [
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
}

fn validate_terminal_record(
    record: &TerminalRecord,
    file_id: &str,
    attempt_digest: &str,
) -> Result<()> {
    if record.schema_version != COMPILER_INVOCATION_RECORD_SCHEMA_VERSION
        || record.record_kind != "terminal"
        || record.invocation_id != file_id
        || record.attempt_digest != attempt_digest
        || !matches!(record.status.as_str(), "completed" | "failed")
    {
        bail!("compiler invocation terminal record identity is invalid");
    }
    validate_digest(&record.invocation_id)?;
    validate_digest(&record.start_record_sha256)?;
    Ok(())
}

fn validate_invocation_against_unit(
    record: &StartRecord,
    unit: &RustCargoUnit,
    workspace: &Path,
    cargo_home: &Path,
) -> Result<()> {
    let expected_name = unit.target.name.replace('-', "_");
    let mut expected_types = unit.target.crate_types.clone();
    expected_types.sort();
    expected_types.dedup();
    if record.crate_name != expected_name
        || record.crate_types != expected_types
        || record.source_path != unit.target.src_path
        || record.profile_digest != digest_json(&unit.profile)?
        || record.edition != unit.target.edition
        || record.features != unit.features
        || record.mode != unit.mode
        || record.target != unit.platform
    {
        bail!("compiler invocation does not match its admitted Cargo unit");
    }
    let (source_root, source_relative) =
        if let Some(relative) = record.source_path.strip_prefix("repo://") {
            (workspace, relative)
        } else if let Some(relative) = record.source_path.strip_prefix("cargo-home://") {
            (cargo_home, relative)
        } else {
            bail!("compiler invocation source has an unsupported staged root");
        };
    validate_relative_path(source_relative)?;
    let source = source_root.join(source_relative);
    let metadata = fs::symlink_metadata(&source)
        .context("compiler invocation source is unavailable in the staged workspace")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("compiler invocation source is not a regular staged file");
    }
    let canonical = source
        .canonicalize()
        .context("compiler invocation source is unavailable")?;
    if !canonical.starts_with(source_root)
        || record.source_sha256 != digest_bytes(&fs::read(source)?)
    {
        bail!("compiler invocation source identity is invalid");
    }
    Ok(())
}

fn validate_graph_identity(graph: &RustCargoUnitGraph) -> Result<()> {
    validate_digest(&graph.digest)?;
    let digest = digest_bytes(&serde_json::to_vec(&(&graph.units, &graph.roots))?);
    if digest != graph.digest {
        bail!("Cargo unit graph digest is invalid");
    }
    Ok(())
}

fn record_file_id<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    name.strip_prefix(prefix)
        .and_then(|name| name.strip_suffix(".json"))
        .filter(|id| id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn validate_source_path(value: &str) -> Result<()> {
    let relative = value
        .strip_prefix("repo://")
        .or_else(|| value.strip_prefix("cargo-home://"))
        .context("compiler invocation path is not staged-source-relative")?;
    validate_relative_path(relative)
}

fn validate_relative_path(value: &str) -> Result<()> {
    validate_text("compiler invocation path", value)?;
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_) | Component::CurDir)
                || matches!(component, Component::ParentDir)
        })
    {
        bail!("compiler invocation path is not confined");
    }
    Ok(())
}

fn validate_sorted_unique_identities(label: &str, values: &[String]) -> Result<()> {
    if values.is_empty() || values.len() > 1_024 {
        bail!("{label} count is outside its bounds");
    }
    for value in values {
        validate_identity(label, value)?;
    }
    if !values.windows(2).all(|window| window[0] < window[1]) {
        bail!("{label} must be strictly sorted and unique");
    }
    Ok(())
}

fn validate_sorted_unique_text(label: &str, values: &[String]) -> Result<()> {
    if values.len() > 1_024 {
        bail!("{label} count exceeds its limit");
    }
    for value in values {
        validate_text(label, value)?;
    }
    if !values.windows(2).all(|window| window[0] < window[1]) {
        bail!("{label} must be strictly sorted and unique");
    }
    Ok(())
}

fn validate_identity(label: &str, value: &str) -> Result<()> {
    validate_text(label, value)?;
    if value
        .chars()
        .any(|character| !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-')))
    {
        bail!("{label} is invalid");
    }
    Ok(())
}

fn validate_text(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(|character| character.is_control())
        || secret_shaped_text(value)
    {
        bail!("{label} is invalid or exceeds its text bound");
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("compiler invocation digest is invalid");
    }
    Ok(())
}

fn digest_json(value: &impl Serialize) -> Result<String> {
    let mut value = serde_json::to_value(value)?;
    sort_json(&mut value);
    Ok(digest_bytes(&serde_json::to_vec(&value)?))
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

fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler_precise::{
        COMPILER_PRECISE_UNIT_GRAPH_SCHEMA_VERSION, RustCargoProfile, RustCargoStrip,
        RustCargoTarget,
    };

    fn graph() -> Result<RustCargoUnitGraph> {
        let units = vec![RustCargoUnit {
            unit_id: "cargo-unit:fixture".to_owned(),
            package_id: "path:fixture#0.1.0".to_owned(),
            target: RustCargoTarget {
                kind: vec!["lib".to_owned()],
                crate_types: vec!["lib".to_owned()],
                name: "fixture".to_owned(),
                src_path: "repo://src/lib.rs".to_owned(),
                edition: "2024".to_owned(),
                doc: true,
                doctest: true,
                test: true,
            },
            profile: RustCargoProfile {
                name: "dev".to_owned(),
                opt_level: "0".to_owned(),
                lto: "false".to_owned(),
                codegen_units: None,
                debuginfo: Some(2),
                split_debuginfo: None,
                debug_assertions: true,
                overflow_checks: true,
                rpath: false,
                incremental: false,
                panic: "unwind".to_owned(),
                strip: RustCargoStrip::Deferred("None".to_owned()),
                codegen_backend: None,
            },
            platform: None,
            mode: "build".to_owned(),
            features: Vec::new(),
            is_std: false,
            dependencies: Vec::new(),
        }];
        let roots = vec![units[0].unit_id.clone()];
        Ok(RustCargoUnitGraph {
            schema_version: COMPILER_PRECISE_UNIT_GRAPH_SCHEMA_VERSION.to_owned(),
            digest: digest_bytes(&serde_json::to_vec(&(&units, &roots))?),
            units,
            roots,
        })
    }

    #[test]
    fn invocation_attempt_digest_is_stable() -> Result<()> {
        let digest = "a".repeat(64);
        assert_eq!(
            compiler_invocation_attempt_digest(&digest, &digest, &digest, &digest)?,
            compiler_invocation_attempt_digest(&digest, &digest, &digest, &digest)?
        );
        Ok(())
    }

    #[test]
    fn canonical_argv_rejects_embedded_portable_paths_and_secrets() {
        assert!(contains_unconfined_path_fragment(
            "--emit=dep-info=/tmp/fixture.d"
        ));
        assert!(contains_unconfined_path_fragment(
            "linker=C:\\toolchain\\link.exe"
        ));
        assert!(contains_unconfined_path_fragment(
            "--cfg=source=file:///tmp/fixture"
        ));
        assert!(!contains_unconfined_path_fragment(
            "--extern=fixture=output/libfixture.rlib"
        ));
        assert!(!contains_unconfined_path_fragment("repo://src/lib.rs"));
        assert!(secret_shaped_text("api_key=fixture-secret"));
        assert!(!secret_shaped_text("tokenizers"));
        assert!(!secret_shaped_text("repo://source@fixture/lib.rs"));
    }

    #[test]
    fn complete_ledger_is_canonical_and_conserved() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let workspace = temporary.path().join("workspace");
        let cargo_home = temporary.path().join("cargo-home");
        let ledger = temporary.path().join("ledger");
        fs::create_dir(&workspace)?;
        fs::create_dir(&cargo_home)?;
        fs::create_dir(&ledger)?;
        fs::create_dir(workspace.join("src"))?;
        fs::write(workspace.join("src/lib.rs"), "pub fn fixture() {}\n")?;
        let graph = graph()?;
        let attempt = "a".repeat(64);
        let rustc = "b".repeat(64);
        let verbose = "c".repeat(64);
        let invocation_id = "d".repeat(64);
        let canonical_argv = vec![
            "--crate-name".to_owned(),
            "fixture".to_owned(),
            "repo://src/lib.rs".to_owned(),
        ];
        let start = serde_json::json!({
            "schema_version": COMPILER_INVOCATION_RECORD_SCHEMA_VERSION,
            "record_kind": "start",
            "invocation_id": invocation_id,
            "attempt_digest": attempt,
            "unit_id": "cargo-unit:fixture",
            "crate_name": "fixture",
            "crate_types": ["lib"],
            "source_path": "repo://src/lib.rs",
            "source_sha256": digest_bytes(&fs::read(workspace.join("src/lib.rs"))?),
            "profile_digest": digest_json(&graph.units[0].profile)?,
            "edition": "2024",
            "target": null,
            "mode": "build",
            "features": [],
            "canonical_argv": canonical_argv,
            "argv_digest": digest_json(&canonical_argv)?,
            "rustc_sha256": rustc,
            "rustc_verbose_sha256": verbose,
        });
        let start_bytes = serde_json::to_vec(&start)?;
        fs::write(
            ledger.join(format!("start-{invocation_id}.json")),
            &start_bytes,
        )?;
        fs::write(
            ledger.join(format!("terminal-{invocation_id}.json")),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": COMPILER_INVOCATION_RECORD_SCHEMA_VERSION,
                "record_kind": "terminal",
                "invocation_id": invocation_id,
                "attempt_digest": attempt,
                "start_record_sha256": digest_bytes(&start_bytes),
                "status": "completed",
                "exit_code": 0,
            }))?,
        )?;
        let first = validate_compiler_invocation_ledger(
            &ledger,
            &workspace,
            &cargo_home,
            &graph,
            &attempt,
            &rustc,
            &verbose,
        )?;
        let second = validate_compiler_invocation_ledger(
            &ledger,
            &workspace,
            &cargo_home,
            &graph,
            &attempt,
            &rustc,
            &verbose,
        )?;
        assert_eq!(first, second);
        assert_eq!(first.entries.len(), 1);
        let record_schema: serde_json::Value =
            serde_json::from_str(COMPILER_INVOCATION_RECORD_SCHEMA)?;
        let record_validator = jsonschema::validator_for(&record_schema)?;
        assert!(record_validator.is_valid(&start));
        let terminal_value: serde_json::Value = serde_json::from_slice(&fs::read(
            ledger.join(format!("terminal-{invocation_id}.json")),
        )?)?;
        assert!(record_validator.is_valid(&terminal_value));
        let ledger_schema: serde_json::Value =
            serde_json::from_str(COMPILER_INVOCATION_LEDGER_SCHEMA)?;
        assert!(
            jsonschema::validator_for(&ledger_schema)?.is_valid(&serde_json::to_value(&first)?)
        );
        let serialized = serde_json::to_string(&first)?;
        assert!(!serialized.contains(temporary.path().to_string_lossy().as_ref()));
        let other = tempfile::tempdir()?;
        let other_workspace = other.path().join("workspace");
        let other_cargo_home = other.path().join("cargo-home");
        let other_ledger = other.path().join("ledger");
        fs::create_dir_all(other_workspace.join("src"))?;
        fs::create_dir(&other_cargo_home)?;
        fs::create_dir(&other_ledger)?;
        fs::write(other_workspace.join("src/lib.rs"), "pub fn fixture() {}\n")?;
        fs::copy(
            ledger.join(format!("start-{invocation_id}.json")),
            other_ledger.join(format!("start-{invocation_id}.json")),
        )?;
        fs::copy(
            ledger.join(format!("terminal-{invocation_id}.json")),
            other_ledger.join(format!("terminal-{invocation_id}.json")),
        )?;
        let checkout_independent = validate_compiler_invocation_ledger(
            &other_ledger,
            &other_workspace,
            &other_cargo_home,
            &graph,
            &attempt,
            &rustc,
            &verbose,
        )?;
        assert_eq!(first, checkout_independent);

        let duplicate_id = "e".repeat(64);
        let mut duplicate_start = start.clone();
        duplicate_start["invocation_id"] = serde_json::json!(duplicate_id);
        let duplicate_start_bytes = serde_json::to_vec(&duplicate_start)?;
        fs::write(
            ledger.join(format!("start-{duplicate_id}.json")),
            &duplicate_start_bytes,
        )?;
        fs::write(
            ledger.join(format!("terminal-{duplicate_id}.json")),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": COMPILER_INVOCATION_RECORD_SCHEMA_VERSION,
                "record_kind": "terminal",
                "invocation_id": duplicate_id,
                "attempt_digest": attempt,
                "start_record_sha256": digest_bytes(&duplicate_start_bytes),
                "status": "completed",
                "exit_code": 0,
            }))?,
        )?;
        assert!(
            validate_compiler_invocation_ledger(
                &ledger,
                &workspace,
                &cargo_home,
                &graph,
                &attempt,
                &rustc,
                &verbose,
            )
            .is_err()
        );
        fs::remove_file(ledger.join(format!("start-{duplicate_id}.json")))?;
        fs::remove_file(ledger.join(format!("terminal-{duplicate_id}.json")))?;

        fs::remove_file(ledger.join(format!("terminal-{invocation_id}.json")))?;
        assert!(
            validate_compiler_invocation_ledger(
                &ledger,
                &workspace,
                &cargo_home,
                &graph,
                &attempt,
                &rustc,
                &verbose,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn partial_duplicate_and_path_leaking_ledgers_fail_closed() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let workspace = temporary.path().join("workspace");
        let cargo_home = temporary.path().join("cargo-home");
        let ledger = temporary.path().join("ledger");
        fs::create_dir(&workspace)?;
        fs::create_dir(&cargo_home)?;
        fs::create_dir(&ledger)?;
        fs::create_dir(workspace.join("src"))?;
        fs::write(workspace.join("src/lib.rs"), "pub fn fixture() {}\n")?;
        let graph = graph()?;
        let digest = "a".repeat(64);
        assert!(
            validate_compiler_invocation_ledger(
                &ledger,
                &workspace,
                &cargo_home,
                &graph,
                &digest,
                &digest,
                &digest
            )
            .is_err()
        );
        fs::write(ledger.join("unknown.json"), b"{}")?;
        assert!(
            validate_compiler_invocation_ledger(
                &ledger,
                &workspace,
                &cargo_home,
                &graph,
                &digest,
                &digest,
                &digest
            )
            .is_err()
        );
        Ok(())
    }
}
