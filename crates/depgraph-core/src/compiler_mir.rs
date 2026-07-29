use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    compiler_invocation::RustCompilerInvocationLedger,
    compiler_pack::{COMPILER_PACK_RUSTC_COMMIT, CompilerPackAttestation},
    compiler_precise::RustCargoUnitGraph,
};

pub const COMPILER_PRECISE_MIR_SCHEMA_VERSION: &str = "depgraph-rust-compiler-precise-v1";
pub const COMPILER_PRECISE_MIR_LEDGER_SCHEMA_VERSION: &str =
    "depgraph-rust-compiler-precise-mir-ledger-v1";
pub const COMPILER_PRECISE_MIR_SCHEMA_PATH: &str =
    "schemas/depgraph-rust-compiler-precise-v1.schema.json";
pub const COMPILER_PRECISE_MIR_SCHEMA: &str =
    include_str!("../../../schemas/depgraph-rust-compiler-precise-v1.schema.json");
pub const COMPILER_PRECISE_MIR_LEDGER_SCHEMA_PATH: &str =
    "schemas/depgraph-rust-compiler-precise-mir-ledger-v1.schema.json";
pub const COMPILER_PRECISE_MIR_LEDGER_SCHEMA: &str =
    include_str!("../../../schemas/depgraph-rust-compiler-precise-mir-ledger-v1.schema.json");

const MAX_UNIT_FILES: usize = 100_000;
const MAX_UNIT_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_BODIES_PER_UNIT: usize = 100_000;
const MAX_ATOMS_PER_BODY: usize = 1_000_000;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_TYPE_DEPTH: usize = 32;
const MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustCompilerMirUnit {
    pub schema_version: String,
    pub digest: String,
    pub attempt_digest: String,
    pub invocation_id: String,
    pub unit_id: String,
    pub package_id: String,
    pub target_digest: String,
    pub source_path: String,
    pub source_sha256: String,
    pub profile_digest: String,
    pub compiler_pack_manifest_sha256: String,
    pub rustc_commit: String,
    pub query_capabilities: Vec<String>,
    pub bodies: Vec<RustCompilerMirBody>,
    pub unsupported: Vec<RustCompilerMirUnsupported>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustCompilerMirBody {
    pub body_id: String,
    pub kind: RustCompilerMirBodyKind,
    pub definition: RustCompilerMirDefinition,
    pub span: RustCompilerMirSpan,
    pub types: Vec<RustCompilerMirType>,
    pub constants: Vec<RustCompilerMirConstant>,
    pub locals: Vec<RustCompilerMirLocal>,
    pub places: Vec<RustCompilerMirPlace>,
    pub blocks: Vec<RustCompilerMirBlock>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RustCompilerMirBodyKind {
    Function,
    Method,
    Closure,
    Async,
    Coroutine,
    Const,
    Static,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustCompilerMirDefinition {
    pub definition_id: String,
    pub path: String,
    pub span: RustCompilerMirSpan,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustCompilerMirSpan {
    pub source_path: String,
    pub source_sha256: String,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustCompilerMirType {
    pub type_id: String,
    pub kind: String,
    pub arguments: Vec<String>,
    pub definition_id: Option<String>,
    pub mutability: Option<String>,
    pub value: Option<String>,
    pub unsupported_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustCompilerMirConstant {
    pub constant_id: String,
    pub type_id: String,
    pub kind: String,
    pub value: Option<String>,
    pub definition_id: Option<String>,
    pub unsupported_reason: Option<String>,
    pub span: RustCompilerMirSpan,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustCompilerMirLocal {
    pub local_id: String,
    pub ordinal: u32,
    pub role: String,
    pub type_id: String,
    pub span: RustCompilerMirSpan,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustCompilerMirPlace {
    pub place_id: String,
    pub local_id: String,
    pub projections: Vec<RustCompilerMirProjection>,
    pub type_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustCompilerMirProjection {
    pub kind: String,
    pub index: Option<u64>,
    pub from: Option<u64>,
    pub to: Option<u64>,
    pub from_end: Option<bool>,
    pub type_id: Option<String>,
    pub local_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustCompilerMirBlock {
    pub block_id: String,
    pub ordinal: u32,
    pub operations: Vec<RustCompilerMirOperation>,
    pub successors: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustCompilerMirOperation {
    pub operation_id: String,
    pub ordinal: u32,
    pub kind: String,
    pub span: RustCompilerMirSpan,
    pub places: Vec<String>,
    pub constants: Vec<String>,
    pub unsupported_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustCompilerMirUnsupported {
    pub scope_id: String,
    pub construct_kind: String,
    pub reason_code: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustCompilerMirLedger {
    pub schema_version: String,
    pub digest: String,
    pub attempt_digest: String,
    pub unit_graph_digest: String,
    pub invocation_ledger_digest: String,
    pub entries: Vec<RustCompilerMirUnit>,
}

#[derive(Serialize)]
struct UnitIdentity<'a> {
    attempt_digest: &'a str,
    invocation_id: &'a str,
    unit_id: &'a str,
    package_id: &'a str,
    target_digest: &'a str,
    source_path: &'a str,
    source_sha256: &'a str,
    profile_digest: &'a str,
    compiler_pack_manifest_sha256: &'a str,
    rustc_commit: &'a str,
    query_capabilities: &'a [String],
    bodies: &'a [RustCompilerMirBody],
    unsupported: &'a [RustCompilerMirUnsupported],
}

#[derive(Serialize)]
struct LedgerIdentity<'a> {
    attempt_digest: &'a str,
    unit_graph_digest: &'a str,
    invocation_ledger_digest: &'a str,
    entries: &'a [RustCompilerMirUnit],
}

pub fn compiler_mir_unit_digest(unit: &RustCompilerMirUnit) -> Result<String> {
    digest_json(&UnitIdentity {
        attempt_digest: &unit.attempt_digest,
        invocation_id: &unit.invocation_id,
        unit_id: &unit.unit_id,
        package_id: &unit.package_id,
        target_digest: &unit.target_digest,
        source_path: &unit.source_path,
        source_sha256: &unit.source_sha256,
        profile_digest: &unit.profile_digest,
        compiler_pack_manifest_sha256: &unit.compiler_pack_manifest_sha256,
        rustc_commit: &unit.rustc_commit,
        query_capabilities: &unit.query_capabilities,
        bodies: &unit.bodies,
        unsupported: &unit.unsupported,
    })
}

pub fn validate_compiler_mir_directory(
    directory: &Path,
    workspace: &Path,
    cargo_home: &Path,
    graph: &RustCargoUnitGraph,
    invocation_ledger: &RustCompilerInvocationLedger,
    pack: &CompilerPackAttestation,
) -> Result<RustCompilerMirLedger> {
    validate_digest(&invocation_ledger.attempt_digest)?;
    if invocation_ledger.unit_graph_digest != graph.digest {
        bail!("typed MIR invocation and Cargo unit graph identities differ");
    }
    let workspace = canonical_directory(workspace, "typed MIR workspace")?;
    let cargo_home = canonical_directory(cargo_home, "typed MIR Cargo home")?;
    if workspace.starts_with(&cargo_home) || cargo_home.starts_with(&workspace) {
        bail!("typed MIR source roots overlap");
    }
    let directory = canonical_directory(directory, "typed MIR output")?;

    let invocations = invocation_ledger
        .entries
        .iter()
        .map(|entry| (entry.invocation_id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let units = graph
        .units
        .iter()
        .map(|unit| (unit.unit_id.as_str(), unit))
        .collect::<BTreeMap<_, _>>();
    let mut entries = Vec::new();
    let mut seen_invocations = BTreeSet::new();
    let mut file_count = 0_usize;
    let mut byte_count = 0_u64;
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        file_count = file_count
            .checked_add(1)
            .context("typed MIR output file count overflowed")?;
        if file_count > MAX_UNIT_FILES {
            bail!("typed MIR output exceeds its file count limit");
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_UNIT_FILE_BYTES
        {
            bail!("typed MIR output contains a non-regular or oversized file");
        }
        byte_count = byte_count
            .checked_add(metadata.len())
            .context("typed MIR output byte count overflowed")?;
        if byte_count > MAX_TOTAL_BYTES {
            bail!("typed MIR output exceeds its byte limit");
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("typed MIR output file name is not UTF-8"))?;
        let invocation_id = name
            .strip_prefix("mir-")
            .and_then(|name| name.strip_suffix(".json"))
            .filter(|value| is_digest(value))
            .context("typed MIR output has an unknown file name")?;
        let bytes = fs::read(entry.path())?;
        reject_forbidden_serialized_text(&bytes)?;
        let unit: RustCompilerMirUnit =
            serde_json::from_slice(&bytes).context("typed MIR unit DTO is invalid")?;
        if unit.invocation_id != invocation_id
            || !seen_invocations.insert(unit.invocation_id.clone())
        {
            bail!("typed MIR unit invocation identity is duplicate or mismatched");
        }
        let invocation = invocations
            .get(unit.invocation_id.as_str())
            .context("typed MIR unit references an unknown compiler invocation")?;
        let graph_unit = units
            .get(unit.unit_id.as_str())
            .context("typed MIR unit references an unknown Cargo unit")?;
        validate_unit(
            &unit,
            invocation,
            graph_unit,
            pack,
            &invocation_ledger.attempt_digest,
            &workspace,
            &cargo_home,
        )?;
        entries.push(unit);
    }
    if seen_invocations.len() != invocations.len()
        || seen_invocations
            != invocations
                .keys()
                .map(|value| (*value).to_owned())
                .collect::<BTreeSet<_>>()
    {
        bail!("typed MIR output has missing or extra compiler invocations");
    }
    entries.sort_by(|left, right| left.unit_id.cmp(&right.unit_id));
    let digest = digest_json(&LedgerIdentity {
        attempt_digest: &invocation_ledger.attempt_digest,
        unit_graph_digest: &graph.digest,
        invocation_ledger_digest: &invocation_ledger.digest,
        entries: &entries,
    })?;
    Ok(RustCompilerMirLedger {
        schema_version: COMPILER_PRECISE_MIR_LEDGER_SCHEMA_VERSION.to_owned(),
        digest,
        attempt_digest: invocation_ledger.attempt_digest.clone(),
        unit_graph_digest: graph.digest.clone(),
        invocation_ledger_digest: invocation_ledger.digest.clone(),
        entries,
    })
}

fn validate_unit(
    unit: &RustCompilerMirUnit,
    invocation: &crate::compiler_invocation::RustCompilerInvocation,
    graph_unit: &crate::compiler_precise::RustCargoUnit,
    pack: &CompilerPackAttestation,
    attempt_digest: &str,
    workspace: &Path,
    cargo_home: &Path,
) -> Result<()> {
    if unit.schema_version != COMPILER_PRECISE_MIR_SCHEMA_VERSION
        || unit.attempt_digest != attempt_digest
        || unit.invocation_id != invocation.invocation_id
        || unit.unit_id != invocation.unit_id
        || unit.unit_id != graph_unit.unit_id
        || unit.package_id != graph_unit.package_id
        || unit.target_digest != digest_json(&graph_unit.target)?
        || unit.source_path != invocation.source_path
        || unit.source_sha256 != invocation.source_sha256
        || unit.profile_digest != invocation.profile_digest
        || unit.compiler_pack_manifest_sha256 != pack.manifest_sha256
        || unit.rustc_commit != COMPILER_PACK_RUSTC_COMMIT
        || unit.query_capabilities != ["typed_mir"]
        || unit.digest != compiler_mir_unit_digest(unit)?
    {
        bail!("typed MIR unit identity is invalid");
    }
    validate_source_identity(
        &unit.source_path,
        &unit.source_sha256,
        workspace,
        cargo_home,
    )?;
    if unit.bodies.is_empty() || unit.bodies.len() > MAX_BODIES_PER_UNIT {
        bail!("typed MIR body count is outside its bounds");
    }
    if unit.unsupported.len() > MAX_ATOMS_PER_BODY {
        bail!("typed MIR unsupported coverage exceeds its count limit");
    }
    if !unit
        .bodies
        .windows(2)
        .all(|window| window[0].body_id < window[1].body_id)
    {
        bail!("typed MIR bodies must be strictly sorted and unique");
    }
    let mut all_scope_ids = BTreeSet::new();
    let mut required_unsupported = BTreeSet::new();
    for body in &unit.bodies {
        validate_body(
            body,
            unit,
            workspace,
            cargo_home,
            &mut all_scope_ids,
            &mut required_unsupported,
        )?;
    }
    if !unit.unsupported.windows(2).all(|window| {
        (
            &window[0].scope_id,
            &window[0].construct_kind,
            &window[0].reason_code,
        ) < (
            &window[1].scope_id,
            &window[1].construct_kind,
            &window[1].reason_code,
        )
    }) {
        bail!("typed MIR unsupported coverage must be canonical");
    }
    for unsupported in &unit.unsupported {
        if !all_scope_ids.contains(unsupported.scope_id.as_str()) {
            bail!("typed MIR unsupported coverage has a dangling scope");
        }
        validate_text("typed MIR construct kind", &unsupported.construct_kind)?;
        validate_reason_code(&unsupported.reason_code)?;
    }
    let actual_unsupported = unit
        .unsupported
        .iter()
        .map(|value| {
            (
                value.scope_id.clone(),
                value.construct_kind.clone(),
                value.reason_code.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    if !required_unsupported.is_subset(&actual_unsupported) {
        bail!("typed MIR unsupported constructs are missing reason-coded coverage");
    }
    Ok(())
}

fn validate_body(
    body: &RustCompilerMirBody,
    unit: &RustCompilerMirUnit,
    workspace: &Path,
    cargo_home: &Path,
    all_scope_ids: &mut BTreeSet<String>,
    required_unsupported: &mut BTreeSet<(String, String, String)>,
) -> Result<()> {
    validate_digest(&body.body_id)?;
    if !all_scope_ids.insert(body.body_id.clone()) {
        bail!("typed MIR body identity is duplicate");
    }
    validate_definition(&body.definition, workspace, cargo_home)?;
    validate_span(&body.span, workspace, cargo_home)?;
    let expected_body_id = digest_json(&(
        unit.unit_id.as_str(),
        unit.package_id.as_str(),
        unit.target_digest.as_str(),
        unit.profile_digest.as_str(),
        &body.kind,
        &body.definition,
    ))?;
    if body.body_id != expected_body_id {
        bail!("typed MIR body canonical identity is invalid");
    }
    if body.types.is_empty() || body.locals.is_empty() || body.blocks.is_empty() {
        bail!("typed MIR body is structurally incomplete");
    }
    let nested_atoms = body
        .places
        .iter()
        .try_fold(0_usize, |total, place| {
            total.checked_add(place.projections.len())
        })
        .and_then(|total| {
            body.blocks.iter().try_fold(total, |total, block| {
                total
                    .checked_add(block.operations.len())
                    .and_then(|total| total.checked_add(block.successors.len()))
            })
        })
        .context("typed MIR nested atom count overflowed")?;
    let total_atoms = body
        .types
        .len()
        .checked_add(body.constants.len())
        .and_then(|value| value.checked_add(body.locals.len()))
        .and_then(|value| value.checked_add(body.places.len()))
        .and_then(|value| value.checked_add(body.blocks.len()))
        .and_then(|value| value.checked_add(nested_atoms))
        .context("typed MIR body atom count overflowed")?;
    if total_atoms > MAX_ATOMS_PER_BODY {
        bail!("typed MIR body exceeds its atom count limit");
    }
    validate_sorted_ids(
        body.types.iter().map(|value| value.type_id.as_str()),
        "typed MIR types",
    )?;
    validate_sorted_ids(
        body.constants
            .iter()
            .map(|value| value.constant_id.as_str()),
        "typed MIR constants",
    )?;
    validate_sorted_ordinals(
        body.locals.iter().map(|value| value.ordinal),
        "typed MIR locals",
    )?;
    validate_sorted_ids(
        body.places.iter().map(|value| value.place_id.as_str()),
        "typed MIR places",
    )?;
    validate_sorted_ordinals(
        body.blocks.iter().map(|value| value.ordinal),
        "typed MIR blocks",
    )?;

    let type_by_id = body
        .types
        .iter()
        .map(|value| (value.type_id.as_str(), value))
        .collect::<BTreeMap<_, _>>();
    for ty in &body.types {
        validate_type(ty, &type_by_id, &body.definition.definition_id)?;
        all_scope_ids.insert(ty.type_id.clone());
        if let Some(reason) = &ty.unsupported_reason {
            required_unsupported.insert((ty.type_id.clone(), ty.kind.clone(), reason.clone()));
        }
    }
    for ty in &body.types {
        validate_type_depth(ty.type_id.as_str(), &type_by_id, &mut BTreeSet::new(), 0)?;
    }
    let local_ids = body
        .locals
        .iter()
        .map(|value| value.local_id.as_str())
        .collect::<BTreeSet<_>>();
    for local in &body.locals {
        validate_digest(&local.local_id)?;
        if local.local_id != digest_json(&(body.body_id.as_str(), "local", local.ordinal))?
            || !matches!(local.role.as_str(), "return" | "argument" | "local")
            || !type_by_id.contains_key(local.type_id.as_str())
        {
            bail!("typed MIR local identity is invalid");
        }
        validate_span(&local.span, workspace, cargo_home)?;
        all_scope_ids.insert(local.local_id.clone());
    }
    let constant_ids = body
        .constants
        .iter()
        .map(|value| value.constant_id.as_str())
        .collect::<BTreeSet<_>>();
    for constant in &body.constants {
        validate_constant(constant, body, &type_by_id, workspace, cargo_home)?;
        if let Some(reason) = &constant.unsupported_reason {
            required_unsupported.insert((
                constant.constant_id.clone(),
                constant.kind.clone(),
                reason.clone(),
            ));
        }
        all_scope_ids.insert(constant.constant_id.clone());
    }
    let place_ids = body
        .places
        .iter()
        .map(|value| value.place_id.as_str())
        .collect::<BTreeSet<_>>();
    for place in &body.places {
        validate_place(place, body, &local_ids, &type_by_id)?;
        all_scope_ids.insert(place.place_id.clone());
    }
    let block_ids = body
        .blocks
        .iter()
        .map(|value| value.block_id.as_str())
        .collect::<BTreeSet<_>>();
    for block in &body.blocks {
        if block.block_id != digest_json(&(body.body_id.as_str(), "block", block.ordinal))? {
            bail!("typed MIR block identity is invalid");
        }
        if !block
            .successors
            .windows(2)
            .all(|window| window[0] < window[1])
            || block
                .successors
                .iter()
                .any(|successor| !block_ids.contains(successor.as_str()))
        {
            bail!("typed MIR block successors are non-canonical or dangling");
        }
        validate_sorted_ordinals(
            block.operations.iter().map(|value| value.ordinal),
            "typed MIR operations",
        )?;
        for operation in &block.operations {
            if operation.operation_id
                != digest_json(&(
                    body.body_id.as_str(),
                    block.block_id.as_str(),
                    operation.ordinal,
                    operation.kind.as_str(),
                ))?
            {
                bail!("typed MIR operation identity is invalid");
            }
            validate_text("typed MIR operation kind", &operation.kind)?;
            validate_span(&operation.span, workspace, cargo_home)?;
            if !operation
                .places
                .windows(2)
                .all(|window| window[0] < window[1])
                || operation
                    .places
                    .iter()
                    .any(|place| !place_ids.contains(place.as_str()))
                || !operation
                    .constants
                    .windows(2)
                    .all(|window| window[0] < window[1])
                || operation
                    .constants
                    .iter()
                    .any(|constant| !constant_ids.contains(constant.as_str()))
            {
                bail!("typed MIR operation contains non-canonical or dangling atoms");
            }
            if let Some(reason) = &operation.unsupported_reason {
                validate_reason_code(reason)?;
                required_unsupported.insert((
                    operation.operation_id.clone(),
                    operation.kind.clone(),
                    reason.clone(),
                ));
            }
            all_scope_ids.insert(operation.operation_id.clone());
        }
        all_scope_ids.insert(block.block_id.clone());
    }
    Ok(())
}

fn validate_definition(
    definition: &RustCompilerMirDefinition,
    workspace: &Path,
    cargo_home: &Path,
) -> Result<()> {
    validate_text("typed MIR definition path", &definition.path)?;
    validate_span(&definition.span, workspace, cargo_home)?;
    if definition.definition_id
        != digest_json(&(
            definition.path.as_str(),
            definition.span.source_path.as_str(),
            definition.span.source_sha256.as_str(),
            definition.span.start_line,
            definition.span.start_column,
            definition.span.end_line,
            definition.span.end_column,
        ))?
    {
        bail!("typed MIR definition identity is invalid");
    }
    Ok(())
}

fn validate_type(
    ty: &RustCompilerMirType,
    all: &BTreeMap<&str, &RustCompilerMirType>,
    body_definition_id: &str,
) -> Result<()> {
    validate_text("typed MIR type kind", &ty.kind)?;
    if ty
        .arguments
        .iter()
        .any(|argument| !all.contains_key(argument.as_str()))
    {
        bail!("typed MIR type arguments are non-canonical or dangling");
    }
    if let Some(definition) = &ty.definition_id {
        validate_digest(definition)?;
        if definition != body_definition_id {
            validate_digest(definition)?;
        }
    }
    if let Some(mutability) = &ty.mutability
        && !matches!(mutability.as_str(), "mutable" | "immutable")
    {
        bail!("typed MIR type mutability is invalid");
    }
    if let Some(value) = &ty.value {
        validate_text("typed MIR type value", value)?;
    }
    if let Some(reason) = &ty.unsupported_reason {
        validate_reason_code(reason)?;
    }
    if ty.type_id
        != digest_json(&(
            ty.kind.as_str(),
            &ty.arguments,
            &ty.definition_id,
            &ty.mutability,
            &ty.value,
            &ty.unsupported_reason,
        ))?
    {
        bail!("typed MIR type identity is invalid");
    }
    Ok(())
}

fn validate_type_depth<'a>(
    id: &'a str,
    all: &BTreeMap<&'a str, &'a RustCompilerMirType>,
    active: &mut BTreeSet<&'a str>,
    depth: usize,
) -> Result<()> {
    if depth > MAX_TYPE_DEPTH {
        bail!("typed MIR type exceeds its nesting depth limit");
    }
    if !active.insert(id) {
        bail!("typed MIR type graph contains a cycle");
    }
    let ty = all.get(id).context("typed MIR type is dangling")?;
    for argument in &ty.arguments {
        validate_type_depth(argument, all, active, depth + 1)?;
    }
    active.remove(id);
    Ok(())
}

fn validate_constant(
    constant: &RustCompilerMirConstant,
    body: &RustCompilerMirBody,
    types: &BTreeMap<&str, &RustCompilerMirType>,
    workspace: &Path,
    cargo_home: &Path,
) -> Result<()> {
    validate_text("typed MIR constant kind", &constant.kind)?;
    if !types.contains_key(constant.type_id.as_str()) {
        bail!("typed MIR constant has a dangling type");
    }
    if let Some(value) = &constant.value {
        validate_text("typed MIR constant value", value)?;
    }
    if let Some(definition) = &constant.definition_id {
        validate_digest(definition)?;
    }
    if let Some(reason) = &constant.unsupported_reason {
        validate_reason_code(reason)?;
    }
    validate_span(&constant.span, workspace, cargo_home)?;
    if constant.constant_id
        != digest_json(&(
            body.body_id.as_str(),
            constant.type_id.as_str(),
            constant.kind.as_str(),
            &constant.value,
            &constant.definition_id,
            &constant.unsupported_reason,
            &constant.span,
        ))?
    {
        bail!("typed MIR constant identity is invalid");
    }
    Ok(())
}

fn validate_place(
    place: &RustCompilerMirPlace,
    body: &RustCompilerMirBody,
    locals: &BTreeSet<&str>,
    types: &BTreeMap<&str, &RustCompilerMirType>,
) -> Result<()> {
    if !locals.contains(place.local_id.as_str()) || !types.contains_key(place.type_id.as_str()) {
        bail!("typed MIR place has a dangling local or type");
    }
    if place.projections.len() > MAX_TYPE_DEPTH {
        bail!("typed MIR place exceeds its projection depth limit");
    }
    for projection in &place.projections {
        validate_text("typed MIR projection kind", &projection.kind)?;
        if projection
            .type_id
            .as_ref()
            .is_some_and(|value| !types.contains_key(value.as_str()))
            || projection
                .local_id
                .as_ref()
                .is_some_and(|value| !locals.contains(value.as_str()))
        {
            bail!("typed MIR projection has a dangling identity");
        }
    }
    if place.place_id
        != digest_json(&(
            body.body_id.as_str(),
            place.local_id.as_str(),
            &place.projections,
            place.type_id.as_str(),
        ))?
    {
        bail!("typed MIR place identity is invalid");
    }
    Ok(())
}

fn validate_span(span: &RustCompilerMirSpan, workspace: &Path, cargo_home: &Path) -> Result<()> {
    validate_source_identity(
        &span.source_path,
        &span.source_sha256,
        workspace,
        cargo_home,
    )?;
    if span.start_line == 0
        || span.start_column == 0
        || span.end_line == 0
        || span.end_column == 0
        || (span.end_line, span.end_column) < (span.start_line, span.start_column)
    {
        bail!("typed MIR span is malformed");
    }
    let source = resolve_source(&span.source_path, workspace, cargo_home)?;
    let metadata = fs::metadata(&source)?;
    if metadata.len() > MAX_SOURCE_BYTES {
        bail!("typed MIR span source exceeds its byte limit");
    }
    let line_count = fs::read_to_string(source)
        .context("typed MIR span source is not UTF-8")?
        .lines()
        .count()
        .max(1);
    if usize::try_from(span.end_line).unwrap_or(usize::MAX) > line_count {
        bail!("typed MIR span exceeds its source");
    }
    Ok(())
}

fn validate_source_identity(
    logical: &str,
    expected_digest: &str,
    workspace: &Path,
    cargo_home: &Path,
) -> Result<()> {
    validate_digest(expected_digest)?;
    let source = resolve_source(logical, workspace, cargo_home)?;
    let metadata = fs::symlink_metadata(&source).context("typed MIR source is unavailable")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("typed MIR source is not a regular file");
    }
    let canonical = source
        .canonicalize()
        .context("typed MIR source is unavailable")?;
    let expected_root = if logical.starts_with("repo://") {
        workspace
    } else {
        cargo_home
    };
    if !canonical.starts_with(expected_root) || digest_file(&canonical)? != expected_digest {
        bail!("typed MIR source identity is invalid");
    }
    Ok(())
}

fn resolve_source(
    logical: &str,
    workspace: &Path,
    cargo_home: &Path,
) -> Result<std::path::PathBuf> {
    let (root, relative) = if let Some(relative) = logical.strip_prefix("repo://") {
        (workspace, relative)
    } else if let Some(relative) = logical.strip_prefix("cargo-home://") {
        (cargo_home, relative)
    } else {
        bail!("typed MIR source path is not confined");
    };
    validate_relative_path(relative)?;
    Ok(root.join(relative))
}

fn validate_relative_path(value: &str) -> Result<()> {
    validate_text("typed MIR source path", value)?;
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        bail!("typed MIR source path is not canonical");
    }
    Ok(())
}

fn validate_reason_code(value: &str) -> Result<()> {
    if !matches!(
        value,
        "unsupported_type"
            | "unsupported_constant"
            | "unsupported_statement"
            | "unsupported_terminator"
            | "unsupported_projection"
            | "generated_span"
            | "external_span"
            | "depth_limit"
            | "count_limit"
    ) {
        bail!("typed MIR unsupported reason code is unknown");
    }
    Ok(())
}

fn validate_sorted_ids<'a>(values: impl Iterator<Item = &'a str>, label: &str) -> Result<()> {
    let values = values.collect::<Vec<_>>();
    for value in &values {
        validate_digest(value)?;
    }
    if !values.windows(2).all(|window| window[0] < window[1]) {
        bail!("{label} must be strictly sorted and unique");
    }
    Ok(())
}

fn validate_sorted_ordinals(values: impl Iterator<Item = u32>, label: &str) -> Result<()> {
    let values = values.collect::<Vec<_>>();
    if values
        .iter()
        .enumerate()
        .any(|(index, value)| usize::try_from(*value).ok() != Some(index))
    {
        bail!("{label} ordinals must be contiguous and canonical");
    }
    Ok(())
}

fn canonical_directory(path: &Path, label: &str) -> Result<std::path::PathBuf> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("{label} is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("{label} is not a real directory");
    }
    path.canonicalize()
        .with_context(|| format!("{label} is unavailable"))
}

fn reject_forbidden_serialized_text(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes).context("typed MIR DTO is not UTF-8")?;
    let lower = text.to_ascii_lowercase();
    if ["defid(", "tyctxt", "allocid(", "threadlocalindex", "0x"]
        .iter()
        .any(|marker| lower.contains(marker))
        || secret_shaped_text(text)
    {
        bail!("typed MIR DTO contains forbidden compiler, address, or secret text");
    }
    Ok(())
}

fn validate_text(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
        || Path::new(value).is_absolute()
        || is_portable_windows_absolute(value)
        || value.contains("file://")
        || contains_parent_traversal(value)
        || secret_shaped_text(value)
    {
        bail!("{label} is invalid, unbounded, or unconfined");
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

fn is_portable_windows_absolute(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

fn secret_shaped_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "authorization:",
        "bearer ",
        "password=",
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
}

fn validate_digest(value: &str) -> Result<()> {
    if !is_digest(value) {
        bail!("typed MIR digest is invalid");
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn digest_file(path: &Path) -> Result<String> {
    Ok(digest_bytes(&fs::read(path)?))
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
    use crate::{
        compiler_invocation::RustCompilerInvocation,
        compiler_precise::{RustCargoProfile, RustCargoStrip, RustCargoTarget, RustCargoUnit},
    };

    fn fixture(
        root: &Path,
    ) -> Result<(
        RustCompilerMirUnit,
        RustCompilerInvocation,
        RustCargoUnit,
        CompilerPackAttestation,
    )> {
        fs::create_dir_all(root.join("src"))?;
        fs::write(root.join("src/lib.rs"), "pub fn fixture() {}\n")?;
        let source_sha256 = digest_file(&root.join("src/lib.rs"))?;
        let span = RustCompilerMirSpan {
            source_path: "repo://src/lib.rs".to_owned(),
            source_sha256: source_sha256.clone(),
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 1,
        };
        let definition = RustCompilerMirDefinition {
            definition_id: digest_json(&(
                "fixture::fixture",
                span.source_path.as_str(),
                span.source_sha256.as_str(),
                1_u32,
                1_u32,
                1_u32,
                1_u32,
            ))?,
            path: "fixture::fixture".to_owned(),
            span: span.clone(),
        };
        let target = RustCargoTarget {
            kind: vec!["lib".to_owned()],
            crate_types: vec!["lib".to_owned()],
            name: "fixture".to_owned(),
            src_path: "repo://src/lib.rs".to_owned(),
            edition: "2024".to_owned(),
            doc: true,
            doctest: true,
            test: true,
        };
        let profile = RustCargoProfile {
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
        };
        let unit_id = "cargo-unit:fixture".to_owned();
        let package_id = "path:fixture#0.1.0".to_owned();
        let target_digest = digest_json(&target)?;
        let profile_digest = digest_json(&profile)?;
        let body_id = digest_json(&(
            unit_id.as_str(),
            package_id.as_str(),
            target_digest.as_str(),
            profile_digest.as_str(),
            RustCompilerMirBodyKind::Function,
            &definition,
        ))?;
        let ty = RustCompilerMirType {
            type_id: digest_json(&(
                "unit",
                Vec::<String>::new(),
                Option::<String>::None,
                Option::<String>::None,
                Option::<String>::None,
                Option::<String>::None,
            ))?,
            kind: "unit".to_owned(),
            arguments: Vec::new(),
            definition_id: None,
            mutability: None,
            value: None,
            unsupported_reason: None,
        };
        let local = RustCompilerMirLocal {
            local_id: digest_json(&(body_id.as_str(), "local", 0_u32))?,
            ordinal: 0,
            role: "return".to_owned(),
            type_id: ty.type_id.clone(),
            span: span.clone(),
        };
        let place = RustCompilerMirPlace {
            place_id: digest_json(&(
                body_id.as_str(),
                local.local_id.as_str(),
                Vec::<RustCompilerMirProjection>::new(),
                ty.type_id.as_str(),
            ))?,
            local_id: local.local_id.clone(),
            projections: Vec::new(),
            type_id: ty.type_id.clone(),
        };
        let block_id = digest_json(&(body_id.as_str(), "block", 0_u32))?;
        let operation = RustCompilerMirOperation {
            operation_id: digest_json(&(body_id.as_str(), block_id.as_str(), 0_u32, "return"))?,
            ordinal: 0,
            kind: "return".to_owned(),
            span: span.clone(),
            places: Vec::new(),
            constants: Vec::new(),
            unsupported_reason: None,
        };
        let body = RustCompilerMirBody {
            body_id,
            kind: RustCompilerMirBodyKind::Function,
            definition,
            span: span.clone(),
            types: vec![ty],
            constants: Vec::new(),
            locals: vec![local],
            places: vec![place],
            blocks: vec![RustCompilerMirBlock {
                block_id,
                ordinal: 0,
                operations: vec![operation],
                successors: Vec::new(),
            }],
        };
        let pack = CompilerPackAttestation {
            contract_version: "compiler-precise-rust-v1".to_owned(),
            host: "x86_64-unknown-linux-gnu".to_owned(),
            target: "x86_64-unknown-linux-gnu".to_owned(),
            manifest_sha256: "a".repeat(64),
            closed_tree_sha256: "b".repeat(64),
            cargo_sha256: "c".repeat(64),
            rustc_sha256: "d".repeat(64),
            wrapper_sha256: "e".repeat(64),
            query_sha256: "f".repeat(64),
        };
        let invocation = RustCompilerInvocation {
            unit_id: unit_id.clone(),
            invocation_id: "1".repeat(64),
            invocation_digest: "2".repeat(64),
            crate_name: "fixture".to_owned(),
            crate_types: vec!["lib".to_owned()],
            source_path: span.source_path.clone(),
            source_sha256: source_sha256.clone(),
            profile_digest: profile_digest.clone(),
            edition: "2024".to_owned(),
            target: Some("x86_64-unknown-linux-gnu".to_owned()),
            mode: "build".to_owned(),
            features: Vec::new(),
            canonical_argv: vec!["--crate-name".to_owned()],
            argv_digest: "3".repeat(64),
            rustc_sha256: pack.rustc_sha256.clone(),
            rustc_verbose_sha256: "4".repeat(64),
            terminal_status: "completed".to_owned(),
            exit_code: 0,
        };
        let graph_unit = RustCargoUnit {
            unit_id: unit_id.clone(),
            package_id: package_id.clone(),
            target,
            profile,
            platform: invocation.target.clone(),
            mode: "build".to_owned(),
            features: Vec::new(),
            is_std: false,
            dependencies: Vec::new(),
        };
        let mut unit = RustCompilerMirUnit {
            schema_version: COMPILER_PRECISE_MIR_SCHEMA_VERSION.to_owned(),
            digest: String::new(),
            attempt_digest: "5".repeat(64),
            invocation_id: invocation.invocation_id.clone(),
            unit_id,
            package_id,
            target_digest,
            source_path: span.source_path,
            source_sha256,
            profile_digest,
            compiler_pack_manifest_sha256: pack.manifest_sha256.clone(),
            rustc_commit: COMPILER_PACK_RUSTC_COMMIT.to_owned(),
            query_capabilities: vec!["typed_mir".to_owned()],
            bodies: vec![body],
            unsupported: Vec::new(),
        };
        unit.digest = compiler_mir_unit_digest(&unit)?;
        Ok((unit, invocation, graph_unit, pack))
    }

    #[test]
    fn typed_mir_golden_is_checkout_and_repeat_deterministic() -> Result<()> {
        let first = tempfile::tempdir()?;
        let second = tempfile::tempdir()?;
        let cargo_first = tempfile::tempdir()?;
        let cargo_second = tempfile::tempdir()?;
        let output_first = tempfile::tempdir()?;
        let output_second = tempfile::tempdir()?;
        let (first_unit, first_invocation, first_graph, first_pack) = fixture(first.path())?;
        let (second_unit, second_invocation, second_graph, second_pack) = fixture(second.path())?;
        fs::write(
            output_first
                .path()
                .join(format!("mir-{}.json", first_unit.invocation_id)),
            canonical_json_bytes(&first_unit)?,
        )?;
        fs::write(
            output_second
                .path()
                .join(format!("mir-{}.json", second_unit.invocation_id)),
            canonical_json_bytes(&second_unit)?,
        )?;
        let first_graph = RustCargoUnitGraph {
            schema_version: "depgraph-rust-cargo-unit-graph-v1".to_owned(),
            digest: "7".repeat(64),
            roots: vec![first_graph.unit_id.clone()],
            units: vec![first_graph],
        };
        let second_graph = RustCargoUnitGraph {
            schema_version: "depgraph-rust-cargo-unit-graph-v1".to_owned(),
            digest: "7".repeat(64),
            roots: vec![second_graph.unit_id.clone()],
            units: vec![second_graph],
        };
        let first_invocations = RustCompilerInvocationLedger {
            schema_version: "depgraph-rust-compiler-invocation-ledger-v1".to_owned(),
            digest: "6".repeat(64),
            attempt_digest: first_unit.attempt_digest.clone(),
            unit_graph_digest: first_graph.digest.clone(),
            entries: vec![first_invocation],
        };
        let second_invocations = RustCompilerInvocationLedger {
            schema_version: "depgraph-rust-compiler-invocation-ledger-v1".to_owned(),
            digest: "6".repeat(64),
            attempt_digest: second_unit.attempt_digest.clone(),
            unit_graph_digest: second_graph.digest.clone(),
            entries: vec![second_invocation],
        };
        let first_ledger = validate_compiler_mir_directory(
            output_first.path(),
            first.path(),
            cargo_first.path(),
            &first_graph,
            &first_invocations,
            &first_pack,
        )?;
        let second_ledger = validate_compiler_mir_directory(
            output_second.path(),
            second.path(),
            cargo_second.path(),
            &second_graph,
            &second_invocations,
            &second_pack,
        )?;
        assert_eq!(
            canonical_json_bytes(&first_unit)?,
            canonical_json_bytes(&second_unit)?
        );
        assert_eq!(first_unit.digest, second_unit.digest);
        assert_eq!(
            canonical_json_bytes(&first_ledger)?,
            canonical_json_bytes(&second_ledger)?
        );
        assert_eq!(first_ledger.digest, second_ledger.digest);
        let unit_schema: serde_json::Value = serde_json::from_str(COMPILER_PRECISE_MIR_SCHEMA)?;
        let ledger_schema: serde_json::Value =
            serde_json::from_str(COMPILER_PRECISE_MIR_LEDGER_SCHEMA)?;
        assert!(
            jsonschema::validator_for(&unit_schema)?.is_valid(&serde_json::to_value(&first_unit)?)
        );
        assert!(
            jsonschema::validator_for(&ledger_schema)?
                .is_valid(&serde_json::to_value(&first_ledger)?)
        );
        Ok(())
    }

    #[test]
    fn typed_mir_rejects_malformed_dangling_unknown_oversized_and_internal_data() -> Result<()> {
        let checkout = tempfile::tempdir()?;
        let cargo_home = tempfile::tempdir()?;
        let (unit, invocation, graph, pack) = fixture(checkout.path())?;

        let mut malformed = unit.clone();
        malformed.bodies[0].span.end_line = 99;
        malformed.digest = compiler_mir_unit_digest(&malformed)?;
        assert!(
            validate_unit(
                &malformed,
                &invocation,
                &graph,
                &pack,
                &malformed.attempt_digest,
                checkout.path(),
                cargo_home.path(),
            )
            .is_err()
        );

        let mut dangling = unit.clone();
        dangling.bodies[0].places[0].type_id = "9".repeat(64);
        dangling.digest = compiler_mir_unit_digest(&dangling)?;
        assert!(
            validate_unit(
                &dangling,
                &invocation,
                &graph,
                &pack,
                &dangling.attempt_digest,
                checkout.path(),
                cargo_home.path(),
            )
            .is_err()
        );

        let mut unknown = serde_json::to_value(&unit)?;
        unknown
            .as_object_mut()
            .context("fixture unit is not an object")?
            .insert("raw_def_id".to_owned(), serde_json::json!("DefId(7)"));
        assert!(serde_json::from_value::<RustCompilerMirUnit>(unknown).is_err());
        let mut unknown_schema = unit.clone();
        unknown_schema.schema_version = "depgraph-rust-compiler-precise-v2".to_owned();
        unknown_schema.digest = compiler_mir_unit_digest(&unknown_schema)?;
        assert!(
            validate_unit(
                &unknown_schema,
                &invocation,
                &graph,
                &pack,
                &unknown_schema.attempt_digest,
                checkout.path(),
                cargo_home.path(),
            )
            .is_err()
        );
        assert!(reject_forbidden_serialized_text(b"{\"value\":\"TyCtxt\"}").is_err());

        let directory = tempfile::tempdir()?;
        let oversized = directory
            .path()
            .join(format!("mir-{}.json", "1".repeat(64)));
        let file = fs::File::create(oversized)?;
        file.set_len(MAX_UNIT_FILE_BYTES + 1)?;
        let ledger = RustCompilerInvocationLedger {
            schema_version: "depgraph-rust-compiler-invocation-ledger-v1".to_owned(),
            digest: "6".repeat(64),
            attempt_digest: unit.attempt_digest,
            unit_graph_digest: "7".repeat(64),
            entries: vec![invocation],
        };
        let graph = RustCargoUnitGraph {
            schema_version: "depgraph-rust-cargo-unit-graph-v1".to_owned(),
            digest: ledger.unit_graph_digest.clone(),
            units: vec![graph],
            roots: vec!["cargo-unit:fixture".to_owned()],
        };
        assert!(
            validate_compiler_mir_directory(
                directory.path(),
                checkout.path(),
                cargo_home.path(),
                &graph,
                &ledger,
                &pack,
            )
            .is_err()
        );
        Ok(())
    }

    fn canonical_json_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(value)?;
        sort_json(&mut value);
        Ok(serde_json::to_vec(&value)?)
    }
}
